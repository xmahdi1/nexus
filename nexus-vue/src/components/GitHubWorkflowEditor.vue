<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type GitHubWorkflowFile, type GitHubChange } from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import { yamlIssues } from '@/lib/yaml-assist';
import { workflowDiff } from '@/lib/workflow-diff';
import YamlTextEditor from '@/components/YamlTextEditor.vue';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';
const props = defineProps<{
  serverId: string;
  connectionId: string;
  repository: string;
  workflowPath: string;
}>();
const { confirm } = useConfirm();
const branch = ref('main'),
  content = ref(''),
  title = ref('Update workflow'),
  snapshot = ref<GitHubWorkflowFile>(),
  history = ref<GitHubChange[]>([]),
  pending = ref(''),
  busy = ref(false),
  error = ref(''),
  epoch = ref(0),
  reviewed = ref(false);
let generation = 0,
  alive = true;
const readable = computed(
  () => can('github.workflows.read', props.serverId) && can('secrets.use', props.serverId),
);
const writable = computed(() => readable.value && can('github.workflows.write', props.serverId));
const sameBranch = computed(() => !!snapshot.value && snapshot.value.baseBranch === branch.value);
const diff = computed(() => (snapshot.value ? workflowDiff(snapshot.value.content, content.value) : ''));
const issues = computed(() => yamlIssues(content.value));
const ready = computed(
  () =>
    !!snapshot.value &&
    sameBranch.value &&
    writable.value &&
    !busy.value &&
    !pending.value &&
    !!diff.value &&
    reviewed.value &&
    title.value.trim().length > 0 &&
    title.value.length <= 120 &&
    new TextEncoder().encode(content.value).length <= 32768 &&
    !issues.value.some((issue) => issue.severity === 'error'),
);
function clear() {
  generation++;
  snapshot.value = undefined;
  content.value = '';
  history.value = [];
  pending.value = '';
  reviewed.value = false;
  epoch.value++;
}
watch(
  () => [props.serverId, props.connectionId, props.workflowPath, readable.value, writable.value].join(','),
  clear,
  { flush: 'sync' },
);
watch([content, title], () => {
  reviewed.value = false;
});
onUnmounted(() => {
  alive = false;
  clear();
});
function current(version: number) {
  return alive && version === generation;
}
async function historyOnly() {
  if (!readable.value) return;
  const version = generation;
  try {
    const rows = await api.githubActions.changes(props.serverId);
    if (current(version)) {
      history.value = rows.filter(
        (row) => row.connectionId === props.connectionId && row.kind === 'workflow_edit',
      );
      if (
        history.value.some(
          (row) => row.id === pending.value && ['applied', 'not_submitted', 'incomplete'].includes(row.state),
        )
      )
        pending.value = '';
      if (!pending.value)
        pending.value =
          history.value.find((row) => !['applied', 'not_submitted', 'incomplete'].includes(row.state))?.id ??
          '';
    }
  } catch (e) {
    if (current(version)) error.value = e instanceof Error ? e.message : 'Change history unavailable.';
  }
}
async function open() {
  if (busy.value || !readable.value) return;
  const version = generation,
    name = branch.value;
  if (
    diff.value &&
    !(await confirm({
      title: 'Discard workflow draft?',
      message: 'Opening the file replaces this in-memory draft. It does not change GitHub.',
      confirmText: 'Open workflow',
    }))
  )
    return;
  if (!current(version)) return;
  busy.value = true;
  error.value = '';
  try {
    const file = await api.githubActions.workflowFile(
      props.serverId,
      props.connectionId,
      name,
      props.workflowPath,
    );
    if (current(version) && branch.value === name) {
      snapshot.value = file;
      content.value = file.content;
      reviewed.value = false;
      epoch.value++;
    }
  } catch (e) {
    if (current(version)) error.value = e instanceof Error ? e.message : 'Workflow could not be opened.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function publish() {
  if (!ready.value || !snapshot.value) return;
  const version = generation,
    input = {
      ...snapshot.value,
      content: content.value,
      title: title.value.trim(),
    };
  if (
    !(await confirm({
      title: 'Create workflow draft PR?',
      message: `Create a new branch and draft pull request for ${props.workflowPath} in ${props.repository}, based on ${input.baseBranch} at ${input.baseSha}? Pushing a branch or opening a PR may trigger GitHub workflows. Nothing is merged or deployed by Nexus. Partial changes remain if a later step fails.`,
      confirmText: 'Create draft PR',
      destructive: true,
    }))
  )
    return;
  if (!current(version) || busy.value || !writable.value) return;
  const requestId = crypto.randomUUID().replaceAll('-', '');
  pending.value = requestId;
  busy.value = true;
  error.value = '';
  try {
    const result = await api.githubActions.publishWorkflow(props.serverId, props.connectionId, {
      ...input,
      requestId,
    });
    if (!current(version)) return;
    history.value.unshift(result.change);
    if (['applied', 'not_submitted', 'incomplete'].includes(result.change.state)) pending.value = '';
    if (result.change.state === 'applied') {
      snapshot.value = undefined;
      content.value = '';
      epoch.value++;
    } else
      error.value = `Change ${result.change.state} at ${result.change.phase || 'preparation'}. Check GitHub and the saved branch before another request.`;
    reviewed.value = false;
  } catch (e) {
    if (current(version))
      error.value =
        (e instanceof Error ? e.message : 'Change unconfirmed.') + ' Retained request ' + requestId + '.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function acknowledge() {
  const version = generation;
  if (
    (await confirm({
      title: 'Allow a new workflow change?',
      message:
        'Check GitHub for the saved branch, commit and pull request first. A new request can create another branch and PR. The old request is never replayed.',
      confirmText: 'I checked GitHub',
    })) &&
    current(version)
  )
    pending.value = '';
}
onMounted(historyOnly);
</script>
<template>
  <section aria-label="GitHub workflow editor" class="border rounded p-4 space-y-3">
    <h4 class="font-medium">Review workflow YAML</h4>
    <p class="font-mono text-xs break-all">{{ repository }} / {{ workflowPath }}</p>
    <p class="text-sm">
      Open an existing workflow, edit it and review the diff. Publishing creates a new branch and draft PR. It
      does not write to the selected base branch or merge. GitHub may run workflows after a push or PR.
    </p>
    <div class="flex gap-2 items-end">
      <label class="flex-1 text-sm">Workflow base branch<Input v-model="branch" :disabled="busy" /></label
      ><Button variant="outline" :disabled="busy || !readable" @click="open">Open workflow</Button>
    </div>
    <p v-if="error" role="alert" class="text-sm text-destructive">
      {{ error }}
    </p>
    <p v-if="snapshot" class="text-xs font-mono break-all">
      Reviewed base {{ snapshot.baseSha }} · file {{ snapshot.blobSha }}
    </p>
    <p v-if="snapshot && !sameBranch" class="text-sm">Open the new branch before editing or publishing.</p>
    <YamlTextEditor
      v-if="snapshot"
      :key="epoch"
      v-model="content"
      profile="github"
      :readonly="busy || !writable || !sameBranch"
      label="Workflow YAML content"
    />
    <p v-for="(issue, index) in issues" :key="index" class="text-xs">
      {{ issue.severity }}: {{ issue.message }}
    </p>
    <p v-if="snapshot" class="text-xs">
      Maximum 32 KiB. Syntax suggestions do not certify a valid or safe workflow. Keep credentials in GitHub
      secrets.
    </p>
    <template v-if="snapshot && writable"
      ><label class="text-sm block"
        >Pull request title<Input v-model="title" :disabled="busy" maxlength="120"
      /></label>
      <details :open="!!diff">
        <summary>Workflow diff</summary>
        <pre
          class="text-xs whitespace-pre-wrap break-all max-h-96 overflow-auto border rounded p-3"
          aria-label="Workflow diff"
          >{{ diff || 'No changes.' }}</pre>
      </details>
      <label class="flex gap-2 text-sm"
        ><input v-model="reviewed" type="checkbox" :disabled="!diff || busy" />I reviewed this workflow diff
        and title</label
      ><Button :disabled="!ready" @click="publish">Create draft PR</Button></template
    >
    <div v-if="pending" class="text-sm break-all">
      <p>Retained workflow request: {{ pending }}</p>
      <Button variant="outline" :disabled="busy" @click="acknowledge">I checked the workflow change</Button>
    </div>
    <Button variant="outline" :disabled="busy || !readable" @click="historyOnly"
      >Refresh workflow changes</Button
    >
    <div v-for="row in history" :key="row.id" class="text-xs break-all border rounded p-2 space-y-1">
      <p>{{ row.id }} · {{ row.state }} · {{ row.phase }}</p>
      <p v-if="row.branch">Branch {{ row.branch }} · {{ row.commitSha }}</p>
      <a
        v-if="row.pullNumber"
        :href="`https://github.com/${repository}/pull/${row.pullNumber}`"
        target="_blank"
        rel="noopener noreferrer"
        class="underline"
        >Open draft PR {{ row.pullNumber }}</a
      >
    </div>
  </section>
</template>
