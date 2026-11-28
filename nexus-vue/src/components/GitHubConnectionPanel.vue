<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, onUnmounted, ref, watch } from 'vue';
import {
  api,
  type GitHubConnection,
  type GitHubWorkflow,
  type GitHubSubmission,
  type GitHubRun,
} from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import { toolEnabled } from '@/lib/tool-preferences';
import GitHubProviderRunners from '@/components/GitHubProviderRunners.vue';
import GitHubRunPanel from '@/components/GitHubRunPanel.vue';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';
const GitHubWebhookPanel = defineAsyncComponent(() => import('@/components/GitHubWebhookPanel.vue'));
const GitHubWorkflowEditor = defineAsyncComponent(() => import('@/components/GitHubWorkflowEditor.vue'));
const editingPath = ref('');
const props = defineProps<{ serverId: string }>(),
  { confirm } = useConfirm();
const connections = ref<GitHubConnection[]>([]),
  workflows = ref<GitHubWorkflow[]>([]),
  history = ref<GitHubSubmission[]>([]),
  runs = ref<GitHubRun[]>([]),
  inspectedRun = ref(0);
const selected = ref(''),
  workflow = ref(0),
  refName = ref('main'),
  inputs = ref('{}'),
  privateKey = ref(''),
  owner = ref(''),
  repository = ref(''),
  repositoryId = ref<number>(),
  clientId = ref(''),
  installationId = ref<number>();
const busy = ref(false),
  error = ref(''),
  pending = ref(''),
  page = ref(1),
  total = ref(0),
  runPage = ref(1),
  runTotal = ref(0);
let generation = 0,
  alive = true;
const readable = computed(() => can('github.actions.read', props.serverId));
const manageable = computed(
  () =>
    readable.value &&
    can('github.connections.manage', props.serverId) &&
    can('secrets.create', props.serverId) &&
    can('secrets.use', props.serverId),
);
const dispatchable = computed(
  () =>
    readable.value && can('github.actions.dispatch', props.serverId) && can('secrets.use', props.serverId),
);
const connection = computed(() =>
  connections.value.find((row) => row.id === selected.value && !row.disabled),
);
function clear() {
  generation++;
  privateKey.value = '';
  inputs.value = '{}';
  connections.value = [];
  workflows.value = [];
  history.value = [];
  runs.value = [];
  inspectedRun.value = 0;
  editingPath.value = '';
  selected.value = '';
  workflow.value = 0;
  pending.value = '';
}
watch(
  () =>
    [
      props.serverId,
      readable.value,
      manageable.value,
      dispatchable.value,
      can('secrets.use', props.serverId),
    ].join(','),
  clear,
  { flush: 'sync' },
);
watch(
  selected,
  () => {
    generation++;
    workflows.value = [];
    runs.value = [];
    inspectedRun.value = 0;
    editingPath.value = '';
    workflow.value = 0;
    inputs.value = '{}';
    privateKey.value = '';
    page.value = 1;
    runPage.value = 1;
    total.value = 0;
    runTotal.value = 0;
  },
  { flush: 'sync' },
);
onUnmounted(() => {
  alive = false;
  clear();
});
async function perform(work: (version: number) => Promise<void>) {
  if (busy.value || !readable.value) return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  try {
    await work(version);
  } catch (e) {
    if (alive && version === generation)
      error.value = e instanceof Error ? e.message : 'GitHub operation unavailable.';
  } finally {
    if (alive) busy.value = false;
  }
}
function current(version: number) {
  return alive && version === generation;
}
async function load() {
  privateKey.value = '';
  await perform(async (version) => {
    const [list, submissions] = await Promise.all([
      api.githubActions.connections(props.serverId),
      api.githubActions.history(props.serverId),
    ]);
    if (current(version)) {
      connections.value = list;
      history.value = submissions;
      if (
        submissions.some(
          (row) => row.id === pending.value && ['submitted', 'not_submitted'].includes(row.state),
        )
      )
        pending.value = '';
      if (!pending.value)
        pending.value =
          submissions.find((row) => ['prepared', 'submitting', 'unknown'].includes(row.state))?.id ?? '';
    }
  });
}
async function create() {
  if (!manageable.value) return;
  await perform(async (version) => {
    const pem = privateKey.value;
    privateKey.value = '';
    const row = await api.githubActions.create(props.serverId, {
      owner: owner.value.trim(),
      name: repository.value.trim(),
      repositoryId: repositoryId.value ?? 0,
      clientId: clientId.value.trim(),
      installationId: installationId.value ?? 0,
      privateKey: pem,
    });
    if (current(version)) {
      connections.value.unshift(row);
    }
  });
}
async function browse(kind: 'workflows' | 'runs', next: number) {
  if (!connection.value || !can('secrets.use', props.serverId)) return;
  await perform(async (version) => {
    if (kind === 'workflows') {
      const result = await api.githubActions.workflows(props.serverId, selected.value, next);
      if (current(version)) {
        workflows.value = result.workflows;
        total.value = result.total_count;
        page.value = next;
      }
    } else {
      const result = await api.githubActions.runs(props.serverId, selected.value, next);
      if (current(version)) {
        runs.value = result.workflow_runs;
        runTotal.value = result.total_count;
        runPage.value = next;
        inspectedRun.value = 0;
      }
    }
  });
}
function inspectJobs(id: number) {
  inspectedRun.value = id;
}
async function disable() {
  if (!connection.value || !manageable.value) return;
  const id = selected.value,
    version = generation;
  if (
    !(await confirm({
      title: 'Disable GitHub connection?',
      message:
        'Stop using this connection for new API operations. Existing GitHub workflows continue independently. History and encrypted credentials are retained.',
      confirmText: 'Disable connection',
      destructive: true,
    }))
  )
    return;
  if (!current(version)) return;
  await perform(async (v) => {
    await api.githubActions.disable(props.serverId, id);
    if (current(v)) {
      const row = connections.value.find((row) => row.id === id);
      if (row) row.disabled = true;
      workflows.value = [];
      runs.value = [];
      inspectedRun.value = 0;
      editingPath.value = '';
    }
  });
}
async function dispatch() {
  if (
    busy.value ||
    pending.value ||
    !dispatchable.value ||
    !connection.value ||
    !workflow.value ||
    workflows.value.find((row) => row.id === workflow.value)?.state !== 'active'
  )
    return;
  let values: Record<string, string | boolean>;
  try {
    const parsed = JSON.parse(inputs.value);
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed) ||
      Object.keys(parsed).length > 25 ||
      Object.values(parsed).some((value) => typeof value !== 'string' && typeof value !== 'boolean')
    )
      throw new Error();
    values = parsed;
  } catch {
    error.value =
      'Use a JSON object of up to 25 string/boolean inputs. GitHub validates these against the workflow declaration.';
    return;
  }
  const version = generation,
    id = selected.value,
    workflowId = workflow.value,
    reference = refName.value;
  if (
    !(await confirm({
      title: 'Dispatch GitHub workflow?',
      message: `Trigger workflow ${workflowId} in ${connection.value.owner}/${connection.value.name} at named ref ${reference}? Branches and tags can move. This can execute workflow code and does not grant Nexus deployment authority.`,
      confirmText: 'Dispatch once',
      destructive: true,
    }))
  )
    return;
  if (!current(version) || busy.value || !dispatchable.value) return;
  const requestId = crypto.randomUUID().replaceAll('-', '');
  pending.value = requestId;
  inputs.value = '{}';
  busy.value = true;
  error.value = '';
  try {
    const result = await api.githubActions.dispatch(props.serverId, id, {
      requestId,
      workflowId,
      ref: reference,
      inputs: values,
    });
    if (current(version)) {
      history.value.unshift(result.submission);
      if (['submitted', 'not_submitted'].includes(result.submission.state)) pending.value = '';
      else
        error.value = 'Submission unconfirmed. Inspect GitHub and retained history before another dispatch.';
    }
  } catch (e) {
    if (current(version)) {
      const failed = e as { status?: number };
      if ([400, 401, 403, 409].includes(failed.status ?? 0)) pending.value = '';
      error.value =
        (e instanceof Error ? e.message : 'Submission unconfirmed.') + ' Retained request ' + requestId + '.';
    }
  } finally {
    if (alive) busy.value = false;
  }
}
async function acknowledge() {
  if (
    await confirm({
      title: 'Allow a new dispatch?',
      message:
        'Only continue after checking GitHub for the earlier request. A new request can create another workflow run. The old request will never be replayed.',
      confirmText: 'I checked GitHub',
    })
  )
    pending.value = '';
}
onMounted(load);
</script>
<template>
  <section aria-label="GitHub repository connection" class="space-y-4 border-t pt-3">
    <div class="flex justify-between">
      <h3 class="font-medium">Repository connections</h3>
      <Button :disabled="busy" variant="outline" @click="load">Refresh connections</Button>
    </div>
    <p v-if="error" role="alert" class="text-sm">{{ error }}</p>
    <details v-if="manageable" class="border rounded p-3">
      <summary>Add GitHub App connection</summary>
      <p class="text-sm my-3">
        Install your GitHub App for the selected repository. Grant Actions read/write, Contents read and
        Metadata read. The App key is encrypted at rest and never revealed; repository-restricted installation
        tokens are minted only for each operation. No personal access token is saved.
      </p>
      <form class="grid sm:grid-cols-2 gap-3" @submit.prevent="create">
        <label>Repository owner<Input v-model="owner" required :disabled="busy" /></label
        ><label>Repository name<Input v-model="repository" required :disabled="busy" /></label
        ><label
          >Repository numeric ID<Input
            v-model.number="repositoryId"
            type="number"
            min="1"
            required
            :disabled="busy" /></label
        ><label>GitHub App client ID<Input v-model="clientId" required :disabled="busy" /></label
        ><label
          >Installation ID<Input
            v-model.number="installationId"
            type="number"
            min="1"
            required
            :disabled="busy" /></label
        ><label class="sm:col-span-2"
          >App private key (PEM)<textarea
            v-model="privateKey"
            rows="5"
            required
            spellcheck="false"
            autocomplete="off"
            :disabled="busy"
            class="block w-full rounded border p-2 bg-background font-mono text-xs"
          /></label
        ><Button type="submit" :disabled="busy">Verify and save connection</Button>
      </form>
    </details>
    <label
      >Connection<select
        v-model="selected"
        aria-label="GitHub connection"
        :disabled="busy"
        class="block border rounded p-2 bg-background w-full"
      >
        <option value="">Choose repository</option>
        <option v-for="row in connections" :key="row.id" :value="row.id" :disabled="row.disabled">
          {{ row.owner }}/{{ row.name }}{{ row.disabled ? ' (disabled)' : '' }}
        </option>
      </select></label
    >
    <template v-if="connection">
      <GitHubWebhookPanel
        :key="connection.id"
        :server-id="serverId"
        :connection-id="connection.id"
        @inspect="inspectedRun = $event"
      />
      <div class="flex gap-2 flex-wrap">
        <Button :disabled="busy || !can('secrets.use', serverId)" @click="browse('workflows', 1)"
          >List workflows</Button
        ><Button
          :disabled="busy || !can('secrets.use', serverId)"
          variant="outline"
          @click="browse('runs', 1)"
          >List workflow runs</Button
        ><Button v-if="manageable" :disabled="busy" variant="destructive" @click="disable"
          >Disable connection</Button
        >
      </div>
      <label v-if="workflows.length"
        >Workflow<select
          v-model.number="workflow"
          aria-label="GitHub workflow"
          :disabled="busy"
          class="block border rounded p-2 bg-background w-full"
        >
          <option :value="0">Choose workflow</option>
          <option v-for="row in workflows" :key="row.id" :value="row.id">
            {{ row.name }} · {{ row.path }} · {{ row.state }}
          </option>
        </select></label
      >
      <div v-if="total > 50" class="flex gap-2">
        <Button :disabled="busy || page <= 1" @click="browse('workflows', page - 1)"
          >Previous workflows</Button
        ><Button :disabled="busy || page * 50 >= total" @click="browse('workflows', page + 1)"
          >Next workflows</Button
        >
      </div>
      <Button
        v-if="workflow && can('github.workflows.read', serverId)"
        variant="outline"
        :disabled="busy"
        @click="editingPath = workflows.find((row) => row.id === workflow)?.path ?? ''"
        >Review workflow YAML</Button
      >
      <GitHubWorkflowEditor
        v-if="editingPath && can('github.workflows.read', serverId)"
        :key="selected + editingPath"
        :server-id="serverId"
        :connection-id="selected"
        :repository="connection.owner + '/' + connection.name"
        :workflow-path="editingPath"
      />
      <GitHubProviderRunners
        v-if="toolEnabled('runners') && can('github.runners.provider.read', serverId)"
        :key="selected"
        :server-id="serverId"
        :connection-id="selected"
        :repository="connection.owner + '/' + connection.name"
      />
      <template
        v-if="
          dispatchable && workflow && workflows.some((row) => row.id === workflow && row.state === 'active')
        "
        ><label>Branch or tag<Input v-model="refName" :disabled="busy" /></label
        ><label
          >Workflow inputs (JSON)<textarea
            v-model="inputs"
            autocomplete="off"
            spellcheck="false"
            :disabled="busy"
            rows="4"
            class="block w-full rounded border p-2 bg-background font-mono text-xs"
          />
        </label>
        <p class="text-xs">
          Use repository secrets for sensitive values. Only string/boolean inputs are supported here; GitHub
          validates declared inputs. Named refs are mutable. No dispatch retries automatically.
        </p>
        <Button :disabled="busy || !!pending" @click="dispatch">Dispatch selected workflow</Button></template
      >
      <div v-if="pending" class="text-sm">
        <p class="break-all">Retained request: {{ pending }}</p>
        <Button :disabled="busy" variant="outline" @click="acknowledge">I checked the earlier request</Button>
      </div>
      <div v-for="run in runs" :key="run.id" class="border rounded p-3 text-sm">
        <p>Run {{ run.id }} · {{ run.status }} · {{ run.conclusion ?? 'pending' }} · {{ run.head_branch }}</p>
        <p class="font-mono break-all">{{ run.head_sha }}</p>
        <Button :disabled="busy" variant="outline" @click="inspectJobs(run.id)">Inspect jobs</Button
        ><a
          :href="`https://github.com/${connection.owner}/${connection.name}/actions/runs/${run.id}`"
          target="_blank"
          rel="noopener noreferrer"
          class="underline ml-3"
          >Open in GitHub</a
        >
      </div>
      <div v-if="runTotal > 50" class="flex gap-2">
        <Button :disabled="busy || runPage <= 1" @click="browse('runs', runPage - 1)">Previous runs</Button
        ><Button :disabled="busy || runPage * 50 >= runTotal" @click="browse('runs', runPage + 1)"
          >Next runs</Button
        >
      </div>
      <GitHubRunPanel
        v-if="inspectedRun"
        :key="selected + ':' + inspectedRun"
        :server-id="serverId"
        :connection-id="selected"
        :run-id="inspectedRun"
      />
    </template>
    <h4 class="font-medium">Dispatch history</h4>
    <p v-for="row in history" :key="row.id" class="text-sm break-all">
      {{ row.id }} · {{ new Date(row.createdAt).toLocaleString() }} · {{ row.state }} · workflow
      {{ row.workflowId }} · {{ row.ref }} ·
      {{ row.runId ? `GitHub run ${row.runId}` : 'no confirmed run ID' }}
    </p>
  </section>
</template>
