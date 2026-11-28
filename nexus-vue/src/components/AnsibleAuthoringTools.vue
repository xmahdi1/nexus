<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue';
import {
  api,
  type AnsibleBundle,
  type AnsibleProjectTemplate,
  type AnsibleRevision,
  type GitHubConnection,
} from '@/lib/api';
import { can } from '@/lib/auth';
import { checkAnsibleBundle } from '@/lib/ansible-checks';
import { useConfirm } from '@/composables/useConfirm';
import Button from './ui/Button.vue';
import Input from './ui/Input.vue';
const props = defineProps<{ serverId: string; projectId: string; bundle: AnsibleBundle }>();
const emit = defineEmits<{ load: [bundle: AnsibleBundle]; imported: [revision: AnsibleRevision] }>();
const { confirm } = useConfirm();
const templates = ref<AnsibleProjectTemplate[]>([]),
  repositories = ref<GitHubConnection[]>([]);
const templateId = ref(''),
  name = ref(''),
  connectionId = ref(''),
  commitSha = ref(''),
  paths = ref('main.yml'),
  main = ref('main.yml');
const busy = ref(false),
  error = ref(''),
  notice = ref('');
let generation = 0,
  alive = true;
const editable = computed(() => can('ansible.projects.manage', props.serverId));
const revealable = computed(
  () => can('ansible.projects.read', props.serverId) && can('secrets.reveal', props.serverId),
);
const importable = computed(
  () =>
    editable.value &&
    can('github.projects.read', props.serverId) &&
    can('secrets.use', props.serverId) &&
    can('secrets.create', props.serverId),
);
const checks = computed(() => checkAnsibleBundle(props.bundle));
function clear() {
  generation++;
  templates.value = [];
  repositories.value = [];
  templateId.value = '';
  connectionId.value = '';
  commitSha.value = '';
  error.value = '';
  notice.value = '';
}
watch(
  () =>
    [
      props.serverId,
      props.projectId,
      editable.value,
      revealable.value,
      importable.value,
      can('secrets.create', props.serverId),
    ].join(','),
  clear,
  { flush: 'sync' },
);
onUnmounted(() => {
  alive = false;
  clear();
});
function current(version: number) {
  return alive && version === generation && editable.value;
}
async function perform(work: (version: number) => Promise<void>) {
  if (busy.value || !editable.value) return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  notice.value = '';
  try {
    await work(version);
  } catch (e) {
    if (current(version)) error.value = e instanceof Error ? e.message : 'Project helper unavailable.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function listTemplates() {
  await perform(async (version) => {
    const result = await api.playbooks.templates(props.serverId);
    if (current(version)) templates.value = result;
  });
}
async function saveTemplate() {
  if (!can('secrets.create', props.serverId)) return;
  const before = generation,
    snapshot = JSON.parse(JSON.stringify(props.bundle)) as AnsibleBundle,
    templateName = name.value;
  if (
    !(await confirm({
      title: 'Save a reusable project template?',
      message:
        'Save these files, variables and collection locks as a new template? This does not save targets or approvals and starts no job.',
      confirmText: 'Save template',
    }))
  )
    return;
  if (!current(before) || busy.value || !can('secrets.create', props.serverId)) return;
  await perform(async (version) => {
    const result = await api.playbooks.createTemplate(props.serverId, templateName, snapshot);
    if (current(version)) {
      templates.value.unshift(result);
      name.value = '';
      notice.value =
        'Template saved. Each use still needs a revision and an independently approved target plan.';
    }
  });
}
async function loadTemplate() {
  if (!revealable.value || !templateId.value) return;
  const before = generation,
    id = templateId.value,
    baseline = JSON.stringify(props.bundle);
  if (
    !(await confirm({
      title: 'Load template content?',
      message:
        'Reveal its saved files and replace the current editor draft? Unsaved edits will be lost. No job will run.',
      confirmText: 'Load template',
    }))
  )
    return;
  if (!current(before) || busy.value || !revealable.value) return;
  await perform(async (version) => {
    const result = await api.playbooks.templateContent(props.serverId, id);
    if (current(version) && revealable.value) {
      if (JSON.stringify(props.bundle) !== baseline) {
        notice.value = 'The draft changed while loading. Save it before loading the template again.';
        return;
      }
      emit('load', result);
    }
  });
}
async function archiveTemplate() {
  const before = generation,
    id = templateId.value;
  if (
    !id ||
    !(await confirm({
      title: 'Archive this template?',
      message:
        'Keep its saved definition but prevent future loading. Existing project revisions are unaffected.',
      confirmText: 'Archive',
    }))
  )
    return;
  if (!current(before) || busy.value) return;
  await perform(async (version) => {
    await api.playbooks.archiveTemplate(props.serverId, id);
    if (current(version))
      templates.value = templates.value.map((row) => (row.id === id ? { ...row, archived: true } : row));
  });
}
async function listRepositories() {
  if (importable.value)
    await perform(async (version) => {
      const rows = await api.githubActions.connections(props.serverId);
      if (current(version) && importable.value) repositories.value = rows;
    });
}
async function importRevision() {
  if (!importable.value || !connectionId.value) return;
  const before = generation,
    id = props.projectId;
  const input = {
    connectionId: connectionId.value,
    commitSha: commitSha.value.trim(),
    main: main.value.trim(),
    paths: paths.value
      .split('\n')
      .map((p) => p.trim())
      .filter(Boolean),
    variables: JSON.parse(JSON.stringify(props.bundle.variables)),
    collections: JSON.parse(JSON.stringify(props.bundle.collections ?? [])),
  };
  if (
    !(await confirm({
      title: 'Import this GitHub revision?',
      message:
        'Import only the selected files at this exact commit into a saved project revision? Review the content before preparing a target plan. No code executes during import.',
      confirmText: 'Import revision',
    }))
  )
    return;
  if (!current(before) || busy.value || !importable.value) return;
  await perform(async (version) => {
    const result = await api.playbooks.importRevision(props.serverId, id, input);
    if (current(version) && importable.value) {
      emit('imported', result);
      notice.value = 'Imported a saved revision. Load and review its content before preparing a plan.';
    }
  });
}
</script>
<template>
  <section v-if="editable" aria-label="Ansible project helpers" class="space-y-3">
    <details class="border rounded p-3">
      <summary>Project checks · {{ checks.length }} findings</summary>
      <p class="text-sm my-2">
        Local YAML and authoring checks. These do not execute Jinja or plugins and do not replace Ansible
        syntax/check mode or independent review.
      </p>
      <p v-if="!checks.length" class="text-sm">No findings from these checks.</p>
      <ul class="text-sm space-y-1">
        <li v-for="(issue, i) in checks" :key="i">
          {{ issue.file }}:{{ issue.line }} · {{ issue.level }} · {{ issue.message }}
        </li>
      </ul>
    </details>
    <p v-if="error" role="alert" class="text-sm">{{ error }}</p>
    <p v-if="notice" role="status" class="text-sm">{{ notice }}</p>
    <details class="border rounded p-3 space-y-3">
      <summary>Reusable project templates</summary>
      <Button variant="outline" :disabled="busy" @click="listTemplates">List project templates</Button>
      <form v-if="can('secrets.create', serverId)" class="flex gap-2" @submit.prevent="saveTemplate">
        <Input v-model="name" placeholder="Template name" required :disabled="busy" /><Button
          type="submit"
          :disabled="busy"
          >Save current draft as template</Button
        >
      </form>
      <label class="block text-sm"
        >Template<select
          v-model="templateId"
          aria-label="Ansible project template"
          :disabled="busy"
          class="block w-full border rounded bg-background p-2"
        >
          <option value="">Choose template</option>
          <option v-for="row in templates" :key="row.id" :value="row.id" :disabled="row.archived">
            {{ row.name }}{{ row.archived ? ' (archived)' : '' }}
          </option>
        </select></label
      >
      <div class="flex gap-2">
        <Button :disabled="busy || !templateId || !revealable" @click="loadTemplate"
          >Reveal and load template</Button
        ><Button variant="outline" :disabled="busy || !templateId" @click="archiveTemplate"
          >Archive template</Button
        >
      </div>
    </details>
    <details v-if="importable" class="border rounded p-3 space-y-3">
      <summary>Import files from GitHub</summary>
      <p class="text-sm">
        Use a repository App connection saved for this controller scope with Contents read and the
        github-projects-reader role. Enter an exact commit SHA and one path per line. Regular files only; no
        symlinks, submodules, hidden paths or ansible.cfg. Limits: 32 files, 16 KiB per file, 32 KiB combined.
        The repository tree must fit the bounded GitHub response.
      </p>
      <Button variant="outline" :disabled="busy" @click="listRepositories"
        >Load repository connections</Button
      >
      <label class="block text-sm"
        >Repository connection<select
          v-model="connectionId"
          aria-label="Ansible source repository"
          :disabled="busy"
          class="block w-full border rounded bg-background p-2"
        >
          <option value="">Choose repository</option>
          <option v-for="row in repositories" :key="row.id" :value="row.id" :disabled="row.disabled">
            {{ row.owner }}/{{ row.name }}
          </option>
        </select></label
      >
      <label class="block text-sm"
        >Exact commit SHA<Input v-model="commitSha" required :disabled="busy"
      /></label>
      <label class="block text-sm"
        >Main playbook path<Input v-model="main" required :disabled="busy"
      /></label>
      <label class="block text-sm"
        >Selected repository files<textarea
          v-model="paths"
          rows="4"
          :disabled="busy"
          class="block w-full border rounded bg-background p-2 font-mono text-xs"
        />
      </label>
      <p class="text-sm">
        The current editor’s variable declarations and collection locks are included. The selected files keep
        their repository paths. Import starts no job.
      </p>
      <Button :disabled="busy || !connectionId || !commitSha || !paths" @click="importRevision"
        >Import saved revision</Button
      >
    </details>
  </section>
</template>
