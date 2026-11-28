<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import {
  api,
  type AnsiblePreset,
  type AnsibleProject,
  type AnsibleRevision,
  type AnsibleBundle,
  type AnsibleCollectionLock,
  type AnsibleVariable,
  type AnsiblePlan,
  type AnsiblePlanView,
  type AnsiblePlanOptions,
  type AnsibleVaultReference,
  type Server,
} from '@/lib/api';
import { can, canAny } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';
import AnsibleVaultReferenceFields from '@/components/AnsibleVaultReference.vue';
import AnsibleRunsPanel from '@/components/AnsibleRunsPanel.vue';
import AnsibleOrchestrationPanel from '@/components/AnsibleOrchestrationPanel.vue';
import AnsibleAuthoringTools from '@/components/AnsibleAuthoringTools.vue';

const props = defineProps<{
  serverId: string;
  servers?: Server[];
  vaultEnabled?: boolean;
}>();
const { confirm } = useConfirm();
const projects = ref<AnsibleProject[]>([]),
  revisions = ref<AnsibleRevision[]>([]),
  plans = ref<AnsiblePlan[]>([]);
const projectId = ref(''),
  revisionId = ref(''),
  newName = ref(''),
  actor = ref(''),
  busy = ref(false),
  error = ref('');
const files = ref<Record<string, string>>({
  'main.yml':
    '---\n- hosts: all\n  gather_facts: false\n  tasks:\n    - name: Check connectivity\n      ansible.builtin.ping:\n',
});
const collections = ref<AnsibleCollectionLock[]>([]);
const main = ref('main.yml'),
  activeFile = ref('main.yml'),
  fileName = ref(''),
  schema = ref<AnsibleVariable[]>([]),
  loaded = ref<AnsibleBundle | null>(null);
const review = ref<{ plan: AnsiblePlanView; bundle: AnsibleBundle } | null>(null);
const groups = ref<Array<{ id: string; name: string }>>([]),
  groupId = ref(''),
  targets = ref<Array<{ id: string; host: string; user: string; port: number }>>([]),
  selected = ref<string[]>([]);
const presets = ref<AnsiblePreset[]>([]),
  presetId = ref(''),
  activePresetId = ref(''),
  presetName = ref('');
const notice = ref('');
const mode = ref<'syntax' | 'check' | 'apply'>('check'),
  timeout = ref(300),
  tags = ref(''),
  skipTags = ref('');
const strings = ref<Record<string, string>>({}),
  booleans = ref<Record<string, boolean>>({}),
  vaultValues = ref<Record<string, AnsibleVaultReference>>({});
const useVaultPassword = ref(false),
  vaultPassword = ref<AnsibleVaultReference>(newRef());
let generation = 0,
  alive = true;
const readable = computed(() => can('ansible.projects.read', props.serverId));
const editable = computed(() => can('ansible.projects.manage', props.serverId));
const revealable = computed(() => readable.value && can('secrets.reveal', props.serverId));
const preparable = computed(() => readable.value && can('ansible.playbooks.execute', props.serverId));
const approvable = computed(() => revealable.value && can('ansible.playbooks.approve', props.serverId));
const revision = computed(() => revisions.value.find((row) => row.id === revisionId.value));
const project = computed(() => projects.value.find((row) => row.id === projectId.value));
const vaultServers = computed(() =>
  (props.servers ?? []).filter((server) =>
    ['integrations.manage', 'servers.connect', 'secrets.use'].every((p) => can(p, server.id)),
  ),
);
function newRef(): AnsibleVaultReference {
  return {
    serverId: '',
    mount: 'secret',
    path: '',
    field: 'password',
    version: 1,
  };
}
function clear() {
  generation++;
  presets.value = [];
  presetId.value = '';
  activePresetId.value = '';
  presetName.value = '';
  projects.value = [];
  revisions.value = [];
  plans.value = [];
  loaded.value = null;
  review.value = null;
  files.value = {};
  schema.value = [];
  collections.value = [];
  strings.value = {};
  booleans.value = {};
  vaultValues.value = {};
  useVaultPassword.value = false;
  vaultPassword.value = newRef();
  targets.value = [];
  selected.value = [];
  busy.value = false;
}
watch(
  () =>
    [
      props.serverId,
      readable.value,
      revealable.value,
      editable.value,
      preparable.value,
      approvable.value,
    ].join(','),
  clear,
  { flush: 'sync' },
);
watch(
  () => [projectId.value, revisionId.value],
  () => {
    activePresetId.value = '';
  },
  { flush: 'sync' },
);
watch(groupId, () => {
  targets.value = [];
  selected.value = [];
});
onUnmounted(() => {
  alive = false;
  clear();
});
function failure(e: unknown) {
  error.value = e instanceof Error ? e.message : 'Ansible operation unavailable.';
}
async function perform(work: (server: string, current: number) => Promise<void>) {
  if (busy.value || !readable.value) return;
  const current = ++generation,
    server = props.serverId;
  busy.value = true;
  error.value = '';
  notice.value = '';
  try {
    await work(server, current);
  } catch (e) {
    if (alive && current === generation) {
      if ([401, 403, 404].includes((e as { status?: number })?.status ?? 0)) clear();
      failure(e);
    }
  } finally {
    if (alive && current === generation) busy.value = false;
  }
}
function current(version: number) {
  return alive && version === generation;
}
async function load() {
  await perform(async (server, version) => {
    const [nextProjects, nextPlans, me, nextPresets] = await Promise.all([
      api.playbooks.projects(server),
      api.playbooks.plans(server),
      api.auth.me(),
      api.playbooks.presets(server),
    ]);
    if (!current(version)) return;
    projects.value = nextProjects;
    presets.value = nextPresets;
    plans.value = nextPlans;
    actor.value = me.user.id;
    if (canAny('ansible.inventory.read')) {
      const nextGroups = await api.ansible.groups();
      if (current(version)) groups.value = nextGroups;
    }
  });
}
async function chooseProject() {
  revisions.value = [];
  revisionId.value = '';
  loaded.value = null;
  review.value = null;
  await perform(async (server, version) => {
    if (!projectId.value) return;
    const next = await api.playbooks.revisions(server, projectId.value);
    if (current(version)) revisions.value = next;
  });
}
async function create() {
  await perform(async (server, version) => {
    const row = await api.playbooks.create(server, newName.value);
    if (current(version)) {
      projects.value.unshift(row);
      projectId.value = row.id;
      revisions.value = [];
      revisionId.value = '';
      newName.value = '';
      loaded.value = null;
    }
  });
}
function addFile() {
  const name = fileName.value.trim();
  if (!name || files.value[name] !== undefined) return;
  files.value[name] = '';
  activeFile.value = name;
  fileName.value = '';
}
function addVariable() {
  schema.value.push({ name: '', kind: 'string', required: true, choices: [] });
}
function kindChanged(variable: AnsibleVariable) {
  if (variable.kind !== 'choice') variable.choices = [];
}
function loadValues(bundle: AnsibleBundle) {
  loaded.value = bundle;
  strings.value = {};
  booleans.value = {};
  vaultValues.value = {};
  for (const v of bundle.variables) {
    if (v.kind === 'vault') vaultValues.value[v.name] = newRef();
    else if (v.kind === 'boolean') booleans.value[v.name] = false;
    else strings.value[v.name] = '';
  }
}
async function publish() {
  await perform(async (server, version) => {
    const bundle: AnsibleBundle = {
      main: main.value,
      files: { ...files.value },
      collections: collections.value.map((c) => ({ ...c })),
      variables: schema.value.map((v) => ({
        ...v,
        choices: v.kind === 'choice' ? v.choices : [],
      })),
    };
    const row = await api.playbooks.publish(server, projectId.value, bundle);
    if (current(version)) {
      revisions.value.unshift(row);
      revisionId.value = row.id;
      loadValues(bundle);
    }
  });
}
async function revealRevision() {
  if (!revision.value || !revealable.value) return;
  if (
    !(await confirm({
      title: 'Reveal saved playbook?',
      message:
        'Load the saved project files and variable schema into this editor? They may contain sensitive content. The action is audited.',
      confirmText: 'Reveal content',
    }))
  )
    return;
  await perform(async (server, version) => {
    const bundle = await api.playbooks.content(server, projectId.value, revisionId.value);
    if (current(version)) {
      files.value = { ...bundle.files };
      main.value = bundle.main;
      activeFile.value = bundle.main;
      schema.value = bundle.variables.map((v) => ({ ...v }));
      collections.value = (bundle.collections ?? []).map((c) => ({ ...c }));
      loadValues(bundle);
    }
  });
}
async function previewTargets() {
  await perform(async (_server, version) => {
    const result = await api.ansible.preview(groupId.value);
    if (current(version)) {
      selected.value = [];
      targets.value = Object.values(result.inventory._meta.hostvars)
        .filter((host) => host.nexus_server_id !== props.serverId)
        .map((host) => ({
          id: host.nexus_server_id,
          host: host.ansible_host,
          user: host.ansible_user,
          port: host.ansible_port,
        }));
    }
  });
}
function variables() {
  const values: Record<string, unknown> = {};
  for (const v of loaded.value?.variables ?? []) {
    if (v.kind === 'boolean') values[v.name] = booleans.value[v.name] ?? false;
    else if (v.kind === 'vault') {
      const ref = vaultValues.value[v.name];
      if (ref?.serverId || v.required) values[v.name] = ref;
    } else {
      const text = strings.value[v.name] ?? '';
      if (v.kind === 'integer' && v.required && text.trim() === '')
        throw new Error('Enter an integer for ' + v.name);
      if (text !== '' || v.required) values[v.name] = v.kind === 'integer' ? Number(text) : text;
    }
  }
  return values;
}
async function prepare() {
  if (!revision.value || !loaded.value) return;
  const chosen = revision.value;
  await perform(async (server, version) => {
    const options: AnsiblePlanOptions = {
      mode: mode.value,
      tags: tags.value
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean),
      skipTags: skipTags.value
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean),
      verbosity: 0,
      timeoutSeconds: timeout.value,
      ...(useVaultPassword.value ? { vaultPassword: vaultPassword.value } : {}),
    };
    const row = activePresetId.value
      ? await api.playbooks.preparePreset(server, activePresetId.value, variables(), options.vaultPassword)
      : await api.playbooks.prepare(server, projectId.value, {
          revisionId: chosen.id,
          revisionDigest: chosen.digest,
          groupId: groupId.value,
          serverIds: [...selected.value],
          variables: variables(),
          options,
        });
    if (current(version)) {
      plans.value.unshift(row);
      notice.value = 'Frozen plan saved. A different authorized person must review and approve it.';
    }
  });
}
async function savePreset(plan: AnsiblePlan) {
  if (!editable.value || plan.actorId !== actor.value || !presetName.value.trim()) return;
  await perform(async (server, version) => {
    const row = await api.playbooks.createPreset(server, presetName.value.trim(), plan.id);
    if (current(version)) {
      presets.value.unshift(row);
      presetId.value = row.id;
      presetName.value = '';
      notice.value = 'Selection saved. Variable values, Vault password and approval were not copied.';
    }
  });
}
async function loadPreset() {
  if (busy.value || !presetId.value || !revealable.value || !preparable.value) return;
  const id = presetId.value,
    version = generation;
  if (
    !(await confirm({
      title: 'Load execution preset?',
      message:
        'Replace the planning form with the saved revision, targets and options? Project files will be revealed. Enter new variable values and request a new approval.',
      confirmText: 'Load preset',
    }))
  )
    return;
  if (!current(version) || busy.value || !revealable.value || !preparable.value) return;
  await perform(async (server, version) => {
    const draft = () =>
      JSON.stringify([
        projectId.value,
        revisionId.value,
        main.value,
        files.value,
        schema.value,
        collections.value,
      ]);
    const before = draft();
    const selection = await api.playbooks.presetContent(server, id);
    const [nextRevisions, bundle, preview] = await Promise.all([
      api.playbooks.revisions(server, selection.projectId),
      api.playbooks.content(server, selection.projectId, selection.revisionId),
      api.ansible.preview(selection.groupId),
    ]);
    if (!current(version)) return;
    if (before !== draft()) {
      notice.value = 'The draft changed while loading. Load the preset again to replace it.';
      return;
    }
    const rows = Object.values(preview.inventory._meta.hostvars)
      .filter((h) => h.nexus_server_id !== server)
      .map((h) => ({
        id: h.nexus_server_id,
        host: h.ansible_host,
        user: h.ansible_user,
        port: h.ansible_port,
      }));
    if (selection.serverIds.some((id) => !rows.some((row) => row.id === id)))
      throw new Error('A saved target is no longer available. Edit the selection and create a new preset.');
    projectId.value = selection.projectId;
    revisions.value = nextRevisions;
    revisionId.value = selection.revisionId;
    files.value = { ...bundle.files };
    main.value = bundle.main;
    activeFile.value = bundle.main;
    schema.value = bundle.variables.map((v) => ({ ...v }));
    collections.value = (bundle.collections ?? []).map((c) => ({ ...c }));
    loadValues(bundle);
    review.value = null;
    groupId.value = selection.groupId;
    await nextTick();
    if (!current(version)) return;
    targets.value = rows;
    selected.value = [...selection.serverIds];
    mode.value = selection.options.mode;
    timeout.value = selection.options.timeoutSeconds;
    tags.value = (selection.options.tags ?? []).join(',');
    skipTags.value = (selection.options.skipTags ?? []).join(',');
    useVaultPassword.value = false;
    vaultPassword.value = newRef();
    activePresetId.value = id;
    notice.value = 'Preset loaded. Enter new values, then save a fresh plan for independent review.';
  });
}
async function archivePreset() {
  if (!editable.value || !presetId.value || busy.value) return;
  const id = presetId.value,
    version = generation;
  if (
    !(await confirm({
      title: 'Archive execution preset?',
      message:
        'Prevent new plans from using this selection. Existing frozen plans and run history remain available.',
      confirmText: 'Archive preset',
    }))
  )
    return;
  if (!current(version) || busy.value || !editable.value) return;
  await perform(async (server, version) => {
    await api.playbooks.archivePreset(server, id);
    if (current(version)) {
      presets.value = presets.value.map((p) => (p.id === id ? { ...p, archived: true } : p));
      if (activePresetId.value === id) activePresetId.value = '';
      presetId.value = '';
    }
  });
}
async function revealPlan(plan: AnsiblePlan) {
  if (!revealable.value) return;
  if (
    !(await confirm({
      title: 'Reveal plan and playbook?',
      message:
        'Reveal the frozen variables, selected targets and exact saved project for review? Secret values written directly into files or variables may be visible. Vault references do not retrieve secrets here.',
      confirmText: 'Reveal review',
    }))
  )
    return;
  await perform(async (server, version) => {
    review.value = null;
    const [view, bundle] = await Promise.all([
      api.playbooks.reveal(server, plan.id),
      api.playbooks.content(server, plan.projectId, plan.revisionId),
    ]);
    if (current(version)) review.value = { plan: view, bundle };
  });
}
async function approve() {
  if (!review.value || !approvable.value) return;
  const item = review.value;
  await perform(async (server, version) => {
    const result = await api.playbooks.approve(server, item.plan);
    if (current(version)) {
      review.value = { ...item, plan: result };
      plans.value = plans.value.map((p) => (p.id === result.id ? result : p));
    }
  });
}
async function cancel(plan: AnsiblePlan) {
  if (!editable.value) return;
  await perform(async (server, version) => {
    await api.playbooks.cancel(server, plan.id);
    if (current(version)) {
      plans.value = plans.value.map((p) => (p.id === plan.id ? { ...p, state: 'cancelled' } : p));
      review.value = null;
    }
  });
}
async function archive() {
  if (!project.value || !editable.value) return;
  const id = project.value.id;
  if (
    !(await confirm({
      title: 'Archive this project?',
      message: 'Retain its revisions and cancel its prepared or approved plans.',
      confirmText: 'Archive',
      destructive: true,
    }))
  )
    return;
  await perform(async (server, version) => {
    await api.playbooks.archive(server, id);
    if (current(version)) {
      projects.value = projects.value.map((p) => (p.id === id ? { ...p, archived: true } : p));
      review.value = null;
      plans.value = await api.playbooks.plans(server);
    }
  });
}
function useTemplate(bundle: AnsibleBundle) {
  files.value = { ...bundle.files };
  main.value = bundle.main;
  activeFile.value = bundle.main;
  schema.value = bundle.variables.map((v) => ({
    ...v,
    choices: v.choices ? [...v.choices] : [],
  }));
  collections.value = (bundle.collections ?? []).map((c) => ({ ...c }));
  revisionId.value = '';
  loaded.value = null;
  review.value = null;
  notice.value = 'Template loaded as a draft. Publish and review a new revision before planning.';
}
function importedRevision(row: AnsibleRevision) {
  revisions.value.unshift(row);
  revisionId.value = row.id;
  loaded.value = null;
  review.value = null;
  notice.value = 'Imported a saved revision. Load and review its files before preparing a plan.';
}
onMounted(load);
</script>

<template>
  <section aria-label="Playbook project workspace" class="space-y-5 border-t pt-4">
    <div class="flex justify-between items-center">
      <h3 class="font-semibold">Projects and approved plans</h3>
      <Button variant="outline" :disabled="busy" @click="load">Refresh projects</Button>
    </div>
    <p v-if="error" role="alert" class="text-sm">{{ error }}</p>
    <p v-if="notice" role="status" class="text-sm">{{ notice }}</p>
    <section class="space-y-2 border rounded p-3" aria-label="Ansible execution presets">
      <h4 class="font-medium">Execution presets</h4>
      <p class="text-sm">
        Reuse a revision, target selection and run options. Variable values and approvals are entered again
        for each plan.
      </p>
      <label class="block text-sm"
        >Saved execution preset<select
          v-model="presetId"
          :disabled="busy"
          class="block w-full border rounded p-2 bg-background"
        >
          <option value="">Choose preset</option>
          <option v-for="p in presets.filter((p) => !p.archived)" :key="p.id" :value="p.id">
            {{ p.name }}
          </option>
        </select></label
      >
      <div class="flex gap-2">
        <Button :disabled="busy || !presetId || !revealable || !preparable" @click="loadPreset"
          >Load execution preset</Button
        >
        <Button v-if="editable" variant="outline" :disabled="busy || !presetId" @click="archivePreset"
          >Archive preset</Button
        >
      </div>
      <label v-if="editable" class="block text-sm"
        >New execution preset name<Input
          v-model="presetName"
          :disabled="busy"
          maxlength="80"
          placeholder="Save a selection from one of your plans below"
      /></label>
    </section>
    <form v-if="editable" class="flex gap-2" @submit.prevent="create">
      <Input v-model="newName" placeholder="New project name" :disabled="busy" required /><Button
        type="submit"
        :disabled="busy"
        >Create project</Button
      >
    </form>
    <label class="block text-sm"
      >Project<select
        v-model="projectId"
        :disabled="busy"
        class="block w-full border rounded p-2 bg-background"
        @change="chooseProject"
      >
        <option value="">Choose project</option>
        <option v-for="p in projects" :key="p.id" :value="p.id">
          {{ p.name }}{{ p.archived ? ' (archived)' : '' }}
        </option>
      </select></label
    >
    <template v-if="project">
      <div class="flex gap-2 items-center">
        <label class="flex-1 text-sm"
          >Immutable revision<select
            v-model="revisionId"
            :disabled="busy"
            class="block w-full border rounded p-2 bg-background"
            @change="
              loaded = null;
              review = null;
            "
          >
            <option value="">Choose revision</option>
            <option v-for="r in revisions" :key="r.id" :value="r.id">
              {{ new Date(r.createdAt).toLocaleString() }} ·
              {{ r.id.slice(0, 8) }}
            </option>
          </select></label
        ><Button :disabled="busy || !revision || !revealable" @click="revealRevision"
          >Load saved content</Button
        ><Button v-if="editable && !project.archived" variant="outline" :disabled="busy" @click="archive"
          >Archive</Button
        >
      </div>
      <p v-if="revision?.sourceCommitSha" class="text-xs break-all">
        Repository {{ revision.sourceRepositoryId }} · commit {{ revision.sourceCommitSha }} · connection
        {{ revision.sourceConnectionId }}
      </p>
      <AnsibleAuthoringTools
        v-if="editable && !project.archived"
        :key="project.id"
        :server-id="serverId"
        :project-id="project.id"
        :bundle="{ main, files, variables: schema, collections }"
        @load="useTemplate"
        @imported="importedRevision"
      />
      <details v-if="editable && !project.archived" class="border rounded p-3 space-y-3" open>
        <summary class="font-medium">Playbook editor</summary>
        <p class="text-xs text-muted-foreground">
          Publishing appends a new immutable revision. Review every task and vendored dependency; syntax
          checking does not prove safety. Prefer Vault references for passwords.
        </p>
        <div class="flex flex-wrap gap-2">
          <select v-model="activeFile" :disabled="busy" class="border rounded p-2 bg-background">
            <option v-for="(_, path) in files" :key="path" :value="path">
              {{ path }}
            </option></select
          ><Input v-model="fileName" placeholder="roles/web/tasks/main.yml" :disabled="busy" /><Button
            :disabled="busy"
            @click="addFile"
            >Add file</Button
          >
        </div>
        <label class="block text-sm"
          >File content<textarea
            v-if="activeFile in files"
            v-model="files[activeFile]"
            :disabled="busy"
            spellcheck="false"
            class="block w-full min-h-56 border rounded p-3 bg-background font-mono text-xs"
          />
        </label>
        <label class="block text-sm"
          >Entry playbook<select v-model="main" :disabled="busy" class="border rounded p-2 bg-background">
            <option v-for="(_, path) in files" :key="path" :value="path">
              {{ path }}
            </option>
          </select></label
        >
        <div class="space-y-2 border rounded p-3">
          <h4 class="font-medium text-sm">Collection locks</h4>
          <p class="text-xs">
            Optional: up to four exact versions with SHA-256 archive checksums. Stage reviewed archives in the
            controller cache first. Each approved run installs them privately without downloads or system
            changes. All collection dependencies must be locked too.
          </p>
          <div v-for="(collection, index) in collections" :key="index" class="grid sm:grid-cols-2 gap-2">
            <label class="text-xs">Namespace<Input v-model="collection.namespace" :disabled="busy" /></label>
            <label class="text-xs">Collection name<Input v-model="collection.name" :disabled="busy" /></label>
            <label class="text-xs"
              >Exact version<Input v-model="collection.version" :disabled="busy" placeholder="1.0.0"
            /></label>
            <label class="text-xs"
              >Archive SHA-256<Input v-model="collection.sha256" :disabled="busy"
            /></label>
            <Button variant="outline" :disabled="busy" @click="collections.splice(index, 1)"
              >Remove collection lock</Button
            >
          </div>
          <Button
            variant="outline"
            :disabled="busy || collections.length >= 4"
            @click="
              collections.push({
                namespace: '',
                name: '',
                version: '',
                sha256: '',
              })
            "
            >Add collection lock</Button
          >
        </div>
        <div class="space-y-2">
          <h4 class="font-medium text-sm">Declared run variables</h4>
          <div v-for="(variable, index) in schema" :key="index" class="flex flex-wrap gap-2 items-center">
            <Input v-model="variable.name" placeholder="variable_name" :disabled="busy" /><select
              v-model="variable.kind"
              :disabled="busy"
              class="border rounded p-2 bg-background"
              @change="kindChanged(variable)"
            >
              <option v-for="kind in ['string', 'integer', 'boolean', 'choice', 'vault']" :key="kind">
                {{ kind }}
              </option></select
            ><label class="text-sm"
              ><input v-model="variable.required" type="checkbox" :disabled="busy" /> Required</label
            ><Input
              v-if="variable.kind === 'choice'"
              :model-value="variable.choices?.join(', ')"
              placeholder="development, staging"
              :disabled="busy"
              @update:model-value="
                variable.choices = String($event)
                  .split(',')
                  .map((v) => v.trim())
                  .filter(Boolean)
              "
            /><Button variant="ghost" :disabled="busy" @click="schema.splice(index, 1)"
              >Remove variable</Button
            >
          </div>
          <Button variant="outline" :disabled="busy" @click="addVariable">Add variable</Button>
        </div>
        <Button :disabled="busy || !can('secrets.create', serverId)" @click="publish"
          >Publish new revision</Button
        >
      </details>
      <section v-if="preparable && !project.archived" class="space-y-3 border rounded p-3">
        <h4 class="font-medium">Freeze a target plan</h4>
        <p v-if="activePresetId" class="text-sm">
          Using a saved execution preset.
          <Button variant="outline" :disabled="busy" @click="activePresetId = ''">Edit selection</Button>
        </p>
        <p class="text-sm text-muted-foreground">
          Load or publish a revision, then select targets. The controller is excluded. Every selected host
          needs a verified SSH host-key pin and execution authority. New group members will not join this
          plan.
        </p>
        <div class="flex gap-2">
          <select
            aria-label="Automation group"
            v-model="groupId"
            :disabled="busy || !!activePresetId"
            class="border rounded p-2 bg-background"
          >
            <option value="">Choose automation group</option>
            <option v-for="g in groups" :key="g.id" :value="g.id">
              {{ g.name }}
            </option></select
          ><Button :disabled="busy || !!activePresetId || !groupId" @click="previewTargets"
            >Preview eligible targets</Button
          >
        </div>
        <label v-for="target in targets" :key="target.id" class="flex items-center gap-2 text-sm"
          ><input
            v-model="selected"
            type="checkbox"
            :value="target.id"
            :disabled="busy || !!activePresetId"
          />{{ target.id }} · {{ target.user }}@{{ target.host }}:{{ target.port }}</label
        >
        <p class="text-xs text-muted-foreground">{{ selected.length }} selected · maximum 10 per plan</p>
        <div v-for="variable in loaded?.variables ?? []" :key="variable.name" class="space-y-2">
          <label v-if="variable.kind === 'boolean'" class="text-sm"
            ><input v-model="booleans[variable.name]" type="checkbox" :disabled="busy" />
            {{ variable.name }}</label
          >
          <template v-else-if="variable.kind === 'vault'"
            ><p class="text-sm">{{ variable.name }} · Vault reference</p>
            <AnsibleVaultReferenceFields
              v-if="vaultValues[variable.name]"
              v-model="vaultValues[variable.name]"
              :servers="vaultServers"
              :disabled="busy || !vaultEnabled"
          /></template>
          <label v-else class="block text-sm"
            >{{ variable.name }}{{ variable.required ? ' *' : ''
            }}<select
              v-if="variable.kind === 'choice'"
              v-model="strings[variable.name]"
              :disabled="busy"
              class="block border rounded p-2 bg-background"
            >
              <option value="">Choose value</option>
              <option v-for="choice in variable.choices" :key="choice">
                {{ choice }}
              </option></select
            ><Input
              v-else
              v-model="strings[variable.name]"
              :disabled="busy"
              :type="variable.kind === 'integer' ? 'number' : 'text'"
          /></label>
        </div>
        <label class="block text-sm"
          ><input v-model="useVaultPassword" type="checkbox" :disabled="busy || !vaultEnabled" /> Use Vault
          for the Ansible Vault password</label
        >
        <AnsibleVaultReferenceFields
          v-if="useVaultPassword"
          v-model="vaultPassword"
          :servers="vaultServers"
          :disabled="busy || !vaultEnabled"
        />
        <p v-if="!vaultEnabled" class="text-xs text-muted-foreground">
          Vault references are optional. Enable and configure the Vault integration to use them.
        </p>
        <div class="flex flex-wrap gap-3 items-center">
          <label class="text-sm"
            >Mode<select
              v-model="mode"
              :disabled="busy || !!activePresetId"
              class="border rounded p-2 bg-background"
            >
              <option value="syntax">Syntax check</option>
              <option value="check">Check mode</option>
              <option value="apply">Apply</option>
            </select></label
          ><label class="text-sm"
            >Timeout (seconds)<input
              v-model.number="timeout"
              type="number"
              min="10"
              max="600"
              :disabled="busy || !!activePresetId"
              class="border rounded p-2 bg-background w-24" /></label
          ><Input
            v-model="tags"
            placeholder="Tags (comma separated)"
            :disabled="busy || !!activePresetId"
          /><Input v-model="skipTags" placeholder="Skip tags" :disabled="busy || !!activePresetId" />
        </div>
        <Button
          :disabled="busy || !loaded || !revision || !selected.length || selected.length > 10"
          @click="prepare"
          >Save frozen plan for review</Button
        >
        <p class="text-xs text-muted-foreground">
          Preparing a plan does not run or syntax-check a playbook, retrieve a Vault secret, or contact
          targets. Check mode can still have side effects when executed.
        </p>
      </section>
    </template>
    <section class="space-y-3">
      <h4 class="font-medium">Recent target plans</h4>
      <div v-for="plan in plans" :key="plan.id" class="border rounded p-3 text-sm space-y-2">
        <p class="font-mono break-all">{{ plan.id }}</p>
        <p>
          {{ plan.state }} · expires {{ new Date(plan.expiresAt).toLocaleString()
          }}{{ plan.actorId === actor ? ' · created by you' : '' }}
        </p>
        <Button
          v-if="editable && plan.actorId === actor"
          variant="outline"
          :disabled="busy || !presetName.trim() || !can('secrets.create', serverId)"
          @click="savePreset(plan)"
          >Save selection as preset</Button
        >
        <p v-if="plan.presetId" class="text-xs font-mono">Preset {{ plan.presetId }}</p>
        <div class="flex gap-2">
          <Button :disabled="busy || !revealable" @click="revealPlan(plan)">Review plan and revision</Button
          ><Button
            v-if="editable && plan.state !== 'cancelled'"
            :disabled="busy"
            variant="outline"
            @click="cancel(plan)"
            >Cancel plan</Button
          >
        </div>
      </div>
    </section>
    <section v-if="review" class="space-y-3 border rounded p-3">
      <div class="flex justify-between">
        <h4 class="font-medium">Exact frozen review</h4>
        <Button variant="ghost" @click="review = null">Hide review</Button>
      </div>
      <p class="text-sm">
        Controller {{ review.plan.serverId }} · {{ review.plan.options.mode }} ·
        {{ review.plan.targets.length }} frozen targets. Approval is invalidated by loss of current authority
        or changed target identity.
      </p>
      <pre class="text-xs whitespace-pre-wrap break-all max-h-96 overflow-auto">{{
        JSON.stringify(
          {
            targets: review.plan.targets,
            variables: review.plan.variables,
            options: review.plan.options,
            bundle: review.bundle,
          },
          null,
          2,
        )
      }}</pre>
      <p class="text-xs break-all">
        Revision {{ review.plan.revisionDigest }} · plan
        {{ review.plan.digest }}
      </p>
      <Button
        :disabled="busy || !approvable || review.plan.actorId === actor || review.plan.state !== 'prepared'"
        @click="approve"
        >Approve exact plan and revision</Button
      >
      <p v-if="review.plan.actorId === actor" class="text-sm">
        A different authorized person must approve your plan.
      </p>
    </section>
    <AnsibleOrchestrationPanel
      v-if="actor"
      :key="'queue:' + serverId + ':' + actor"
      :server-id="serverId"
      :actor-id="actor"
      :plan="review?.plan"
      @refresh="load"
    />
    <AnsibleRunsPanel
      v-if="actor"
      :key="serverId + ':' + actor"
      :server-id="serverId"
      :actor-id="actor"
      :plan="review?.plan"
    />
  </section>
</template>
