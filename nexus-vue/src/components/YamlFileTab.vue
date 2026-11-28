<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue';
import { api, type FileEntry } from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import {
  detectYamlProfile,
  isComposeDocument,
  profiles,
  yamlIssues,
  type YamlProfile,
} from '@/lib/yaml-assist';
import YamlTextEditor from '@/components/YamlTextEditor.vue';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';
const props = defineProps<{
  serverId: string;
  supervision: boolean;
  operate: (action: 'compose-up' | 'compose-down', path: string) => Promise<void>;
}>();
const { confirm } = useConfirm();
const path = ref('/root/docker-compose.yml'),
  content = ref(''),
  baseline = ref(''),
  loadedPath = ref(''),
  loadedTransport = ref<'compose' | 'files'>('compose'),
  format = ref<'auto' | YamlProfile>('auto');
const busy = ref(false),
  error = ref(''),
  status = ref(''),
  output = ref(''),
  editorEpoch = ref(0),
  writeUnconfirmed = ref(false),
  editor = ref<InstanceType<typeof YamlTextEditor>>();
const browserOpen = ref(false),
  directory = ref('/root'),
  entries = ref<FileEntry[]>([]);
let generation = 0,
  alive = true;
const profile = computed(() =>
  format.value === 'auto'
    ? detectYamlProfile(path.value, loadedPath.value === path.value ? content.value : '')
    : format.value,
);
const transport = computed(() =>
  'compose' === profile.value && can('compose.read', props.serverId) ? 'compose' : 'files',
);
const readable = computed(() =>
  can(transport.value === 'compose' ? 'compose.read' : 'files.read', props.serverId),
);
const writable = computed(
  () =>
    !!loadedPath.value &&
    can(loadedTransport.value === 'compose' ? 'compose.write' : 'files.write', props.serverId) &&
    can(loadedTransport.value === 'compose' ? 'compose.read' : 'files.read', props.serverId),
);
const dirty = computed(() => !!loadedPath.value && content.value !== baseline.value);
const issues = computed(() => yamlIssues(content.value)),
  syntaxValid = computed(() => !issues.value.some((issue) => issue.severity === 'error'));
const samePath = computed(() => path.value === loadedPath.value);
const deployable = computed(
  () =>
    samePath.value &&
    !dirty.value &&
    !writeUnconfirmed.value &&
    syntaxValid.value &&
    isComposeDocument(content.value) &&
    profile.value === 'compose' &&
    can('deployments.execute', props.serverId) &&
    can('compose.write', props.serverId) &&
    can('secrets.use', props.serverId) &&
    (!props.supervision || can('servers.execute', props.serverId)),
);
function clear() {
  generation++;
  content.value = '';
  baseline.value = '';
  loadedPath.value = '';
  output.value = '';
  writeUnconfirmed.value = false;
  entries.value = [];
  browserOpen.value = false;
  editorEpoch.value++;
}
watch(
  () =>
    [
      props.serverId,
      can('compose.read', props.serverId),
      can('files.read', props.serverId),
      can('secrets.use', props.serverId),
      can('secrets.reveal', props.serverId),
    ].join(','),
  clear,
  { flush: 'sync' },
);
watch(
  () => can('files.list', props.serverId),
  (allowed) => {
    if (!allowed) {
      generation++;
      entries.value = [];
      browserOpen.value = false;
    }
  },
  { flush: 'sync' },
);
onUnmounted(() => {
  alive = false;
  clear();
});
function current(version: number) {
  return alive && version === generation;
}
function validPath(value: string) {
  return (
    value.startsWith('/') &&
    /\.ya?ml$/i.test(value) &&
    // eslint-disable-next-line no-control-regex -- Reject control bytes in remote file paths.
    !/[\x00-\x1f\x7f]/.test(value) &&
    !value.split('/').includes('..') &&
    value.length <= 1024
  );
}
async function read(value: string, kind: 'compose' | 'files') {
  if (kind === 'compose') return (await api.compose.read(props.serverId, value)).content;
  const result = await api.files.preview(props.serverId, value);
  if (result.binary || result.truncated)
    throw new Error(
      'Open a complete UTF-8 YAML file of at most 256 KiB. Truncated previews cannot be edited.',
    );
  return result.content;
}
async function open() {
  if (busy.value || !readable.value) return;
  if (!validPath(path.value)) {
    error.value = 'Use an absolute .yml or .yaml path without traversal.';
    return;
  }
  const version = generation,
    value = path.value,
    kind = transport.value;
  if (
    dirty.value &&
    !(await confirm({
      title: 'Discard unsaved YAML edits?',
      message:
        'Opening another file replaces this in-memory draft. File contents are not saved in browser storage.',
      confirmText: 'Open file',
    }))
  )
    return;
  if (!current(version)) return;
  busy.value = true;
  error.value = '';
  output.value = '';
  status.value = '';
  try {
    const text = await read(value, kind);
    if (new TextEncoder().encode(text).length > 262144) throw new Error('Editor limit: 256 KiB.');
    if (current(version) && path.value === value) {
      content.value = text;
      baseline.value = text;
      loadedPath.value = value;
      loadedTransport.value = kind;
      writeUnconfirmed.value = false;
      editorEpoch.value++;
      status.value = 'File loaded.';
    }
  } catch (e) {
    if (current(version)) {
      if ([401, 403].includes((e as { status?: number }).status ?? 0)) clear();
      error.value = e instanceof Error ? e.message : 'File could not be loaded.';
    }
  } finally {
    if (alive) busy.value = false;
  }
}
async function save() {
  if (
    busy.value ||
    !writable.value ||
    writeUnconfirmed.value ||
    !samePath.value ||
    !dirty.value ||
    !syntaxValid.value
  )
    return;
  const version = generation,
    value = loadedPath.value,
    text = content.value,
    previous = baseline.value,
    kind = loadedTransport.value;
  if (
    !(await confirm({
      title: 'Replace YAML file?',
      message: `Replace ${value} on this server with the edited YAML? Keep a recovery copy for live configuration. Saving does not run Compose, Kubernetes or GitHub Actions.`,
      confirmText: 'Save YAML',
      destructive: true,
    }))
  )
    return;
  if (!current(version) || !writable.value || !samePath.value) return;
  busy.value = true;
  error.value = '';
  status.value = '';
  let attempted = false;
  try {
    const existing = await read(value, kind);
    if (!current(version) || !writable.value) return;
    if (existing !== previous)
      throw new Error(
        'The remote file changed since it was opened. Reopen and reconcile your edits before saving.',
      );
    attempted = true;
    if (kind === 'compose') await api.compose.write(props.serverId, value, text);
    else await api.files.write(props.serverId, value, text);
    if (current(version)) {
      baseline.value = text;
      status.value = 'YAML file saved.';
    }
  } catch (e) {
    if (current(version)) {
      writeUnconfirmed.value = attempted;
      error.value =
        (e instanceof Error ? e.message : 'Save could not be confirmed.') +
        (attempted ? ' Reopen the file to inspect server contents before another save or deployment.' : '');
    }
  } finally {
    if (alive) busy.value = false;
  }
}
async function deploy(action: 'up' | 'down') {
  if (busy.value || !deployable.value) return;
  const version = generation,
    value = loadedPath.value;
  if (
    !(await confirm({
      title: action === 'up' ? 'Apply Compose deployment?' : 'Stop Compose deployment?',
      message: `Use the saved Compose recipe ${value}? ${action === 'up' ? 'Services may be recreated.' : 'Containers will stop; named volumes are retained.'} Unsaved files are never deployed.`,
      confirmText: action === 'up' ? 'Apply' : 'Stop deployment',
      destructive: true,
    }))
  )
    return;
  if (!current(version) || !deployable.value) return;
  busy.value = true;
  error.value = '';
  output.value = '';
  try {
    if (props.supervision) await props.operate(action === 'up' ? 'compose-up' : 'compose-down', value);
    else {
      const result = await api.compose[action](props.serverId, value);
      if (current(version)) output.value = result.output || 'Compose operation completed.';
    }
  } catch (e) {
    if (current(version))
      error.value =
        e instanceof Error ? e.message : 'Operation unconfirmed. Inspect history before retrying.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function browse(value = directory.value) {
  if (busy.value || !can('files.list', props.serverId)) return;
  const version = generation;
  busy.value = true;
  error.value = '';
  try {
    const result = await api.files.list(props.serverId, value);
    if (current(version)) {
      directory.value = result.path;
      entries.value = result.entries.filter((entry) => entry.isDir || /\.ya?ml$/i.test(entry.name));
      browserOpen.value = true;
    }
  } catch (e) {
    if (current(version)) error.value = e instanceof Error ? e.message : 'Directory unavailable.';
  } finally {
    if (alive) busy.value = false;
  }
}
</script>
<template>
  <section aria-label="YAML file editor" class="space-y-4">
    <p class="text-sm text-muted-foreground">
      Edit server YAML with local syntax highlighting, validation and suggestions. Choose Docker Compose,
      GitHub Actions, Kubernetes or general YAML. Assist does not certify a provider schema or execute a
      workflow or cluster command.
    </p>
    <div class="flex gap-2 flex-wrap">
      <label class="flex-1 min-w-64 text-sm"
        >Server YAML path<Input v-model="path" :disabled="busy" @keydown.enter="open" /></label
      ><Button variant="outline" :disabled="busy || !readable" class="self-end" @click="open">Open</Button
      ><Button
        v-if="can('files.list', serverId)"
        variant="outline"
        :disabled="busy"
        class="self-end"
        @click="browse()"
        >Browse server</Button
      >
    </div>
    <p v-if="!readable" class="text-sm">
      Opening this file requires
      {{ transport === 'compose' ? 'compose.read' : 'files.read' }} and the server's existing credential
      permissions.
    </p>
    <div v-if="browserOpen" class="border rounded p-3 space-y-2" aria-label="Choose server YAML file">
      <div class="flex gap-2">
        <Input v-model="directory" aria-label="Server directory" :disabled="busy" /><Button
          :disabled="busy"
          @click="browse()"
          >List directory</Button
        ><Button variant="ghost" @click="browserOpen = false">Close browser</Button>
      </div>
      <Button
        variant="outline"
        :disabled="busy || directory === '/'"
        @click="browse(directory.slice(0, directory.lastIndexOf('/')) || '/')"
        >Parent directory</Button
      >
      <div class="max-h-64 overflow-auto">
        <button
          v-for="entry in entries"
          :key="entry.path"
          type="button"
          :disabled="busy"
          class="block w-full text-left p-1 font-mono text-xs hover:bg-muted"
          @click="entry.isDir ? browse(entry.path) : ((path = entry.path), (browserOpen = false))"
        >
          {{ entry.isDir ? '📁' : '📄' }} {{ entry.name }}
        </button>
      </div>
    </div>
    <div class="flex gap-3 flex-wrap items-end">
      <label class="text-sm"
        >YAML assist profile<select
          v-model="format"
          aria-label="YAML assist profile"
          class="block rounded border p-2 bg-background"
        >
          <option value="auto">Auto detect</option>
          <option v-for="(label, key) in profiles" :key="key" :value="key">
            {{ label }}
          </option>
        </select></label
      ><Button variant="outline" :disabled="!loadedPath || !writable" @click="editor?.suggest()"
        >Suggest keys</Button
      ><Button
        :disabled="busy || !writable || writeUnconfirmed || !samePath || !dirty || !syntaxValid"
        @click="save"
        >Save YAML</Button
      ><span class="text-xs text-muted-foreground">Ctrl+Space: suggestions · Tab: indent · Ctrl+Z: undo</span>
    </div>
    <p v-if="loadedPath" class="text-xs font-mono break-all">
      Editing {{ loadedPath }} · {{ profiles[profile] }}{{ dirty ? ' · unsaved changes' : '' }}
    </p>
    <p v-if="loadedPath && !samePath" class="text-sm">Open the new path before editing or saving it.</p>
    <p v-if="error" role="alert" class="text-sm text-destructive">
      {{ error }}
    </p>
    <p v-if="status" role="status" class="text-sm">{{ status }}</p>
    <YamlTextEditor
      ref="editor"
      :key="editorEpoch"
      v-model="content"
      :profile="profile"
      :readonly="busy || !writable || !samePath"
    />
    <ul v-if="issues.length" class="text-xs space-y-1">
      <li
        v-for="(issue, index) in issues"
        :key="index"
        :class="issue.severity === 'error' ? 'text-destructive' : 'text-muted-foreground'"
      >
        {{ issue.severity }}: {{ issue.message }}
      </li>
    </ul>
    <p v-else-if="loadedPath" class="text-xs text-muted-foreground">
      YAML syntax is valid. Provider-specific behavior still needs review.
    </p>
    <div v-if="profile === 'compose' && loadedPath" class="border rounded p-3 space-y-2">
      <p class="text-sm font-medium">Saved Docker Compose file</p>
      <p class="text-xs text-muted-foreground">
        Compose controls require a saved, valid document with a services map. Other YAML profiles only edit
        files.
      </p>
      <div class="flex gap-2">
        <Button variant="outline" :disabled="busy || !deployable" @click="deploy('up')">up -d</Button
        ><Button variant="destructive" :disabled="busy || !deployable" @click="deploy('down')">down</Button>
      </div>
    </div>
    <div v-if="output">
      <Button variant="ghost" @click="output = ''">Hide output</Button>
      <pre class="whitespace-pre-wrap break-all rounded border p-3 text-xs">{{ output }}</pre>
    </div>
  </section>
</template>
