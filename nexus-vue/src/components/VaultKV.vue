<script setup lang="ts">
import { ref, onUnmounted, watch } from 'vue';
import { api, type VaultKVInput } from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';

const props = defineProps<{ serverId: string; mounts: string[] }>();
const { confirm } = useConfirm();
const mount = ref(props.mounts[0] ?? '');
const path = ref('');
const token = ref('');
const editor = ref('{}');
const revealed = ref('');
const error = ref('');
const status = ref('');
const keys = ref<string[]>([]);
const version = ref(0);
const busy = ref(false);
let generation = 0;
let alive = true;

type Action = 'list' | 'metadata' | 'read' | 'write';
function clear() {
  generation++;
  token.value = '';
  editor.value = '{}';
  revealed.value = '';
  keys.value = [];
  version.value = 0;
  error.value = '';
  status.value = '';
}
onUnmounted(() => {
  alive = false;
  clear();
});
watch([() => props.serverId, mount, path], clear);
watch(
  () => props.mounts,
  () => {
    clear();
    if (!props.mounts.includes(mount.value)) mount.value = props.mounts[0] ?? '';
  },
);
function permitted(action: Action) {
  const extra =
    action === 'read' ? 'secrets.reveal' : action === 'write' ? 'secrets.create' : 'secrets.metadata.read';
  return ['integrations.manage', 'servers.connect', 'secrets.use', extra].every((permission) =>
    can(permission, props.serverId),
  );
}
async function perform(action: Action) {
  if (busy.value || !permitted(action)) return;
  const server = props.serverId;
  const sequence = generation;
  const input: VaultKVInput = { token: token.value, mount: mount.value.replace(/\/$/, ''), path: path.value };
  if (!input.token) {
    error.value = 'Supply a short-lived Vault token for this operation.';
    return;
  }
  if (action === 'write') {
    try {
      const data = JSON.parse(editor.value);
      if (!data || Array.isArray(data) || typeof data !== 'object') throw new Error();
      if (!Number.isInteger(version.value) || version.value < 0 || version.value > 2147483646)
        throw new Error();
      input.dataJson = editor.value;
      input.version = version.value;
    } catch {
      error.value = 'Write data must be a JSON object with a valid expected version.';
      return;
    }
    const accepted = await confirm({
      title: 'Write Vault secret version?',
      message:
        version.value === 0
          ? 'Create this key only if it does not already exist?'
          : 'Write a new version only if the current version is ' +
            version.value +
            '? Existing values will be replaced by this JSON object.',
      confirmText: 'Write version',
      destructive: true,
    });
    if (!accepted || !alive || sequence !== generation || busy.value || !permitted(action)) return;
  }
  token.value = '';
  busy.value = true;
  error.value = '';
  status.value = '';
  revealed.value = '';
  try {
    const result = await api.vault.kv(server, action, input);
    if (!alive || server !== props.serverId || sequence !== generation) return;
    if (result.keys) keys.value = result.keys;
    if (result.metadata) version.value = result.metadata.version;
    if (action === 'read' && result.dataJson) revealed.value = result.dataJson;
    if (action === 'write') {
      editor.value = '{}';
      status.value = 'Written version ' + result.metadata?.version + '.';
    }
  } catch (cause) {
    if (alive && sequence === generation)
      error.value = cause instanceof Error ? cause.message : 'Vault operation failed';
  } finally {
    input.token = '';
    input.dataJson = undefined;
    busy.value = false;
  }
}
</script>

<template>
  <section class="border rounded-lg p-4 space-y-3" aria-label="Vault KV-v2 secrets">
    <h3 class="font-semibold">KV-v2 secrets</h3>
    <p class="text-xs text-muted-foreground">
      Values are revealed only on request. Writes always check the expected version. Nothing retries
      automatically; inspect remote metadata after an uncertain write.
    </p>
    <label class="block text-sm"
      >KV-v2 mount<select
        v-model="mount"
        class="block rounded border bg-background p-2 w-full"
        :disabled="busy"
      >
        <option v-for="name in mounts" :key="name">{{ name }}</option>
      </select></label
    >
    <label class="block text-sm"
      >Secret key or directory<Input v-model="path" placeholder="team/application" :disabled="busy"
    /></label>
    <label class="block text-sm"
      >Vault token for this operation<Input
        v-model="token"
        type="password"
        autocomplete="off"
        :disabled="busy"
    /></label>
    <p v-if="error" role="alert" class="text-destructive">{{ error }}</p>
    <p v-if="status" role="status">{{ status }}</p>
    <div class="flex flex-wrap gap-2">
      <Button v-if="permitted('list')" :disabled="busy" variant="outline" @click="perform('list')"
        >List directory</Button
      >
      <Button
        v-if="permitted('metadata')"
        :disabled="busy || !path"
        variant="outline"
        @click="perform('metadata')"
        >Read version metadata</Button
      >
      <Button v-if="permitted('read')" :disabled="busy || !path" variant="outline" @click="perform('read')"
        >Reveal values</Button
      >
    </div>
    <p v-if="!permitted('read')" class="text-xs text-muted-foreground">
      Secret values require a separate secrets.reveal grant.
    </p>
    <ul v-if="keys.length" class="text-sm">
      <li v-for="entry in keys" :key="entry">{{ entry }}</li>
    </ul>
    <div v-if="revealed" class="space-y-2">
      <Button variant="outline" @click="revealed = ''">Hide values</Button>
      <pre class="overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-3 text-xs">{{
        revealed
      }}</pre>
    </div>
    <div v-if="permitted('write')" class="space-y-3">
      <label class="block text-sm"
        >Expected current version<Input
          v-model.number="version"
          type="number"
          min="0"
          max="2147483646"
          :disabled="busy"
      /></label>
      <p class="text-xs text-muted-foreground">
        Zero creates only. Read metadata to obtain the version for an existing key. A stale version is
        rejected.
      </p>
      <label class="block text-sm"
        >New secret JSON<textarea
          v-model="editor"
          class="block w-full rounded border bg-background p-2 font-mono text-xs"
          rows="6"
          autocomplete="off"
          :disabled="busy"
        />
      </label>
      <Button :disabled="busy || !path" @click="perform('write')">Write secret version</Button>
    </div>
  </section>
</template>
