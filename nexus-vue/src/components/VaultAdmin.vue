<script setup lang="ts">
import { computed, nextTick, onUnmounted, ref, watch } from 'vue';
import { api, type VaultAdminField, type VaultAdminOperation, type VaultAdminResult } from '@/lib/api';
import { can } from '@/lib/auth';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';

const props = defineProps<{ serverId: string }>();
const operations = ref<VaultAdminOperation[]>([]);
const selected = ref('');
const values = ref<Record<string, string | boolean>>({});
const token = ref('');
const confirmation = ref('');
const error = ref('');
const result = ref<VaultAdminResult | null>(null);
const busy = ref(false);
const loading = ref(false);
const revealConsent = ref(false);
const visible = ref(false);
let generation = 0;
let alive = true;
const permitted = computed(() =>
  operations.value.filter((op) => op.permissions.every((permission) => can(permission, props.serverId))),
);
const groups = computed(() => [...new Set(permitted.value.map((op) => op.group))]);
const operation = computed(() => permitted.value.find((op) => op.id === selected.value));
const policyDraft = ref<{ name: string; policy: string; revision: string } | null>(null);

function clear() {
  generation++;
  busy.value = false;
  values.value = {};
  token.value = '';
  confirmation.value = '';
  error.value = '';
  result.value = null;
  revealConsent.value = false;
  visible.value = false;
  policyDraft.value = null;
}
watch(selected, clear);
watch(
  () => props.serverId,
  () => {
    clear();
    void load();
  },
);
onUnmounted(() => {
  alive = false;
  clear();
});
async function load() {
  const server = props.serverId;
  const sequence = generation;
  loading.value = true;
  operations.value = [];
  try {
    const manifest = await api.vault.operations(server);
    if (alive && server === props.serverId && sequence === generation) operations.value = manifest.operations;
  } catch (cause) {
    if (alive && sequence === generation)
      error.value = cause instanceof Error ? cause.message : 'Could not load Vault actions';
  } finally {
    if (alive && sequence === generation) loading.value = false;
  }
}
void load();

function fieldValue(field: VaultAdminField): unknown {
  const raw = values.value[field.key];
  if (field.kind === 'bool') return raw === true;
  const text = typeof raw === 'string' ? raw : '';
  if (['versions', 'policies', 'strings', 'domains', 'ids'].includes(field.kind)) {
    const entries = text
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter(Boolean);
    if (field.kind !== 'versions') return entries;
    if (entries.some((value) => !/^[1-9][0-9]{0,9}$/.test(value) || Number(value) > 2147483647))
      throw new Error('Versions must be positive whole numbers.');
    return entries.map(Number);
  }
  if (
    ['seconds', 'positive', 'nonnegative', 'duration', 'inherited-duration', 'retention'].includes(field.kind)
  ) {
    if (!/^[0-9]{1,10}$/.test(text)) throw new Error(field.label + ': enter a whole number.');
    return Number(text);
  }
  return text;
}

async function execute() {
  const op = operation.value;
  if (
    !op ||
    busy.value ||
    (op.mutation && confirmation.value !== op.id) ||
    (op.sensitive && !revealConsent.value)
  )
    return;
  error.value = '';
  result.value = null;
  policyDraft.value = null;
  visible.value = false;
  const params: Record<string, unknown> = {};
  try {
    for (const field of op.fields ?? []) {
      if (!field.required && (values.value[field.key] === undefined || values.value[field.key] === ''))
        continue;
      params[field.key] = fieldValue(field);
    }
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : 'Check the form fields';
    return;
  }
  if (!token.value) {
    error.value = 'Supply a short-lived non-root Vault token.';
    return;
  }
  const input = { token: token.value, params, ...(op.mutation ? { confirmation: confirmation.value } : {}) };
  const server = props.serverId;
  const sequence = generation;
  busy.value = true;
  token.value = '';
  confirmation.value = '';
  for (const field of op.fields ?? []) if (field.kind === 'password') values.value[field.key] = '';
  try {
    const response = await api.vault.admin(server, op.id, input);
    if (alive && server === props.serverId && sequence === generation) {
      result.value = response;
      visible.value = !op.sensitive;
      // Policy JSON contains source text and identifiers, never numeric values.
      if (op.id === 'policy-read' && response.revision && !response.redacted) {
        const source = JSON.parse(response.dataJson) as { name: string; policy: string };
        policyDraft.value = { ...source, revision: response.revision };
      }
      if (op.mutation) values.value = {};
    }
  } catch (cause) {
    if (alive && sequence === generation)
      error.value =
        cause instanceof Error
          ? cause.message
          : 'Vault action failed. Inspect remote state before retrying a change.';
  } finally {
    input.token = '';
    for (const key of Object.keys(params)) delete params[key];
    if (alive && sequence === generation) busy.value = false;
  }
}
async function editPolicy(action: 'policy-save' | 'policy-delete') {
  const draft = policyDraft.value;
  if (!draft || busy.value) return;
  selected.value = action;
  await nextTick();
  values.value = {
    name: draft.name,
    revision: draft.revision,
    ...(action === 'policy-save' ? { policy: draft.policy } : {}),
  };
}
function hideResult() {
  result.value = null;
  policyDraft.value = null;
  visible.value = false;
}
</script>

<template>
  <section class="border rounded-lg p-4 space-y-4" aria-label="Vault administration">
    <div>
      <h3 class="font-semibold">Vault administration</h3>
      <p class="text-xs text-muted-foreground">
        Community management actions. Each action uses a fresh non-root token with at most 24 hours remaining.
        Vault policies and your Nexus permissions both apply.
      </p>
    </div>
    <p v-if="loading" role="status">Loading available actions…</p>
    <p v-if="!loading && !permitted.length" class="text-sm text-muted-foreground">
      No management actions are available with your current permissions.
    </p>
    <label v-if="permitted.length" class="block text-sm"
      >Management action
      <select
        v-model="selected"
        aria-label="Management action"
        :disabled="busy"
        class="block w-full rounded border bg-background p-2"
      >
        <option value="">Choose an action</option>
        <optgroup v-for="group in groups" :key="group" :label="group">
          <option v-for="op in permitted.filter((item) => item.group === group)" :key="op.id" :value="op.id">
            {{ op.label }}
          </option>
        </optgroup>
      </select>
    </label>
    <form v-if="operation" class="space-y-3" @submit.prevent="execute">
      <p class="rounded border p-3 text-sm" :role="operation.mutation ? 'note' : undefined">
        {{ operation.notice }}
      </p>
      <label v-for="field in operation.fields" :key="field.key" class="block text-sm">
        <template v-if="field.kind === 'bool'"
          ><input v-model="values[field.key]" type="checkbox" :disabled="busy" /> {{ field.label }}</template
        >
        <template v-else
          >{{ field.label }}{{ field.required ? ' *' : '' }}
          <select
            v-if="field.kind === 'choice'"
            v-model="values[field.key]"
            :aria-label="field.label + (field.required ? ' *' : '')"
            :disabled="busy"
            :required="field.required"
            class="block w-full rounded border bg-background p-2"
          >
            <option value="">Choose…</option>
            <option v-for="choice in field.choices" :key="choice" :value="choice">{{ choice }}</option>
          </select>
          <textarea
            v-else-if="
              [
                'text',
                'pem',
                'csr',
                'certificates',
                'versions',
                'policies',
                'strings',
                'domains',
                'ids',
              ].includes(field.kind)
            "
            v-model="values[field.key] as string"
            :rows="field.kind === 'text' ? 10 : 4"
            :disabled="busy"
            :required="field.required"
            spellcheck="false"
            autocomplete="off"
            class="block w-full rounded border bg-background p-2 font-mono text-xs"
          />
          <Input
            v-else
            v-model="values[field.key] as string"
            :type="field.kind === 'password' ? 'password' : 'text'"
            :disabled="busy"
            :required="field.required"
            autocomplete="off"
            spellcheck="false"
          />
        </template>
      </label>
      <label class="block text-sm"
        >Vault token for this action<Input
          v-model="token"
          type="password"
          autocomplete="off"
          :disabled="busy"
          required
      /></label>
      <label v-if="operation.sensitive" class="block text-sm"
        ><input v-model="revealConsent" type="checkbox" :disabled="busy" /> I intend to reveal this action’s
        sensitive result. I will save any newly generated credential before leaving this view.</label
      >
      <label v-if="operation.mutation" class="block text-sm"
        >To confirm these changes, type <code>{{ operation.id }}</code><Input
          v-model="confirmation"
          :disabled="busy"
          autocomplete="off"
          required
      /></label>
      <Button
        type="submit"
        :disabled="
          busy ||
          !token ||
          (operation.mutation && confirmation !== operation.id) ||
          (operation.sensitive && !revealConsent)
        "
        >{{ busy ? 'Working…' : operation.label }}</Button
      >
      <p v-if="operation.mutation" class="text-xs text-muted-foreground">
        Changes are sent once. If the outcome is uncertain, inspect Vault before retrying. Acknowledgement
        does not verify downstream applications or external credentials.
      </p>
    </form>
    <p v-if="error" role="alert" class="text-destructive">{{ error }}</p>
    <div v-if="result" class="space-y-2" role="status">
      <p v-if="result.redacted" class="text-sm">
        The supplied token was redacted from the result. Redacted policy content cannot be reused for an edit.
      </p>
      <p v-if="result.revision" class="text-xs break-all">Policy revision: {{ result.revision }}</p>
      <div class="flex flex-wrap gap-2">
        <Button v-if="!visible" variant="outline" @click="visible = true">Reveal one-time result</Button
        ><Button variant="outline" @click="hideResult">Hide and clear result</Button>
      </div>
      <pre
        v-if="visible"
        class="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-3 text-xs"
        >{{ result.dataJson }}</pre>
      <div v-if="policyDraft" class="flex gap-2">
        <Button
          v-if="permitted.some((op) => op.id === 'policy-save')"
          variant="outline"
          @click="editPolicy('policy-save')"
          >Edit this policy</Button
        ><Button
          v-if="policyDraft.revision !== 'missing' && permitted.some((op) => op.id === 'policy-delete')"
          variant="outline"
          @click="editPolicy('policy-delete')"
          >Prepare policy deletion</Button
        >
      </div>
    </div>
  </section>
</template>
