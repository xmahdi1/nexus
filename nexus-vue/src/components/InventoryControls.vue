<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type InventoryPolicy, type InventoryPolicyInput } from '@/lib/api';
import { can } from '@/lib/auth';
import Button from './ui/Button.vue';

const props = defineProps<{ serverId: string }>();
const emit = defineEmits<{ saved: [] }>();
const policy = ref<InventoryPolicy | null>(null);
const draft = ref<InventoryPolicyInput | null>(null);
const busy = ref(false),
  error = ref('');
const readable = computed(() => can('inventory.read', props.serverId));
const editable = computed(() =>
  ['inventory.read', 'inventory.edit', 'inventory.discover', 'secrets.use'].every((p) =>
    can(p, props.serverId),
  ),
);
let generation = 0,
  alive = true;

function current(version: number, server: string) {
  return alive && version === generation && server === props.serverId && readable.value;
}
function reset() {
  generation++;
  policy.value = null;
  draft.value = null;
  error.value = '';
  busy.value = false;
}
function accept(result: InventoryPolicy) {
  policy.value = result;
  draft.value = {
    enabled: result.enabled,
    intervalMinutes: result.intervalMinutes,
    freshnessMinutes: result.freshnessMinutes,
    retentionDays: result.retentionDays,
    revision: result.revision,
  };
}
async function load() {
  if (!readable.value || busy.value) return;
  const version = generation,
    server = props.serverId;
  busy.value = true;
  error.value = '';
  try {
    const result = await api.inventory.policy(server);
    if (current(version, server)) accept(result);
  } catch (cause) {
    if (current(version, server))
      error.value = cause instanceof Error ? cause.message : 'Collection settings unavailable.';
  } finally {
    if (current(version, server)) busy.value = false;
  }
}
async function save() {
  if (!editable.value || !draft.value || busy.value) return;
  const version = generation,
    server = props.serverId;
  const input = { ...draft.value };
  busy.value = true;
  error.value = '';
  try {
    const result = await api.inventory.savePolicy(server, input);
    if (current(version, server) && editable.value) {
      accept(result);
      emit('saved');
    }
  } catch (cause) {
    if (current(version, server))
      error.value = cause instanceof Error ? cause.message : 'Could not save collection settings.';
  } finally {
    if (current(version, server)) busy.value = false;
  }
}
watch(
  [() => props.serverId, readable, editable],
  () => {
    reset();
    void load();
  },
  { flush: 'sync' },
);
onMounted(load);
onUnmounted(() => {
  alive = false;
  reset();
});
</script>

<template>
  <section v-if="readable" aria-label="Collection settings" class="rounded-md border p-3 space-y-3">
    <div class="flex items-center justify-between gap-2">
      <h3 class="font-medium">Collection settings</h3>
      <Button variant="outline" :disabled="busy" @click="load">Reload settings</Button>
    </div>
    <p v-if="error" role="alert" class="text-sm text-destructive">{{ error }}</p>
    <form v-if="draft && policy" class="space-y-3" @submit.prevent="save">
      <fieldset :disabled="busy || !editable" class="space-y-3">
        <label class="flex items-center gap-2 text-sm"
          ><input v-model="draft.enabled" type="checkbox" />Schedule read-only collection for this host</label
        >
        <div class="flex flex-wrap gap-4">
          <label class="text-sm"
            >Interval (minutes)<input
              v-model.number="draft.intervalMinutes"
              class="block rounded border bg-background p-2"
              type="number"
              min="5"
              max="1440"
              required
          /></label>
          <label class="text-sm"
            >Freshness (minutes)<input
              v-model.number="draft.freshnessMinutes"
              class="block rounded border bg-background p-2"
              type="number"
              min="5"
              max="10080"
              required
          /></label>
          <label class="text-sm"
            >History retention (days)<input
              v-model.number="draft.retentionDays"
              class="block rounded border bg-background p-2"
              type="number"
              min="0"
              max="3650"
              required
          /></label>
        </div>
      </fieldset>
      <p class="text-xs text-muted-foreground">
        Schedules use the saving administrator’s current permissions. Protected hosts require interactive
        collection. Failed or incomplete collections back off up to 24 hours.
      </p>
      <p class="text-xs text-muted-foreground">
        Retention of 0 keeps history indefinitely. A positive value removes older changes and unused
        collection runs when settings are saved or collection finishes. Resources, saved notes, audit records
        and runs referenced by observations remain.
      </p>
      <p class="text-xs">
        {{ policy.enabled ? 'Schedule enabled' : 'Schedule disabled'
        }}<span v-if="policy.enabled"> · Next attempt: {{ new Date(policy.nextRunAt).toLocaleString() }}</span
        ><span v-if="policy.lastStatus"> · {{ policy.lastStatus }}</span>
      </p>
      <Button v-if="editable" type="submit" :disabled="busy">Save collection settings</Button>
    </form>
  </section>
</template>
