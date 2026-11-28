<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue';
import { api, type InventoryDocument } from '@/lib/api';
import { can } from '@/lib/auth';
import Button from './ui/Button.vue';

const props = defineProps<{ serverId: string }>();
const report = ref<InventoryDocument | null>(null);
const notes = ref('');
const savedNotes = ref('');
const revision = ref(0);
const busy = ref(false);
const error = ref('');
const canExport = computed(
  () => can('inventory.read', props.serverId) && can('inventory.export', props.serverId),
);
const canEdit = computed(() => can('inventory.edit', props.serverId));
const dirty = computed(() => notes.value !== savedNotes.value);
let generation = 0;

function reset() {
  generation++;
  report.value = null;
  notes.value = '';
  savedNotes.value = '';
  revision.value = 0;
  busy.value = false;
  error.value = '';
}

watch([() => props.serverId, canExport, canEdit], reset, { flush: 'sync' });
onUnmounted(reset);

function current(version: number, server: string) {
  return version === generation && server === props.serverId && canExport.value;
}

async function refresh(discardDraft = false) {
  if (busy.value || !canExport.value) return;
  const version = generation;
  const server = props.serverId;
  busy.value = true;
  error.value = '';
  try {
    const result = await api.inventory.document(server);
    if (!current(version, server)) return;
    report.value = result;
    if (discardDraft || !dirty.value) {
      notes.value = savedNotes.value = result.manual.notes;
      revision.value = result.manual.revision;
    }
  } catch (cause) {
    if (current(version, server))
      error.value = cause instanceof Error ? cause.message : 'Could not load the report.';
  } finally {
    if (current(version, server)) busy.value = false;
  }
}

async function save() {
  if (busy.value || !dirty.value || !canEdit.value || !canExport.value) return;
  const version = generation;
  const server = props.serverId;
  busy.value = true;
  error.value = '';
  try {
    const result = await api.inventory.saveNotes(server, { notes: notes.value, revision: revision.value });
    if (!current(version, server)) return;
    notes.value = savedNotes.value = result.notes;
    revision.value = result.revision;
    report.value = null;
  } catch (cause) {
    if (current(version, server))
      error.value = cause instanceof Error ? cause.message : 'Could not save notes.';
    return;
  } finally {
    if (current(version, server)) busy.value = false;
  }
  if (current(version, server)) await refresh();
}

function download(format: 'md' | 'json') {
  if (!canExport.value || !report.value) return;
  const markdown = format === 'md';
  const text = markdown ? report.value.markdown : JSON.stringify(report.value, null, 2);
  const url = URL.createObjectURL(
    new Blob([text], { type: markdown ? 'text/markdown' : 'application/json' }),
  );
  const link = document.createElement('a');
  link.href = url;
  link.download = 'nexus-inventory.' + format;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
</script>

<template>
  <section v-if="canExport" class="space-y-3 rounded-md border p-3" aria-label="Infrastructure documentation">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h3 class="font-medium">Infrastructure documentation</h3>
      <Button variant="outline" :disabled="busy" @click="refresh()">
        {{ report ? 'Refresh report' : 'Generate report' }}
      </Button>
    </div>
    <p v-if="error" role="alert" class="text-sm text-destructive">{{ error }}</p>
    <template v-if="report">
      <div v-if="canEdit" class="space-y-2">
        <label class="block text-sm font-medium">
          Manual notes
          <textarea
            v-model="notes"
            :disabled="busy"
            maxlength="32768"
            rows="5"
            class="mt-1 block w-full rounded-md border bg-background p-2 text-sm"
            placeholder="Runbooks, maintenance windows, and recovery steps"
          />
        </label>
        <p v-if="dirty" class="text-sm text-muted-foreground">The report includes the last saved notes.</p>
        <div class="flex flex-wrap gap-2">
          <Button :disabled="busy || !dirty" @click="save">Save notes</Button>
          <Button v-if="dirty" variant="outline" :disabled="busy" @click="refresh(true)"
            >Discard draft and reload</Button
          >
        </div>
      </div>
      <div class="flex flex-wrap gap-2">
        <Button variant="outline" :disabled="busy" @click="download('md')">Download Markdown</Button>
        <Button variant="outline" :disabled="busy" @click="download('json')">Download JSON</Button>
      </div>
      <details>
        <summary class="cursor-pointer text-sm">View report text</summary>
        <pre
          class="mt-2 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 text-xs"
          >{{ report.markdown }}</pre>
      </details>
    </template>
  </section>
</template>
