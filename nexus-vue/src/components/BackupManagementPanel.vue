<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import {
  api,
  type BackupHealth,
  type BackupResult,
  type BackupRun,
  type BackupSettings,
  type BackupPolicy,
} from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';
const props = defineProps<{
  serverId?: string;
  supervised?: boolean;
  runs: BackupRun[];
  policies?: BackupPolicy[];
  inspection?: { runId: string; policyId: string; data: BackupResult } | null;
}>();
const emit = defineEmits<{ changed: []; clearInspection: [] }>();
const scope = computed(() => props.serverId ?? '');
const readable = computed(
  () => can('backups.read', scope.value) && (!!scope.value || can('backups.nexus.manage')),
);
const manageable = computed(() => readable.value && can('backups.manage', scope.value));
const runnable = computed(
  () =>
    manageable.value &&
    (!scope.value || props.supervised) &&
    can('jobs.execute', scope.value) &&
    can('secrets.use', scope.value),
);
const { confirm } = useConfirm();
const report = ref<BackupHealth | null>(null),
  busy = ref(false),
  error = ref(''),
  notice = ref(''),
  selected = ref(''),
  folder = ref(''),
  watchGaps = ref(true);
const settings = ref<BackupSettings>({
  keepLast: 7,
  maxAgeMinutes: 0,
  verifyAfterDays: 30,
});
const pending = ref(''),
  consumedPreview = ref('');
let generation = 0,
  alive = true;
const preview = computed(() =>
  props.inspection?.policyId === selected.value &&
  props.inspection.data.state === 'retention_preview' &&
  props.inspection.data.verified
    ? props.inspection
    : null,
);
const applyAllowed = computed(
  () =>
    runnable.value &&
    can('backups.prune', scope.value) &&
    !!preview.value?.data.retention?.removeIds.length &&
    preview.value.runId !== consumedPreview.value,
);
const labels: Record<string, string> = {
  authority_changed: 'The policy owner, permissions or saved SSH identity changed.',
  run_unknown: 'Backup result is unknown. Inspect its retained run.',
  backup_failed: 'The latest backup did not complete successfully.',
  backup_overdue: 'The last successful backup is overdue.',
  restore_overdue: 'A restore verification is overdue.',
  schedule_paused: 'The backup schedule is paused.',
  sources_unprotected: 'Discovered sources have no successful backup.',
  coverage_stale: 'Coverage has not been scanned in the past day.',
  coverage_incomplete: 'Discovery was limited; coverage is incomplete.',
};
function message(code: string) {
  return labels[code] ?? code.replaceAll('_', ' ');
}
function current(v: number) {
  return alive && generation === v && readable.value;
}
function reset() {
  generation++;
  report.value = null;
  error.value = '';
  notice.value = '';
  selected.value = '';
  pending.value = '';
  consumedPreview.value = '';
  busy.value = false;
}
watch(
  () =>
    [
      scope.value,
      readable.value,
      manageable.value,
      can('backups.prune', scope.value),
      can('secrets.use', scope.value),
      can('jobs.execute', scope.value),
    ].join(','),
  () => {
    reset();
    void load();
  },
  { flush: 'sync' },
);
watch(
  () => props.policies,
  () => {
    if (!busy.value && readable.value) void load();
  },
);
watch(
  () => props.runs,
  (rows) => {
    if (rows.some((r) => r.id === pending.value)) pending.value = '';
  },
  { deep: true },
);
watch(
  () => [selected.value, report.value],
  () => {
    const row = report.value?.policies.find((p) => p.policyId === selected.value);
    if (row) settings.value = { ...row.settings };
  },
  { flush: 'sync' },
);
async function work(fn: (sid: string, v: number) => Promise<void>, preserveNotice = false) {
  if (busy.value || !readable.value) return;
  const v = ++generation,
    sid = scope.value;
  busy.value = true;
  error.value = '';
  if (!preserveNotice) notice.value = '';
  try {
    await fn(sid, v);
  } catch (e) {
    if (current(v)) {
      error.value = e instanceof Error ? e.message : 'Backup management unavailable.';
      const failure = e as { status?: number; code?: string } | null;
      if (
        failure?.status === 400 ||
        ['backup_busy', 'backup_conflict', 'feature_disabled'].includes(failure?.code ?? '')
      ) {
        pending.value = '';
        consumedPreview.value = '';
      }
      emit('changed');
    }
  } finally {
    if (alive && v === generation) busy.value = false;
  }
}
async function refresh(sid: string, v: number) {
  const next = await api.backups.health(sid);
  if (current(v)) {
    report.value = next;
    if (!next.policies.some((p) => p.policyId === selected.value))
      selected.value = next.policies[0]?.policyId ?? '';
  }
}
async function load() {
  await work(refresh, true);
}
async function scan() {
  if (!manageable.value || !can('secrets.use', scope.value)) return;
  await work(async (sid, v) => {
    await api.backups.coverage(sid, folder.value, watchGaps.value);
    if (current(v)) await refresh(sid, v);
  });
}
async function saveSettings() {
  if (!manageable.value || !selected.value) return;
  const id = selected.value,
    v = generation,
    value = { ...settings.value };
  if (
    !(await confirm({
      title: 'Save backup management settings?',
      message: `Keep the latest ${value.keepLast} successful snapshots for cleanup previews. Backup age: ${value.maxAgeMinutes || 'schedule default'} minutes. Restore check age: ${value.verifyAfterDays || 'disabled'} days. Saving does not delete snapshots.`,
      confirmText: 'Save settings',
    }))
  )
    return;
  if (!current(v) || !manageable.value || id !== selected.value) return;
  await work(async (sid, v) => {
    await api.backups.saveSettings(sid, id, value);
    if (current(v)) {
      await refresh(sid, v);
      notice.value = 'Settings saved. Create a fresh retention preview before cleanup.';
      emit('clearInspection');
    }
  });
}
async function retention(action: 'retention-preview' | 'retention-apply') {
  if (
    !runnable.value ||
    !selected.value ||
    pending.value ||
    (action === 'retention-apply' && !applyAllowed.value)
  )
    return;
  const id = selected.value,
    v = generation,
    inspected = preview.value,
    previewID = action === 'retention-apply' ? inspected!.runId : '';
  const count = inspected?.data.retention?.removeIds.length ?? 0;
  if (
    !(await confirm({
      title: action === 'retention-preview' ? 'Preview backup retention?' : 'Remove previewed snapshots?',
      message:
        action === 'retention-preview'
          ? 'Read all snapshots for this policy and show what its saved retention rule would remove? No snapshots are deleted.'
          : `Delete exactly ${count} previewed snapshot(s), then reclaim unused repository data? This cannot be undone. The repository and rule must still match this preview. Other policy snapshots and unclassified snapshots are kept.`,
      confirmText: action === 'retention-preview' ? 'Preview retention' : 'Remove snapshots',
    }))
  )
    return;
  if (
    !current(v) ||
    id !== selected.value ||
    !runnable.value ||
    (action === 'retention-apply' && (!applyAllowed.value || preview.value?.runId !== previewID))
  )
    return;
  await work(async (sid, v) => {
    const request = crypto.randomUUID().replaceAll('-', '');
    pending.value = request;
    if (action === 'retention-apply') consumedPreview.value = previewID;
    await api.backups.retention(sid, id, request, action, previewID);
    if (current(v)) {
      emit('clearInspection');
      emit('changed');
      notice.value =
        'Operation saved. Refresh run history and inspect its retained ID. A preview expires after 30 minutes and can be applied once.';
      await refresh(sid, v);
    }
  });
}
onMounted(load);
onUnmounted(() => {
  alive = false;
  generation++;
});
</script>
<template>
  <section aria-label="Backup health and retention" class="space-y-4 rounded border p-4">
    <div class="flex flex-wrap justify-between gap-2">
      <h3 class="font-semibold">Health, coverage and retention</h3>
      <Button variant="outline" :disabled="busy" @click="load">Refresh backup health</Button>
    </div>
    <p v-if="error" role="alert" class="text-sm text-destructive">
      {{ error }}
    </p>
    <p v-if="notice" role="status" class="text-sm">{{ notice }}</p>
    <p v-if="pending" class="text-xs font-mono break-all">
      Retained management request: {{ pending }}. Refresh run history before another submission.
    </p>
    <template v-if="report">
      <ul class="space-y-2 text-sm">
        <li v-for="policy in report.policies" :key="policy.policyId">
          <strong>{{ policy.name }}</strong><span v-if="!policy.issues.length">
            · No current policy issues</span
          >
          <ul class="list-disc pl-5">
            <li v-for="issue in policy.issues" :key="issue.code">
              {{ message(issue.code) }}
            </li>
          </ul>
        </li>
      </ul>
      <details v-if="report.alerts.length">
        <summary class="text-sm">
          Alert history ·
          {{ report.alerts.filter((a) => a.state === 'open').length }} open
        </summary>
        <ul class="list-disc pl-5 text-sm">
          <li v-for="alert in report.alerts" :key="alert.id">
            {{ alert.state }} · {{ message(alert.code) }} · First seen
            {{ new Date(alert.firstSeenAt).toLocaleString()
            }}<span v-if="alert.resolvedAt">
              · Resolved {{ new Date(alert.resolvedAt).toLocaleString() }}</span
            >
          </li>
        </ul>
      </details>
      <p class="text-xs text-muted-foreground">
        Alerts appear here. Background checks run in bounded batches each minute; no Telegram message is sent
        for backup alerts.
      </p>
      <details>
        <summary>Source coverage</summary>
        <div class="space-y-3 pt-3">
          <template v-if="manageable"
            ><label v-if="serverId" class="block text-sm"
              >Coverage folder (optional)<Input v-model="folder" placeholder="/srv" :disabled="busy" /></label
            ><label class="block text-sm"
              ><input v-model="watchGaps" type="checkbox" :disabled="busy" /> Watch this scan for backup
              gaps</label
            ><Button :disabled="busy || !can('secrets.use', scope)" @click="scan"
              >Refresh source coverage</Button
            ></template
          >
          <p class="text-xs">
            Coverage compares discovered sources with current policies and recorded successful backups. File
            copies do not count as native database exports. A scan is not a complete inventory of every
            application.
          </p>
          <template v-if="report.coverage"
            ><p class="text-sm">
              Scanned
              {{ new Date(report.coverage.scannedAt).toLocaleString() }} ·
              {{ report.coverage.truncated ? 'Limited scan' : 'Discovery results' }}
              ·
              {{ report.coverage.watchGaps ? 'Gaps watched' : 'Gaps not watched' }}
            </p>
            <ul class="space-y-1 text-sm">
              <li v-for="item in report.coverage.items" :key="item.candidate.id">
                {{ item.candidate.source.label }} · {{ item.candidate.source.kind }} ·
                {{ item.state.replaceAll('_', ' ')
                }}<span v-if="item.lastSuccessAt">
                  · Last success
                  {{ new Date(item.lastSuccessAt).toLocaleString() }}</span
                >
              </li>
            </ul></template
          >
          <p v-else class="text-sm">No coverage scan saved for this target.</p>
        </div>
      </details>
      <details v-if="report.policies.length">
        <summary>Retention and health settings</summary>
        <div class="space-y-3 pt-3">
          <label class="block text-sm"
            >Policy to manage<select
              v-model="selected"
              aria-label="Policy to manage"
              class="block border rounded p-2 bg-background w-full"
              :disabled="busy"
            >
              <option v-for="policy in report.policies" :key="policy.policyId" :value="policy.policyId">
                {{ policy.name }}
              </option>
            </select></label
          >
          <div class="grid gap-3 sm:grid-cols-3">
            <label class="text-sm"
              >Keep latest successful snapshots<Input
                v-model.number="settings.keepLast"
                type="number"
                min="1"
                max="500"
                :disabled="busy || !manageable" /></label
            ><label class="text-sm"
              >Maximum backup age (minutes)<Input
                v-model.number="settings.maxAgeMinutes"
                type="number"
                min="0"
                max="525600"
                :disabled="busy || !manageable" /></label
            ><label class="text-sm"
              >Restore verification age (days)<Input
                v-model.number="settings.verifyAfterDays"
                type="number"
                min="0"
                max="3650"
                :disabled="busy || !manageable"
            /></label>
          </div>
          <p class="text-xs">
            Backup age 0 uses twice the recurring interval; manual policies have no age deadline until
            configured. Restore age 0 disables that reminder. Cleanup keeps snapshots without successful Nexus
            run evidence. Preview is limited to repositories with at most 500 snapshots for this policy.
            Cleanup is manual.
          </p>
          <div class="flex flex-wrap gap-2">
            <Button v-if="manageable" :disabled="busy" @click="saveSettings">Save management settings</Button
            ><Button
              v-if="runnable"
              variant="outline"
              :disabled="busy || !!pending"
              @click="retention('retention-preview')"
              >Preview retention</Button
            >
          </div>
          <div v-if="preview?.data.retention" class="space-y-2 border rounded p-3 text-sm">
            <p>
              Preview: {{ preview.data.retention.removeIds.length }} to remove ·
              {{ preview.data.retention.keptCount }} kept ·
              {{ preview.data.retention.unclassifiedCount }} unclassified snapshots kept.
            </p>
            <details>
              <summary>Snapshot IDs to remove</summary>
              <ul class="font-mono text-xs break-all">
                <li v-for="id in preview.data.retention.removeIds" :key="id">
                  {{ id }}
                </li>
              </ul>
            </details>
            <p v-if="!can('backups.prune', scope)">
              Applying cleanup needs the separate backup retention manager role.
            </p>
            <Button
              v-if="can('backups.prune', scope)"
              :disabled="busy || !!pending || !applyAllowed"
              @click="retention('retention-apply')"
              >Apply retention preview</Button
            >
          </div>
        </div>
      </details>
    </template>
  </section>
</template>
