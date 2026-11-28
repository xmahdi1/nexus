<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import {
  api,
  type BackupAction,
  type BackupCandidate,
  type BackupDefinition,
  type BackupPolicy,
  type BackupRepository,
  type BackupResult,
  type BackupRun,
  type BackupSource,
  type BackupSourceKind,
} from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import BackupSourceFields from '@/components/BackupSourceFields.vue';
import BackupManagementPanel from '@/components/BackupManagementPanel.vue';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';
const props = defineProps<{ serverId?: string; serverName?: string }>();
const scope = computed(() => props.serverId ?? '');
const { confirm } = useConfirm();
const enabled = ref(false),
  supervised = ref(false),
  busy = ref(false),
  error = ref(''),
  notice = ref('');
const policies = ref<BackupPolicy[]>([]),
  runs = ref<BackupRun[]>([]),
  candidates = ref<BackupCandidate[]>([]),
  tools = ref<Record<string, boolean>>({}),
  truncated = ref(false);
const chosen = ref<Array<{ key: string; source: BackupSource }>>([]),
  search = ref(''),
  browsePath = ref(''),
  manualKind = ref<BackupSourceKind>('files');
const wizard = ref(false),
  step = ref(0),
  name = ref(''),
  repository = ref<BackupRepository>(newRepository()),
  mode = ref<'manual' | 'once' | 'interval'>('manual'),
  at = ref(''),
  interval = ref(1440),
  runtime = ref(3600),
  exportLimit = ref(10),
  liveFiles = ref(false);
const pending = ref<{ id: string; kind: 'policy' | 'run' } | null>(null),
  result = ref<{ runId: string; policyId: string; data: BackupResult } | null>(null),
  snapshot = ref('');
let generation = 0,
  alive = true,
  secretEpoch = 0;
const readable = computed(
  () => can('backups.read', scope.value) && (!!scope.value || can('backups.nexus.manage')),
);
const manageable = computed(
  () => readable.value && can('backups.manage', scope.value) && can('secrets.create', scope.value),
);
const historyReadable = computed(() => readable.value && can('jobs.read', scope.value));
const filtered = computed(() =>
  candidates.value.filter((c) =>
    JSON.stringify([c.source.label, c.source.path, c.source.kind, c.source.volume])
      .toLowerCase()
      .includes(search.value.toLowerCase()),
  ),
);
const hasFiles = computed(() =>
  chosen.value.some((c) => ['files', 'docker-bind', 'docker-volume'].includes(c.source.kind)),
);
const readyToSave = computed(
  () =>
    manageable.value &&
    !!name.value.trim() &&
    chosen.value.length > 0 &&
    chosen.value.length <= 25 &&
    !!repository.value.password &&
    !!repository.value.location &&
    (!hasFiles.value || liveFiles.value),
);
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
function newRepository(): BackupRepository {
  return {
    kind: 'local',
    location: '',
    password: '',
    accessKey: '',
    secretKey: '',
    sessionToken: '',
    region: '',
  };
}
function clearSecrets() {
  secretEpoch++;
  repository.value.password = '';
  repository.value.accessKey = '';
  repository.value.secretKey = '';
  repository.value.sessionToken = '';
  for (const entry of chosen.value) if (entry.source.database) entry.source.database.password = '';
}
function reset() {
  generation++;
  clearSecrets();
  policies.value = [];
  runs.value = [];
  candidates.value = [];
  chosen.value = [];
  result.value = null;
  pending.value = null;
  wizard.value = false;
  step.value = 0;
  name.value = '';
  repository.value = newRepository();
  busy.value = false;
  error.value = '';
  notice.value = '';
}
watch(
  () =>
    [
      scope.value,
      readable.value,
      manageable.value,
      can('backups.execute', scope.value),
      can('backups.restore', scope.value),
      can('backups.schedule', scope.value),
      can('jobs.read', scope.value),
      can('jobs.execute', scope.value),
      can('jobs.cancel', scope.value),
      can('jobs.manage', scope.value),
      can('logs.read', scope.value),
      can('secrets.use', scope.value),
      can('secrets.reveal', scope.value),
      can('servers.connect', scope.value),
    ].join(','),
  reset,
  { flush: 'sync' },
);
function current(v: number) {
  return alive && v === generation && readable.value;
}
async function work(fn: (sid: string, v: number) => Promise<void>) {
  if (busy.value || !readable.value) return;
  const v = ++generation,
    sid = scope.value;
  busy.value = true;
  error.value = '';
  notice.value = '';
  try {
    await fn(sid, v);
  } catch (e) {
    if (current(v)) {
      const failure = e as { status?: number; code?: string } | null;
      if (
        failure?.status === 400 ||
        ['backup_busy', 'backup_conflict', 'feature_disabled'].includes(failure?.code ?? '')
      )
        pending.value = null;
      error.value = e instanceof Error ? e.message : 'Backups unavailable.';
    }
  } finally {
    if (alive && v === generation) busy.value = false;
  }
}
async function refresh(sid: string, v: number) {
  const [next, nextRuns] = await Promise.all([
    api.backups.policies(sid),
    historyReadable.value ? api.backups.runs(sid) : Promise.resolve([]),
  ]);
  if (current(v)) {
    policies.value = next;
    runs.value = nextRuns;
    if (
      pending.value &&
      ((pending.value.kind === 'policy' && next.some((p) => p.id === pending.value!.id)) ||
        (pending.value.kind === 'run' && nextRuns.some((r) => r.id === pending.value!.id)))
    )
      pending.value = null;
  }
}
async function load() {
  await work(async (sid, v) => {
    const flags = await api.features();
    if (!current(v)) return;
    enabled.value = flags.backups;
    supervised.value = flags.operationSupervision;
    if (enabled.value) await refresh(sid, v);
  });
}
async function discover() {
  if (!manageable.value) return;
  await work(async (sid, v) => {
    const data = await api.backups.discover(sid, browsePath.value);
    if (current(v)) {
      candidates.value = data.sources;
      tools.value = data.tools;
      truncated.value = data.truncated;
    }
  });
}
function selected(id: string) {
  return chosen.value.some((c) => c.key === id);
}
function toggle(candidate: BackupCandidate) {
  if (busy.value || candidate.state === 'unsupported') return;
  const index = chosen.value.findIndex((c) => c.key === candidate.id);
  if (index >= 0) chosen.value.splice(index, 1);
  else if (chosen.value.length < 25)
    chosen.value.push({ key: candidate.id, source: clone(candidate.source) });
}
function addManual() {
  if (busy.value || !scope.value || chosen.value.length >= 25) return;
  const kind = manualKind.value;
  const source: BackupSource = { kind, label: 'Manual ' + kind };
  if (['postgres', 'mysql', 'mariadb', 'mongodb'].includes(kind))
    source.database = {
      host: '127.0.0.1',
      port: kind === 'postgres' ? 5432 : kind === 'mongodb' ? 27017 : 3306,
      user: kind === 'postgres' ? 'postgres' : kind === 'mongodb' ? '' : 'root',
      password: '',
    };
  chosen.value.push({ key: crypto.randomUUID(), source });
}
watch(
  () => repository.value.kind,
  () => {
    repository.value.location = '';
    repository.value.bucketLookup = repository.value.kind === 's3' ? 'auto' : undefined;
    clearSecrets();
  },
);
function definition(): BackupDefinition {
  let time: string | undefined;
  if (at.value) {
    const parsed = new Date(at.value);
    if (!Number.isFinite(parsed.getTime())) throw new Error('Choose a valid backup time.');
    time = parsed.toISOString();
  }
  if (mode.value === 'once' && !time) throw new Error('Choose the one-time backup date.');
  return {
    name: name.value.trim(),
    repository: clone(repository.value),
    sources: chosen.value.map((c) => clone(c.source)),
    timing: {
      mode: mode.value,
      ...(mode.value !== 'manual' && time ? { at: time } : {}),
      ...(mode.value === 'interval' ? { intervalMinutes: interval.value } : {}),
    },
    runtimeSeconds: runtime.value,
    exportLimitGiB: exportLimit.value,
    allowLiveFiles: liveFiles.value,
  };
}
async function save() {
  if (busy.value || pending.value || !readyToSave.value) return;
  let data: BackupDefinition;
  try {
    data = definition();
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Check backup settings.';
    return;
  }
  const v = generation,
    epoch = secretEpoch;
  if (
    !(await confirm({
      title: 'Save this backup policy?',
      message: `Save ${data.sources.length} selected source(s) on ${props.serverName ?? (scope.value || 'Nexus')} to ${data.repository.location}? Repository and database credentials are saved for these backup operations. New resources will not be added automatically. Schedules remain paused until the repository is checked or a manual backup succeeds.`,
      confirmText: 'Save backup policy',
    }))
  )
    return;
  if (!current(v) || busy.value || !manageable.value || epoch !== secretEpoch) return;
  await work(async (sid, v) => {
    const id = crypto.randomUUID().replaceAll('-', '');
    pending.value = { id, kind: 'policy' };
    try {
      await api.backups.create(sid, id, data);
      if (current(v)) {
        clearSecrets();
        chosen.value = [];
        wizard.value = false;
        step.value = 0;
        await refresh(sid, v);
        notice.value =
          'Policy saved. Install the backup tool, initialize a new repository or use your existing one, then check the repository or run a manual backup before enabling its schedule.';
      }
    } finally {
      data.repository.password = '';
      data.repository.accessKey = '';
      data.repository.secretKey = '';
      data.repository.sessionToken = '';
      for (const source of data.sources) if (source.database) source.database.password = '';
      if (current(v)) clearSecrets();
    }
  });
}
function allowed(action: BackupAction) {
  if (
    !enabled.value ||
    (!!scope.value && !supervised.value) ||
    !can('jobs.execute', scope.value) ||
    !can('secrets.use', scope.value)
  )
    return false;
  if (action === 'install' || action === 'init') return can('backups.manage', scope.value);
  if (action === 'backup') return can('backups.execute', scope.value);
  if (action === 'restore' || action === 'verify') return can('backups.restore', scope.value);
  return readable.value;
}
async function start(policy: BackupPolicy | undefined, action: BackupAction, snapshotId = '') {
  if (!policy || busy.value || pending.value || !allowed(action)) return;
  const v = generation;
  const messages: Record<BackupAction, string> = {
    install:
      'Install or verify the pinned Restic binary in the managed backup directory? Existing system packages are not changed.',
    init: 'Initialize this repository? Choose this only for a new repository. Existing repositories are not replaced.',
    backup:
      'Back up this policy’s exact selected sources now? File copies can contain concurrent writes. Database exports use their source adapter.',
    snapshots: 'Read recent snapshots belonging to this policy?',
    check: 'Read and check all stored repository data? This can take time and use storage bandwidth.',
    restore:
      'Restore this snapshot into a new private directory? Live files and databases will not be overwritten or imported.',
    verify:
      'Restore this snapshot into a temporary directory and verify its file contents, then remove that test copy? This does not test application startup.',
  };
  if (
    !(await confirm({
      title:
        action === 'restore'
          ? 'Restore a backup copy?'
          : action === 'verify'
            ? 'Verify a restore copy?'
            : 'Start backup operation?',
      message: messages[action],
      confirmText:
        action === 'restore' ? 'Restore copy' : action === 'verify' ? 'Verify restore' : 'Start operation',
    }))
  )
    return;
  if (!current(v) || busy.value || !allowed(action)) return;
  await work(async (sid, v) => {
    const id = crypto.randomUUID().replaceAll('-', '');
    pending.value = { id, kind: 'run' };
    result.value = null;
    await api.backups.start(sid, policy.id, id, action, snapshotId);
    if (current(v)) {
      await refresh(sid, v);
      notice.value =
        'Operation saved. Refresh and inspect its retained run ID. Submissions are never retried automatically.';
    }
  });
}
async function control(run: BackupRun, action: 'inspect' | 'cancel' | 'cleanup') {
  if (busy.value) return;
  const v = generation;
  if (
    action !== 'inspect' &&
    !(await confirm({
      title: action === 'cancel' ? 'Stop backup operation?' : 'Clean backup job files?',
      message:
        action === 'cancel'
          ? 'Stop managed backup processes? Already uploaded snapshots may exist; inspect the repository before a new backup.'
          : 'Remove private job/export files after verified termination. Saved history, repository snapshots and restored copies remain.',
      confirmText: action === 'cancel' ? 'Stop operation' : 'Clean job files',
    }))
  )
    return;
  if (!current(v) || busy.value) return;
  await work(async (sid, v) => {
    const response = await api.backups[action](sid, run.id);
    if (current(v)) {
      result.value = response.result
        ? { runId: run.id, policyId: run.policyId, data: response.result }
        : null;
      snapshot.value = '';
      await refresh(sid, v);
    }
  });
}
async function setSchedule(policy: BackupPolicy) {
  if (busy.value || !can('backups.schedule', scope.value)) return;
  const v = generation;
  if (
    !(await confirm({
      title: policy.enabled ? 'Pause scheduled backups?' : 'Enable scheduled backups?',
      message: policy.enabled
        ? 'Stop future scheduling and withdraw authority from an active scheduled backup? Manual runs have separate stop controls.'
        : 'Run this saved backup policy while its owner account, permissions and source identity remain valid, including while signed out? New sources are not added. Protected servers require manual execution with fresh MFA. A due one-time schedule can start immediately.',
      confirmText: policy.enabled ? 'Pause schedule' : 'Enable schedule',
    }))
  )
    return;
  if (!current(v) || busy.value || !can('backups.schedule', scope.value)) return;
  await work(async (sid, v) => {
    await api.backups.schedule(sid, policy.id, !policy.enabled);
    if (current(v)) await refresh(sid, v);
  });
}
async function archive(policy: BackupPolicy) {
  if (busy.value || !manageable.value) return;
  const v = generation;
  if (
    !(await confirm({
      title: 'Archive backup policy?',
      message:
        'Disable future backups and request cancellation of any active run for this policy? Repository snapshots and restored copies are retained.',
      confirmText: 'Archive policy',
    }))
  )
    return;
  if (!current(v) || busy.value || !manageable.value) return;
  await work(async (sid, v) => {
    await api.backups.archive(sid, policy.id);
    if (current(v)) await refresh(sid, v);
  });
}
function hidden() {
  if (document.hidden) clearSecrets();
}
onMounted(() => {
  document.addEventListener('visibilitychange', hidden);
  void load();
});
onUnmounted(() => {
  alive = false;
  clearSecrets();
  generation++;
  document.removeEventListener('visibilitychange', hidden);
});
</script>
<template>
  <section aria-label="Backup workspace" class="space-y-5">
    <div class="flex flex-wrap justify-between gap-2">
      <h2 class="text-xl font-semibold">Backups · {{ serverName ?? (serverId || 'Nexus') }}</h2>
      <Button variant="outline" :disabled="busy" @click="load">Refresh backups</Button>
    </div>
    <p v-if="!readable" class="text-sm">
      Assign a backup role for this server, or the global Nexus backup role for recovery data.
    </p>
    <p v-if="error" role="alert" class="text-sm text-destructive">
      {{ error }}
    </p>
    <p v-if="notice" role="status" class="text-sm">{{ notice }}</p>
    <p v-if="pending" class="font-mono text-xs break-all">
      Retained {{ pending.kind }} request: {{ pending.id }}. Refresh history before submitting another
      request.
    </p>
    <p v-if="!enabled && readable" class="text-sm">
      Enable backups in Nexus configuration. Source selection and repository access require explicit backup
      roles.
    </p>
    <p v-if="serverId && !supervised && enabled" class="text-sm">
      Remote execution requires operation supervision, root SSH, Python 3 and systemd/cgroup v2 on this
      server.
    </p>
    <template v-if="enabled && readable">
      <BackupManagementPanel
        :server-id="serverId"
        :supervised="supervised"
        :policies="policies"
        :runs="runs"
        :inspection="result"
        @changed="load"
        @clear-inspection="result = null"
      />
      <Button v-if="manageable && !wizard" :disabled="busy || !!pending" @click="wizard = true"
        >Set up a backup</Button
      >
      <section v-if="wizard && manageable" aria-label="Backup setup" class="space-y-4 rounded border p-4">
        <div class="flex justify-between">
          <h3 class="font-semibold">
            {{ ['1. Choose sources', '2. Choose storage', '3. Choose timing', '4. Review backup'][step] }}
          </h3>
          <Button
            variant="ghost"
            :disabled="busy"
            @click="
              wizard = false;
              clearSecrets();
            "
            >Close setup</Button
          >
        </div>
        <template v-if="step === 0">
          <p class="text-sm">
            Detect resources, select the items to protect, or add a manual source. The list can grow with more
            source adapters. New resources do not join an existing policy automatically.
          </p>
          <div class="flex flex-wrap gap-2">
            <Input
              v-if="serverId"
              v-model="browsePath"
              :disabled="busy"
              placeholder="Optional folder to browse: /srv"
            /><Button :disabled="busy" @click="discover">Detect backup sources</Button>
          </div>
          <p v-if="Object.keys(tools).length" class="text-xs">
            Detected tools:
            {{
              Object.keys(tools)
                .filter((k) => tools[k])
                .join(', ') || 'none'
            }}. The managed backup binary is verified at execution.
          </p>
          <Input v-model="search" placeholder="Filter discovered sources" :disabled="busy" />
          <div class="max-h-80 overflow-auto space-y-2">
            <label v-for="candidate in filtered" :key="candidate.id" class="block border rounded p-2 text-sm"
              ><input
                type="checkbox"
                :checked="selected(candidate.id)"
                :disabled="
                  busy ||
                  candidate.state === 'unsupported' ||
                  (!selected(candidate.id) && chosen.length >= 25)
                "
                @change="toggle(candidate)"
              />
              {{ candidate.source.label }} · {{ candidate.source.kind
              }}<span class="block text-xs text-muted-foreground"
                >{{ candidate.consistency }} {{ candidate.note }}</span
              ></label
            >
          </div>
          <p v-if="truncated" class="text-sm">
            Discovery was limited. Browse a narrower folder or add a manual source.
          </p>
          <div v-if="serverId" class="flex gap-2">
            <select
              v-model="manualKind"
              aria-label="Manual source type"
              :disabled="busy"
              class="border rounded p-2 bg-background"
            >
              <option
                v-for="kind in [
                  'files',
                  'sqlite',
                  'docker-volume',
                  'docker-bind',
                  'postgres',
                  'mysql',
                  'mariadb',
                  'mongodb',
                ]"
                :key="kind"
                :value="kind"
              >
                {{ kind }}
              </option></select
            ><Button :disabled="busy || chosen.length >= 25" @click="addManual">Add manual source</Button>
          </div>
          <div v-for="(entry, index) in chosen" :key="entry.key" class="space-y-2 rounded border p-3">
            <div class="flex justify-between">
              <h4 class="font-medium">{{ entry.source.kind }}</h4>
              <Button variant="ghost" :disabled="busy" @click="chosen.splice(index, 1)">Remove source</Button>
            </div>
            <BackupSourceFields
              v-if="entry.source.kind !== 'nexus'"
              v-model="entry.source"
              :disabled="busy"
            />
            <p v-else class="text-sm">
              A consistent database copy, matching data key and recovery metadata. Server app data, Vault
              storage and other external state need their own sources.
            </p>
          </div>
          <label v-if="hasFiles" class="block text-sm"
            ><input v-model="liveFiles" type="checkbox" :disabled="busy" /> I understand file and volume
            copies can contain live writes. I will quiesce applications that need it, or use a database
            export.</label
          >
          <p class="text-xs">
            {{ chosen.length }} selected · maximum 25 per policy. Nexus does not stop applications
            automatically.
          </p>
        </template>
        <template v-if="step === 1">
          <label class="block text-sm"
            >Repository type<select
              v-model="repository.kind"
              aria-label="Repository type"
              :disabled="busy"
              class="block border rounded p-2 bg-background"
            >
              <option value="local">Mounted folder or network storage</option>
              <option value="s3">S3-compatible storage</option>
            </select></label
          >
          <label class="block text-sm"
            >Repository location<Input
              v-model="repository.location"
              :disabled="busy"
              :placeholder="
                repository.kind === 'local'
                  ? '/mnt/backups/repository'
                  : 's3:https://s3.example.com/bucket/nexus'
              "
          /></label>
          <p class="text-xs">
            This location is reached from
            {{ serverName ?? (serverId || 'the Nexus process') }}. Mount network storage first. The repository
            and managed work directory are excluded from file backups.
          </p>
          <label class="block text-sm"
            >Repository password<Input
              v-model="repository.password"
              type="password"
              :disabled="busy"
              autocomplete="new-password"
          /></label>
          <p class="text-xs">
            Keep a separate copy of the repository password. You may need it before Nexus itself can be
            restored.
          </p>
          <template v-if="repository.kind === 's3'"
            ><label class="block text-sm"
              >Bucket addressing<select
                v-model="repository.bucketLookup"
                aria-label="Bucket addressing"
                :disabled="busy"
                class="block border rounded p-2 bg-background w-full"
              >
                <option value="auto">Automatic</option>
                <option value="path">Path style</option>
                <option value="dns">DNS style</option>
              </select></label
            ><label class="block text-sm"
              >S3 access key<Input
                v-model="repository.accessKey"
                :disabled="busy"
                autocomplete="off" /></label
            ><label class="block text-sm"
              >S3 secret key<Input
                v-model="repository.secretKey"
                type="password"
                :disabled="busy"
                autocomplete="new-password" /></label
            ><label class="block text-sm"
              >Region (optional)<Input v-model="repository.region" :disabled="busy" /></label
            ><label class="block text-sm"
              >Session token (optional)<Input
                v-model="repository.sessionToken"
                type="password"
                :disabled="busy"
                autocomplete="new-password"
            /></label>
            <p class="text-xs">
              HTTPS is required. The selected machine must trust the repository's certificate.
            </p></template
          >
        </template>
        <template v-if="step === 2">
          <label class="block text-sm"
            >Backup timing<select
              v-model="mode"
              aria-label="Backup timing"
              :disabled="busy"
              class="block border rounded p-2 bg-background"
            >
              <option value="manual">Manual backups</option>
              <option value="once">One-time backup</option>
              <option value="interval">Recurring backups</option>
            </select></label
          >
          <label v-if="mode !== 'manual'" class="block text-sm"
            >{{ mode === 'once' ? 'Run once at' : 'First scheduled backup (optional)'
            }}<Input v-model="at" type="datetime-local" :disabled="busy"
          /></label>
          <label v-if="mode === 'interval'" class="block text-sm"
            >Repeat every<select
              v-model.number="interval"
              aria-label="Repeat every"
              :disabled="busy"
              class="block border rounded p-2 bg-background"
            >
              <option :value="60">Hour</option>
              <option :value="360">6 hours</option>
              <option :value="1440">Day</option>
              <option :value="10080">Week</option>
            </select></label
          >
          <p v-if="mode !== 'manual'" class="text-sm">
            Schedules start paused. Check the repository or complete a manual backup first, then enable
            scheduling. Scheduled backups use the owner's current account permissions while signed out;
            protected servers require manual runs with fresh MFA.
          </p>
          <details class="space-y-2">
            <summary>Resource limits</summary>
            <label class="block text-sm"
              >Maximum run time (seconds)<Input
                v-model.number="runtime"
                type="number"
                min="60"
                max="86400"
                :disabled="busy" /></label
            ><label class="block text-sm"
              >Temporary database export limit (GiB)<Input
                v-model.number="exportLimit"
                type="number"
                min="1"
                max="1024"
                :disabled="busy"
            /></label>
            <p class="text-xs">
              Native database exports need temporary disk space. Files are read directly into the repository.
              A capacity failure is reported as a failed backup.
            </p>
          </details>
        </template>
        <template v-if="step === 3">
          <label class="block text-sm"
            >Backup name<Input v-model="name" :disabled="busy" maxlength="80"
          /></label>
          <p class="text-sm">
            Destination: {{ repository.location }} · {{ mode
            }}<span v-if="mode === 'interval'"> · every {{ interval }} minutes</span>.
          </p>
          <ul class="list-disc pl-5 text-sm">
            <li v-for="entry in chosen" :key="entry.key">
              {{ entry.source.label }} · {{ entry.source.kind }}
              {{ entry.source.path ?? entry.source.volume ?? entry.source.containerId ?? '' }}
            </li>
          </ul>
          <p class="text-sm">
            Saving configures the policy. It does not claim a completed backup. Install the tool, initialize a
            new repository if needed, then back up and test a restore copy.
          </p>
          <Button :disabled="busy || !!pending || !readyToSave" @click="save">Save backup policy</Button>
        </template>
        <div class="flex gap-2">
          <Button v-if="step > 0" variant="outline" :disabled="busy" @click="step--">Back</Button
          ><Button
            v-if="step < 3"
            :disabled="busy || (step === 0 && (!chosen.length || (hasFiles && !liveFiles)))"
            @click="step++"
            >Continue setup</Button
          >
        </div>
      </section>
      <section aria-label="Saved backups" class="space-y-3">
        <h3 class="font-semibold">Saved backup policies</h3>
        <p v-if="!policies.length" class="text-sm">No policies configured.</p>
        <article v-for="policy in policies" :key="policy.id" class="space-y-2 border rounded p-3 text-sm">
          <h4 class="font-medium">{{ policy.name }}{{ policy.archived ? ' · archived' : '' }}</h4>
          <p>
            {{ policy.lastState.replaceAll('_', ' ') }} · {{ policy.mode }}
            {{ policy.mode !== 'manual' ? (policy.enabled ? '· enabled' : '· paused') : '' }}
          </p>
          <p class="break-all">{{ policy.repository.kind }} · {{ policy.repository.location }}</p>
          <ul class="list-disc pl-5">
            <li v-for="(source, index) in policy.sources" :key="index">
              {{ source.label }} · {{ source.kind }}
              {{ source.path ?? source.volume ?? '' }}
            </li>
          </ul>
          <p>
            Last successful backup:
            {{ policy.lastSuccessAt ? new Date(policy.lastSuccessAt).toLocaleString() : 'none' }}
          </p>
          <p>
            Repository checked:
            {{ policy.lastCheckAt ? new Date(policy.lastCheckAt).toLocaleString() : 'not checked' }}
            · Restore contents verified:
            {{ policy.lastRestoreAt ? new Date(policy.lastRestoreAt).toLocaleString() : 'not tested' }}
          </p>
          <p v-if="policy.nextAt && !policy.archived">
            Next configured time: {{ new Date(policy.nextAt).toLocaleString() }}
          </p>
          <div v-if="!policy.archived" class="flex flex-wrap gap-2">
            <Button
              v-for="action in ['install', 'init', 'backup', 'snapshots', 'check'] as const"
              :key="action"
              :disabled="busy || !!pending || !allowed(action)"
              variant="outline"
              @click="start(policy, action)"
              >{{
                {
                  install: 'Install / verify tool',
                  init: 'Initialize new repository',
                  backup: 'Back up now',
                  snapshots: 'List snapshots',
                  check: 'Check repository',
                }[action]
              }}</Button
            >
            <Button
              v-if="
                policy.mode !== 'manual' && can('backups.schedule', scope) && can('backups.manage', scope)
              "
              :disabled="busy || (!policy.enabled && !policy.lastSuccessAt && !policy.lastCheckAt)"
              variant="outline"
              @click="setSchedule(policy)"
              >{{ policy.enabled ? 'Pause schedule' : 'Enable schedule' }}</Button><Button
              v-if="manageable"
              variant="outline"
              :disabled="busy"
              @click="archive(policy)"
              >Archive policy</Button
            >
          </div>
        </article>
      </section>
      <section v-if="historyReadable" aria-label="Backup run history" class="space-y-3">
        <h3 class="font-semibold">Run history</h3>
        <article v-for="run in runs" :key="run.id" class="rounded border p-3 text-sm space-y-1">
          <p class="font-mono break-all">{{ run.id }}</p>
          <p>
            {{ run.action?.replace('backup:', '') }} · {{ run.state }} ·
            {{ new Date(run.createdAt).toLocaleString() }}
          </p>
          <p v-if="run.detail">{{ run.detail.replaceAll('_', ' ') }}</p>
          <div class="flex gap-2 flex-wrap">
            <Button
              variant="outline"
              :disabled="busy || !can('logs.read', scope) || !can('secrets.use', scope)"
              @click="control(run, 'inspect')"
              >Inspect backup run</Button
            ><Button
              v-if="!run.finishedAt && can('jobs.cancel', scope)"
              variant="outline"
              :disabled="busy"
              @click="control(run, 'cancel')"
              >Stop backup operation</Button
            ><Button
              v-if="
                run.finishedAt && (!run.artifactsRemoved || !run.stagingClean) && can('jobs.manage', scope)
              "
              variant="outline"
              :disabled="busy"
              @click="control(run, 'cleanup')"
              >Clean backup job files</Button
            >
          </div>
        </article>
      </section>
      <section v-if="result" aria-label="Backup result" class="space-y-2 border rounded p-3 text-sm">
        <div class="flex justify-between">
          <h3 class="font-medium">{{ result.data.state }}</h3>
          <Button variant="ghost" @click="result = null">Hide backup result</Button>
        </div>
        <p v-if="result.data.phase">Phase: {{ result.data.phase.replaceAll('_', ' ') }}</p>
        <p v-if="result.data.snapshotId" class="font-mono break-all">Snapshot {{ result.data.snapshotId }}</p>
        <p v-if="result.data.files !== undefined">
          {{ result.data.files }} files · {{ result.data.bytes ?? 0 }} bytes
        </p>
        <p v-if="result.data.restorePath" class="break-all">Restored copy: {{ result.data.restorePath }}</p>
        <p v-if="result.data.verified">
          This operation's check passed. Application startup and live database import are separate steps.
        </p>
        <template v-if="result.data.snapshots?.length"
          ><label class="block"
            >Snapshot to restore<select
              v-model="snapshot"
              aria-label="Snapshot to restore"
              :disabled="busy"
              class="block border rounded p-2 bg-background w-full"
            >
              <option value="">Choose snapshot</option>
              <option v-for="item in result.data.snapshots" :key="item.id" :value="item.id">
                {{ new Date(item.time).toLocaleString() }} ·
                {{ item.id.slice(0, 12) }}
              </option>
            </select></label
          >
          <div class="flex gap-2">
            <Button
              :disabled="busy || !snapshot || !!pending || !allowed('restore')"
              @click="
                start(
                  policies.find((p) => p.id === result!.policyId)!,
                  'restore',
                  snapshot,
                )
              "
              >Restore a copy</Button
            ><Button
              variant="outline"
              :disabled="busy || !snapshot || !!pending || !allowed('verify')"
              @click="
                start(
                  policies.find((p) => p.id === result!.policyId)!,
                  'verify',
                  snapshot,
                )
              "
              >Verify restore copy</Button
            >
          </div></template
        >
      </section>
    </template>
  </section>
</template>
