<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type GitHubRun, type GitHubJob, type GitHubArtifact, type GitHubCancellation } from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Button from '@/components/ui/Button.vue';
const props = defineProps<{
  serverId: string;
  connectionId: string;
  runId: number;
}>();
const { confirm } = useConfirm();
const run = ref<GitHubRun>(),
  jobs = ref<GitHubJob[]>([]),
  artifacts = ref<GitHubArtifact[]>([]),
  history = ref<GitHubCancellation[]>([]);
const jobPage = ref(1),
  jobTotal = ref(0),
  artifactPage = ref(1),
  artifactTotal = ref(0);
const busy = ref(false),
  error = ref(''),
  status = ref(''),
  log = ref(''),
  logJob = ref(0),
  pending = ref('');
let generation = 0,
  alive = true;
const readable = computed(
  () => can('github.actions.read', props.serverId) && can('secrets.use', props.serverId),
);
const logsAllowed = computed(() => readable.value && can('github.actions.logs.read', props.serverId));
const artifactsAllowed = computed(
  () => readable.value && can('github.actions.artifacts.read', props.serverId),
);
const cancelAllowed = computed(() => readable.value && can('github.actions.cancel', props.serverId));
function clear() {
  generation++;
  run.value = undefined;
  jobs.value = [];
  artifacts.value = [];
  history.value = [];
  log.value = '';
  logJob.value = 0;
  pending.value = '';
  status.value = '';
}
watch(
  () =>
    [
      props.serverId,
      props.connectionId,
      props.runId,
      readable.value,
      logsAllowed.value,
      artifactsAllowed.value,
      cancelAllowed.value,
    ].join(','),
  clear,
  { flush: 'sync' },
);
onUnmounted(() => {
  alive = false;
  clear();
});
function current(version: number) {
  return alive && generation === version;
}
async function perform(work: (version: number) => Promise<void>) {
  if (busy.value || !readable.value) return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  try {
    await work(version);
  } catch (e) {
    if (current(version)) error.value = e instanceof Error ? e.message : 'GitHub operation unavailable.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function refresh() {
  log.value = '';
  logJob.value = 0;
  await perform(async (version) => {
    const [remote, cancellations] = await Promise.all([
      api.githubActions.run(props.serverId, props.connectionId, props.runId),
      api.githubActions.cancellations(props.serverId),
    ]);
    if (!current(version)) return;
    run.value = remote;
    history.value = cancellations.filter(
      (row) => row.connectionId === props.connectionId && row.runId === props.runId,
    );
    if (
      history.value.some(
        (row) => row.id === pending.value && ['requested', 'not_submitted'].includes(row.state),
      )
    )
      pending.value = '';
    if (!pending.value)
      pending.value =
        history.value.find((row) => ['prepared', 'submitting', 'unknown'].includes(row.state))?.id ?? '';
    status.value = remote.status === 'completed' ? 'GitHub reports this run completed.' : '';
  });
}
async function list(kind: 'jobs' | 'artifacts', page: number) {
  await perform(async (version) => {
    if (kind === 'jobs') {
      const result = await api.githubActions.jobs(props.serverId, props.connectionId, props.runId, page);
      if (current(version)) {
        jobs.value = result.jobs;
        jobTotal.value = result.total_count;
        jobPage.value = page;
        log.value = '';
        logJob.value = 0;
      }
    } else {
      const result = await api.githubActions.artifacts(props.serverId, props.connectionId, props.runId, page);
      if (current(version)) {
        artifacts.value = result.artifacts;
        artifactTotal.value = result.total_count;
        artifactPage.value = page;
      }
    }
  });
}
async function revealLog(job: number) {
  if (busy.value || !logsAllowed.value) return;
  const version = generation;
  if (
    !(await confirm({
      title: 'Read raw workflow logs?',
      message:
        'Logs may contain secrets and untrusted text. They are not redacted by Nexus. Only open logs you are authorized to read.',
      confirmText: 'Read logs',
    }))
  )
    return;
  if (!current(version) || !logsAllowed.value) return;
  log.value = '';
  logJob.value = 0;
  await perform(async (next) => {
    const result = await api.githubActions.jobLog(props.serverId, props.connectionId, props.runId, job);
    if (current(next) && logsAllowed.value) {
      log.value = result.content;
      logJob.value = job;
    }
  });
}
async function download(artifact: GitHubArtifact) {
  if (busy.value || !artifactsAllowed.value || artifact.expired || artifact.size_in_bytes > 16777216) return;
  const version = generation;
  if (
    !(await confirm({
      title: 'Download workflow artifact?',
      message: `Download artifact ${artifact.id} (${artifact.name})? Archives may contain secrets or untrusted files. Nexus does not extract or execute their contents.`,
      confirmText: 'Download ZIP',
    }))
  )
    return;
  if (!current(version) || !artifactsAllowed.value) return;
  await perform(async (next) => {
    const blob = await api.githubActions.artifactDownload(
      props.serverId,
      props.connectionId,
      props.runId,
      artifact.id,
    );
    if (!current(next) || !artifactsAllowed.value) return;
    const url = URL.createObjectURL(blob),
      link = document.createElement('a');
    link.href = url;
    link.download = `github-artifact-${artifact.id}.zip`;
    link.rel = 'noopener';
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    status.value = 'Artifact downloaded to this browser.';
  });
}
async function cancelRun() {
  if (
    busy.value ||
    pending.value ||
    !cancelAllowed.value ||
    !run.value?.run_attempt ||
    run.value.status === 'completed'
  )
    return;
  const version = generation,
    attempt = run.value.run_attempt;
  if (
    !(await confirm({
      title: 'Request workflow cancellation?',
      message: `Ask GitHub to cancel run ${props.runId}, observed attempt ${attempt}? Cancellation is asynchronous and cannot undo workflow effects. No force-cancel or automatic retry is used.`,
      confirmText: 'Request cancellation',
      destructive: true,
    }))
  )
    return;
  if (!current(version) || busy.value || !cancelAllowed.value) return;
  const requestId = crypto.randomUUID().replaceAll('-', '');
  pending.value = requestId;
  await perform(async (next) => {
    const result = await api.githubActions.cancelRun(
      props.serverId,
      props.connectionId,
      props.runId,
      requestId,
      attempt,
    );
    if (!current(next)) return;
    history.value.unshift(result.cancellation);
    if (['requested', 'not_submitted'].includes(result.cancellation.state)) pending.value = '';
    status.value =
      result.cancellation.state === 'requested'
        ? 'GitHub accepted the cancellation request. Refresh status to check completion.'
        : 'Cancellation is ' + result.cancellation.state + '. Inspect GitHub before a new request.';
  });
}
async function acknowledge() {
  const version = generation;
  if (
    (await confirm({
      title: 'Allow another cancellation request?',
      message:
        'Only continue after checking GitHub and the retained request. A new request may affect a later attempt of this run. The earlier request is never replayed.',
      confirmText: 'I checked GitHub',
    })) &&
    current(version)
  )
    pending.value = '';
}
onMounted(async () => {
  await refresh();
  if (alive && readable.value) await list('jobs', 1);
});
</script>
<template>
  <section aria-label="GitHub run details" class="border rounded p-4 space-y-3">
    <h4 class="font-medium">Run {{ runId }} details</h4>
    <p v-if="error" role="alert" class="text-sm text-destructive">
      {{ error }}
    </p>
    <p v-if="status" role="status" class="text-sm">{{ status }}</p>
    <p v-if="run" class="text-sm">
      Attempt {{ run.run_attempt }} · {{ run.status }} ·
      {{ run.conclusion ?? 'pending' }}
    </p>
    <div class="flex gap-2 flex-wrap">
      <Button variant="outline" :disabled="busy || !readable" @click="refresh">Refresh run status</Button>
      <Button
        v-if="cancelAllowed"
        variant="destructive"
        :disabled="busy || !!pending || !run?.run_attempt || run.status === 'completed'"
        @click="cancelRun"
        >Request cancellation</Button
      >
    </div>
    <div v-if="pending" class="text-sm break-all">
      <p>Retained cancellation request: {{ pending }}</p>
      <Button variant="outline" :disabled="busy" @click="acknowledge"
        >I checked the cancellation request</Button
      >
    </div>
    <p v-for="row in history" :key="row.id" class="text-xs break-all">
      {{ row.id }} · attempt {{ row.runAttempt }} · {{ row.state }}
    </p>
    <h5 class="font-medium">Jobs</h5>
    <Button variant="outline" :disabled="busy || !readable" @click="list('jobs', 1)">Refresh jobs</Button>
    <div v-for="job in jobs" :key="job.id" class="text-sm flex gap-3 items-center flex-wrap">
      <span>{{ job.name }} · {{ job.status }} · {{ job.conclusion ?? 'pending' }}</span
      ><Button v-if="logsAllowed" variant="outline" :disabled="busy" @click="revealLog(job.id)"
        >Read logs for job {{ job.id }}</Button
      >
    </div>
    <div v-if="jobTotal > 50" class="flex gap-2">
      <Button :disabled="busy || jobPage <= 1" @click="list('jobs', jobPage - 1)">Previous jobs</Button
      ><Button :disabled="busy || jobPage * 50 >= jobTotal" @click="list('jobs', jobPage + 1)"
        >Next jobs</Button
      >
    </div>
    <div v-if="logJob" class="space-y-2">
      <p class="text-sm">Raw logs for job {{ logJob }} · unredacted · at most 1 MiB</p>
      <Button
        variant="outline"
        @click="
          log = '';
          logJob = 0;
        "
        >Hide workflow logs</Button
      >
      <pre class="whitespace-pre-wrap break-all text-xs max-h-96 overflow-auto border rounded p-3">{{
        log
      }}</pre>
    </div>
    <h5 class="font-medium">Artifacts</h5>
    <Button variant="outline" :disabled="busy || !readable" @click="list('artifacts', 1)"
      >List artifacts</Button
    >
    <div v-for="artifact in artifacts" :key="artifact.id" class="text-sm border rounded p-2 space-y-1">
      <p>
        {{ artifact.name }} · {{ artifact.size_in_bytes }} bytes ·
        {{ artifact.expired ? 'expired' : 'available' }}
      </p>
      <Button
        v-if="artifactsAllowed"
        variant="outline"
        :disabled="busy || artifact.expired || artifact.size_in_bytes > 16777216"
        @click="download(artifact)"
        >Download artifact {{ artifact.id }}</Button
      >
      <p v-if="artifact.size_in_bytes > 16777216" class="text-xs">Exceeds the 16 MiB download limit.</p>
    </div>
    <div v-if="artifactTotal > 50" class="flex gap-2">
      <Button :disabled="busy || artifactPage <= 1" @click="list('artifacts', artifactPage - 1)"
        >Previous artifacts</Button
      ><Button
        :disabled="busy || artifactPage * 50 >= artifactTotal"
        @click="list('artifacts', artifactPage + 1)"
        >Next artifacts</Button
      >
    </div>
    <p class="text-xs text-muted-foreground">
      Logs and downloads require separate scoped permissions. Contents are not redacted or saved in Nexus.
      Downloaded files remain in your browser's download location.
    </p>
  </section>
</template>
