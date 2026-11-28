<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type RunnerProfile, type InteractiveRun } from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Dialog from '@/components/ui/Dialog.vue';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';

const props = defineProps<{ serverId: string }>();
const emit = defineEmits<{ close: [] }>();
const { confirm } = useConfirm();
const enabled = ref(false),
  busy = ref(false),
  error = ref(''),
  token = ref(''),
  url = ref(''),
  name = ref('nexus-build'),
  labels = ref('nexus'),
  group = ref(''),
  lifetime = ref(3600),
  dedicated = ref(false),
  pending = ref('');
const runners = ref<Array<{ run: InteractiveRun; profile: RunnerProfile & { version: string } }>>([]);
const inspection = ref('');
const allowed = computed(() => ['github.runners.read', 'jobs.read'].every((p) => can(p, props.serverId)));
const manageable = computed(
  () =>
    allowed.value &&
    [
      'github.runners.manage',
      'servers.execute',
      'secrets.use',
      'logs.read',
      'jobs.cancel',
      'jobs.manage',
    ].every((p) => can(p, props.serverId)),
);
let generation = 0,
  alive = true;
const organization = computed(() => /^https:\/\/github\.com\/[^/]+$/.test(url.value));
function close() {
  token.value = '';
  generation++;
  emit('close');
}
function clear() {
  generation++;
  token.value = '';
  inspection.value = '';
  runners.value = [];
  error.value = '';
  busy.value = false;
}
watch(() => [props.serverId, allowed.value, manageable.value].join(','), clear, { flush: 'sync' });
watch(
  () => props.serverId,
  () => {
    pending.value = '';
  },
  { flush: 'sync' },
);
onUnmounted(() => {
  alive = false;
  clear();
});
async function load() {
  if (busy.value || !allowed.value) return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  token.value = '';
  try {
    const [features, items] = await Promise.all([api.features(), api.runners.list(props.serverId)]);
    if (alive && version === generation) {
      enabled.value = features.automation && features.operationSupervision;
      runners.value = items;
    }
  } catch (e) {
    if (alive && version === generation) {
      runners.value = [];
      error.value = e instanceof Error ? e.message : 'Runner history unavailable.';
    }
  } finally {
    if (alive && version === generation) busy.value = false;
  }
}
async function start() {
  if (busy.value || !enabled.value || !manageable.value || !dedicated.value || pending.value) return;
  const version = generation,
    server = props.serverId;
  if (
    !(await confirm({
      title: 'Enroll one-job runner?',
      message:
        'This lets trusted GitHub workflows execute code on this build server under a separate account. The runner stops after one job, its lifetime limit, cancellation or loss of Nexus authority. Its workspace is temporary. Use GitHub runner-group restrictions for organization access.',
      confirmText: 'Enroll runner',
      destructive: true,
    }))
  )
    return;
  if (!alive || version !== generation || server !== props.serverId) return;
  busy.value = true;
  error.value = '';
  const requestId = crypto.randomUUID().replaceAll('-', '');
  pending.value = requestId;
  const registrationToken = token.value;
  token.value = '';
  try {
    const result = await api.runners.start(server, {
      requestId,
      registrationToken,
      url: url.value.trim(),
      name: name.value.trim(),
      labels: labels.value
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean),
      group: organization.value ? group.value.trim() : '',
      lifetimeSeconds: lifetime.value,
    });
    if (alive && version === generation) {
      error.value = 'Submitted. Inspect the retained run before enrolling again.';
      await refreshItems(server, version);
      if (result.run.finishedAt) pending.value = '';
    }
  } catch (e) {
    if (alive && version === generation) {
      const failure = e as { status?: number; run?: unknown; code?: string };
      const rejected =
        [400, 401, 403, 404, 409, 503].includes(failure?.status ?? 0) &&
        !failure?.run &&
        failure?.code !== 'remote_outcome_unknown';
      if (rejected) pending.value = '';
      error.value =
        (e instanceof Error ? e.message : 'Submission could not be confirmed.') +
        (rejected
          ? ' Enter a fresh registration token before another explicit submission.'
          : ' Retained request: ' + requestId + '. Refresh/inspect before retrying.');
    }
  } finally {
    if (alive && version === generation) busy.value = false;
  }
}
async function refreshItems(server: string, version: number) {
  const items = await api.runners.list(server);
  if (alive && version === generation) {
    runners.value = items;
    const current = items.find((item) => item.run.id === pending.value);
    if (current?.run.finishedAt) pending.value = '';
  }
}
async function control(action: 'inspect' | 'cancel' | 'release', id: string) {
  if (busy.value || !manageable.value) return;
  const version = generation,
    server = props.serverId;
  if (
    action !== 'inspect' &&
    !(await confirm({
      title: action === 'cancel' ? 'Stop runner and its job?' : 'Clean runner artifacts?',
      message:
        action === 'cancel'
          ? 'Stop the runner and all processes in its managed job group. Remote effects cannot be undone. If no job completed, remove any offline registration in GitHub.'
          : 'Remove the completed run’s private supervisor files and any reserved runner account. This does not delete a registration from GitHub.',
      confirmText: action === 'cancel' ? 'Stop runner' : 'Clean artifacts',
      destructive: true,
    }))
  )
    return;
  if (!alive || version !== generation || server !== props.serverId) return;
  busy.value = true;
  error.value = '';
  token.value = '';
  try {
    const result = await api.operations[action](server, id);
    if (alive && version === generation) {
      inspection.value = result.observation.output || result.run.state;
      await refreshItems(server, version);
    }
  } catch (e) {
    if (alive && version === generation)
      error.value = e instanceof Error ? e.message : 'Could not confirm runner state.';
  } finally {
    if (alive && version === generation) busy.value = false;
  }
}
function inspected() {
  if (!pending.value) return;
  void control('inspect', pending.value);
}
onMounted(load);
</script>

<template>
  <Dialog :open="true" max-width="max-w-3xl" @update:open="close">
    <section aria-label="GitHub runner setup" class="p-6 space-y-4 max-h-[90vh] overflow-y-auto">
      <div class="flex justify-between items-center">
        <h2 class="text-lg font-semibold">GitHub Actions runner</h2>
        <Button variant="ghost" @click="close">Close</Button>
      </div>
      <p class="text-sm font-medium">Build server: {{ serverId }}</p>
      <p class="text-sm">
        One-job Linux runner with a dedicated account, no supplementary groups or Docker socket, a temporary 1
        GiB workspace, 2 GiB memory limit and two CPU cores. Runner files and job output are discarded when it
        stops. Use a dedicated build server for trusted workflows.
      </p>
      <p v-if="!allowed" role="alert">
        Runner-read and job-read grants are required. Assign the github-runners role explicitly for this
        server.
      </p>
      <p v-if="allowed && !manageable">
        Setup and lifecycle controls also need runner-manage, SSH execution, secret-use, log-read and job
        cancel/manage grants.
      </p>
      <p v-if="allowed && !enabled">Enable automation and operation supervision before enrolling a runner.</p>
      <p class="text-xs text-muted-foreground">
        Requires root SSH with a verified host-key pin (test the server connection first), systemd/cgroup v2,
        Python 3.12+, useradd and the GitHub runner’s OS dependencies. Setup reports failure if prerequisites
        are missing; it does not change OS packages.
      </p>
      <form v-if="manageable" class="space-y-3" @submit.prevent="start">
        <label class="block text-sm"
          >GitHub.com repository or organization URL<Input
            v-model="url"
            placeholder="https://github.com/owner/repository"
            :disabled="busy"
            required
        /></label>
        <div class="grid sm:grid-cols-2 gap-3">
          <label class="block text-sm">Runner name<Input v-model="name" :disabled="busy" required /></label
          ><label class="block text-sm"
            >Custom labels (comma separated)<Input v-model="labels" :disabled="busy"
          /></label>
        </div>
        <label v-if="organization" class="block text-sm"
          >Organization runner group<Input
            v-model="group"
            :disabled="busy"
            placeholder="Restricted build group"
            required
        /></label>
        <label class="block text-sm"
          >Short-lived registration token<Input
            v-model="token"
            type="password"
            autocomplete="off"
            :disabled="busy"
            required
        /></label>
        <p class="text-xs text-muted-foreground">
          Get it from GitHub → repository/organization Settings → Actions → Runners → New self-hosted runner.
          Paste the registration token, not a personal access or GitHub App token. Nexus does not save it; it
          is cleared on submit or close. Never reuse a token from an uncertain enrollment.
        </p>
        <label class="block text-sm"
          >Maximum runner lifetime
          <select v-model="lifetime" class="border rounded p-2 bg-background" :disabled="busy">
            <option :value="900">15 minutes</option>
            <option :value="1800">30 minutes</option>
            <option :value="3600">1 hour</option>
          </select></label
        >
        <label class="flex items-start gap-2 text-sm"
          ><input v-model="dedicated" type="checkbox" :disabled="busy" />This is a dedicated build server for
          trusted workflows. Runner labels do not prevent untrusted pull requests from executing code;
          repository/group restrictions must be configured in GitHub.</label
        >
        <Button type="submit" :disabled="busy || !enabled || !dedicated || !!pending"
          >Enroll one-job runner</Button
        >
      </form>
      <p v-if="error" role="alert" class="text-sm break-all">{{ error }}</p>
      <pre v-if="inspection" class="text-xs whitespace-pre-wrap break-all border rounded p-3">{{
        inspection
      }}</pre>
      <div v-if="pending" class="text-sm space-y-2">
        <p class="break-all">Retained request: {{ pending }}</p>
        <Button :disabled="busy || !manageable" @click="inspected">Inspect retained request</Button>
      </div>
      <div class="flex justify-between items-center">
        <h3 class="font-medium">Runner history on this server</h3>
        <Button :disabled="busy || !allowed" variant="outline" @click="load">Refresh</Button>
      </div>
      <p class="text-xs text-muted-foreground">
        “Running” means the managed runner process is active; GitHub is authoritative for online/busy status
        and workflow results. After a completed job, create a fresh one-job runner when needed.
      </p>
      <div v-for="item in runners" :key="item.run.id" class="border rounded p-3 space-y-2 text-sm">
        <p class="font-medium">
          {{ item.profile.name }} · {{ item.run.state }} ·
          {{ item.profile.version }}
        </p>
        <p class="break-all">{{ item.profile.url }}</p>
        <p class="font-mono break-all">{{ item.run.id }}</p>
        <div class="flex gap-2 flex-wrap">
          <Button :disabled="busy || !manageable" @click="control('inspect', item.run.id)">Inspect</Button
          ><Button
            v-if="!item.run.finishedAt"
            :disabled="busy || !manageable"
            @click="control('cancel', item.run.id)"
            >Stop runner</Button
          ><Button
            v-else-if="!item.run.artifactsRemoved"
            :disabled="busy || !manageable"
            @click="control('release', item.run.id)"
            >Clean artifacts</Button
          >
        </div>
      </div>
    </section>
  </Dialog>
</template>
