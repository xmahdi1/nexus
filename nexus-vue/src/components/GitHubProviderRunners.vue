<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type GitHubProviderRunner, type GitHubChange } from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Button from '@/components/ui/Button.vue';
const props = defineProps<{
  serverId: string;
  connectionId: string;
  repository: string;
}>();
const { confirm } = useConfirm();
const rows = ref<GitHubProviderRunner[]>([]),
  history = ref<GitHubChange[]>([]),
  page = ref(1),
  total = ref(0),
  busy = ref(false),
  error = ref(''),
  pending = ref('');
const readable = computed(
  () => can('github.runners.provider.read', props.serverId) && can('secrets.use', props.serverId),
);
const manageable = computed(() => readable.value && can('github.runners.provider.manage', props.serverId));
let generation = 0,
  alive = true;
function clear() {
  generation++;
  rows.value = [];
  history.value = [];
  pending.value = '';
  total.value = 0;
}
watch(() => [props.serverId, props.connectionId, readable.value, manageable.value].join(','), clear, {
  flush: 'sync',
});
onUnmounted(() => {
  alive = false;
  clear();
});
function current(version: number) {
  return alive && version === generation;
}
async function refresh(next = page.value) {
  if (busy.value || !readable.value) return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  try {
    const [result, changes] = await Promise.all([
      api.githubActions.providerRunners(props.serverId, props.connectionId, next),
      api.githubActions.changes(props.serverId),
    ]);
    if (!current(version)) return;
    rows.value = result.runners;
    page.value = next;
    total.value = result.total_count;
    history.value = changes.filter(
      (row) => row.connectionId === props.connectionId && row.kind === 'runner_remove',
    );
    if (
      history.value.some(
        (row) => row.id === pending.value && ['applied', 'not_submitted'].includes(row.state),
      )
    )
      pending.value = '';
    if (!pending.value)
      pending.value =
        history.value.find((row) => !['applied', 'not_submitted'].includes(row.state))?.id ?? '';
  } catch (e) {
    if (current(version)) error.value = e instanceof Error ? e.message : 'Runner status unavailable.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function remove(runner: GitHubProviderRunner) {
  if (busy.value || pending.value || !manageable.value || runner.status !== 'offline' || runner.busy) return;
  const version = generation,
    id = runner.id,
    name = runner.name;
  if (
    !(await confirm({
      title: 'Remove GitHub runner registration?',
      message: `Remove registration ${id} (${name}) from ${props.repository}? Stop its host process first. A name match does not prove host ownership. GitHub currently reports it offline and idle; that can change before removal. This does not stop a process or clean host files.`,
      confirmText: 'Remove registration',
      destructive: true,
    }))
  )
    return;
  if (!current(version) || busy.value || !manageable.value) return;
  const requestId = crypto.randomUUID().replaceAll('-', '');
  pending.value = requestId;
  busy.value = true;
  error.value = '';
  try {
    const result = await api.githubActions.removeProviderRunner(
      props.serverId,
      props.connectionId,
      requestId,
      id,
      name,
    );
    if (!current(version)) return;
    history.value.unshift(result.change);
    if (result.change.state === 'applied') {
      rows.value = rows.value.filter((row) => row.id !== id);
      total.value = Math.max(0, total.value - 1);
      pending.value = '';
    } else if (result.change.state === 'not_submitted') {
      pending.value = '';
      error.value = 'No registration was removed. Refresh GitHub status before trying again.';
    } else error.value = 'Removal is unconfirmed. Check GitHub before another request.';
  } catch (e) {
    if (current(version))
      error.value =
        (e instanceof Error ? e.message : 'Removal unconfirmed.') + ' Retained request ' + requestId + '.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function acknowledge() {
  const version = generation;
  if (
    (await confirm({
      title: 'Allow a new runner removal request?',
      message:
        'Check the saved request and the exact registration ID in GitHub first. The old request is never replayed.',
      confirmText: 'I checked GitHub',
    })) &&
    current(version)
  )
    pending.value = '';
}
onMounted(() => refresh(1));
</script>
<template>
  <section aria-label="GitHub repository runners" class="border rounded p-4 space-y-3">
    <h4 class="font-medium">Repository runner registrations</h4>
    <p class="text-sm">
      GitHub reports online/offline and busy state. These registrations are separate from Nexus's host process
      history. Matching names do not prove the same host or enrollment. Only repository runners are supported
      here.
    </p>
    <p class="text-xs">
      The App needs Administration read to list runners, or write to remove one. Nexus requests that
      permission only for these operations. It is not needed for workflow dispatch.
    </p>
    <p v-if="error" role="alert" class="text-sm text-destructive">
      {{ error }}
    </p>
    <Button variant="outline" :disabled="busy || !readable" @click="refresh()">Refresh GitHub runners</Button>
    <div v-for="runner in rows" :key="runner.id" class="border rounded p-3 text-sm space-y-1">
      <p>Registration {{ runner.id }} · {{ runner.name }} · {{ runner.os }}</p>
      <p>
        {{ runner.status }} · {{ runner.busy ? 'busy' : 'idle' }} ·
        {{ runner.ephemeral ? 'ephemeral' : 'persistent' }} ·
        {{ runner.version }}
      </p>
      <p>{{ runner.labels.map((label) => label.name).join(', ') }}</p>
      <Button
        v-if="manageable"
        variant="destructive"
        :disabled="busy || !!pending || runner.busy || runner.status !== 'offline'"
        @click="remove(runner)"
        >Remove registration {{ runner.id }}</Button
      >
    </div>
    <div v-if="total > 50" class="flex gap-2">
      <Button :disabled="busy || page <= 1" @click="refresh(page - 1)">Previous runners</Button
      ><Button :disabled="busy || page * 50 >= total" @click="refresh(page + 1)">Next runners</Button>
    </div>
    <p v-if="!rows.length && !busy && !error && readable" class="text-sm">
      No registrations on this page. This does not inspect organization runner groups or prove a host process
      has stopped.
    </p>
    <div v-if="pending" class="text-sm break-all">
      <p>Retained removal request: {{ pending }}</p>
      <Button variant="outline" :disabled="busy" @click="acknowledge">I checked the runner removal</Button>
    </div>
    <p v-for="row in history" :key="row.id" class="text-xs break-all">
      {{ row.id }} · registration {{ row.resourceId }} · {{ row.state }}
    </p>
  </section>
</template>
