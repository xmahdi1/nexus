<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type AnsiblePlanView, type AnsibleQueueEntry, type AnsibleSchedule } from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';
const props = defineProps<{
  serverId: string;
  actorId: string;
  plan?: AnsiblePlanView;
}>();
const emit = defineEmits<{ refresh: [] }>();
const { confirm } = useConfirm();
const queue = ref<AnsibleQueueEntry[]>([]),
  schedules = ref<AnsibleSchedule[]>([]),
  busy = ref(false),
  error = ref(''),
  notice = ref(''),
  pending = ref(''),
  enabled = ref(false);
const notBefore = ref(''),
  afterRunId = ref(''),
  name = ref(''),
  interval = ref(1440),
  firstAt = ref('');
let generation = 0,
  alive = true;
const readable = computed(
  () => can('ansible.projects.read', props.serverId) && can('jobs.read', props.serverId),
);
const queueable = computed(
  () =>
    enabled.value &&
    readable.value &&
    can('ansible.playbooks.execute', props.serverId) &&
    can('jobs.execute', props.serverId) &&
    props.plan?.state === 'approved' &&
    props.plan.actorId === props.actorId &&
    !pending.value &&
    !queue.value.some((q) => q.planId === props.plan?.id),
);
const schedulable = computed(
  () =>
    readable.value &&
    can('ansible.schedules.manage', props.serverId) &&
    can('secrets.create', props.serverId) &&
    can('secrets.use', props.serverId) &&
    props.plan?.actorId === props.actorId &&
    !!props.plan.presetId,
);
const hasVault = computed(
  () =>
    !!props.plan?.options.vaultPassword ||
    Object.values(props.plan?.variables ?? {}).some((v) => v && typeof v === 'object' && 'serverId' in v),
);
function clear() {
  generation++;
  queue.value = [];
  schedules.value = [];
  pending.value = '';
  name.value = '';
  error.value = '';
  notice.value = '';
  busy.value = false;
}
watch(
  () =>
    [
      props.serverId,
      props.actorId,
      readable.value,
      can('ansible.schedules.manage', props.serverId),
      can('jobs.execute', props.serverId),
    ].join(','),
  clear,
  { flush: 'sync' },
);
onUnmounted(() => {
  alive = false;
  clear();
});
function current(v: number) {
  return alive && v === generation && readable.value;
}
async function work(fn: (server: string, v: number) => Promise<void>) {
  if (busy.value || !readable.value) return;
  const v = ++generation,
    server = props.serverId;
  busy.value = true;
  error.value = '';
  notice.value = '';
  try {
    await fn(server, v);
  } catch (e) {
    if (current(v)) error.value = e instanceof Error ? e.message : 'Automation controls unavailable.';
  } finally {
    if (alive && v === generation) busy.value = false;
  }
}
async function rows(server: string, v: number) {
  const [nextQueue, nextSchedules, flags] = await Promise.all([
    api.playbooks.queue(server),
    api.playbooks.schedules(server),
    api.features(),
  ]);
  if (current(v)) {
    queue.value = nextQueue;
    schedules.value = nextSchedules;
    enabled.value = flags.automation && flags.operationSupervision;
    if (nextQueue.some((q) => q.id === pending.value)) pending.value = '';
  }
}
async function load() {
  await work(rows);
}
function timestamp(value: string) {
  if (!value) return undefined;
  const time = new Date(value);
  if (!Number.isFinite(time.getTime())) throw new Error('Choose a valid date and time.');
  return time.toISOString();
}
async function enqueue() {
  if (!queueable.value || busy.value || !props.plan || hasVault.value) return;
  const plan = props.plan,
    v = generation;
  if (
    !(await confirm({
      title: 'Queue approved run?',
      message:
        'Run this exact approved plan when its hosts are free, after the chosen time and any successful dependency? Its existing approval expiry and both sessions still apply. No automatic retry follows a submission.',
      confirmText: 'Queue run',
    }))
  )
    return;
  if (!current(v) || busy.value || !queueable.value || props.plan?.id !== plan.id) return;
  await work(async (server, v) => {
    const id = crypto.randomUUID().replaceAll('-', '');
    const time = timestamp(notBefore.value);
    pending.value = id;
    await api.playbooks.enqueue(server, plan.id, {
      requestId: id,
      ...(time ? { notBefore: time } : {}),
      ...(afterRunId.value.trim() ? { afterRunId: afterRunId.value.trim() } : {}),
    });
    if (current(v)) {
      await rows(server, v);
      notice.value =
        'Queued. Expired or revoked approval blocks admission; an admitted run is never replayed.';
    }
  });
}
async function cancel(id: string) {
  if (!can('jobs.cancel', props.serverId) || busy.value) return;
  const v = generation;
  if (
    !(await confirm({
      title: 'Cancel queued run?',
      message:
        'Remove this waiting submission. If it was already admitted, use its run controls instead. A cancelled queue entry cannot reuse its plan.',
      confirmText: 'Cancel queued run',
    }))
  )
    return;
  if (!current(v) || busy.value || !can('jobs.cancel', props.serverId)) return;
  await work(async (server, v) => {
    await api.playbooks.cancelQueue(server, id);
    if (current(v)) await rows(server, v);
  });
}
async function createSchedule() {
  if (!schedulable.value || busy.value || !props.plan || !name.value.trim()) return;
  const plan = props.plan,
    v = generation;
  if (
    !(await confirm({
      title: 'Schedule fresh plan reviews?',
      message:
        'Save this preset and its current variable values for recurring planning? Each occurrence creates a new plan for independent review. It does not run a playbook or keep an old approval. Vault tokens are never saved. The schedule pauses when your session or permissions expire.',
      confirmText: 'Save review schedule',
    }))
  )
    return;
  if (!current(v) || busy.value || !schedulable.value || props.plan?.id !== plan.id) return;
  await work(async (server, v) => {
    await api.playbooks.createSchedule(server, {
      name: name.value.trim(),
      planId: plan.id,
      intervalMinutes: interval.value,
      ...(firstAt.value ? { firstAt: timestamp(firstAt.value) } : {}),
    });
    if (current(v)) {
      name.value = '';
      await rows(server, v);
      notice.value =
        'Review schedule saved. Each due plan still needs a different approver and explicit execution.';
    }
  });
}
async function setSchedule(row: AnsibleSchedule) {
  if (busy.value || !can('ansible.schedules.manage', props.serverId)) return;
  const v = generation;
  if (
    !row.enabled &&
    !(await confirm({
      title: 'Resume review schedule?',
      message:
        'Bind future plan creation to your current session and permissions? Existing plans retain their original authority and expiry.',
      confirmText: 'Resume schedule',
    }))
  )
    return;
  if (!current(v) || busy.value || !can('ansible.schedules.manage', props.serverId)) return;
  await work(async (server, v) => {
    await api.playbooks.setSchedule(server, row.id, !row.enabled);
    if (current(v)) await rows(server, v);
  });
}
onMounted(load);
</script>
<template>
  <section v-if="readable" aria-label="Ansible queue and schedules" class="space-y-4 border-t pt-4">
    <div class="flex justify-between">
      <h4 class="font-medium">Queue and review schedules</h4>
      <Button variant="outline" :disabled="busy" @click="load">Refresh automation queue</Button>
    </div>
    <p v-if="error" role="alert" class="text-sm">{{ error }}</p>
    <p v-if="notice" role="status" class="text-sm">{{ notice }}</p>
    <p v-if="pending" class="font-mono text-xs break-all">
      Retained queue request: {{ pending }}. Refresh before submitting another request.
    </p>
    <div v-if="plan?.actorId === actorId && plan.state === 'approved'" class="space-y-2 rounded border p-3">
      <h5 class="font-medium">Queue this approved plan</h5>
      <p class="text-sm">
        Wait for busy hosts, or choose a one-time start within the plan's existing expiry. Expired approvals
        are never extended.
      </p>
      <p v-if="hasVault" class="text-sm">
        This plan needs transient Vault tokens. Execute it interactively; queued runs do not store tokens.
      </p>
      <label class="block text-sm"
        >Earliest run time (optional)<Input
          v-model="notBefore"
          type="datetime-local"
          :disabled="busy || hasVault"
      /></label>
      <label class="block text-sm"
        >Successful prior run ID (optional)<Input
          v-model="afterRunId"
          :disabled="busy || hasVault"
          placeholder="Existing Ansible run on this controller"
      /></label>
      <Button :disabled="busy || !queueable || hasVault" @click="enqueue">Queue approved plan</Button>
    </div>
    <p v-else class="text-sm">
      Review your approved plan above to queue it. Queueing never grants or renews approval.
    </p>
    <div v-for="entry in queue" :key="entry.id" class="rounded border p-3 text-sm space-y-1">
      <p class="font-mono break-all">{{ entry.id }}</p>
      <p>{{ entry.state }} · {{ entry.detail.replaceAll('_', ' ') }}</p>
      <p>
        Earliest {{ new Date(entry.notBefore).toLocaleString() }} · expires
        {{ new Date(entry.expiresAt).toLocaleString() }}
      </p>
      <p v-if="entry.afterRunId" class="font-mono text-xs">After {{ entry.afterRunId }}</p>
      <Button
        v-if="entry.state === 'waiting' && can('jobs.cancel', serverId)"
        variant="outline"
        :disabled="busy"
        @click="cancel(entry.id)"
        >Cancel queued run</Button
      >
      <p v-if="entry.state === 'admitted'">
        Admitted with this run ID. Use Controller runs to inspect or stop it.
      </p>
    </div>
    <div v-if="schedulable" class="space-y-2 border rounded p-3">
      <h5 class="font-medium">Repeat this preset for review</h5>
      <p class="text-sm">
        Save the current plan's values. Each occurrence creates a fresh plan; it waits for independent review
        and explicit execution. Your session must remain valid. This is not unattended recurring playbook
        execution.
      </p>
      <label class="block text-sm"
        >Review schedule name<Input v-model="name" :disabled="busy" maxlength="80"
      /></label>
      <label class="block text-sm"
        >Repeat review every<select
          v-model.number="interval"
          :disabled="busy"
          class="border rounded p-2 bg-background"
        >
          <option :value="15">15 minutes</option>
          <option :value="60">Hour</option>
          <option :value="360">6 hours</option>
          <option :value="1440">Day</option>
          <option :value="10080">Week</option>
        </select></label
      >
      <label class="block text-sm"
        >First review time (optional)<Input v-model="firstAt" type="datetime-local" :disabled="busy"
      /></label>
      <Button :disabled="busy || !name.trim()" @click="createSchedule">Save review schedule</Button>
    </div>
    <p v-else-if="can('ansible.schedules.manage', serverId)" class="text-sm">
      Reveal your own plan created from an execution preset to save a recurring review schedule.
    </p>
    <div v-for="row in schedules" :key="row.id" class="border rounded p-3 space-y-1 text-sm">
      <p class="font-medium">{{ row.name }} · {{ row.enabled ? 'enabled' : 'paused' }}</p>
      <p>
        {{ row.lastState.replaceAll('_', ' ') }} · next
        {{ new Date(row.nextAt).toLocaleString() }}
      </p>
      <p v-if="row.pendingPlanId" class="font-mono text-xs break-all">Plan {{ row.pendingPlanId }}</p>
      <Button
        v-if="can('ansible.schedules.manage', serverId) && (row.enabled || row.actorId === actorId)"
        variant="outline"
        :disabled="busy"
        @click="setSchedule(row)"
        >{{ row.enabled ? 'Pause review schedule' : 'Resume review schedule' }}</Button
      >
    </div>
    <Button
      v-if="schedules.some((s) => s.pendingPlanId)"
      variant="outline"
      :disabled="busy"
      @click="emit('refresh')"
      >Refresh plans for review</Button
    >
  </section>
</template>
