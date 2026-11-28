<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type AnsiblePlanView, type AnsibleRun, type AnsibleExecutionResult } from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';

const props = defineProps<{
  serverId: string;
  actorId: string;
  plan?: AnsiblePlanView;
}>();
const { confirm } = useConfirm();
const runs = ref<AnsibleRun[]>([]),
  tokens = ref<Record<string, string>>({}),
  pending = ref(''),
  busy = ref(false),
  error = ref(''),
  output = ref(''),
  enabled = ref(false);
const taskResult = ref<{ id: string; data: AnsibleExecutionResult } | null>(null);
let generation = 0,
  alive = true;
const readable = computed(
  () => can('ansible.projects.read', props.serverId) && can('jobs.read', props.serverId),
);
const executable = computed(
  () =>
    readable.value && can('ansible.playbooks.execute', props.serverId) && can('jobs.execute', props.serverId),
);
const inspectable = computed(
  () => readable.value && can('logs.read', props.serverId) && can('secrets.use', props.serverId),
);
const vaultServers = computed(() => {
  const ids = new Set<string>();
  const password = props.plan?.options.vaultPassword;
  if (password) ids.add(password.serverId);
  for (const value of Object.values(props.plan?.variables ?? {}))
    if (value && typeof value === 'object' && 'serverId' in value && typeof value.serverId === 'string')
      ids.add(value.serverId);
  return [...ids].sort();
});
const startable = computed(
  () =>
    enabled.value &&
    executable.value &&
    props.plan?.state === 'approved' &&
    props.plan.actorId === props.actorId &&
    !pending.value &&
    !runs.value.some((run) => !run.finishedAt || run.planId === props.plan?.id),
);
function clear() {
  generation++;
  tokens.value = {};
  output.value = '';
  taskResult.value = null;
  runs.value = [];
  pending.value = '';
}
watch(
  () => [props.serverId, props.actorId, readable.value, executable.value, inspectable.value].join(','),
  clear,
  { flush: 'sync' },
);
watch(
  () => props.plan?.id,
  () => {
    generation++;
    tokens.value = {};
    output.value = '';
    taskResult.value = null;
  },
  { flush: 'sync' },
);
onUnmounted(() => {
  alive = false;
  clear();
});
async function refreshRows(version: number) {
  const rows = await api.playbooks.runs(props.serverId);
  if (alive && version === generation) {
    runs.value = rows;
    if (rows.find((row) => row.id === pending.value)?.finishedAt) pending.value = '';
  }
}
async function load() {
  if (busy.value || !readable.value) return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  tokens.value = {};
  output.value = '';
  taskResult.value = null;
  try {
    const flags = await api.features();
    if (alive && version === generation) enabled.value = flags.automation && flags.operationSupervision;
    await refreshRows(version);
  } catch (e) {
    if (alive && version === generation) {
      runs.value = [];
      error.value = e instanceof Error ? e.message : 'Run history unavailable.';
    }
  } finally {
    if (alive) busy.value = false;
  }
}
async function start() {
  if (busy.value || !startable.value || !props.plan) return;
  const version = generation,
    server = props.serverId,
    plan = props.plan;
  if (
    !(await confirm({
      title: 'Execute approved playbook?',
      message: `Run the exact approved ${plan.options.mode} plan on controller ${server} against ${plan.targets.length} frozen targets? Check mode and syntax checks can execute project code.`,
      confirmText: 'Run approved plan',
      destructive: plan.options.mode === 'apply',
    }))
  )
    return;
  if (!alive || version !== generation || busy.value || !startable.value) return;
  if (vaultServers.value.some((id) => !tokens.value[id])) {
    error.value = 'Supply a short-lived token for each referenced Vault server.';
    return;
  }
  const privateTokens = { ...tokens.value },
    id = crypto.randomUUID().replaceAll('-', '');
  pending.value = id;
  tokens.value = {};
  busy.value = true;
  error.value = '';
  output.value = '';
  taskResult.value = null;
  try {
    const result = await api.playbooks.run(server, plan.id, id, privateTokens);
    if (alive && version === generation) {
      error.value = result.error ?? '';
      await refreshRows(version);
    }
  } catch (e) {
    if (alive && version === generation) {
      const failure = e as { status?: number; run?: unknown };
      const rejected = [400, 401, 403, 404, 409, 503].includes(failure.status ?? 0) && !failure.run;
      if (rejected) pending.value = '';
      error.value =
        (e instanceof Error ? e.message : 'Submission unconfirmed.') +
        (rejected ? '' : ' Retained request ' + id + '. Refresh and inspect before any new submission.');
    }
  } finally {
    for (const id of Object.keys(privateTokens)) privateTokens[id] = '';
    if (alive) busy.value = false;
  }
}
async function control(action: 'inspect' | 'cancel' | 'release', id: string) {
  if (busy.value || !readable.value) return;
  const version = generation;
  if (
    action !== 'inspect' &&
    !(await confirm({
      title: action === 'cancel' ? 'Stop playbook run?' : 'Clean playbook artifacts?',
      message:
        action === 'cancel'
          ? 'Stop all processes in the managed controller job. Tasks already completed on targets cannot be undone.'
          : 'Remove verified terminal supervisor artifacts and any reserved job account. Execution history remains available.',
      confirmText: action === 'cancel' ? 'Stop run' : 'Clean artifacts',
      destructive: true,
    }))
  )
    return;
  if (!alive || version !== generation || busy.value) return;
  busy.value = true;
  error.value = '';
  tokens.value = {};
  try {
    const result = await api.playbooks[
      action === 'inspect' ? 'inspectRun' : action === 'cancel' ? 'cancelRun' : 'releaseRun'
    ](props.serverId, id);
    if (alive && version === generation) {
      output.value = result.run.state;
      taskResult.value =
        action === 'inspect' && 'result' in result && result.result
          ? { id, data: result.result as AnsibleExecutionResult }
          : null;
      await refreshRows(version);
    }
  } catch (e) {
    if (alive && version === generation)
      error.value = e instanceof Error ? e.message : 'Run state unconfirmed.';
  } finally {
    if (alive) busy.value = false;
  }
}
onMounted(load);
</script>
<template>
  <section v-if="readable" class="space-y-3 border-t pt-4" aria-label="Ansible execution">
    <div class="flex justify-between">
      <h4 class="font-medium">Controller runs</h4>
      <Button :disabled="busy" variant="outline" @click="load">Refresh runs</Button>
    </div>
    <p class="text-sm">
      Ansible runs on controller {{ serverId }} under a separate job account. Only selected target credentials
      are supplied. All frozen hosts stay reserved until termination is verified. Raw task output and secret
      values are suppressed; results contain host recaps and task status/timing.
    </p>
    <p class="text-xs text-muted-foreground">
      Requires the managed Ansible environment, Python 3.13–3.15, root SSH and systemd/cgroup v2 on the
      controller. Target SSH credentials must differ from the controller credential. Reviewed playbooks are
      trusted code and can delegate tasks; inventory selection is not a network restriction.
    </p>
    <p v-if="!enabled" class="text-sm">
      Enable automation and operation supervision to execute reviewed plans.
    </p>
    <p v-if="error" role="alert" class="text-sm">{{ error }}</p>
    <p v-if="pending" class="font-mono text-sm break-all">Retained request: {{ pending }}</p>
    <template v-if="plan && plan.actorId === actorId">
      <p class="text-sm">
        Reviewed plan {{ plan.id }} · {{ plan.state }}. A plan can be submitted once. Retries and reloads
        never execute it again.
      </p>
      <label v-for="id in vaultServers" :key="id" class="block text-sm"
        >Short-lived Vault token for {{ id
        }}<Input v-model="tokens[id]" type="password" autocomplete="off" :disabled="busy || !executable"
      /></label>
      <Button :disabled="busy || !startable" @click="start">Execute approved plan</Button>
    </template>
    <p v-else class="text-sm">
      Reveal your approved frozen plan above to execute it. A different person must approve it first.
    </p>
    <div v-for="run in runs" :key="run.id" class="rounded border p-3 text-sm space-y-2">
      <p class="font-mono break-all">{{ run.id }}</p>
      <p>
        {{ run.state }} · {{ new Date(run.createdAt).toLocaleString() }} ·
        {{ run.detail }}
      </p>
      <div class="flex gap-2 flex-wrap">
        <Button :disabled="busy || !inspectable" variant="outline" @click="control('inspect', run.id)"
          >Inspect run</Button
        ><Button
          v-if="!run.finishedAt"
          :disabled="busy || !can('jobs.cancel', serverId)"
          variant="destructive"
          @click="control('cancel', run.id)"
          >Stop run</Button
        ><Button
          v-else-if="!run.artifactsRemoved"
          :disabled="busy || !inspectable || !can('jobs.manage', serverId)"
          variant="outline"
          @click="control('release', run.id)"
          >Clean artifacts</Button
        >
      </div>
    </div>
    <section v-if="taskResult" aria-label="Ansible task history" class="space-y-3">
      <h4 class="font-medium">Task history</h4>
      <p class="font-mono text-xs break-all">Run {{ taskResult.id }}</p>
      <p v-if="taskResult.data.stage" class="text-sm">
        Stopped during {{ taskResult.data.stage.replaceAll('_', ' ') }}.
      </p>
      <template v-else>
        <p class="text-sm">
          Exit code {{ taskResult.data.exitCode }} · Ansible
          {{ taskResult.data.version }}
        </p>
        <div class="overflow-auto">
          <table class="w-full text-sm">
            <caption class="sr-only">
              Host recap
            </caption>
            <thead>
              <tr>
                <th class="text-left">Server</th>
                <th
                  v-for="key in ['ok', 'changed', 'failures', 'unreachable', 'skipped', 'rescued', 'ignored']"
                  :key="key"
                >
                  {{ key }}
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(counts, id) in taskResult.data.hosts" :key="id">
                <td>{{ id }}</td>
                <td
                  v-for="key in ['ok', 'changed', 'failures', 'unreachable', 'skipped', 'rescued', 'ignored']"
                  :key="key"
                  class="text-center"
                >
                  {{ counts[key] ?? 0 }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-if="taskResult.data.tasks.length" class="max-h-80 overflow-auto">
          <table class="w-full text-sm">
            <caption class="sr-only">
              Task timing
            </caption>
            <thead>
              <tr>
                <th class="text-left">Task</th>
                <th class="text-left">Server</th>
                <th class="text-left">Status</th>
                <th>Started</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(task, index) in taskResult.data.tasks" :key="index">
                <td>Task {{ task.task }}</td>
                <td>{{ task.serverId }}</td>
                <td>{{ task.status }}</td>
                <td class="text-center">{{ (task.startedMs / 1000).toFixed(3) }}s</td>
                <td class="text-center">{{ (task.durationMs / 1000).toFixed(3) }}s</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="text-sm">
          No task timing was recorded. Syntax checks and older runs may only have recaps.
        </p>
        <p v-if="taskResult.data.tasksTruncated" class="text-sm">
          Showing the first 200 task results. The host recap includes the full run.
        </p>
        <p class="text-xs text-muted-foreground">
          Task numbers follow controller observation order, including handlers. Names, arguments and output
          are omitted. History is available when a playbook finishes; interrupted runs may have no recap.
        </p>
      </template>
    </section>
    <div v-if="output">
      <Button
        variant="ghost"
        @click="
          output = '';
          taskResult = null;
        "
        >Hide result</Button
      >
      <pre class="whitespace-pre-wrap break-all text-xs rounded bg-muted p-3">{{ output }}</pre>
    </div>
  </section>
</template>
