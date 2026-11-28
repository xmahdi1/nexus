<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type InteractiveRun, type RunObservation } from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Button from '@/components/ui/Button.vue';

const props = defineProps<{ serverId: string; selectedId?: string; enabled: boolean }>();
const { confirm } = useConfirm();
const runs = ref<InteractiveRun[]>([]);
const result = ref<RunObservation | null>(null);
const resultId = ref('');
const error = ref('');
const busy = ref(false);
let alive = true;
let generation = 0;
const labels: Record<string, string> = {
  'github-runner': 'Ephemeral GitHub runner',
  'ansible-environment-install': 'Install Ansible environment',
  'ansible-environment-update': 'Update Ansible environment',
  'ansible-environment-health': 'Check Ansible environment',
  'ansible-environment-remove': 'Remove Ansible environment',
  'compose-up': 'Start Compose services',
  'compose-down': 'Stop Compose services',
  'container-start': 'Start container',
  'container-stop': 'Stop container',
  'container-restart': 'Restart container',
  'container-remove': 'Remove stopped container',
};
function readPermission(run: InteractiveRun) {
  return run.action === 'github-runner'
    ? 'github.runners.read'
    : run.action.startsWith('ansible-environment-')
      ? 'ansible.environment.read'
      : run.action.startsWith('compose-')
        ? 'compose.read'
        : 'docker.read';
}
function viewable(run: InteractiveRun) {
  return [readPermission(run), 'jobs.read', 'logs.read', 'secrets.use'].every((p) => can(p, props.serverId));
}
function cancellable(run: InteractiveRun) {
  const extra =
    run.action === 'github-runner'
      ? ['github.runners.manage']
      : run.action.startsWith('ansible-environment-')
        ? [
            run.action === 'ansible-environment-health'
              ? 'ansible.environment.read'
              : 'ansible.environment.manage',
          ]
        : run.action.startsWith('compose-')
          ? ['compose.write', 'deployments.execute']
          : [run.action === 'container-remove' ? 'docker.remove' : 'docker.manage'];
  return ['jobs.cancel', 'servers.execute', 'secrets.use', ...extra].every((p) => can(p, props.serverId));
}
function clear() {
  generation++;
  runs.value = [];
  result.value = null;
  resultId.value = '';
  error.value = '';
  busy.value = false;
}
watch(
  () => props.serverId,
  () => {
    clear();
    void load();
  },
);
watch(
  () => props.selectedId,
  () => {
    generation++;
    busy.value = false;
    result.value = null;
    resultId.value = '';
    void load();
  },
);
watch(
  () => can('jobs.read', props.serverId),
  (allowed) => {
    clear();
    if (allowed) void load();
  },
);
watch(
  () =>
    [
      'logs.read',
      'secrets.use',
      'compose.read',
      'docker.read',
      'ansible.environment.read',
      'ansible.environment.manage',
      'github.runners.read',
      'github.runners.manage',
    ]
      .map((p) => can(p, props.serverId))
      .join(','),
  () => {
    generation++;
    busy.value = false;
    result.value = null;
    resultId.value = '';
  },
);
onUnmounted(() => {
  alive = false;
  clear();
});
async function load() {
  if (busy.value || !can('jobs.read', props.serverId)) return;
  const version = generation,
    server = props.serverId;
  busy.value = true;
  error.value = '';
  result.value = null;
  resultId.value = '';
  try {
    const data = await api.operations.list(server);
    if (alive && version === generation && server === props.serverId) runs.value = data;
  } catch (cause) {
    if (alive && version === generation)
      error.value = cause instanceof Error ? cause.message : 'Could not load operation history';
  } finally {
    if (alive && version === generation) busy.value = false;
  }
}
async function act(action: 'read' | 'inspect' | 'cancel' | 'release', run: InteractiveRun) {
  if (busy.value) return;
  const version = generation,
    server = props.serverId;
  if (action === 'cancel' || action === 'release') {
    const ok = await confirm({
      title: action === 'cancel' ? 'Cancel operation?' : 'Remove operation artifacts?',
      message:
        action === 'cancel'
          ? `Stop the command for run ${run.id}? This cannot undo changes already applied by the operation.`
          : `Remove retained remote supervisor files for completed run ${run.id}? The saved Nexus result remains in history.`,
      confirmText: action === 'cancel' ? 'Cancel operation' : 'Remove artifacts',
      destructive: true,
    });
    if (!ok || !alive || version !== generation || server !== props.serverId) return;
  }
  busy.value = true;
  error.value = '';
  result.value = null;
  resultId.value = '';
  try {
    const response = await api.operations[action](server, run.id);
    if (alive && version === generation && server === props.serverId) {
      resultId.value = run.id;
      result.value = response;
      const latest = await api.operations.list(server);
      if (alive && version === generation && server === props.serverId) runs.value = latest;
    }
  } catch (cause) {
    if (alive && version === generation)
      error.value =
        cause instanceof Error ? cause.message : 'Could not verify operation state; inspect before retrying';
  } finally {
    if (alive && version === generation) busy.value = false;
  }
}
onMounted(load);
</script>

<template>
  <section aria-label="Supervised operations" class="space-y-4">
    <div class="flex flex-wrap justify-between gap-2">
      <h2 class="font-semibold">Operation history</h2>
      <Button variant="outline" :disabled="busy" @click="load">Refresh history</Button>
    </div>
    <p class="text-sm text-muted-foreground">
      Server commands can be inspected after a disconnect or restart. An uncertain result is never resubmitted
      automatically. Cancellation stops the command; Changes may already have been applied.
    </p>
    <p v-if="!enabled" class="text-sm">
      New supervised operations are disabled. Existing runs remain available for inspection and cleanup.
    </p>
    <p v-if="selectedId" class="text-sm break-all">Submitted run ID: {{ selectedId }}</p>
    <p v-if="error" role="alert" class="text-destructive">{{ error }}</p>
    <p v-if="!runs.length && !busy" class="text-sm">No saved interactive operations.</p>
    <div class="overflow-x-auto">
      <table v-if="runs.length" class="w-full text-sm">
        <thead>
          <tr>
            <th class="text-left p-2">Action / run</th>
            <th class="text-left p-2">Status</th>
            <th class="text-left p-2">Created</th>
            <th class="text-left p-2">Controls</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="run in runs"
            :key="run.id"
            class="border-t"
            :aria-current="run.id === selectedId ? 'true' : undefined"
          >
            <td class="p-2">
              {{ labels[run.action] ?? run.action }}<br /><code class="text-xs break-all">{{ run.id }}</code>
            </td>
            <td class="p-2">
              {{ run.state }}<span v-if="run.detail" class="block text-xs">{{ run.detail }}</span>
            </td>
            <td class="p-2">{{ new Date(run.createdAt).toLocaleString() }}</td>
            <td class="p-2">
              <div class="flex flex-wrap gap-2">
                <Button v-if="viewable(run)" variant="outline" :disabled="busy" @click="act('read', run)"
                  >View saved result</Button
                >
                <Button
                  v-if="viewable(run) && can('servers.execute', serverId)"
                  variant="outline"
                  :disabled="busy"
                  @click="act('inspect', run)"
                  >Inspect operation</Button
                >
                <Button
                  v-if="!run.finishedAt && cancellable(run)"
                  variant="outline"
                  :disabled="busy"
                  @click="act('cancel', run)"
                  >Cancel operation</Button
                >
                <Button
                  v-if="
                    run.finishedAt &&
                    !run.artifactsRemoved &&
                    viewable(run) &&
                    can('jobs.manage', serverId) &&
                    can('servers.execute', serverId)
                  "
                  variant="outline"
                  :disabled="busy"
                  @click="act('release', run)"
                  >Remove artifacts</Button
                >
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="result" role="status" class="space-y-2 rounded border p-3">
      <p class="text-sm break-all">
        Run {{ resultId }} · {{ result.observation.state }} · verified
        {{ result.observation.verified ? 'yes' : 'no' }} · process group empty
        {{ result.observation.empty ? 'yes' : 'no' }}
      </p>
      <p v-if="result.observation.noDispatch" class="text-sm">The command was not dispatched.</p>
      <p v-if="result.observation.truncated" class="text-sm">The saved output is truncated.</p>
      <pre
        v-if="result.observation.output"
        class="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-3 text-xs"
        >{{ result.observation.output }}</pre>
      <Button
        variant="outline"
        @click="
          result = null;
          resultId = '';
        "
        >Hide saved result</Button
      >
    </div>
  </section>
</template>
