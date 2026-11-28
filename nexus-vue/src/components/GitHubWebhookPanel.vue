<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type GitHubWebhookInfo, type GitHubRunObservation } from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Button from './ui/Button.vue';
const props = defineProps<{ serverId: string; connectionId: string }>();
const emit = defineEmits<{ inspect: [runId: number] }>();
const { confirm } = useConfirm();
const info = ref<GitHubWebhookInfo>(),
  runs = ref<GitHubRunObservation[]>([]);
const secret = ref(''),
  showSecret = ref(false),
  busy = ref(false),
  error = ref('');
const readable = computed(() => can('github.actions.read', props.serverId));
const manageable = computed(() => readable.value && can('github.webhooks.manage', props.serverId));
const creatable = computed(
  () => manageable.value && can('secrets.create', props.serverId) && can('secrets.reveal', props.serverId),
);
let generation = 0,
  alive = true,
  timer: ReturnType<typeof setTimeout> | undefined;
let poll: ReturnType<typeof setInterval> | undefined;
function clearSecret() {
  secret.value = '';
  showSecret.value = false;
  if (timer) clearTimeout(timer);
  timer = undefined;
}
function clear() {
  generation++;
  clearSecret();
  info.value = undefined;
  runs.value = [];
  error.value = '';
}
watch(
  () => [props.serverId, props.connectionId, readable.value, manageable.value, creatable.value].join(','),
  clear,
  { flush: 'sync' },
);
onUnmounted(() => {
  alive = false;
  clear();
  if (poll) clearInterval(poll);
});
function current(version: number) {
  return alive && version === generation && readable.value;
}
async function load() {
  if (busy.value || !readable.value) return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  try {
    const result = await api.githubActions.webhookEvents(props.serverId, props.connectionId);
    if (!current(version)) return;
    runs.value = result;
    if (manageable.value) {
      const result = await api.githubActions.webhook(props.serverId, props.connectionId);
      if (current(version) && manageable.value) info.value = result;
    }
  } catch (e) {
    if (current(version)) error.value = e instanceof Error ? e.message : 'Received status unavailable.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function rotate() {
  if (!creatable.value || busy.value) return;
  const confirmedGeneration = generation;
  if (
    !(await confirm({
      title: 'Create a new webhook secret?',
      message:
        'This replaces the current endpoint and secret. Update the repository webhook in GitHub afterwards. The secret is shown only in this response.',
      confirmText: 'Create secret',
      destructive: true,
    }))
  )
    return;
  if (!creatable.value || busy.value || !alive || generation !== confirmedGeneration) return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  clearSecret();
  try {
    const result = await api.githubActions.rotateWebhook(props.serverId, props.connectionId);
    if (current(version) && creatable.value) {
      info.value = result.webhook;
      secret.value = result.secret;
      timer = setTimeout(clearSecret, 120_000);
    }
  } catch (e) {
    if (current(version))
      error.value =
        (e instanceof Error ? e.message : 'Secret creation unconfirmed.') +
        ' Refresh configuration. If the reply was lost, create a new secret and update GitHub.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function disable() {
  if (!manageable.value || busy.value) return;
  const confirmedGeneration = generation;
  if (
    !(await confirm({
      title: 'Disable webhook intake?',
      message:
        'Nexus will stop accepting this endpoint. You can also remove the repository webhook in GitHub.',
      confirmText: 'Disable',
      destructive: true,
    }))
  )
    return;
  if (!manageable.value || busy.value || !alive || generation !== confirmedGeneration) return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  clearSecret();
  try {
    await api.githubActions.disableWebhook(props.serverId, props.connectionId);
    if (current(version) && info.value) info.value = { ...info.value, disabled: true };
  } catch (e) {
    if (current(version))
      error.value = e instanceof Error ? e.message : 'Disable unconfirmed. Refresh configuration.';
  } finally {
    if (alive) busy.value = false;
  }
}
function hidden() {
  if (document.hidden) clearSecret();
}
onUnmounted(() => {
  if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', hidden);
});
onMounted(() => {
  document.addEventListener('visibilitychange', hidden);
  void load();
  poll = setInterval(() => {
    if (readable.value && !secret.value) void load();
  }, 30_000);
});
</script>
<template>
  <section v-if="readable" aria-label="GitHub webhook updates" class="border rounded p-3 space-y-3">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h3 class="font-medium">Received workflow status</h3>
      <Button variant="outline" :disabled="busy" @click="load">Refresh received status</Button>
    </div>
    <p class="text-sm">
      Verified repository webhooks update this history. They do not deploy applications or start jobs. This
      panel refreshes every 30 seconds while open.
    </p>
    <p v-if="error" role="alert" class="text-sm">{{ error }}</p>
    <details v-if="manageable" class="border rounded p-3">
      <summary>Webhook setup</summary>
      <p class="text-sm my-2">
        Create a secret, then add a repository webhook in GitHub Settings → Webhooks. Use your Nexus HTTPS
        origin plus the path below, select JSON and Workflow runs, and enter the secret. This is a repository
        webhook, separate from your GitHub App’s webhook setting.
      </p>
      <p v-if="info?.configured" class="text-sm">
        {{ info.disabled ? 'Intake disabled' : 'Intake configured' }}
      </p>
      <label v-if="info?.configured" class="block text-sm"
        >Endpoint path<input
          :value="info.path"
          readonly
          aria-label="Webhook endpoint path"
          class="block w-full bg-background border rounded p-2 font-mono text-xs"
      /></label>
      <div class="flex flex-wrap gap-2 my-2">
        <Button v-if="creatable" :disabled="busy" @click="rotate">Create new webhook secret</Button>
        <Button
          v-if="info?.configured && !info.disabled"
          variant="destructive"
          :disabled="busy"
          @click="disable"
          >Disable intake</Button
        >
      </div>
      <div v-if="secret" class="space-y-2 border rounded p-3">
        <label class="block text-sm"
          >One-time webhook secret<input
            :value="secret"
            :type="showSecret ? 'text' : 'password'"
            readonly
            autocomplete="off"
            aria-label="One-time webhook secret"
            class="block w-full bg-background border rounded p-2 font-mono text-xs"
        /></label>
        <label class="text-sm flex items-center gap-2"
          ><input v-model="showSecret" type="checkbox" /> Show secret</label
        >
        <p class="text-sm">Save it in GitHub now. This view clears after two minutes or when you leave.</p>
        <Button variant="outline" @click="clearSecret">Clear secret</Button>
      </div>
    </details>
    <p v-if="!runs.length" class="text-sm">
      No workflow status received. Check GitHub delivery history and your webhook configuration.
    </p>
    <ul class="space-y-2">
      <li v-for="run in runs" :key="run.runId" class="border rounded p-2 text-sm">
        <p>
          Run {{ run.runId }} · attempt {{ run.runAttempt }} · {{ run.status
          }}{{ run.conclusion ? ` / ${run.conclusion}` : '' }}
        </p>
        <p class="break-all font-mono text-xs">{{ run.headSha }}</p>
        <p class="text-xs">Source {{ run.sourceUpdatedAt }} · received {{ run.receivedAt }}</p>
        <Button variant="outline" :disabled="busy" @click="emit('inspect', run.runId)"
          >Inspect received run</Button
        >
      </li>
    </ul>
  </section>
</template>
