<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import {
  api,
  type GitHubOrganization,
  type GitHubOrganizationChange,
  type GitHubProviderRunner,
} from '@/lib/api';
import { can } from '@/lib/auth';
import { useConfirm } from '@/composables/useConfirm';
import Button from './ui/Button.vue';
import Input from './ui/Input.vue';
const props = defineProps<{ serverId: string }>();
const { confirm } = useConfirm();
const connections = ref<GitHubOrganization[]>([]),
  history = ref<GitHubOrganizationChange[]>([]),
  runners = ref<GitHubProviderRunner[]>([]);
const selected = ref(''),
  login = ref(''),
  organizationId = ref<number>(),
  clientId = ref(''),
  installationId = ref<number>(),
  privateKey = ref('');
const busy = ref(false),
  error = ref(''),
  ready = ref(false),
  page = ref(1),
  total = ref(0);
const pending = ref(''),
  acknowledged = ref(new Set<string>()),
  credential = ref(''),
  expiresAt = ref(''),
  showToken = ref(false);
let generation = 0,
  alive = true,
  timer: ReturnType<typeof setTimeout> | undefined;
const readable = computed(() => can('github.organizations.read', props.serverId));
const usable = computed(() => readable.value && can('secrets.use', props.serverId));
const configurable = computed(
  () =>
    usable.value &&
    can('github.organizations.connections.manage', props.serverId) &&
    can('secrets.create', props.serverId),
);
const manageable = computed(() => usable.value && can('github.organizations.runners.manage', props.serverId));
const enrollable = computed(
  () =>
    usable.value &&
    can('github.organizations.runners.register', props.serverId) &&
    can('secrets.reveal', props.serverId),
);
const connection = computed(() =>
  connections.value.find((row) => row.id === selected.value && !row.disabled),
);
const unresolved = computed(() =>
  history.value.filter(
    (row) =>
      row.connectionId === selected.value &&
      ['prepared', 'submitting', 'unknown'].includes(row.state) &&
      !acknowledged.value.has(row.id),
  ),
);
const blocked = computed(() => !!pending.value || unresolved.value.length > 0 || !ready.value);
function clearCredential() {
  credential.value = '';
  expiresAt.value = '';
  showToken.value = false;
  if (timer) clearTimeout(timer);
  timer = undefined;
}
function clear() {
  generation++;
  clearCredential();
  privateKey.value = '';
  connections.value = [];
  history.value = [];
  runners.value = [];
  selected.value = '';
  ready.value = false;
  pending.value = '';
  acknowledged.value = new Set();
  error.value = '';
}
watch(
  () =>
    [
      props.serverId,
      readable.value,
      usable.value,
      configurable.value,
      manageable.value,
      enrollable.value,
    ].join(','),
  clear,
  { flush: 'sync' },
);
watch(
  selected,
  () => {
    generation++;
    clearCredential();
    privateKey.value = '';
    runners.value = [];
    page.value = 1;
    total.value = 0;
    acknowledged.value = new Set();
  },
  { flush: 'sync' },
);
onUnmounted(() => {
  alive = false;
  clear();
});
function current(version: number) {
  return alive && version === generation && readable.value;
}
async function load() {
  if (busy.value || !readable.value) return;
  const version = ++generation;
  busy.value = true;
  ready.value = false;
  error.value = '';
  clearCredential();
  privateKey.value = '';
  try {
    const [rows, changes] = await Promise.all([
      api.githubOrganizations.list(props.serverId),
      api.githubOrganizations.history(props.serverId),
    ]);
    if (current(version)) {
      connections.value = rows;
      history.value = changes;
      ready.value = true;
      if (changes.some((row) => row.id === pending.value && ['applied', 'not_submitted'].includes(row.state)))
        pending.value = '';
    }
  } catch (e) {
    if (current(version))
      error.value = e instanceof Error ? e.message : 'Organization connections unavailable.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function create() {
  if (busy.value || !configurable.value) return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  const input = {
    login: login.value,
    organizationId: organizationId.value!,
    clientId: clientId.value,
    installationId: installationId.value!,
    privateKey: privateKey.value,
  };
  privateKey.value = '';
  try {
    const result = await api.githubOrganizations.create(props.serverId, input);
    if (current(version)) connections.value.unshift(result);
  } catch (e) {
    if (current(version))
      error.value = e instanceof Error ? e.message : 'Organization connection unavailable.';
  } finally {
    input.privateKey = '';
    if (alive) busy.value = false;
  }
}
async function browse(nextPage = 1) {
  if (busy.value || !usable.value || !connection.value) return;
  const version = ++generation,
    id = selected.value;
  busy.value = true;
  error.value = '';
  runners.value = [];
  clearCredential();
  try {
    const result = await api.githubOrganizations.runners(props.serverId, id, nextPage);
    if (current(version)) {
      runners.value = result.runners;
      total.value = result.total_count;
      page.value = nextPage;
    }
  } catch (e) {
    if (current(version)) error.value = e instanceof Error ? e.message : 'Runner status unavailable.';
  } finally {
    if (alive) busy.value = false;
  }
}
async function change(kind: 'registration' | 'runner_remove', runner?: GitHubProviderRunner) {
  if (
    busy.value ||
    blocked.value ||
    !connection.value ||
    (kind === 'registration' ? !enrollable.value : !manageable.value)
  )
    return;
  if (kind === 'runner_remove' && (!runner || runner.status !== 'offline' || runner.busy)) return;
  const before = generation,
    id = selected.value,
    org = connection.value.login;
  const message =
    kind === 'registration'
      ? `Create a registration token for ${org}? Anyone holding it can enroll runners in this organization until it expires. Use it only on your selected build host and choose an approved runner group. Nexus will reveal it once.`
      : `Remove offline runner ${runner!.name} (${runner!.id}) from ${org}? Stop its host process first. An offline status does not prove that process stopped.`;
  if (
    !(await confirm({
      title: kind === 'registration' ? 'Create runner registration token?' : 'Remove organization runner?',
      message,
      confirmText: kind === 'registration' ? 'Create token once' : 'Remove registration',
      destructive: true,
    }))
  )
    return;
  if (
    !alive ||
    generation !== before ||
    busy.value ||
    blocked.value ||
    !connection.value ||
    (kind === 'registration' ? !enrollable.value : !manageable.value)
  )
    return;
  const version = ++generation,
    requestId = crypto.randomUUID().replaceAll('-', '');
  busy.value = true;
  error.value = '';
  clearCredential();
  pending.value = requestId;
  try {
    const result =
      kind === 'registration'
        ? await api.githubOrganizations.registration(props.serverId, id, requestId)
        : await api.githubOrganizations.remove(props.serverId, id, requestId, runner!.id, runner!.name);
    if (current(version)) {
      history.value.unshift(result.change);
      if (['applied', 'not_submitted'].includes(result.change.state)) pending.value = '';
      if (kind === 'registration' && enrollable.value && result.credential) {
        credential.value = result.credential.token;
        expiresAt.value = result.credential.expiresAt;
        timer = setTimeout(
          clearCredential,
          Math.min(120_000, Math.max(0, Date.parse(expiresAt.value) - Date.now())),
        );
      } else if (result.change.state !== 'not_submitted' && kind === 'registration')
        error.value =
          'Token unavailable. A saved request never reveals it again. Inspect history before creating a new request.';
      if (kind === 'runner_remove' && result.change.state === 'applied')
        runners.value = runners.value.filter((row) => row.id !== runner!.id);
    }
  } catch (e) {
    if (current(version)) {
      error.value =
        (e instanceof Error ? e.message : 'Change unconfirmed.') + ` Retained request ${requestId}.`;
      if ([400, 401, 403, 409].includes((e as { status?: number }).status ?? 0)) pending.value = '';
    }
  } finally {
    if (alive) busy.value = false;
  }
}
async function acknowledge() {
  const before = generation;
  if (
    !(await confirm({
      title: 'Allow a new runner request?',
      message:
        'Check GitHub and the saved history first. A new token request can create another valid credential. Earlier requests will never be sent again.',
      confirmText: 'I checked GitHub',
    }))
  )
    return;
  if (!alive || before !== generation || !readable.value) return;
  acknowledged.value = new Set([...acknowledged.value, ...unresolved.value.map((row) => row.id)]);
  pending.value = '';
}
async function disable() {
  if (busy.value || !connection.value || !can('github.organizations.connections.manage', props.serverId))
    return;
  const before = generation,
    id = selected.value;
  if (
    !(await confirm({
      title: 'Disable organization connection?',
      message:
        'Future Nexus provider operations will be denied. Existing GitHub registrations, tokens and host processes remain; manage those separately.',
      confirmText: 'Disable',
      destructive: true,
    }))
  )
    return;
  if (
    !alive ||
    before !== generation ||
    busy.value ||
    !can('github.organizations.connections.manage', props.serverId)
  )
    return;
  const version = ++generation;
  busy.value = true;
  error.value = '';
  clearCredential();
  try {
    await api.githubOrganizations.disable(props.serverId, id);
    if (current(version)) {
      const row = connections.value.find((row) => row.id === id);
      if (row) row.disabled = true;
      selected.value = '';
    }
  } catch (e) {
    if (current(version)) error.value = e instanceof Error ? e.message : 'Disable unconfirmed.';
  } finally {
    if (alive) busy.value = false;
  }
}
function hidden() {
  if (document.hidden) clearCredential();
}
onMounted(() => {
  document.addEventListener('visibilitychange', hidden);
  void load();
});
onUnmounted(() => {
  if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', hidden);
});
</script>
<template>
  <section v-if="readable" aria-label="GitHub organization runners" class="border-t pt-4 space-y-3">
    <div class="flex flex-wrap justify-between gap-2">
      <h3 class="font-medium">Organization runners</h3>
      <Button variant="outline" :disabled="busy" @click="load">Refresh organization connections</Button>
    </div>
    <p class="text-sm">
      Organization connections are separate from repository connections. GitHub controls runner-group access.
      A runner name does not identify a Nexus-managed host.
    </p>
    <p v-if="error" role="alert" class="text-sm">{{ error }}</p>
    <details v-if="configurable" class="border rounded p-3">
      <summary>Add organization App connection</summary>
      <p class="text-sm my-2">
        Install the App on the organization with Self-hosted runners read/write. Nexus verifies the
        installation’s organization ID and login. App keys are used only to obtain the permissions needed for
        each operation.
      </p>
      <form class="grid sm:grid-cols-2 gap-3" @submit.prevent="create">
        <label>Organization login<Input v-model="login" required :disabled="busy" /></label>
        <label
          >Organization numeric ID<Input
            v-model.number="organizationId"
            type="number"
            min="1"
            required
            :disabled="busy"
        /></label>
        <label>App client ID<Input v-model="clientId" required :disabled="busy" /></label>
        <label
          >Installation ID<Input
            v-model.number="installationId"
            type="number"
            min="1"
            required
            :disabled="busy"
        /></label>
        <label class="sm:col-span-2"
          >App private key (PEM)<textarea
            v-model="privateKey"
            required
            rows="4"
            spellcheck="false"
            autocomplete="off"
            :disabled="busy"
            class="block w-full border rounded bg-background p-2 font-mono text-xs"
          />
        </label>
        <Button type="submit" :disabled="busy">Verify and save organization</Button>
      </form>
    </details>
    <label class="block text-sm"
      >Organization connection<select
        v-model="selected"
        aria-label="GitHub organization connection"
        :disabled="busy"
        class="block w-full border rounded bg-background p-2"
      >
        <option value="">Choose organization</option>
        <option v-for="row in connections" :key="row.id" :value="row.id" :disabled="row.disabled">
          {{ row.login }}{{ row.disabled ? ' (disabled)' : '' }}
        </option>
      </select></label
    >
    <template v-if="connection">
      <div class="flex flex-wrap gap-2">
        <Button :disabled="busy || !usable" @click="browse(1)">List organization runners</Button>
        <Button v-if="enrollable" :disabled="busy || blocked" @click="change('registration')"
          >Create registration token</Button
        >
        <Button
          v-if="can('github.organizations.connections.manage', serverId)"
          variant="destructive"
          :disabled="busy"
          @click="disable"
          >Disable organization connection</Button
        >
      </div>
      <p v-if="blocked" class="text-sm">
        Load the saved history and inspect unconfirmed requests before another provider change.
      </p>
      <Button
        v-if="pending || unresolved.length"
        variant="outline"
        :disabled="busy || !ready"
        @click="acknowledge"
        >I checked the earlier requests</Button
      >
      <div v-if="credential" class="border rounded p-3 space-y-2">
        <label class="block text-sm"
          >One-time runner registration token<input
            :value="credential"
            :type="showToken ? 'text' : 'password'"
            readonly
            autocomplete="off"
            class="block w-full border rounded bg-background p-2 font-mono text-xs"
        /></label>
        <label class="flex items-center gap-2 text-sm"
          ><input v-model="showToken" type="checkbox" />Show token</label
        >
        <p class="text-sm">
          Expires {{ expiresAt }}. Use it in Apps → GitHub Actions Runner on your chosen build host, with
          organization URL https://github.com/{{ connection.login }} and an explicit runner group. This view
          clears within two minutes.
        </p>
        <Button variant="outline" @click="clearCredential">Clear token</Button>
      </div>
      <details class="border rounded p-3 text-sm">
        <summary>Replace a runner</summary>
        <ol class="list-decimal pl-5 space-y-1 mt-2">
          <li>
            Stop the old runner on its actual host. Finish or cancel its work through the appropriate host and
            GitHub controls.
          </li>
          <li>Refresh this list. Remove its registration only after it is offline and idle.</li>
          <li>
            Create a new registration token. On a selected build host, use Apps → GitHub Actions Runner with
            an approved group and labels.
          </li>
          <li>
            Verify the new registration in GitHub and inspect the managed runner on its host. Clean the old
            host’s verified terminal artifacts separately.
          </li>
        </ol>
        <p class="mt-2">
          These are explicit operator steps. Nexus does not drain or replace an arbitrary GitHub runner
          automatically.
        </p>
      </details>
      <p v-if="total" class="text-sm">Page {{ page }} · {{ total }} registrations</p>
      <div class="flex gap-2">
        <Button v-if="page > 1" variant="outline" :disabled="busy" @click="browse(page - 1)"
          >Previous runners</Button
        ><Button v-if="page * 50 < total" variant="outline" :disabled="busy" @click="browse(page + 1)"
          >Next runners</Button
        >
      </div>
      <ul class="space-y-2">
        <li v-for="runner in runners" :key="runner.id" class="border rounded p-3 text-sm">
          <p>
            {{ runner.name }} · {{ runner.id }} · {{ runner.os }} · {{ runner.status }} ·
            {{ runner.busy ? 'busy' : 'idle' }}
          </p>
          <p>{{ runner.labels.map((label) => label.name).join(', ') }}</p>
          <Button
            v-if="manageable"
            variant="destructive"
            :disabled="busy || blocked || runner.status !== 'offline' || runner.busy"
            @click="change('runner_remove', runner)"
            >Remove offline registration</Button
          >
        </li>
      </ul>
    </template>
    <details v-if="history.length" class="text-sm">
      <summary>Organization request history</summary>
      <ul class="space-y-2 mt-2">
        <li v-for="row in history" :key="row.id" class="border rounded p-2">
          <p class="font-mono break-all">{{ row.id }}</p>
          <p>
            {{ row.kind }} · {{ row.state }}{{ row.resourceId ? ` · runner ${row.resourceId}` : ''
            }}{{ row.expiresAt ? ` · token expires ${row.expiresAt}` : '' }}
          </p>
        </li>
      </ul>
    </details>
  </section>
</template>
