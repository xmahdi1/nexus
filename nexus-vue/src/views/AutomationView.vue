<script setup lang="ts">
import { toolEnabled } from '@/lib/tool-preferences';
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type AnsibleInventoryPreview, type AnsibleInventoryToken } from '@/lib/api';
import { verifySession, canAny } from '@/lib/auth';
import AppLayout from '@/components/AppLayout.vue';
import AnsibleWorkspace from '@/components/AnsibleWorkspace.vue';
import GitHubWorkspace from '@/components/GitHubWorkspace.vue';
import Button from '@/components/ui/Button.vue';

const enabled = ref(false);
const groups = ref<Array<{ id: string; name: string }>>([]);
const selected = ref('');
const preview = ref<AnsibleInventoryPreview | null>(null);
const tokens = ref<AnsibleInventoryToken[]>([]);
const issued = ref('');
const busy = ref(false);
const error = ref('');
const lifetime = ref(300);
let generation = 0;
let clearTimer: ReturnType<typeof setTimeout> | undefined;
let mounted = true;
const hosts = computed(() => Object.entries(preview.value?.inventory._meta.hostvars ?? {}));
function clearSecret() {
  issued.value = '';
  clearTimeout(clearTimer);
}
function clearData() {
  groups.value = [];
  preview.value = null;
  tokens.value = [];
  clearSecret();
}
watch(
  () => canAny('ansible.inventory.read'),
  (allowed) => {
    if (!allowed) {
      generation++;
      if (
        !canAny('ansible.projects.read') &&
        !canAny('github.actions.read') &&
        !canAny('github.organizations.read')
      )
        enabled.value = false;
      clearData();
      error.value = 'Inventory access was revoked.';
    }
  },
  { flush: 'sync' },
);
watch(
  selected,
  () => {
    generation++;
    preview.value = null;
    clearSecret();
  },
  { flush: 'sync' },
);
async function load() {
  if (busy.value) return;
  busy.value = true;
  error.value = '';
  const current = ++generation;
  clearData();
  try {
    if (!(await verifySession())) throw new Error('Sign in again.');
    if (
      !canAny('ansible.inventory.read') &&
      !canAny('ansible.projects.read') &&
      !canAny('github.actions.read') &&
      !canAny('github.organizations.read')
    )
      throw new Error(
        'An explicit Ansible or GitHub Actions role is required. Assign scoped roles in Settings.',
      );
    const features = await api.features();
    if (!mounted || current !== generation) return;
    enabled.value = features.automation;
    if (!enabled.value || !canAny('ansible.inventory.read')) return;
    const [nextGroups, nextTokens] = await Promise.all([api.ansible.groups(), api.ansible.tokens()]);
    if (!mounted || current !== generation) return;
    groups.value = nextGroups;
    tokens.value = nextTokens;
    if (!groups.value.some((group) => group.id === selected.value))
      selected.value = groups.value[0]?.id ?? '';
  } catch (e) {
    if (mounted && current === generation) {
      clearData();
      error.value = e instanceof Error ? e.message : 'Automation unavailable.';
    }
  } finally {
    if (mounted) busy.value = false;
  }
}
async function inspect() {
  if (busy.value || !selected.value) return;
  busy.value = true;
  error.value = '';
  preview.value = null;
  clearSecret();
  const current = ++generation;
  try {
    const result = await api.ansible.preview(selected.value);
    if (mounted && current === generation) preview.value = result;
  } catch (e) {
    if (mounted && current === generation)
      error.value = e instanceof Error ? e.message : 'Inventory unavailable.';
  } finally {
    if (mounted) busy.value = false;
  }
}
async function issue() {
  if (busy.value || !selected.value || !preview.value) return;
  busy.value = true;
  error.value = '';
  clearSecret();
  const current = ++generation;
  try {
    const result = await api.ansible.issue(selected.value, lifetime.value);
    if (!mounted || current !== generation) return;
    issued.value = result.token;
    // Keep only public token metadata in lists, and clear the revealed value.
    tokens.value = [
      { id: result.id, groupId: result.groupId, createdAt: result.createdAt, expiresAt: result.expiresAt },
      ...tokens.value,
    ];
    clearTimer = setTimeout(
      clearSecret,
      Math.min(60000, Math.max(0, Date.parse(result.expiresAt) - Date.now())),
    );
  } catch (e) {
    if (mounted && current === generation) {
      preview.value = null;
      error.value =
        (e instanceof Error ? e.message : 'Credential creation could not be confirmed.') +
        ' Refresh credentials before trying again.';
    }
  } finally {
    if (mounted) busy.value = false;
  }
}
async function revoke(id: string) {
  if (busy.value) return;
  busy.value = true;
  error.value = '';
  clearSecret();
  try {
    await api.ansible.revoke(id);
    if (mounted) tokens.value = tokens.value.filter((token) => token.id !== id);
  } catch (e) {
    if (mounted)
      error.value =
        e instanceof Error ? e.message : 'Revocation could not be confirmed. Refresh to inspect its state.';
  } finally {
    if (mounted) busy.value = false;
  }
}
function hidden() {
  if (document.hidden) clearSecret();
}
onMounted(() => {
  document.addEventListener('visibilitychange', hidden);
  void load();
});
onUnmounted(() => {
  mounted = false;
  generation++;
  clearSecret();
  document.removeEventListener('visibilitychange', hidden);
});
</script>

<template>
  <AppLayout>
    <div class="p-6 space-y-6 max-w-6xl mx-auto">
      <div class="flex justify-between gap-4 items-center">
        <div>
          <h1 class="text-2xl font-semibold">Automation</h1>
          <p class="text-muted-foreground">
            Manage Ansible projects, registered-server inventory and GitHub workflows.
          </p>
        </div>
        <Button :disabled="busy" @click="load">Refresh access</Button>
      </div>
      <p v-if="error" role="alert" class="text-destructive">{{ error }}</p>
      <p v-if="!enabled && !error && !busy">
        Enable automation in the Nexus configuration to use these integrations.
      </p>
      <GitHubWorkspace
        v-if="
          enabled &&
          toolEnabled('github') &&
          (canAny('github.actions.read') || canAny('github.organizations.read'))
        "
      />
      <AnsibleWorkspace v-if="enabled && toolEnabled('ansible') && canAny('ansible.projects.read')" />
      <template v-if="enabled && toolEnabled('ansible') && canAny('ansible.inventory.read')">
        <section class="border rounded-lg p-4 space-y-4">
          <h2 class="font-semibold">Dynamic inventory</h2>
          <p class="text-sm text-muted-foreground">
            Only currently authorized servers in the selected group are included. Inventory credentials do not
            grant SSH access or permission to run playbooks.
          </p>
          <div class="flex flex-wrap gap-3 items-center">
            <label for="automation-group">Server group</label
            ><select
              id="automation-group"
              v-model="selected"
              :disabled="busy"
              class="border rounded p-2 bg-background"
            >
              <option v-for="group in groups" :key="group.id" :value="group.id">
                {{ group.name }}
              </option></select
            ><Button :disabled="busy || !selected" @click="inspect">Preview current targets</Button>
          </div>
          <p v-if="!groups.length && !busy">
            No authorized server groups. Ask an administrator to assign the inventory role and add registered
            servers to a group.
          </p>
          <template v-if="preview">
            <div class="overflow-x-auto">
              <table class="w-full text-sm text-left">
                <thead>
                  <tr>
                    <th class="p-2">Server ID</th>
                    <th class="p-2">Address</th>
                    <th class="p-2">Port</th>
                    <th class="p-2">User</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="[alias, host] in hosts" :key="alias">
                    <td class="p-2">{{ host.nexus_server_id }}</td>
                    <td class="p-2">{{ host.ansible_host }}</td>
                    <td class="p-2">{{ host.ansible_port }}</td>
                    <td class="p-2">{{ host.ansible_user }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <details class="text-sm">
              <summary>Inventory aliases and revision</summary>
              <p class="break-all">{{ preview.revision }}</p>
              <dl v-for="(name, alias) in preview.groups" :key="alias" class="mt-2">
                <dt>{{ name }}</dt>
                <dd class="font-mono break-all">{{ alias }}</dd>
              </dl>
            </details>
            <div class="flex gap-3 items-center flex-wrap">
              <label for="automation-ttl">Credential lifetime</label
              ><select
                id="automation-ttl"
                v-model="lifetime"
                :disabled="busy"
                class="border rounded p-2 bg-background"
              >
                <option :value="60">1 minute</option>
                <option :value="300">5 minutes</option>
                <option :value="900">15 minutes</option></select
              ><Button :disabled="busy" @click="issue">Create inventory credential</Button>
            </div>
          </template>
          <div v-if="issued" class="space-y-2">
            <label for="automation-token">Copy once into a private token file (mode 0600)</label
            ><textarea
              id="automation-token"
              :value="issued"
              readonly
              autocomplete="off"
              spellcheck="false"
              class="w-full border rounded p-2 font-mono bg-background"
            />
            <p class="text-sm text-muted-foreground">
              This value clears after one minute or when you leave this screen. Revoking the token or signing
              out invalidates it.
            </p>
            <Button @click="clearSecret">Hide credential</Button>
          </div>
          <p class="text-sm">
            Point the Nexus inventory adapter at this Nexus HTTPS address and your private token file, then
            use <code>ansible-inventory --list</code> or <code>--graph</code>. Each refresh checks current
            access. The adapter and setup instructions are in <code>integrations/ansible</code>.
          </p>
        </section>
        <section class="border rounded-lg p-4 space-y-3">
          <h2 class="font-semibold">Your active inventory credentials</h2>
          <p v-if="!tokens.length">No active credentials.</p>
          <div v-for="token in tokens" :key="token.id" class="flex gap-4 items-center justify-between">
            <div class="text-sm">
              <p class="font-mono break-all">{{ token.id }}</p>
              <p>
                Group {{ groups.find((group) => group.id === token.groupId)?.name ?? token.groupId }} ·
                expires {{ new Date(token.expiresAt).toLocaleString() }}
              </p>
            </div>
            <Button :disabled="busy" @click="revoke(token.id)">Revoke</Button>
          </div>
        </section>
      </template>
    </div>
  </AppLayout>
</template>
