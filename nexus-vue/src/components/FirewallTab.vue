<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { toast } from 'vue-sonner';
import { Loader2, Plus, RefreshCw, Shield, ShieldOff, Trash2, X } from '@lucide/vue';
import type { FirewallStatus } from '@/lib/api';
import { api } from '@/lib/api';
import { can } from '@/lib/auth';
import Button from '@/components/ui/Button.vue';
import { useConfirm } from '@/composables/useConfirm';
const { confirm } = useConfirm();

const CACHE_TTL = 45_000;

interface CacheEntry {
  data: FirewallStatus;
  ts: number;
}

const cache = new Map<string, CacheEntry>();

function getCached(id: string): FirewallStatus | null {
  const e = cache.get(id);
  if (!e) return null;
  if (Date.now() - e.ts > CACHE_TTL) {
    cache.delete(id);
    return null;
  }
  return e.data;
}

function setCached(id: string, data: FirewallStatus) {
  cache.set(id, { data, ts: Date.now() });
}

const props = defineProps<{ serverId: string }>();

const loading = ref(true);
const toggling = ref(false);
const deleting = ref<number | null>(null);
const status = ref<FirewallStatus | null>(null);

const showForm = ref(false);
const formPort = ref('');
const formProto = ref('tcp');
const formAction = ref('allow');
const formFrom = ref('');
const adding = ref(false);

function portService(to: string): string {
  const m = to.match(/^(\d+)/);
  if (!m || !status.value?.ports?.length) return '';
  return status.value.ports.find((p) => p.port === m[1])?.process || '';
}

function portCmdline(to: string): string {
  const m = to.match(/^(\d+)/);
  if (!m || !status.value?.ports?.length) return '';
  return status.value.ports.find((p) => p.port === m[1])?.cmdline || '';
}

async function load(force = false) {
  if (!force) {
    const cached = getCached(props.serverId);
    if (cached) {
      status.value = cached;
      loading.value = false;
      return;
    }
  }
  loading.value = true;
  try {
    const data = await api.firewall.status(props.serverId);
    status.value = data;
    setCached(props.serverId, data);
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to load firewall');
  } finally {
    loading.value = false;
  }
}

async function toggle() {
  if (!status.value || !can('firewall.manage', props.serverId)) return;
  const action = status.value.status === 'active' ? 'Disable' : 'Enable';
  if (
    !(await confirm({
      title: `${action} firewall?`,
      message:
        'This changes network access immediately and may disconnect SSH or Nexus. Verify a recovery connection before continuing.',
      confirmText: action,
      destructive: true,
    }))
  )
    return;
  toggling.value = true;
  try {
    if (status.value.status === 'active') {
      await api.firewall.disable(props.serverId);
      toast.success('UFW disabled');
    } else {
      await api.firewall.enable(props.serverId);
      toast.success('UFW enabled');
    }
    await load(true);
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed');
  } finally {
    toggling.value = false;
  }
}

async function addRule() {
  if (!formPort.value.trim() || !can('firewall.manage', props.serverId)) return;
  if (
    formAction.value === 'deny' &&
    !(await confirm({
      title: 'Deny network access?',
      message: `Deny ${formPort.value}/${formProto.value} from ${formFrom.value || 'Anywhere'}? This may disconnect a management connection.`,
      confirmText: 'Add deny rule',
      destructive: true,
    }))
  )
    return;
  adding.value = true;
  try {
    const port = formProto.value === 'any' ? formPort.value : `${formPort.value}/${formProto.value}`;
    await api.firewall.addRule(props.serverId, {
      port,
      action: formAction.value,
      from: formFrom.value || 'Anywhere',
    });
    toast.success('Rule added');
    showForm.value = false;
    formPort.value = '';
    formProto.value = 'tcp';
    formAction.value = 'allow';
    formFrom.value = '';
    await load(true);
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to add rule');
  } finally {
    adding.value = false;
  }
}

async function deleteRule(n: number) {
  if (!can('firewall.manage', props.serverId)) return;
  if (
    !(await confirm({
      title: 'Delete firewall rule?',
      message: `Remove rule ${n}? This immediately changes access and may disconnect a management connection.`,
      confirmText: 'Delete',
      destructive: true,
    }))
  )
    return;
  deleting.value = n;
  try {
    await api.firewall.deleteRule(props.serverId, n);
    toast.success('Rule deleted');
    await load(true);
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to delete rule');
  } finally {
    deleting.value = null;
  }
}

onMounted(() => load());
</script>

<template>
  <div class="space-y-6">
    <template v-if="loading">
      <div class="rounded-xl border border-border px-5 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="w-2.5 h-2.5 rounded-full bg-muted animate-pulse shrink-0" />
          <div class="h-4 w-24 bg-muted animate-pulse rounded" />
          <div class="h-3.5 w-14 bg-muted animate-pulse rounded" />
        </div>
        <div class="h-8 w-20 bg-muted animate-pulse rounded-lg" />
      </div>
      <div class="space-y-3">
        <div class="flex items-center justify-between">
          <div class="h-4 w-28 bg-muted animate-pulse rounded" />
          <div class="h-8 w-24 bg-muted animate-pulse rounded-lg" />
        </div>
        <div class="border border-border rounded-xl overflow-hidden">
          <div class="border-b border-border bg-muted/40 px-4 py-2.5 flex gap-6">
            <div
              v-for="w in ['w-4', 'w-14', 'w-16', 'w-14', 'w-12']"
              :key="w"
              :class="`h-3 ${w} bg-muted animate-pulse rounded`"
            />
          </div>
          <div
            v-for="i in 4"
            :key="i"
            class="border-b border-border last:border-0 px-4 py-3 flex gap-6 items-center"
          >
            <div class="h-3 w-4 bg-muted animate-pulse rounded" />
            <div class="h-3 w-14 bg-muted animate-pulse rounded" />
            <div class="h-3 w-16 bg-muted animate-pulse rounded" />
            <div class="h-5 w-16 bg-muted animate-pulse rounded-md" />
            <div class="h-3 w-14 bg-muted animate-pulse rounded" />
          </div>
        </div>
      </div>
      <div class="space-y-3">
        <div class="h-4 w-36 bg-muted animate-pulse rounded" />
        <div class="border border-border rounded-xl overflow-hidden">
          <div class="border-b border-border bg-muted/40 px-4 py-2.5 flex gap-6">
            <div
              v-for="w in ['w-8', 'w-10', 'w-24', 'w-32']"
              :key="w"
              :class="`h-3 ${w} bg-muted animate-pulse rounded`"
            />
          </div>
          <div
            v-for="i in 5"
            :key="i"
            class="border-b border-border last:border-0 px-4 py-3 flex gap-6 items-center"
          >
            <div class="h-3 w-8 bg-muted animate-pulse rounded" />
            <div class="h-5 w-10 bg-muted animate-pulse rounded-md" />
            <div class="h-3 w-24 bg-muted animate-pulse rounded" />
            <div class="space-y-1.5">
              <div class="h-3 w-24 bg-muted animate-pulse rounded" />
              <div class="h-2.5 w-40 bg-muted animate-pulse rounded" />
            </div>
          </div>
        </div>
      </div>
    </template>

    <template v-else-if="status">
      <div
        v-if="!status.available"
        class="rounded-xl border border-border p-6 text-center text-sm text-muted-foreground"
      >
        UFW is not installed on this server. Install it with
        <code class="font-mono text-xs bg-muted px-1 py-0.5 rounded">apt install ufw</code>.
      </div>

      <template v-if="status.available">
        <div class="flex items-center justify-between gap-4 rounded-xl border border-border px-5 py-4">
          <div class="flex items-center gap-3">
            <div
              :class="[
                'w-2.5 h-2.5 rounded-full flex-shrink-0',
                status.status === 'active' ? 'bg-green-500' : 'bg-zinc-400',
              ]"
            />
            <span class="font-medium">UFW Firewall</span>
            <span class="text-sm text-muted-foreground capitalize">{{ status.status }}</span>
          </div>
          <Button
            v-if="can('firewall.manage', serverId)"
            variant="outline"
            size="sm"
            class="gap-2"
            :disabled="toggling"
            @click="toggle"
          >
            <Loader2 v-if="toggling" class="h-3.5 w-3.5 animate-spin" />
            <ShieldOff v-else-if="status.status === 'active'" class="h-3.5 w-3.5" />
            <Shield v-else class="h-3.5 w-3.5" />
            {{ status.status === 'active' ? 'Disable' : 'Enable' }}
          </Button>
        </div>

        <div>
          <div class="flex items-center justify-between mb-3">
            <h3 class="font-medium text-sm">Firewall Rules</h3>
            <div class="flex items-center gap-2">
              <Button variant="ghost" size="sm" class="h-8 w-8 p-0" @click="load(true)">
                <RefreshCw class="h-3.5 w-3.5" />
              </Button>
              <Button
                v-if="can('firewall.manage', serverId)"
                size="sm"
                class="gap-1.5 h-8"
                @click="showForm = !showForm"
              >
                <X v-if="showForm" class="h-3.5 w-3.5" />
                <Plus v-else class="h-3.5 w-3.5" />
                {{ showForm ? 'Cancel' : 'Add Rule' }}
              </Button>
            </div>
          </div>

          <div
            v-if="showForm && can('firewall.manage', serverId)"
            class="mb-3 rounded-xl border border-border p-4"
          >
            <div class="flex flex-wrap gap-3 items-end">
              <div class="flex flex-col gap-1.5">
                <label class="text-xs text-muted-foreground">Port</label>
                <input
                  v-model="formPort"
                  placeholder="80 or 8000:9000"
                  class="h-8 rounded-lg border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring w-40"
                />
              </div>
              <div class="flex flex-col gap-1.5">
                <label class="text-xs text-muted-foreground">Protocol</label>
                <select
                  v-model="formProto"
                  class="h-8 rounded-lg border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="any">Any</option>
                </select>
              </div>
              <div class="flex flex-col gap-1.5">
                <label class="text-xs text-muted-foreground">Action</label>
                <select
                  v-model="formAction"
                  class="h-8 rounded-lg border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="allow">Allow</option>
                  <option value="deny">Deny</option>
                </select>
              </div>
              <div class="flex flex-col gap-1.5">
                <label class="text-xs text-muted-foreground">From (optional)</label>
                <input
                  v-model="formFrom"
                  placeholder="Anywhere"
                  class="h-8 rounded-lg border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring w-36"
                />
              </div>
              <Button size="sm" class="h-8" :disabled="adding || !formPort.trim()" @click="addRule">
                <Loader2 v-if="adding" class="h-3.5 w-3.5 animate-spin mr-1.5" />
                Add
              </Button>
            </div>
          </div>

          <div
            v-if="!status.rules?.length"
            class="rounded-xl border border-border p-6 text-center text-sm text-muted-foreground"
          >
            No rules configured
          </div>
          <div v-else class="border border-border rounded-xl overflow-hidden">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-border bg-muted/40">
                  <th class="px-4 py-2.5 text-left font-medium text-muted-foreground w-10">#</th>
                  <th class="px-4 py-2.5 text-left font-medium text-muted-foreground">Port</th>
                  <th class="px-4 py-2.5 text-left font-medium text-muted-foreground hidden sm:table-cell">
                    Service
                  </th>
                  <th class="px-4 py-2.5 text-left font-medium text-muted-foreground">Action</th>
                  <th class="px-4 py-2.5 text-left font-medium text-muted-foreground hidden md:table-cell">
                    From
                  </th>
                  <th class="px-4 py-2.5 w-10"></th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="rule in status.rules"
                  :key="rule.number"
                  class="border-b border-border last:border-0 hover:bg-muted/20 transition-colors"
                >
                  <td class="px-4 py-3 text-muted-foreground font-mono text-xs">{{ rule.number }}</td>
                  <td class="px-4 py-3 font-mono text-xs">{{ rule.to }}</td>
                  <td class="px-4 py-3 hidden sm:table-cell">
                    <span
                      v-if="portService(rule.to)"
                      class="text-sm"
                      :title="portCmdline(rule.to) || undefined"
                    >
                      {{ portService(rule.to) }}
                    </span>
                    <span v-else class="text-muted-foreground text-xs">—</span>
                  </td>
                  <td class="px-4 py-3">
                    <span
                      :class="[
                        'inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium',
                        rule.action.includes('ALLOW')
                          ? 'bg-green-500/10 text-green-600 dark:text-green-400'
                          : rule.action.includes('LIMIT')
                            ? 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400'
                            : 'bg-red-500/10 text-red-600 dark:text-red-400',
                      ]"
                    >
                      {{ rule.action }}
                    </span>
                  </td>
                  <td class="px-4 py-3 text-sm text-muted-foreground hidden md:table-cell">
                    {{ rule.from }}
                  </td>
                  <td class="px-4 py-3">
                    <Button
                      v-if="can('firewall.manage', serverId)"
                      :aria-label="`Delete firewall rule ${rule.number}`"
                      variant="ghost"
                      size="sm"
                      class="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                      :disabled="deleting === rule.number"
                      @click="deleteRule(rule.number)"
                    >
                      <Loader2 v-if="deleting === rule.number" class="h-3.5 w-3.5 animate-spin" />
                      <Trash2 v-else class="h-3.5 w-3.5" />
                    </Button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </template>

      <div v-if="status.ports?.length">
        <h3 class="font-medium text-sm mb-3">All Listening Ports</h3>
        <div class="border border-border rounded-xl overflow-hidden">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-border bg-muted/40">
                <th class="px-4 py-2.5 text-left font-medium text-muted-foreground">Port</th>
                <th class="px-4 py-2.5 text-left font-medium text-muted-foreground">Proto</th>
                <th class="px-4 py-2.5 text-left font-medium text-muted-foreground hidden sm:table-cell">
                  Address
                </th>
                <th class="px-4 py-2.5 text-left font-medium text-muted-foreground">Service</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="p in status.ports"
                :key="`${p.protocol}-${p.port}-${p.address}`"
                class="border-b border-border last:border-0 hover:bg-muted/20 transition-colors"
              >
                <td class="px-4 py-3 font-mono text-xs font-medium">{{ p.port }}</td>
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-muted text-muted-foreground uppercase"
                  >
                    {{ p.protocol }}
                  </span>
                </td>
                <td class="px-4 py-3 font-mono text-xs text-muted-foreground hidden sm:table-cell">
                  {{ p.address || '—' }}
                </td>
                <td class="px-4 py-3">
                  <div class="text-sm font-medium">{{ p.process || '—' }}</div>
                  <div
                    v-if="p.cmdline"
                    class="text-xs text-muted-foreground font-mono mt-0.5 truncate max-w-[260px]"
                    :title="p.cmdline"
                  >
                    {{ p.cmdline }}
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>
