<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type InventoryRelationship, type InventorySourceResult, type InventoryChange } from '@/lib/api';
import { can } from '@/lib/auth';
import Button from './ui/Button.vue';
import InventoryDocumentation from './InventoryDocumentation.vue';
import InventoryControls from './InventoryControls.vue';
const props = defineProps<{ serverId: string }>();
type Item = {
  id: string;
  kind: string;
  displayName: string;
  source: string;
  lastRunId: string;
  dataState: string;
  lastVerifiedAt: string;
  details: unknown;
};
const items = ref<Item[]>([]),
  runs = ref<Array<{ id: string; status: string; warning: string; startedAt: string; trigger: string }>>([]);
const relationships = ref<InventoryRelationship[]>([]),
  history = ref<InventoryChange[]>([]);
const next = ref(''),
  relationNext = ref(''),
  historyNext = ref(''),
  historyResource = ref(''),
  historyName = ref('');
const error = ref(''),
  loading = ref(false),
  relationsLoading = ref(false),
  historyLoading = ref(false),
  scanning = ref(false);
const sources = ref<InventorySourceResult[]>([]);
let alive = true,
  generation = 0,
  historyGeneration = 0;
function current(version: number, server: string) {
  return alive && version === generation && server === props.serverId && can('inventory.read', server);
}
function failure(cause: unknown) {
  return cause instanceof Error ? cause.message : 'Inventory unavailable';
}
function reset() {
  generation++;
  historyGeneration++;
  items.value = [];
  runs.value = [];
  sources.value = [];
  relationships.value = [];
  history.value = [];
  next.value = '';
  relationNext.value = '';
  historyNext.value = '';
  historyResource.value = '';
  historyName.value = '';
  error.value = '';
  loading.value = false;
  relationsLoading.value = false;
  historyLoading.value = false;
  scanning.value = false;
}
async function load(more = false) {
  if (loading.value || !can('inventory.read', props.serverId)) return;
  const version = generation,
    server = props.serverId,
    cursor = more ? next.value : '';
  loading.value = true;
  try {
    const result = await api.inventory.read(server, cursor);
    if (current(version, server)) {
      items.value = more ? [...items.value, ...result.items] : result.items;
      runs.value = result.runs;
      sources.value = result.sources;
      next.value = result.next;
    }
  } catch (cause) {
    if (current(version, server)) error.value = failure(cause);
  } finally {
    if (current(version, server)) loading.value = false;
  }
}
async function loadRelations(more = false) {
  if (relationsLoading.value || !can('inventory.read', props.serverId)) return;
  const version = generation,
    server = props.serverId,
    cursor = more ? relationNext.value : '';
  relationsLoading.value = true;
  try {
    const page = await api.inventory.relationships(server, cursor);
    if (current(version, server)) {
      relationships.value = more ? [...relationships.value, ...page.items] : page.items;
      relationNext.value = page.next;
    }
  } catch (cause) {
    if (current(version, server)) error.value = failure(cause);
  } finally {
    if (current(version, server)) relationsLoading.value = false;
  }
}
async function loadHistory(more = false) {
  if (!can('inventory.read', props.serverId)) return;
  const version = generation,
    server = props.serverId,
    request = ++historyGeneration,
    resource = historyResource.value,
    cursor = more ? historyNext.value : '';
  historyLoading.value = true;
  try {
    const page = await api.inventory.history(server, resource, cursor);
    if (current(version, server) && request === historyGeneration) {
      history.value = more ? [...history.value, ...page.items] : page.items;
      historyNext.value = page.next;
    }
  } catch (cause) {
    if (current(version, server) && request === historyGeneration) error.value = failure(cause);
  } finally {
    if (current(version, server) && request === historyGeneration) historyLoading.value = false;
  }
}
function showHistory(item?: Item) {
  historyResource.value = item?.id ?? '';
  historyName.value = item?.displayName ?? '';
  history.value = [];
  historyNext.value = '';
  void loadHistory();
}
async function refresh() {
  error.value = '';
  await Promise.all([load(), loadRelations(), loadHistory()]);
}
async function discover() {
  if (scanning.value) return;
  const version = generation,
    server = props.serverId;
  scanning.value = true;
  error.value = '';
  try {
    await api.inventory.discover(server);
    if (current(version, server)) await refresh();
  } catch (cause) {
    if (current(version, server)) error.value = failure(cause);
  } finally {
    if (current(version, server)) scanning.value = false;
  }
}
function properties(item: Item) {
  const d = item.details as Record<string, unknown>;
  if (!d || typeof d !== 'object') return '';
  const fields: Record<string, string[]> = {
    host: ['hostname', 'os', 'kernel'],
    container: ['image', 'imageId', 'state', 'health', 'composeProject'],
    service: ['load', 'active', 'sub'],
    port: ['protocol', 'address', 'port', 'targetPort', 'exposure'],
    interface: ['mtu', 'state'],
    address: ['interfaceName', 'scope'],
    route: ['family', 'gateway', 'interfaceName', 'metric', 'type', 'weight', 'nextHopId'],
    block_device: ['type', 'deviceNumber', 'sizeBytes', 'readOnly'],
    mount: ['filesystemType', 'deviceNumber'],
    resolver: ['priority'],
    docker_network: ['id', 'driver', 'scope'],
    docker_volume: ['driver', 'scope'],
    docker_image: ['id', 'references'],
    proxy_route: ['engine', 'host', 'port', 'path', 'match', 'tls', 'upstreams'],
    tls_certificate: [
      'engine',
      'host',
      'port',
      'issuer',
      'notBefore',
      'notAfter',
      'nameMatches',
      'fingerprintSha256',
    ],
  };
  return (fields[item.kind] ?? [])
    .filter((key) => d[key] !== undefined && d[key] !== '')
    .map((key) => `${key}: ${String(d[key])}`)
    .join(' · ');
}
watch(
  () => props.serverId,
  () => {
    reset();
    void refresh();
  },
);
watch(
  () => can('inventory.read', props.serverId),
  (allowed) => {
    if (!allowed) reset();
    else void refresh();
  },
);
onMounted(refresh);
onUnmounted(() => {
  alive = false;
  reset();
});
</script>
<template>
  <section aria-label="Observed inventory" class="space-y-4">
    <div class="flex flex-wrap justify-between gap-2">
      <h2 class="font-semibold">Observed inventory</h2>
      <div class="flex gap-2">
        <Button
          variant="outline"
          :disabled="loading || scanning || relationsLoading || historyLoading"
          @click="refresh"
          >Refresh records</Button
        >
        <Button
          v-if="can('inventory.discover', serverId)"
          :disabled="loading || scanning || relationsLoading || historyLoading"
          @click="discover"
          >{{ scanning ? 'Collecting…' : 'Collect read-only inventory' }}</Button
        >
      </div>
    </div>
    <p class="text-sm text-muted-foreground">
      Inventory shows observed host configuration. Proxy routes and certificates come from files on the host.
      Public reachability requires separate verification. Freshness follows this host’s collection settings.
      Incomplete collectors preserve unconfirmed data.
    </p>
    <InventoryControls :server-id="serverId" @saved="refresh" />
    <p v-if="error" role="alert" class="text-sm text-destructive">{{ error }}</p>
    <p v-if="!loading && !items.length" class="text-sm">
      No observations yet. An authorized administrator can collect this host's inventory.
    </p>
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr>
            <th class="p-2 text-left">Resource</th>
            <th class="p-2 text-left">Source / state</th>
            <th class="p-2 text-left">Last verified</th>
            <th class="p-2 text-left">Observed properties</th>
            <th class="p-2 text-left">History</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in items" :key="item.id" class="border-t">
            <td class="p-2">{{ item.kind }} · {{ item.displayName }}</td>
            <td class="p-2">
              {{ item.source }} · {{ item.dataState
              }}<span v-if="item.lastRunId" class="block text-xs break-all">Run {{ item.lastRunId }}</span>
            </td>
            <td class="p-2">{{ new Date(item.lastVerifiedAt).toLocaleString() }}</td>
            <td class="p-2 text-xs break-all">{{ properties(item) }}</td>
            <td class="p-2">
              <Button
                variant="outline"
                :aria-label="'Show history for ' + item.displayName"
                @click="showHistory(item)"
                >History</Button
              >
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <Button v-if="next" variant="outline" :disabled="loading || scanning" @click="load(true)"
      >Load more observations</Button
    >
    <div class="border rounded-md p-3 space-y-2">
      <h3 class="font-medium">Observed relationships</h3>
      <p v-if="!relationships.length && !relationsLoading" class="text-sm">No relationships observed.</p>
      <div class="overflow-x-auto">
        <table v-if="relationships.length" class="w-full text-sm">
          <thead>
            <tr>
              <th class="text-left p-2">From</th>
              <th class="text-left p-2">Relationship</th>
              <th class="text-left p-2">To</th>
              <th class="text-left p-2">Source / state</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="link in relationships" :key="link.id" class="border-t">
              <td class="p-2">{{ link.sourceName }}</td>
              <td class="p-2">{{ link.kind }}</td>
              <td class="p-2">{{ link.targetName }}</td>
              <td class="p-2">{{ link.source }} · {{ link.dataState }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <Button v-if="relationNext" variant="outline" :disabled="relationsLoading" @click="loadRelations(true)"
        >Load more relationships</Button
      >
    </div>
    <div aria-label="Inventory change history" class="border rounded-md p-3 space-y-2">
      <div class="flex justify-between gap-2">
        <h3 class="font-medium">Change history{{ historyName ? ' · ' + historyName : '' }}</h3>
        <Button v-if="historyResource" variant="outline" @click="showHistory()">Show all changes</Button>
      </div>
      <p v-if="!history.length && !historyLoading" class="text-sm">No recorded changes.</p>
      <article v-for="change in history" :key="change.id" class="border-t py-2 space-y-1">
        <p class="text-sm">
          {{ new Date(change.at).toLocaleString() }} · {{ change.kind }} ·
          {{ change.after?.name ?? change.before?.name ?? change.resourceId }}
        </p>
        <details v-if="change.before || change.after">
          <summary class="text-xs cursor-pointer">Compare observed properties</summary>
          <div class="grid gap-2 md:grid-cols-2">
            <div>
              <p class="text-xs font-medium">Before</p>
              <pre class="text-xs whitespace-pre-wrap break-all">{{
                change.before ? JSON.stringify(change.before.details, null, 2) : 'No earlier snapshot'
              }}</pre>
            </div>
            <div>
              <p class="text-xs font-medium">After</p>
              <pre class="text-xs whitespace-pre-wrap break-all">{{
                change.after ? JSON.stringify(change.after.details, null, 2) : 'No current observation'
              }}</pre>
            </div>
          </div>
        </details>
      </article>
      <Button v-if="historyNext" variant="outline" :disabled="historyLoading" @click="loadHistory(true)"
        >Load older changes</Button
      >
    </div>
    <div v-if="sources.length" class="border rounded-md p-3 space-y-2">
      <h3 class="font-medium">Latest collector results</h3>
      <p v-for="source in sources" :key="source.source" class="text-xs">
        {{ source.source }} · {{ source.status }} · {{ new Date(source.collectedAt).toLocaleString() }}
      </p>
    </div>
    <div class="border rounded-md p-3 space-y-2">
      <h3 class="font-medium">Recent collection runs</h3>
      <p v-for="run in runs" :key="run.id" class="text-xs">
        {{ new Date(run.startedAt).toLocaleString() }} · {{ run.status }} · {{ run.trigger }}
        <span>{{ run.warning }}</span>
      </p>
    </div>
    <InventoryDocumentation :server-id="serverId" />
  </section>
</template>
