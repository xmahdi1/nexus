<script setup lang="ts">
import { can } from '@/lib/auth';
import { ref, onMounted } from 'vue';
import { useI18n } from 'vue-i18n';
import { toast } from 'vue-sonner';
import { Plus, ServerOff, Trash2, RefreshCw } from '@lucide/vue';
import { useServersStore } from '@/stores/servers';
import { useConfirm } from '@/composables/useConfirm';
import AppLayout from '@/components/AppLayout.vue';
import Card from '@/components/ui/Card.vue';
import Button from '@/components/ui/Button.vue';
import Table from '@/components/ui/Table.vue';
import TableHeader from '@/components/ui/TableHeader.vue';
import TableBody from '@/components/ui/TableBody.vue';
import TableRow from '@/components/ui/TableRow.vue';
import TableHead from '@/components/ui/TableHead.vue';
import TableCell from '@/components/ui/TableCell.vue';
import StatusDot from '@/components/StatusDot.vue';
import AddServerModal from '@/components/AddServerModal.vue';
import TagBadge from '@/components/TagBadge.vue';

const { t } = useI18n();
const store = useServersStore();
const { confirm } = useConfirm();
const modalOpen = ref(false);

function parseTags(raw: string) {
  return raw
    ? raw
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean)
    : [];
}

async function handleAdd(data: {
  name: string;
  host: string;
  port: number;
  username: string;
  publicKey: string;
  privateKey: string;
}) {
  try {
    await store.addServer(data);
    toast.success(t('servers.added'));
    modalOpen.value = false;
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to add server');
  }
}

async function handleDelete(id: string, name: string) {
  const ok = await confirm({
    title: 'Remove server',
    message: `Remove "${name}" and its stored keys? This cannot be undone.`,
    confirmText: 'Remove',
    destructive: true,
  });
  if (!ok) return;
  try {
    await store.removeServer(id);
    toast.success('Server removed');
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to remove server');
  }
}

async function handleTest(id: string) {
  const result = await store.testConnection(id);
  if (result.ok) toast.success(`Connected — ${result.latencyMs}ms`);
  else toast.error(result.error ?? 'Connection failed');
}

onMounted(() => store.fetchAll());
</script>

<template>
  <AppLayout>
    <div class="max-w-7xl mx-auto">
      <div class="flex items-start justify-between mb-6">
        <div>
          <h1 class="text-xl sm:text-2xl font-semibold tracking-tight">{{ t('servers.title') }}</h1>
          <p class="text-sm text-muted-foreground mt-1">{{ t('servers.subtitle') }}</p>
        </div>
        <Button v-if="can('servers.create')" class="gap-2" @click="modalOpen = true">
          <Plus class="h-4 w-4" />
          <span class="hidden sm:inline">{{ t('servers.add') }}</span>
        </Button>
      </div>

      <div v-if="store.loading" class="grid gap-2">
        <div v-for="i in 3" :key="i" class="h-12 rounded-md bg-muted animate-pulse" />
      </div>

      <Card v-else-if="store.list.length === 0" class="p-12 flex flex-col items-center text-center">
        <ServerOff class="h-10 w-10 text-muted-foreground mb-3" />
        <h3 class="font-medium">{{ t('servers.empty') }}</h3>
        <p class="text-sm text-muted-foreground mt-1">{{ t('servers.emptyHint') }}</p>
      </Card>

      <Card v-else class="overflow-x-auto p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{{ t('servers.displayName') }}</TableHead>
              <TableHead class="hidden sm:table-cell">{{ t('servers.host') }}</TableHead>
              <TableHead class="hidden md:table-cell">{{ t('servers.username') }}</TableHead>
              <TableHead class="hidden sm:table-cell">Tags</TableHead>
              <TableHead>Status</TableHead>
              <TableHead class="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow v-for="s in store.list" :key="s.id">
              <TableCell>
                <RouterLink :to="`/servers/${s.id}`" class="font-medium hover:underline">{{
                  s.name
                }}</RouterLink>
                <p class="text-xs text-muted-foreground font-mono sm:hidden mt-0.5">
                  {{ s.host }}:{{ s.port }}
                </p>
              </TableCell>
              <TableCell class="font-mono text-xs text-muted-foreground hidden sm:table-cell"
                >{{ s.host }}:{{ s.port }}
              </TableCell>
              <TableCell class="font-mono text-xs hidden md:table-cell">{{ s.username }}</TableCell>
              <TableCell class="hidden sm:table-cell">
                <div class="flex gap-1 flex-wrap">
                  <TagBadge v-for="tag in parseTags(s.tags)" :key="tag" :tag="tag" />
                  <span v-if="!s.tags" class="text-xs text-muted-foreground">—</span>
                </div>
              </TableCell>
              <TableCell>
                <div class="flex items-center gap-2 text-sm">
                  <StatusDot :status="s.status === 'unknown' ? 'connecting' : s.status" />
                  <span class="capitalize hidden sm:inline">{{
                    s.status === 'unknown' ? '—' : s.status
                  }}</span>
                </div>
              </TableCell>
              <TableCell>
                <div class="flex items-center justify-end gap-1">
                  <Button
                    v-if="can('servers.connect', s.id)"
                    size="icon"
                    variant="ghost"
                    class="h-7 w-7"
                    @click="handleTest(s.id)"
                  >
                    <RefreshCw class="h-3.5 w-3.5" />
                  </Button>
                  <Button
                    v-if="can('servers.delete', s.id)"
                    size="icon"
                    variant="ghost"
                    class="h-7 w-7 text-destructive hover:text-destructive"
                    @click="handleDelete(s.id, s.name)"
                  >
                    <Trash2 class="h-3.5 w-3.5" />
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </Card>

      <AddServerModal v-model:open="modalOpen" @save="handleAdd" />
    </div>
  </AppLayout>
</template>
