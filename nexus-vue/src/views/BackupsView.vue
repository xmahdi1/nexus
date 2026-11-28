<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { api, type Server } from '@/lib/api';
import { can, canAny } from '@/lib/auth';
import { toolEnabled } from '@/lib/tool-preferences';
import AppLayout from '@/components/AppLayout.vue';
import BackupsWorkspace from '@/components/BackupsWorkspace.vue';
import Button from '@/components/ui/Button.vue';
const servers = ref<Server[]>([]),
  selected = ref(''),
  error = ref('');
let generation = 0,
  alive = true;
const local = computed(() => can('backups.nexus.manage') && can('backups.read'));
const choices = computed(() => servers.value.filter((s) => can('backups.read', s.id)));
const authorized = computed(() =>
  selected.value === 'nexus' ? local.value : choices.value.some((s) => s.id === selected.value),
);
watch(
  () => [local.value, choices.value.map((s) => s.id).join(',')],
  () => {
    if (!authorized.value) selected.value = local.value ? 'nexus' : (choices.value[0]?.id ?? '');
  },
);
async function load() {
  const version = ++generation;
  error.value = '';
  try {
    const next = canAny('servers.read') ? await api.servers.list() : [];
    if (alive && version === generation) {
      servers.value = next;
      if (!authorized.value) selected.value = local.value ? 'nexus' : (choices.value[0]?.id ?? '');
    }
  } catch (e) {
    if (alive && version === generation) {
      servers.value = [];
      error.value = e instanceof Error ? e.message : 'Backup sources unavailable.';
    }
  }
}
onMounted(load);
onUnmounted(() => {
  alive = false;
  generation++;
});
</script>
<template>
  <AppLayout
    ><div class="max-w-6xl mx-auto space-y-5">
      <div class="flex justify-between">
        <div>
          <h1 class="text-2xl font-semibold">Backups</h1>
          <p class="text-muted-foreground">Choose resources, store snapshots and verify restore copies.</p>
        </div>
        <Button variant="outline" @click="load">Refresh backup targets</Button>
      </div>
      <p v-if="error" role="alert">{{ error }}</p>
      <p v-if="!toolEnabled('backups')">Enable Backups in Settings → Tools to show this workspace.</p>
      <template v-else
        ><label class="block text-sm"
          >Backup target<select
            v-model="selected"
            aria-label="Backup target"
            class="block w-full border rounded p-2 bg-background"
          >
            <option value="">Choose target</option>
            <option v-if="local" value="nexus">Nexus recovery data</option>
            <option v-for="server in choices" :key="server.id" :value="server.id">
              {{ server.name }} · {{ server.host }}
            </option>
          </select></label
        >
        <p v-if="!local && !choices.length" class="text-sm">
          Assign a scoped backup role to a registered server, or the global Nexus backup administrator role
          for Nexus recovery data.
        </p>
        <BackupsWorkspace
          v-if="authorized"
          :key="selected"
          :server-id="selected === 'nexus' ? undefined : selected"
          :server-name="selected === 'nexus' ? 'Nexus' : choices.find((s) => s.id === selected)?.name"
        />
      </template></div
  ></AppLayout>
</template>
