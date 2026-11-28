<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, ref } from 'vue';
const GitHubOrganizations = defineAsyncComponent(() => import('@/components/GitHubOrganizations.vue'));
import { api, type Server } from '@/lib/api';
import { can } from '@/lib/auth';
import { toolEnabled } from '@/lib/tool-preferences';
import GitHubConnectionPanel from '@/components/GitHubConnectionPanel.vue';
const servers = ref<Server[]>([]),
  selected = ref(''),
  error = ref('');
const choices = computed(() =>
  servers.value.filter(
    (server) => can('github.actions.read', server.id) || can('github.organizations.read', server.id),
  ),
);
onMounted(async () => {
  try {
    servers.value = await api.servers.list();
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Scopes unavailable.';
  }
});
</script>
<template>
  <section aria-label="GitHub Actions" class="border rounded-lg p-4 space-y-3">
    <h2 class="font-semibold">GitHub Actions</h2>
    <p class="text-sm">
      Choose a Nexus permission scope for the repository connection. GitHub decides where workflows run; this
      selection grants no deployment or Ansible authority.
    </p>
    <p v-if="error" role="alert">{{ error }}</p>
    <label class="block text-sm"
      >Nexus permission scope<select
        v-model="selected"
        aria-label="GitHub permission scope"
        class="block border rounded p-2 w-full bg-background"
      >
        <option value="">Choose a registered server scope</option>
        <option v-for="server in choices" :key="server.id" :value="server.id">
          {{ server.name }}
        </option>
      </select></label
    ><GitHubConnectionPanel
      v-if="
        selected && can('github.actions.read', selected) && choices.some((server) => server.id === selected)
      "
      :key="selected"
      :server-id="selected"
    />
    <GitHubOrganizations
      v-if="
        toolEnabled('runners') &&
        selected &&
        choices.some((server) => server.id === selected) &&
        can('github.organizations.read', selected)
      "
      :key="'org-' + selected"
      :server-id="selected"
    />
  </section>
</template>
