<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { api, type Server } from '@/lib/api';
import { can } from '@/lib/auth';
import Button from '@/components/ui/Button.vue';
import AnsibleEnvironmentTab from '@/components/AnsibleEnvironmentTab.vue';
import AnsibleProjectsPanel from '@/components/AnsibleProjectsPanel.vue';

const servers = ref<Server[]>([]),
  controller = ref(''),
  error = ref(''),
  supervision = ref(false),
  vaultEnabled = ref(false);
const choices = computed(() => servers.value.filter((server) => can('ansible.projects.read', server.id)));
const chosen = computed(() => choices.value.find((server) => server.id === controller.value));
async function load() {
  error.value = '';
  try {
    const [list, features] = await Promise.all([api.servers.list(), api.features()]);
    servers.value = list;
    supervision.value = features.operationSupervision;
    vaultEnabled.value = features.vault;
  } catch (e) {
    servers.value = [];
    error.value = e instanceof Error ? e.message : 'Controller list unavailable.';
  }
}
onMounted(load);
</script>
<template>
  <section aria-label="Ansible projects" class="space-y-4 border rounded-lg p-4">
    <div class="flex justify-between items-center">
      <h2 class="font-semibold">Playbooks and controllers</h2>
      <Button variant="outline" @click="load">Refresh controllers</Button>
    </div>
    <p class="text-sm text-muted-foreground">
      Nexus stores encrypted playbooks and approvals. Choose the registered Linux server that will hold
      Ansible and execute the playbook against your selected targets. The Nexus API process does not execute
      playbooks.
    </p>
    <p v-if="error" role="alert">{{ error }}</p>
    <label class="block text-sm"
      >Ansible controller<select
        aria-label="Ansible controller"
        v-model="controller"
        class="block border rounded p-2 bg-background w-full"
      >
        <option value="">Choose a registered controller</option>
        <option v-for="server in choices" :key="server.id" :value="server.id">
          {{ server.name }} · {{ server.host }} · SSH {{ server.username }}
        </option>
      </select></label
    >
    <p v-if="!choices.length" class="text-sm">
      Register a controller and grant server-read plus Ansible project access to see it here.
    </p>
    <template v-if="chosen">
      <p class="text-sm font-medium">Controller: {{ chosen.name }} ({{ chosen.host }})</p>
      <p v-if="chosen.username !== 'root'" class="text-sm">
        Managed supervision currently requires root SSH on this controller. Playbook execution must use its
        separate restricted job identity.
      </p>
      <AnsibleEnvironmentTab
        v-if="can('ansible.environment.read', chosen.id)"
        :key="'environment-' + chosen.id"
        :server-id="chosen.id"
        :enabled="supervision"
      />
      <AnsibleProjectsPanel
        :key="chosen.id"
        :server-id="chosen.id"
        :servers="servers"
        :vault-enabled="vaultEnabled"
      />
    </template>
  </section>
</template>
