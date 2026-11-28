<script setup lang="ts">
import type { AnsibleVaultReference, Server } from '@/lib/api';
const model = defineModel<AnsibleVaultReference>({ required: true });
defineProps<{ servers: Server[]; disabled?: boolean }>();
</script>
<template>
  <div class="grid sm:grid-cols-2 gap-2 border rounded p-3 text-sm">
    <label
      >Vault server<select
        aria-label="Vault server"
        v-model="model.serverId"
        :disabled="disabled"
        class="block w-full border rounded p-2 bg-background"
      >
        <option value="">Choose configured Vault server</option>
        <option v-for="server in servers" :key="server.id" :value="server.id">
          {{ server.name }}
        </option>
      </select></label
    >
    <label
      >KV v2 mount<input
        v-model="model.mount"
        :disabled="disabled"
        class="block w-full border rounded p-2 bg-background"
        placeholder="secret"
    /></label>
    <label
      >Secret path<input
        v-model="model.path"
        :disabled="disabled"
        class="block w-full border rounded p-2 bg-background"
        placeholder="automation/application"
    /></label>
    <label
      >Secret key<input
        v-model="model.field"
        :disabled="disabled"
        class="block w-full border rounded p-2 bg-background"
        placeholder="password"
    /></label>
    <label
      >Exact secret version<input
        v-model.number="model.version"
        type="number"
        min="1"
        :disabled="disabled"
        class="block w-full border rounded p-2 bg-background"
    /></label>
    <p class="text-xs text-muted-foreground sm:col-span-2">
      Only this reference is saved. Vault tokens and secret values are not part of inventory or plan
      preparation. The selected version is fixed for review.
    </p>
  </div>
</template>
