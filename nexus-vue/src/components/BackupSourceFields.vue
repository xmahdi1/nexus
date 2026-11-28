<script setup lang="ts">
import { computed, watch } from 'vue';
import type { BackupSource } from '@/lib/api';
import Input from '@/components/ui/Input.vue';
const model = defineModel<BackupSource>({ required: true });
defineProps<{ disabled?: boolean }>();
const database = computed(() => ['postgres', 'mysql', 'mariadb', 'mongodb'].includes(model.value.kind));
watch(
  () => model.value.containerId,
  () => {
    if (!database.value) return;
    model.value.database =
      model.value.containerId && model.value.kind !== 'mongodb'
        ? { containerEnvironment: true }
        : {
            host: model.value.containerId ? undefined : '127.0.0.1',
            port: model.value.containerId
              ? undefined
              : model.value.kind === 'postgres'
                ? 5432
                : model.value.kind === 'mongodb'
                  ? 27017
                  : 3306,
            user: model.value.kind === 'postgres' ? 'postgres' : model.value.kind === 'mongodb' ? '' : 'root',
            password: '',
          };
  },
  { flush: 'sync' },
);
</script>
<template>
  <div class="grid gap-2 sm:grid-cols-2">
    <label class="text-sm"
      >Source label<Input v-model="model.label" :disabled="disabled" maxlength="120"
    /></label>
    <label v-if="['files', 'sqlite', 'docker-bind'].includes(model.kind)" class="text-sm"
      >Absolute source path<Input v-model="model.path" :disabled="disabled" placeholder="/srv/application"
    /></label>
    <label v-if="model.kind === 'docker-volume'" class="text-sm"
      >Docker volume name<Input v-model="model.volume" :disabled="disabled"
    /></label>
    <label v-if="database || model.kind === 'docker-bind'" class="text-sm"
      >Container ID {{ database ? '(optional for native databases)' : ''
      }}<Input v-model="model.containerId" :disabled="disabled" placeholder="Full 64-character container ID"
    /></label>
    <template v-if="database && model.database">
      <p v-if="model.database.containerEnvironment" class="text-xs sm:col-span-2">
        Uses the database container's configured credentials. The matching dump tool must exist inside it.
        Environment secrets are not returned by discovery.
      </p>
      <template v-else>
        <label v-if="!model.containerId" class="text-sm"
          >Database host<Input v-model="model.database.host" :disabled="disabled"
        /></label>
        <label v-if="!model.containerId" class="text-sm"
          >Database port<Input
            v-model.number="model.database.port"
            type="number"
            min="1"
            max="65535"
            :disabled="disabled"
        /></label>
        <label class="text-sm"
          >Database user<Input v-model="model.database.user" :disabled="disabled" autocomplete="off"
        /></label>
        <label class="text-sm"
          >Database password<Input
            v-model="model.database.password"
            type="password"
            :disabled="disabled"
            autocomplete="new-password"
        /></label>
        <label class="text-sm"
          >Database name (empty means all)<Input v-model="model.database.name" :disabled="disabled"
        /></label>
        <p v-if="model.kind === 'mongodb'" class="text-xs">
          MongoDB uses admin authentication. For a container without authentication, leave user and password
          empty.
        </p>
      </template>
    </template>
  </div>
</template>
