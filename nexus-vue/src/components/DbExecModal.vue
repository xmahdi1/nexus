<script setup lang="ts">
import { ref, computed } from 'vue';
import { toast } from 'vue-sonner';
import { X, Loader2, Play, Database } from '@lucide/vue';
import { api } from '@/lib/api';
import type { Container } from '@/lib/api';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';
import Label from '@/components/ui/Label.vue';

const props = defineProps<{ serverId: string; container: Container }>();
const emit = defineEmits<{ close: [] }>();

const query = ref('');
const dbUser = ref('');
const dbPassword = ref('');
const output = ref('');
const running = ref(false);

const dbType = computed(() => {
  const img = props.container.image.toLowerCase();
  if (img.includes('postgres')) return 'postgres';
  if (img.includes('mariadb')) return 'mariadb';
  if (img.includes('mysql')) return 'mysql';
  if (img.includes('redis')) return 'redis';
  if (img.includes('mongo')) return 'mongo';
  return 'unknown';
});

const dbColor = computed(
  () =>
    ({
      postgres: 'text-blue-500 bg-blue-500/10',
      mariadb: 'text-orange-500 bg-orange-500/10',
      mysql: 'text-orange-400 bg-orange-400/10',
      redis: 'text-red-500 bg-red-500/10',
      mongo: 'text-green-600 bg-green-600/10',
      unknown: 'text-muted-foreground bg-muted',
    })[dbType.value],
);

const placeholder = computed(
  () =>
    ({
      postgres: 'SELECT version();\nSELECT * FROM pg_tables LIMIT 10;',
      mariadb: 'SHOW DATABASES;\nSELECT * FROM information_schema.tables LIMIT 10;',
      mysql: 'SHOW DATABASES;\nSELECT * FROM information_schema.tables LIMIT 10;',
      redis: 'INFO\nKEYS *\nGET mykey',
      mongo: 'db.runCommand({listCollections:1})\ndb.myCollection.find().limit(5)',
      unknown: '',
    })[dbType.value],
);

const needsCreds = computed(() => ['postgres', 'mysql', 'mariadb'].includes(dbType.value));
const isRedis = computed(() => dbType.value === 'redis');

async function run() {
  if (!query.value.trim()) {
    toast.error('Enter a query');
    return;
  }
  running.value = true;
  output.value = '';
  try {
    const res = await api.containers.exec(props.serverId, props.container.id, {
      query: query.value,
      dbUser: dbUser.value,
      dbPassword: dbPassword.value,
    });
    output.value = res.output;
  } catch (e: any) {
    output.value = e?.error || (e instanceof Error ? e.message : 'Failed');
    toast.error('Query failed');
  } finally {
    running.value = false;
  }
}
</script>

<template>
  <div class="fixed inset-0 z-[200] flex items-end sm:items-center justify-center sm:p-4">
    <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" @click="emit('close')" />
    <div
      class="relative z-10 w-full sm:max-w-2xl bg-card border sm:rounded-2xl rounded-t-2xl shadow-2xl flex flex-col max-h-[92vh]"
    >
      <div class="flex items-center gap-3 p-4 sm:p-5 border-b">
        <Database class="h-5 w-5 text-muted-foreground shrink-0" />
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2 flex-wrap">
            <p class="font-semibold text-sm">{{ container.name || container.id }}</p>
            <span
              :class="['text-[10px] font-semibold px-2 py-0.5 rounded-full uppercase tracking-wide', dbColor]"
            >
              {{ dbType }}
            </span>
          </div>
          <p class="text-xs text-muted-foreground font-mono truncate">{{ container.image }}</p>
        </div>
        <button class="text-muted-foreground hover:text-foreground" @click="emit('close')">
          <X class="h-4 w-4" />
        </button>
      </div>

      <div class="flex-1 overflow-y-auto p-4 sm:p-5 space-y-4">
        <div v-if="needsCreds" class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div class="space-y-1.5">
            <Label>DB User <span class="text-muted-foreground text-xs">(optional)</span></Label>
            <Input
              v-model="dbUser"
              :placeholder="dbType === 'postgres' ? 'postgres' : 'root'"
              class="text-sm"
            />
          </div>
          <div class="space-y-1.5">
            <Label>Password <span class="text-muted-foreground text-xs">(optional)</span></Label>
            <Input v-model="dbPassword" type="password" placeholder="leave empty if none" class="text-sm" />
          </div>
        </div>

        <div class="space-y-1.5">
          <Label>
            {{ isRedis ? 'Command' : 'Query' }}
            <span class="text-muted-foreground text-xs ml-1">
              — {{ isRedis ? 'one command per run' : 'SQL, Ctrl+Enter to run' }}
            </span>
          </Label>
          <textarea
            v-model="query"
            :rows="isRedis ? 3 : 6"
            :placeholder="placeholder"
            class="w-full font-mono text-xs bg-background border rounded-lg px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
            spellcheck="false"
            @keydown.ctrl.enter.prevent="run"
          />
        </div>

        <div v-if="output" class="space-y-1.5">
          <Label>Output</Label>
          <pre
            class="text-xs font-mono bg-muted rounded-lg px-4 py-3 max-h-56 overflow-y-auto whitespace-pre-wrap border text-foreground"
            >{{ output }}</pre>
        </div>
      </div>

      <div class="p-4 sm:p-5 pt-0 flex gap-2">
        <Button class="gap-2 flex-1" :disabled="running" @click="run">
          <Loader2 v-if="running" class="h-4 w-4 animate-spin" />
          <Play v-else class="h-4 w-4" />
          {{ running ? 'Running…' : 'Run' }}
        </Button>
        <Button variant="outline" @click="emit('close')">Close</Button>
      </div>
    </div>
  </div>
</template>
