<script setup lang="ts">
import { ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { toast } from 'vue-sonner';
import { Copy, KeyRound, Loader2 } from '@lucide/vue';
import { api } from '@/lib/api';
import Dialog from './ui/Dialog.vue';
import Button from './ui/Button.vue';
import Input from './ui/Input.vue';
import Label from './ui/Label.vue';
import Textarea from './ui/Textarea.vue';

defineProps<{ open: boolean }>();
const emit = defineEmits<{
  'update:open': [boolean];
  save: [
    { name: string; host: string; port: number; username: string; publicKey: string; privateKey: string },
  ];
}>();

const { t } = useI18n();

const form = ref({ name: '', host: '', port: '22', username: 'root' });
const pubKey = ref('');
const privKey = ref('');
const generatingKey = ref(false);

async function generateKey() {
  generatingKey.value = true;
  try {
    const kp = await api.keys.generate();
    pubKey.value = kp.publicKey;
    privKey.value = kp.privateKey;
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to generate key');
  } finally {
    generatingKey.value = false;
  }
}

function handleSave() {
  if (!form.value.name || !form.value.host) {
    toast.error('Name and host are required');
    return;
  }
  if (!privKey.value) {
    toast.error('Generate a key pair first');
    return;
  }
  emit('save', {
    name: form.value.name,
    host: form.value.host,
    port: parseInt(form.value.port) || 22,
    username: form.value.username,
    publicKey: pubKey.value,
    privateKey: privKey.value,
  });
  form.value = { name: '', host: '', port: '22', username: 'root' };
  pubKey.value = '';
  privKey.value = '';
  emit('update:open', false);
}

async function copyKey() {
  await navigator.clipboard.writeText(pubKey.value);
  toast.success(t('servers.copied'));
}
</script>

<template>
  <Dialog :open="open" @update:open="$emit('update:open', $event)">
    <div class="p-4 sm:p-6">
      <h2 class="text-lg font-semibold mb-4">{{ t('servers.add') }}</h2>

      <div class="grid gap-4">
        <div class="grid gap-2">
          <Label for="n">{{ t('servers.displayName') }}</Label>
          <Input id="n" v-model="form.name" placeholder="prod-web-01" />
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div class="sm:col-span-2 grid gap-2">
            <Label for="h">{{ t('servers.host') }}</Label>
            <Input id="h" v-model="form.host" placeholder="10.0.0.1" />
          </div>
          <div class="grid gap-2">
            <Label for="p">{{ t('servers.port') }}</Label>
            <Input id="p" v-model="form.port" />
          </div>
        </div>

        <div class="grid gap-2">
          <Label for="u">{{ t('servers.username') }}</Label>
          <Input id="u" v-model="form.username" />
        </div>

        <Button
          variant="outline"
          type="button"
          class="gap-2 w-full sm:w-auto"
          :disabled="generatingKey"
          @click="generateKey"
        >
          <Loader2 v-if="generatingKey" class="h-4 w-4 animate-spin" />
          <KeyRound v-else class="h-4 w-4" />
          {{ generatingKey ? 'Generating…' : t('servers.generateKey') }}
        </Button>

        <div v-if="pubKey" class="grid gap-2">
          <div class="flex items-center justify-between">
            <Label>{{ t('servers.publicKey') }}</Label>
            <Button size="sm" variant="ghost" class="h-7 gap-1" @click="copyKey">
              <Copy class="h-3 w-3" />
            </Button>
          </div>
          <Textarea :model-value="pubKey" :read-only="true" class="font-mono text-xs h-20" />
          <p class="text-xs text-muted-foreground">
            Add this to <code class="font-mono">~/.ssh/authorized_keys</code> on your server.
          </p>
        </div>
      </div>

      <div class="flex flex-col-reverse sm:flex-row sm:justify-end gap-2 mt-6">
        <Button variant="ghost" class="w-full sm:w-auto" @click="$emit('update:open', false)">
          {{ t('servers.cancel') }}
        </Button>
        <Button :disabled="!pubKey" class="w-full sm:w-auto" @click="handleSave">
          {{ t('servers.save') }}
        </Button>
      </div>
    </div>
  </Dialog>
</template>
