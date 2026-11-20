<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { toast } from 'vue-sonner'
import { api, type VaultProfile, type VaultObservation } from '@/lib/api'
import { can } from '@/lib/auth'
import { useConfirm } from '@/composables/useConfirm'
import VaultAccess from '@/components/VaultAccess.vue'
import VaultAdmin from '@/components/VaultAdmin.vue'
import VaultKV from '@/components/VaultKV.vue'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'

const props = defineProps<{ serverId: string }>()
const { confirm } = useConfirm()
const defaults = (): VaultProfile => ({ port: 8200, tlsName: '', caPem: '', namespace: '' })
const profile = ref<VaultProfile>(defaults())
const configured = ref(false)
const connectionEpoch = ref(0)
const busy = ref(false)
const token = ref('')
const error = ref('')
const observation = ref<VaultObservation | null>(null)
const kvMounts = computed(() => observation.value?.mountsStatus === 'ok' ? observation.value.mounts.filter(m => m.type === 'kv' && m.version === '2').map(m => m.path) : [])
let generation = 0
let alive = true

function current(version: number, server: string) {
  return alive && version === generation && server === props.serverId
}
function clear() {
  generation++
  token.value = ''
  observation.value = null
  error.value = ''
  configured.value = false
  profile.value = defaults()
}
onUnmounted(() => { alive = false; clear() })
watch(() => props.serverId, () => { clear(); void load() })
onMounted(load)

async function load() {
  const version = ++generation
  const server = props.serverId
  try {
    const result = await api.vault.read(server)
    if (current(version, server)) {
      configured.value = result.configured
      if (result.profile) profile.value = result.profile
    }
  } catch (cause) {
    if (current(version, server)) error.value = cause instanceof Error ? cause.message : 'Could not load Vault settings'
  }
}
async function save() {
  if (busy.value) return
  const server = props.serverId
  const version = generation
  busy.value = true
  try {
    await api.vault.save(server, profile.value)
    if (current(version, server)) {
      configured.value = true
      observation.value = null
      error.value = ''
      connectionEpoch.value++
      toast.success('Vault connection saved')
    }
  } catch (cause) {
    if (current(version, server)) error.value = cause instanceof Error ? cause.message : 'Could not save Vault settings'
  } finally {
    busy.value = false
  }
}
async function inspect() {
  if (busy.value) return
  const server = props.serverId
  const version = generation
  let supplied = token.value
  token.value = ''
  busy.value = true
  error.value = ''
  observation.value = null
  try {
    const result = await api.vault.inspect(server, supplied)
    if (current(version, server)) observation.value = result
  } catch (cause) {
    if (current(version, server)) error.value = cause instanceof Error ? cause.message : 'Vault inspection failed'
  } finally {
    supplied = ''
    busy.value = false
  }
}
async function remove() {
  const server = props.serverId
  const version = generation
  const accepted = await confirm({
    title: 'Remove Vault connection?',
    message: 'Remove Nexus connection settings? Vault storage and services will remain on the managed host.',
    confirmText: 'Remove connection',
    destructive: true,
  })
  if (!accepted || !current(version, server) || busy.value) return
  busy.value = true
  try {
    await api.vault.remove(server)
    if (current(version, server)) clear()
  } catch (cause) {
    if (current(version, server)) error.value = cause instanceof Error ? cause.message : 'Could not remove connection'
  } finally {
    busy.value = false
  }
}
</script>

<template>
 <section class="space-y-4" aria-label="Vault management">
  <div><h2 class="text-lg font-semibold">HashiCorp Vault</h2><p class="text-sm text-muted-foreground">Manage secrets, access, identities, tokens, leases, certificates, transit keys and auditing. Vault stays on the managed host’s loopback interface; Nexus verifies SSH and TLS.</p></div>
  <p v-if="error" role="alert" class="text-destructive">{{error}}</p>
  <form class="space-y-3 border rounded-lg p-4" @submit.prevent="save">
   <label class="block text-sm">Loopback HTTPS port<Input v-model.number="profile.port" type="number" min="1024" max="65535" :disabled="busy" /></label>
   <label class="block text-sm">TLS certificate DNS name<Input v-model="profile.tlsName" placeholder="vault.internal" :disabled="busy" /></label>
   <label class="block text-sm">CA certificate (PEM)<textarea v-model="profile.caPem" class="block w-full rounded border bg-background p-2 font-mono text-xs" rows="5" :disabled="busy" placeholder="Leave blank to use system trust. Never paste a private key here." /></label>
   <p class="text-xs text-muted-foreground">Management uses the root namespace. Enterprise namespaces are unavailable. Connection settings contain no Vault token. Existing settings apply until you save changes.</p>
   <div class="flex gap-2"><Button type="submit" :disabled="busy">Save connection</Button><Button v-if="configured" type="button" variant="outline" :disabled="busy" @click="remove">Remove connection</Button></div>
  </form>
  <div v-if="configured" class="border rounded-lg p-4 space-y-3">
   <label class="block text-sm">Short-lived Vault token (optional for health)<Input v-model="token" type="password" autocomplete="off" placeholder="Non-root token, at most 24 hours remaining" :disabled="busy" /></label>
   <p class="text-xs text-muted-foreground">Used for this request and cleared on submission. Nexus does not save the token. Engine inventory requires permission to read sys/mounts and lookup your own token.</p>
   <Button :disabled="busy || !can('servers.connect',serverId) || !can('secrets.use',serverId)" @click="inspect">{{busy?'Working…':'Inspect Vault'}}</Button>
  </div>
  <div v-if="observation" role="status" class="space-y-3">
   <p>Initialized: {{observation.health.initialized?'Yes':'No'}} · Sealed: {{observation.health.sealed?'Yes':'No'}} · Standby: {{observation.health.standby?'Yes':'No'}} · HTTP {{observation.health.status}}</p>
   <p v-if="observation.mountsStatus==='token_required'">Supply a short-lived token to inspect secrets engines.</p>
   <p v-else-if="observation.mountsStatus==='permission_denied'">Vault denied inventory access. Check the token’s permissions or expiry.</p>
   <p v-else-if="observation.mountsStatus==='unavailable'">Initialize and unseal Vault through your operator procedure before inspecting engines.</p>
   <table v-else class="w-full text-sm"><thead><tr><th class="text-left">Mount</th><th class="text-left">Type</th><th class="text-left">Description</th></tr></thead><tbody><tr v-for="mount in observation.mounts" :key="mount.path"><td>{{mount.path}}</td><td>{{mount.type}} {{mount.version}}</td><td>{{mount.description}}</td></tr></tbody></table>
  </div>
  <VaultAccess v-if="configured" :key="connectionEpoch" :server-id="serverId" />
  <VaultAdmin v-if="configured" :key="connectionEpoch" :server-id="serverId" />
  <VaultKV v-if="kvMounts.length" :server-id="serverId" :mounts="kvMounts" />
 </section>
</template>
