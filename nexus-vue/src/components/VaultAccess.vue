<script setup lang="ts">
import { ref, onUnmounted, watch } from 'vue'
import { api, type VaultAccessInput, type VaultAccessResult } from '@/lib/api'
import { can } from '@/lib/auth'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'

const props = defineProps<{ serverId: string }>()
type Action = 'auth' | 'policies' | 'policy' | 'capabilities'
const token = ref('')
const name = ref('')
const paths = ref('')
const error = ref('')
const result = ref<VaultAccessResult | null>(null)
const busy = ref(false)
let alive = true
let generation = 0

function clear() {
  generation++
  token.value = ''
  name.value = ''
  paths.value = ''
  result.value = null
  error.value = ''
}
onUnmounted(() => { alive = false; clear() })
watch(() => props.serverId, clear)
function permitted(action: Action) {
  const extra = action === 'policies' || action === 'policy' ? 'roles.manage' : 'secrets.metadata.read'
  return ['integrations.manage', 'servers.connect', 'secrets.use', extra].every(permission => can(permission, props.serverId))
}
async function inspect(action: Action) {
  if (busy.value || !permitted(action)) return
  if (!token.value) {
    error.value = 'Supply a short-lived Vault token.'
    return
  }
  const input: VaultAccessInput = { token: token.value }
  if (action === 'policy') input.name = name.value
  if (action === 'capabilities') input.paths = paths.value.split(/\r?\n/).map(path => path.trim()).filter(Boolean)
  const server = props.serverId
  const sequence = generation
  token.value = ''
  busy.value = true
  error.value = ''
  result.value = null
  try {
    const value = await api.vault.access(server, action, input)
    if (alive && server === props.serverId && sequence === generation) result.value = value
  } catch (cause) {
    if (alive && sequence === generation) error.value = cause instanceof Error ? cause.message : 'Vault access inspection failed'
  } finally {
    input.token = ''
    busy.value = false
  }
}
function ttl(value: number | undefined) {
  return value === undefined ? 'Unknown' : value === 0 ? 'Inherit default' : value + 's'
}
</script>

<template>
 <section class="border rounded-lg p-4 space-y-3" aria-label="Vault access inspection">
  <h3 class="font-semibold">Authentication and access</h3>
  <p class="text-xs text-muted-foreground">Inspect authentication methods, ACL policies and your token’s path capabilities. Use Vault administration below to make changes.</p>
  <label class="block text-sm">Vault token for access inspection<Input v-model="token" type="password" autocomplete="off" :disabled="busy" /></label>
  <p v-if="error" role="alert" class="text-destructive">{{error}}</p>
  <div class="flex flex-wrap gap-2">
   <Button v-if="permitted('auth')" variant="outline" :disabled="busy" @click="inspect('auth')">Inspect auth methods</Button>
   <Button v-if="permitted('policies')" variant="outline" :disabled="busy" @click="inspect('policies')">List ACL policies</Button>
  </div>
  <div v-if="permitted('policy')" class="space-y-2">
   <label class="block text-sm">ACL policy name<Input v-model="name" placeholder="application-reader" :disabled="busy" /></label>
   <Button variant="outline" :disabled="busy||!name" @click="inspect('policy')">Read ACL policy</Button>
  </div>
  <div v-if="permitted('capabilities')" class="space-y-2">
   <label class="block text-sm">Capability paths (one per line)<textarea v-model="paths" rows="3" class="block w-full rounded border bg-background p-2 font-mono text-xs" :disabled="busy" placeholder="secret/data/application" /></label>
   <Button variant="outline" :disabled="busy||!paths.trim()" @click="inspect('capabilities')">Inspect caller capabilities</Button>
   <p class="text-xs text-muted-foreground">Path-level capabilities are advisory: parameter constraints and other Vault checks may still deny an operation.</p>
  </div>
  <div v-if="result" role="status" class="space-y-3">
   <table v-if="result.methods" class="w-full text-sm"><thead><tr><th class="text-left">Auth path</th><th class="text-left">Type</th><th class="text-left">Description</th><th class="text-left">Default TTL</th><th class="text-left">Maximum TTL</th></tr></thead><tbody><tr v-for="method in result.methods" :key="method.path"><td>{{method.path}}</td><td>{{method.type}}</td><td>{{method.description}}</td><td>{{ttl(method.defaultTTL)}}</td><td>{{ttl(method.maxTTL)}}</td></tr></tbody></table>
   <ul v-if="result.policies" class="text-sm"><li v-for="policy in result.policies" :key="policy"><button type="button" class="underline" @click="name=policy">{{policy}}</button></li></ul>
   <div v-if="result.policy!==undefined"><p class="text-sm">ACL policy: {{result.name}}</p><p v-if="result.redacted" class="text-xs text-muted-foreground">Credential-like content was redacted from this view.</p><pre class="overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-3 text-xs">{{result.policy}}</pre></div>
   <table v-if="result.capabilities" class="w-full text-sm"><thead><tr><th class="text-left">Path</th><th class="text-left">Caller capabilities</th></tr></thead><tbody><tr v-for="(caps,path) in result.capabilities" :key="path"><td>{{path}}</td><td>{{caps.join(', ')}}</td></tr></tbody></table>
  </div>
 </section>
</template>
