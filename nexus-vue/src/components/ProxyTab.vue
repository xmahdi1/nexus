<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import {
  Globe, Plus, Trash2, ShieldCheck, ShieldOff,
  Loader2, RefreshCw, ExternalLink, AlertTriangle, Pencil, Terminal,
} from '@lucide/vue'
import { api } from '@/lib/api'
import type { ProxyRule } from '@/lib/api'
import { useConfirm } from '@/composables/useConfirm'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
import Label from '@/components/ui/Label.vue'

const props = defineProps<{ serverId: string; prefillTarget?: string; prefillDomain?: string }>()
const emit  = defineEmits<{ prefillConsumed: [] }>()
const { confirm } = useConfirm()

const rules      = ref<ProxyRule[]>([])
const proxyType  = ref<'nginx' | 'caddy' | 'none' | ''>('')
const detecting  = ref(false)
const loading    = ref(false)
const showForm   = ref(false)
const editingId  = ref<string | null>(null)
const saving     = ref(false)
const formError  = ref('')
const form       = ref({ domain: props.prefillDomain ?? '', target: props.prefillTarget ?? '', proxyType: '' as 'nginx' | 'caddy', ssl: false })

const sslRule     = ref<ProxyRule | null>(null)
const sslEmail    = ref('')
const sslWild     = ref(false)
const sslCFToken  = ref('')
const sslLoading  = ref(false)
const sslOutput   = ref('')
const sslDone     = ref(false)
const sslWarning = ref('')

function isIP(s: string) { return /^\d+\.\d+\.\d+\.\d+$/.test(s) }

async function detect() {
  detecting.value = true
  try {
    const res = await api.proxy.detect(props.serverId)
    proxyType.value = res.proxyType as any
    if (res.proxyType !== 'none') form.value.proxyType = res.proxyType as any
  } catch { toast.error('Detection failed') }
  finally { detecting.value = false }
}

async function loadRules() {
  loading.value = true
  try { rules.value = await api.proxy.list(props.serverId) }
  catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
  finally { loading.value = false }
}

function openCreate() {
  editingId.value = null
  form.value      = { domain: props.prefillDomain ?? '', target: props.prefillTarget ?? '', proxyType: proxyType.value as any, ssl: false }
  formError.value = ''
  showForm.value  = true
}

function openEdit(rule: ProxyRule) {
  editingId.value = rule.id
  form.value      = { domain: rule.domain, target: rule.target, proxyType: rule.proxyType, ssl: rule.sslEnabled }
  formError.value = ''
  showForm.value  = true
}

function closeForm() { showForm.value = false; editingId.value = null; formError.value = '' }

async function saveRule() {
  formError.value = ''
  if (!form.value.domain || !form.value.target || !form.value.proxyType) {
    formError.value = 'Domain, target and proxy type are required'; return
  }
  if(editingId.value&&!await confirm({title:'Change proxy route?',message:`Change ${form.value.domain} to ${form.value.target} on ${props.serverId}? This may interrupt requests through the existing route.`,confirmText:'Update route',destructive:true}))return

  saving.value = true
  try {
    if (editingId.value) {
      const updated = await api.proxy.update(props.serverId, editingId.value,
          { domain: form.value.domain, target: form.value.target, proxyType: form.value.proxyType, ssl: form.value.ssl })
      const idx = rules.value.findIndex(r => r.id === editingId.value)
      if (idx >= 0) rules.value[idx] = updated
      if(form.value.ssl && !updated.sslEnabled)toast.warning('Route updated, but certificate setup failed. Inspect the route before retrying certificate issuance.')
      else toast.success('Rule updated')
    } else {
      const rule = await api.proxy.create(props.serverId,
          { domain: form.value.domain, target: form.value.target, proxyType: form.value.proxyType, ssl: form.value.ssl })
      rules.value.unshift(rule)
      if(form.value.ssl && !rule.sslEnabled)toast.warning(`${rule.domain} created, but certificate setup failed. Inspect the route before retrying.`)
      else toast.success(`${rule.domain} created`)
    }
    closeForm()
  } catch (e) { formError.value = e instanceof Error ? e.message : 'Failed' }
  finally { saving.value = false }
}

async function deleteRule(rule: ProxyRule) {
  const ok = await confirm({
    title:       'Remove proxy rule',
    message:     `Remove ${rule.domain} → ${rule.target}? The config will be deleted from the server.`,
    confirmText: 'Remove', destructive: true,
  })
  if (!ok) return
  try {
    await api.proxy.delete(props.serverId, rule.id)
    rules.value = rules.value.filter(r => r.id !== rule.id)
    toast.success('Rule removed')
  } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
}

function openSSL(rule: ProxyRule) {
  if (rule.proxyType === 'caddy') { toast.success('Caddy handles SSL automatically'); return }
  sslRule.value    = rule
  sslEmail.value   = ''
  sslWild.value    = false
  sslCFToken.value = ''
  sslOutput.value  = ''
  sslDone.value    = false
  sslWarning.value = ''
}

function closeSSL() { sslRule.value = null; sslOutput.value = ''; sslDone.value = false; sslCFToken.value = ''; sslWarning.value = '' }

async function submitSSL() {
  if (!sslRule.value) return
  if (sslWild.value && !sslCFToken.value) { toast.error('Cloudflare API token required for wildcard'); return }
  if (sslRule.value.sslEnabled && !await confirm({ title: 'Renew certificate?', message: 'This requests a new certificate and counts toward the certificate authority’s rate limits.', confirmText: 'Renew' })) return
  if (!sslRule.value) return
  sslLoading.value = true; sslOutput.value = ''; sslDone.value = false; sslWarning.value = ''
  try {
    const res = await api.proxy.enableSSL(props.serverId, sslRule.value.id,
        { email: sslEmail.value, wildcard: sslWild.value, cfToken: sslCFToken.value, renew: sslRule.value.sslEnabled })
    const idx = rules.value.findIndex(r => r.id === res.rule.id)
    if (idx >= 0) rules.value[idx] = res.rule
    sslOutput.value = res.output || ''
    sslDone.value   = true
    sslWarning.value = res.warning || ''
    toast.success('SSL certificate issued')
    if (res.warning) toast.warning(res.warning, { duration: 15000 })
  } catch (e: any) {
    sslOutput.value = e?.output || (e instanceof Error ? e.message : 'Certbot failed')
    toast.error('SSL failed — check output below')
    sslDone.value = true
  } finally { sslLoading.value = false; sslCFToken.value = '' }
}

onMounted(async () => {
  await detect(); await loadRules()
  if (props.prefillTarget) { openCreate(); emit('prefillConsumed') }
})
</script>

<template>
  <div class="space-y-4">

    <div class="flex flex-wrap items-center justify-between gap-3 bg-card border rounded-xl px-4 py-3">
      <div class="flex items-center gap-3">
        <div v-if="detecting" class="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 class="h-4 w-4 animate-spin" />Detecting proxy…
        </div>
        <template v-else>
          <div :class="['h-2 w-2 rounded-full', proxyType === 'nginx' || proxyType === 'caddy' ? 'bg-green-500' : 'bg-muted-foreground/40']" />
          <span class="text-sm font-medium capitalize">
            {{ proxyType === 'none' || !proxyType ? 'No proxy detected' : proxyType + ' detected' }}
          </span>
          <span v-if="proxyType === 'none'" class="text-xs text-muted-foreground hidden sm:inline">— install nginx or Caddy</span>
        </template>
      </div>
      <div class="flex items-center gap-2">
        <Button size="sm" variant="outline" class="gap-1.5 h-7 text-xs" :disabled="detecting" @click="detect">
          <RefreshCw class="h-3 w-3" />Re-detect
        </Button>
        <Button size="sm" class="gap-1.5 h-7 text-xs" :disabled="proxyType === 'none' || !proxyType || detecting"
                @click="showForm && editingId === null ? closeForm() : openCreate()">
          <Plus class="h-3.5 w-3.5" />Add rule
        </Button>
      </div>
    </div>

    <div v-if="showForm" class="bg-card border rounded-xl p-4 sm:p-5 space-y-4">
      <h3 class="text-sm font-semibold">{{ editingId ? 'Edit proxy rule' : 'New reverse proxy rule' }}</h3>
      <div class="grid sm:grid-cols-2 gap-3">
        <div class="space-y-1.5">
          <Label>Domain</Label>
          <Input v-model="form.domain" placeholder="app.yourdomain.com" class="font-mono text-sm" />
          <p class="text-xs text-muted-foreground">
            Must point to this server's IP via DNS
            <span class="text-yellow-600 font-medium">· ports 80 and 443 must be open</span>
          </p>
        </div>
        <div class="space-y-1.5">
          <Label>Target (host:port)</Label>
          <Input v-model="form.target" placeholder="localhost:3000" class="font-mono text-sm" />
          <p class="text-xs text-muted-foreground">Where to forward traffic to</p>
        </div>
      </div>
      <div class="flex flex-wrap items-center gap-4 sm:gap-6">
        <div class="flex items-center gap-2 text-sm">
          <span class="text-muted-foreground">Proxy:</span>
          <button v-for="t in ['nginx', 'caddy']" :key="t"
                  :class="['px-3 py-1 rounded-md text-xs font-medium border transition-colors',
              form.proxyType === t ? 'bg-primary text-primary-foreground border-primary' : 'border hover:bg-muted']"
                  @click="form.proxyType = t as any">{{ t }}</button>
        </div>
        <label class="flex items-center gap-2 text-sm cursor-pointer select-none">
          <input type="checkbox" v-model="form.ssl" :disabled="isIP(form.domain)" class="rounded" />
          <span>Enable SSL</span>
          <span v-if="form.proxyType === 'caddy'" class="text-xs text-green-600">— automatic with Caddy</span>
          <span v-else-if="isIP(form.domain)" class="text-xs text-yellow-600">— not available for IPs</span>
        </label>
      </div>
      <p v-if="formError" class="text-sm text-destructive">{{ formError }}</p>
      <div class="flex flex-col-reverse sm:flex-row gap-2">
        <Button variant="outline" class="sm:w-auto" @click="closeForm">Cancel</Button>
        <Button class="gap-2 sm:w-auto" :disabled="saving" @click="saveRule">
          <Loader2 v-if="saving" class="h-4 w-4 animate-spin" />
          <Globe v-else class="h-4 w-4" />
          {{ editingId ? 'Save changes' : 'Create rule' }}
        </Button>
      </div>
    </div>

    <div v-if="loading" class="grid gap-2">
      <div v-for="i in 3" :key="i" class="h-14 rounded-xl bg-muted animate-pulse" />
    </div>

    <div v-else-if="!rules.length && !showForm"
         class="text-center py-12 text-muted-foreground text-sm border rounded-xl">
      <Globe class="h-8 w-8 mx-auto mb-2 opacity-40" />
      No proxy rules yet — add one to expose a service publicly
    </div>

    <div v-else-if="rules.length" class="border rounded-xl overflow-x-auto">
      <table class="w-full text-sm min-w-[480px]">
        <thead class="sticky top-0 z-10 bg-card">
        <tr class="border-b bg-muted/40">
          <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">Domain</th>
          <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide hidden sm:table-cell">Target</th>
          <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">Proxy</th>
          <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">SSL</th>
          <th class="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">Actions</th>
        </tr>
        </thead>
        <tbody>
        <tr v-for="rule in rules" :key="rule.id"
            :class="['border-b last:border-0 hover:bg-muted/10 transition-colors', editingId === rule.id ? 'bg-primary/5' : '']">
          <td class="px-4 py-3">
            <a :href="`${rule.sslEnabled ? 'https' : 'http'}://${rule.domain}`" target="_blank" rel="noopener"
               class="font-medium hover:text-primary transition-colors flex items-center gap-1 w-fit">
              {{ rule.domain }}<ExternalLink class="h-3 w-3 opacity-50" />
            </a>
          </td>
          <td class="px-4 py-3 font-mono text-xs text-muted-foreground hidden sm:table-cell">{{ rule.target }}</td>
          <td class="px-4 py-3">
            <span class="text-xs font-medium px-2 py-0.5 rounded-md bg-muted capitalize">{{ rule.proxyType }}</span>
          </td>
          <td class="px-4 py-3">
            <div class="flex items-center gap-1.5">
              <ShieldCheck v-if="rule.sslEnabled" class="h-4 w-4 text-green-500" />
              <ShieldOff v-else class="h-4 w-4 text-muted-foreground/50" />
              <span class="text-xs" :class="rule.sslEnabled ? 'text-green-600' : 'text-muted-foreground'">
                  {{ rule.sslEnabled ? 'HTTPS' : 'HTTP' }}
                </span>
            </div>
          </td>
          <td class="px-4 py-3">
            <div class="flex items-center justify-end gap-1">
              <Button v-if="!rule.sslEnabled || rule.proxyType === 'nginx'" size="sm" variant="ghost"
                      class="h-7 gap-1.5 text-xs text-green-600 hover:text-green-600" @click="openSSL(rule)">
                <ShieldCheck class="h-3.5 w-3.5" />{{ rule.sslEnabled ? 'Renew' : 'SSL' }}
              </Button>
              <Button size="icon" variant="ghost" class="h-7 w-7" @click="openEdit(rule)">
                <Pencil class="h-3.5 w-3.5" />
              </Button>
              <Button size="icon" variant="ghost" class="h-7 w-7 text-destructive hover:text-destructive"
                      @click="deleteRule(rule)">
                <Trash2 class="h-3.5 w-3.5" />
              </Button>
            </div>
          </td>
        </tr>
        </tbody>
      </table>
    </div>

  </div>

  <Transition enter-active-class="transition-opacity duration-150" enter-from-class="opacity-0"
              leave-active-class="transition-opacity duration-100" leave-to-class="opacity-0">
    <div v-if="sslRule" class="fixed inset-0 z-[200] flex items-end sm:items-center justify-center sm:p-4">
      <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" @click="!sslLoading && closeSSL()" />
      <div class="relative z-10 w-full sm:max-w-lg bg-card border sm:rounded-2xl rounded-t-2xl shadow-2xl p-5 sm:p-6 space-y-4">
        <div class="flex items-center gap-3">
          <div class="h-10 w-10 rounded-full bg-green-500/10 text-green-600 flex items-center justify-center shrink-0">
            <ShieldCheck class="h-5 w-5" />
          </div>
          <div>
            <p class="font-semibold text-sm">{{ sslRule.sslEnabled ? 'Renew' : 'Enable' }} SSL for {{ sslRule.domain }}</p>
            <p class="text-xs text-muted-foreground mt-0.5">Certificate via the configured ACME authority and Certbot</p>
          </div>
        </div>

        <template v-if="!sslDone">
          <div class="bg-yellow-500/10 border border-yellow-500/20 rounded-lg px-3 py-2 flex items-start gap-2 text-xs text-yellow-700 dark:text-yellow-400">
            <AlertTriangle class="h-3.5 w-3.5 shrink-0 mt-0.5" />
            {{ sslWild ? 'Use a scoped DNS token for the certificate’s domains. DNS changes must propagate before validation.' : 'Make sure DNS points to this server and port 80 is open. For an existing DNS certificate, select wildcard and supply a fresh token below.' }}
          </div>
          <div class="space-y-1.5">
            <Label>Email for Let's Encrypt notifications</Label>
            <Input v-model="sslEmail" type="email" :placeholder="`admin@${sslRule.domain}`" />
          </div>
          <div class="border rounded-xl p-4 space-y-3">
            <label class="flex items-center justify-between cursor-pointer">
              <div>
                <p class="text-sm font-medium">Wildcard certificate (*.{{ sslRule.domain }})</p>
                <p class="text-xs text-muted-foreground mt-0.5">Covers all subdomains. Requires Cloudflare DNS.</p>
              </div>
              <input type="checkbox" v-model="sslWild" class="rounded" />
            </label>
            <div v-if="sslWild" class="space-y-1.5">
              <Label>Cloudflare API Token</Label>
              <Input v-model="sslCFToken" type="password" placeholder="Token with DNS:Edit permission" class="font-mono text-xs" />
              <p class="text-xs text-muted-foreground">
                Create at dash.cloudflare.com → My Profile → API Tokens → Create Token
              </p>
              <p class="text-xs text-amber-600 dark:text-amber-400">
                Automatic renewal is not configured. The token is removed after issuance.
                Use Renew with a fresh token before expiry, or configure renewal on the server.
              </p>
            </div>
          </div>
          <div class="flex flex-col-reverse sm:flex-row gap-2">
            <Button variant="outline" :disabled="sslLoading" class="sm:w-auto" @click="closeSSL">Cancel</Button>
            <Button class="gap-2 flex-1" :disabled="sslLoading" @click="submitSSL">
              <Loader2 v-if="sslLoading" class="h-4 w-4 animate-spin" />
              <ShieldCheck v-else class="h-4 w-4" />
              {{ sslRule.sslEnabled ? 'Renew certificate' : 'Issue certificate' }}
            </Button>
          </div>
        </template>

        <p v-if="sslWarning" role="alert" class="text-xs text-amber-600 dark:text-amber-400">{{ sslWarning }}</p>
        <div v-if="sslOutput" class="space-y-2">
          <div class="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
            <Terminal class="h-3.5 w-3.5" />Certbot output
          </div>
          <pre class="text-xs font-mono bg-muted rounded-lg px-4 py-3 max-h-56 overflow-y-auto whitespace-pre-wrap">{{ sslOutput }}</pre>
        </div>

        <Button v-if="sslDone" class="w-full" @click="closeSSL">Close</Button>
      </div>
    </div>
  </Transition>
</template>
