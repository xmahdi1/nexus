<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { toast } from 'vue-sonner'
import { Search, Plus, Trash2, Loader2, Terminal, Package, ExternalLink, Pencil, X, RefreshCw } from '@lucide/vue'
import { api } from '@/lib/api'
import type { AppTemplate, TemplateVar, DeployedApp } from '@/lib/api'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
import Label from '@/components/ui/Label.vue'
import { useConfirm } from '@/composables/useConfirm'

const props  = defineProps<{ serverId: string }>()
const { confirm } = useConfirm()

const VAR_TYPES = ['string', 'password', 'number', 'select']

const isDark      = ref(document.documentElement.classList.contains('dark'))
const templates   = ref<AppTemplate[]>([])
const deployed    = ref<DeployedApp[]>([])
const loading     = ref(true)
const search      = ref('')
const activeCategory = ref('All')

const deploying     = ref(false)
const deployOutput  = ref('')
const deployDone    = ref(false)
const postDeploy    = ref('')
const selectedTpl   = ref<AppTemplate | null>(null)
const deployVars    = ref<Record<string, string>>({})
const deployName    = ref('')

const showCustom      = ref(false)
const editingCustomId = ref<string | null>(null)
const customSaving    = ref(false)
const customForm = ref({
  name: '', icon: '📦', category: '', description: '',
  docUrl: '', postDeploy: '', compose: '',
  vars: [] as TemplateVar[],
})

let themeObserver: MutationObserver | null = null

const categories = computed(() => {
  const cats = new Set(templates.value.map(t => t.category))
  return ['All', ...Array.from(cats).sort()]
})

const filtered = computed(() => {
  let list = templates.value
  if (activeCategory.value !== 'All')
    list = list.filter(t => t.category === activeCategory.value)
  if (search.value)
    list = list.filter(t =>
        t.name.toLowerCase().includes(search.value.toLowerCase()) ||
        t.description.toLowerCase().includes(search.value.toLowerCase()))
  return list
})

function getIcon(tpl: AppTemplate) {
  return isDark.value && tpl.iconLight ? tpl.iconLight : tpl.icon
}

function isUrl(s: string) { return s?.startsWith('/') || s?.startsWith('http') }

function openDeploy(tpl: AppTemplate) {
  selectedTpl.value  = tpl
  deployName.value   = tpl.id
  deployOutput.value = ''
  deployDone.value   = false
  postDeploy.value   = ''
  const vars: Record<string, string> = {}
  for (const v of tpl.vars || []) vars[v.name] = v.default || ''
  deployVars.value = vars
}

function closeDeploy() { selectedTpl.value = null; deployOutput.value = ''; deployDone.value = false }

async function load() {
  try { deployed.value = await api.templates.listDeployed(props.serverId) }
  catch {}
}

async function runDeploy() {
  if (!selectedTpl.value) return
  deploying.value    = true
  deployOutput.value = ''
  try {
    const res = await api.templates.deploy(props.serverId, {
      templateId: selectedTpl.value.id,
      appName:    deployName.value,
      variables:  deployVars.value,
    })
    deployOutput.value = res.output || ''
    postDeploy.value   = res.postDeploy || ''
    deployDone.value   = true
    deployed.value.unshift(res.app)
    toast.success(`${selectedTpl.value.name} deployed!`)
  } catch (e: any) {
    deployOutput.value = e?.output || (e instanceof Error ? e.message : 'Deploy failed')
    deployDone.value   = true
    toast.error('Deploy failed — check output')
  } finally { deploying.value = false }
}

async function removeApp(app: DeployedApp) {
  const ok = await confirm({
    title:       `Remove ${app.name}`,
    message:     'This will run docker compose down -v and delete the app directory. Cannot be undone.',
    confirmText: 'Remove', destructive: true,
  })
  if (!ok) return
  try {
    await api.templates.remove(props.serverId, app.id)
    deployed.value = deployed.value.filter(a => a.id !== app.id)
    toast.success(`${app.name} removed`)
  } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
}

function openCustomCreate() {
  editingCustomId.value = null
  customForm.value = { name: '', icon: '📦', category: '', description: '', docUrl: '', postDeploy: '', compose: '', vars: [] }
  showCustom.value = true
}

function openCustomEdit(tpl: AppTemplate) {
  editingCustomId.value = tpl.id
  customForm.value = {
    name: tpl.name, icon: tpl.icon, category: tpl.category,
    description: tpl.description, docUrl: tpl.docUrl || '',
    postDeploy: tpl.postDeploy || '', compose: (tpl as any).compose || '',
    vars: (tpl.vars || []).map(v => ({ ...v })),
  }
  showCustom.value = true
}

function addVar() {
  customForm.value.vars.push({ name: '', label: '', type: 'string', default: '', required: false, description: '' })
}

function removeVar(i: number) { customForm.value.vars.splice(i, 1) }

async function saveCustom() {
  if (!customForm.value.name || !customForm.value.compose) { toast.error('Name and Compose YAML are required'); return }
  customSaving.value = true
  try {
    if (editingCustomId.value) {
      const updated = await api.templates.updateCustom(editingCustomId.value, customForm.value)
      const idx = templates.value.findIndex(t => t.id === editingCustomId.value)
      if (idx >= 0) templates.value[idx] = { ...updated, builtIn: false }
    } else {
      const created = await api.templates.createCustom(customForm.value)
      templates.value.push({ ...created, builtIn: false, vars: customForm.value.vars })
    }
    showCustom.value = false
    toast.success('Template saved')
  } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
  finally { customSaving.value = false }
}

async function deleteCustom(tpl: AppTemplate) {
  const ok = await confirm({
    title: `Delete template "${tpl.name}"?`,
    message: 'This only removes the template, not any deployed apps.',
    confirmText: 'Delete', destructive: true,
  })
  if (!ok) return
  try {
    await api.templates.deleteCustom(tpl.id)
    templates.value = templates.value.filter(t => t.id !== tpl.id)
    toast.success('Template deleted')
  } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
}

onMounted(async () => {
  themeObserver = new MutationObserver(() => {
    isDark.value = document.documentElement.classList.contains('dark')
  })
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
  try {
    templates.value = await api.templates.list()
    await load()
  } catch { toast.error('Failed to load templates') }
  finally { loading.value = false }
})

onUnmounted(() => themeObserver?.disconnect())
</script>

<template>
  <div class="space-y-6">

    <div class="space-y-3">
      <div class="flex items-center justify-between">
        <h2 class="text-sm font-medium text-muted-foreground uppercase tracking-wide">App Marketplace</h2>
        <Button variant="outline" class="gap-1.5 text-xs sm:text-sm" @click="openCustomCreate">
          <Plus class="h-3.5 w-3.5" />Custom template
        </Button>
      </div>
      <div class="relative">
        <Search class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input v-model="search" class="pl-9" placeholder="Search templates…" />
      </div>
      <div class="flex items-center gap-2 flex-wrap pb-1">
        <button v-for="cat in categories" :key="cat"
                :class="['px-3 py-1.5 rounded-lg text-xs font-medium transition-colors shrink-0',
            activeCategory === cat ? 'bg-primary text-primary-foreground' : 'bg-muted hover:bg-muted/80 text-muted-foreground']"
                @click="activeCategory = cat">
          {{ cat }}
        </button>
      </div>
    </div>

    <div v-if="loading" class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
      <div v-for="i in 8" :key="i" class="h-28 rounded-xl bg-muted animate-pulse" />
    </div>

    <div v-else class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
      <div v-for="tpl in filtered" :key="tpl.id"
           class="group relative bg-card border rounded-xl p-3 sm:p-4 cursor-pointer
               hover:border-primary/50 hover:shadow-md transition-all duration-200 space-y-3"
           @click="openDeploy(tpl)">

        <div v-if="!tpl.builtIn" class="absolute top-2 right-2 hidden group-hover:flex gap-1 z-10" @click.stop>
          <button class="h-6 w-6 rounded bg-background/80 backdrop-blur flex items-center justify-center hover:bg-muted"
                  @click="openCustomEdit(tpl)">
            <Pencil class="h-3 w-3" />
          </button>
          <button class="h-6 w-6 rounded bg-background/80 backdrop-blur flex items-center justify-center hover:bg-destructive/10 text-destructive"
                  @click="deleteCustom(tpl)">
            <Trash2 class="h-3 w-3" />
          </button>
        </div>

        <div class="h-9 w-9 sm:h-10 sm:w-10">
          <img v-if="isUrl(getIcon(tpl))" :src="getIcon(tpl)" :alt="tpl.name"
               class="h-full w-full rounded-xl object-contain"
               @error="($event.target as HTMLImageElement).style.opacity = '0'" />
          <span v-else class="text-2xl sm:text-3xl leading-none">{{ tpl.icon }}</span>
        </div>

        <div>
          <p class="font-semibold text-xs sm:text-sm leading-tight">{{ tpl.name }}</p>
          <p class="text-xs text-muted-foreground mt-0.5 line-clamp-2">{{ tpl.description }}</p>
        </div>
        <div class="flex items-center justify-between">
          <span class="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-medium">{{ tpl.category }}</span>
          <span v-if="!tpl.builtIn" class="text-[10px] text-primary font-medium">custom</span>
        </div>
      </div>

      <div v-if="!filtered.length" class="col-span-full text-center py-12 text-muted-foreground text-sm">
        No templates found
      </div>
    </div>

    <div v-if="deployed.length" class="space-y-3">
      <div class="flex items-center gap-2">
        <h3 class="text-xs font-semibold uppercase tracking-widest text-muted-foreground">Deployed apps</h3>
        <div class="flex-1 h-px bg-border" />
        <p class="text-[10px] text-muted-foreground hidden sm:block">Status reflects last deploy — check Containers tab for live state</p>
        <Button size="sm" variant="ghost" class="h-6 gap-1 text-xs" @click="load">
          <RefreshCw class="h-3 w-3" />Sync
        </Button>
      </div>
      <div class="border rounded-xl overflow-hidden">
        <table class="w-full text-sm">
          <thead>
          <tr class="border-b bg-muted/40">
            <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">App</th>
            <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide hidden sm:table-cell">Path</th>
            <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">Status</th>
            <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide hidden sm:table-cell">Deployed</th>
            <th class="text-right px-4 py-2.5 w-12" />
          </tr>
          </thead>
          <tbody>
          <tr v-for="app in deployed" :key="app.id" class="border-b last:border-0 hover:bg-muted/10 transition-colors">
            <td class="px-4 py-3 font-medium text-sm">{{ app.name }}</td>
            <td class="px-4 py-3 font-mono text-xs text-muted-foreground hidden sm:table-cell">{{ app.composePath }}</td>
            <td class="px-4 py-3">
                <span :class="['text-xs font-medium px-2 py-0.5 rounded-full',
                  app.status === 'running' ? 'bg-green-500/10 text-green-600' :
                  app.status === 'failed'  ? 'bg-red-500/10 text-red-600' :
                  'bg-muted text-muted-foreground']">
                  {{ app.status }}
                </span>
            </td>
            <td class="px-4 py-3 text-xs text-muted-foreground hidden sm:table-cell">
              {{ new Date(app.deployedAt).toLocaleDateString() }}
            </td>
            <td class="px-4 py-3 text-right">
              <Button size="icon" variant="ghost" class="h-7 w-7 text-destructive hover:text-destructive" @click="removeApp(app)">
                <Trash2 class="h-3.5 w-3.5" />
              </Button>
            </td>
          </tr>
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <Transition enter-active-class="transition-opacity duration-150" enter-from-class="opacity-0"
              leave-active-class="transition-opacity duration-100" leave-to-class="opacity-0">
    <div v-if="selectedTpl" class="fixed inset-0 z-[200] flex items-end sm:items-center justify-center sm:p-4">
      <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" @click="!deploying && closeDeploy()" />
      <div class="relative z-10 w-full sm:max-w-lg bg-card border sm:rounded-2xl rounded-t-2xl shadow-2xl flex flex-col max-h-[92vh]">

        <div class="flex items-center gap-3 p-4 sm:p-6 border-b">
          <div class="h-10 w-10 shrink-0">
            <img v-if="isUrl(getIcon(selectedTpl))" :src="getIcon(selectedTpl)" :alt="selectedTpl.name"
                 class="h-10 w-10 rounded-xl object-contain" />
            <span v-else class="text-3xl">{{ selectedTpl.icon }}</span>
          </div>
          <div class="flex-1 min-w-0">
            <p class="font-semibold">Deploy {{ selectedTpl.name }}</p>
            <p class="text-xs text-muted-foreground truncate">{{ selectedTpl.description }}</p>
          </div>
          <a v-if="selectedTpl.docUrl" :href="selectedTpl.docUrl" target="_blank" rel="noopener"
             class="text-muted-foreground hover:text-foreground" @click.stop>
            <ExternalLink class="h-4 w-4" />
          </a>
          <button class="text-muted-foreground hover:text-foreground" :disabled="deploying" @click="closeDeploy()">
            <X class="h-4 w-4" />
          </button>
        </div>

        <div v-if="!deployDone" class="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
          <div class="space-y-1.5">
            <Label>App name <span class="text-muted-foreground text-xs">(directory name)</span></Label>
            <Input v-model="deployName" class="font-mono text-sm" placeholder="my-app" />
          </div>
          <template v-if="selectedTpl.vars?.length">
            <div v-for="v in selectedTpl.vars" :key="v.name" class="space-y-1.5">
              <Label>{{ v.label }}<span v-if="v.required" class="text-destructive ml-0.5">*</span></Label>
              <select v-if="v.type === 'select'" v-model="deployVars[v.name]"
                      class="w-full h-9 px-3 rounded-md border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/50">
                <option v-for="opt in v.options" :key="opt" :value="opt">{{ opt }}</option>
              </select>
              <Input v-else v-model="deployVars[v.name]"
                     :type="v.type === 'password' ? 'password' : v.type === 'number' ? 'number' : 'text'"
                     :placeholder="v.default || v.label"
                     :class="['text-sm', v.type === 'password' || v.type === 'number' ? 'font-mono' : '']" />
              <p v-if="v.description" class="text-xs text-muted-foreground">{{ v.description }}</p>
            </div>
          </template>
        </div>

        <div v-if="deployOutput" class="mx-4 sm:mx-6 mt-4 space-y-1.5">
          <div class="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
            <Terminal class="h-3.5 w-3.5" />Output
          </div>
          <pre class="text-xs font-mono bg-muted rounded-lg px-4 py-3 max-h-40 overflow-y-auto whitespace-pre-wrap">{{ deployOutput }}</pre>
        </div>

        <div v-if="postDeploy && deployDone"
             class="mx-4 sm:mx-6 mt-3 bg-green-500/10 border border-green-500/20 rounded-lg px-4 py-3 text-xs text-green-700 dark:text-green-400">
          {{ postDeploy }}
        </div>

        <div class="p-4 sm:p-6 pt-4 flex gap-2">
          <template v-if="!deployDone">
            <Button class="flex-1 gap-2" :disabled="deploying" @click="runDeploy">
              <Loader2 v-if="deploying" class="h-4 w-4 animate-spin" />
              <Package v-else class="h-4 w-4" />
              {{ deploying ? 'Deploying…' : 'Deploy' }}
            </Button>
            <Button variant="outline" :disabled="deploying" @click="closeDeploy">Cancel</Button>
          </template>
          <Button v-else class="flex-1" @click="closeDeploy">Close</Button>
        </div>
      </div>
    </div>
  </Transition>

  <Transition enter-active-class="transition-opacity duration-150" enter-from-class="opacity-0"
              leave-active-class="transition-opacity duration-100" leave-to-class="opacity-0">
    <div v-if="showCustom" class="fixed inset-0 z-[200] flex items-end sm:items-center justify-center sm:p-4">
      <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" @click="showCustom = false" />
      <div class="relative z-10 w-full sm:max-w-2xl bg-card border sm:rounded-2xl rounded-t-2xl shadow-2xl flex flex-col max-h-[92vh]">
        <div class="flex items-center justify-between p-4 sm:p-6 border-b">
          <h3 class="font-semibold">{{ editingCustomId ? 'Edit template' : 'Create custom template' }}</h3>
          <button class="text-muted-foreground hover:text-foreground" @click="showCustom = false">
            <X class="h-4 w-4" />
          </button>
        </div>

        <div class="flex-1 overflow-y-auto p-4 sm:p-6 space-y-4">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div class="space-y-1.5 sm:col-span-2">
              <Label>Name</Label>
              <Input v-model="customForm.name" placeholder="My App" />
            </div>
            <div class="space-y-1.5">
              <Label>Icon (emoji or /app-logos/... path)</Label>
              <Input v-model="customForm.icon" placeholder="📦 or /app-logos/myapp.png" />
            </div>
            <div class="space-y-1.5">
              <Label>Category</Label>
              <Input v-model="customForm.category" placeholder="Databases" />
            </div>
            <div class="space-y-1.5 sm:col-span-2">
              <Label>Description</Label>
              <Input v-model="customForm.description" placeholder="Short description" />
            </div>
            <div class="space-y-1.5">
              <Label>Docs URL (optional)</Label>
              <Input v-model="customForm.docUrl" placeholder="https://…" />
            </div>
            <div class="space-y-1.5">
              <Label>Post-deploy message (optional)</Label>
              <Input v-model="customForm.postDeploy" placeholder="Open http://… to finish setup" />
            </div>
          </div>

          <div class="space-y-2">
            <div class="flex items-center justify-between">
              <Label>Variables <span class="text-muted-foreground text-xs">— use ${VAR_NAME} in compose</span></Label>
              <Button size="sm" variant="outline" class="gap-1 h-7 text-xs" @click="addVar">
                <Plus class="h-3 w-3" />Add variable
              </Button>
            </div>
            <div v-for="(v, i) in customForm.vars" :key="i" class="grid grid-cols-12 gap-2 p-3 bg-muted/30 rounded-lg">
              <div class="col-span-6 sm:col-span-3">
                <Input v-model="v.name" placeholder="VAR_NAME" class="font-mono text-xs h-8" />
                <p class="text-[10px] text-muted-foreground mt-0.5">Key</p>
              </div>
              <div class="col-span-6 sm:col-span-3">
                <Input v-model="v.label" placeholder="Label" class="text-xs h-8" />
                <p class="text-[10px] text-muted-foreground mt-0.5">Label</p>
              </div>
              <div class="col-span-4 sm:col-span-2">
                <select v-model="v.type" class="w-full h-8 px-2 rounded-md border bg-background text-xs focus:outline-none">
                  <option v-for="t in VAR_TYPES" :key="t" :value="t">{{ t }}</option>
                </select>
                <p class="text-[10px] text-muted-foreground mt-0.5">Type</p>
              </div>
              <div class="col-span-4 sm:col-span-2">
                <Input v-model="v.default" placeholder="default" class="text-xs h-8" />
                <p class="text-[10px] text-muted-foreground mt-0.5">Default</p>
              </div>
              <div class="col-span-2 sm:col-span-1 flex items-start pt-1 justify-center">
                <label class="flex flex-col items-center gap-0.5 cursor-pointer">
                  <input type="checkbox" v-model="v.required" class="rounded" />
                  <span class="text-[10px] text-muted-foreground">Req.</span>
                </label>
              </div>
              <div class="col-span-2 sm:col-span-1 flex items-start pt-1 justify-end">
                <button class="text-destructive hover:text-destructive/80" @click="removeVar(i)">
                  <X class="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>

          <div class="space-y-1.5">
            <Label>docker-compose.yml <span class="text-muted-foreground text-xs">— use ${VAR_NAME} for variables</span></Label>
            <textarea v-model="customForm.compose"
                      class="w-full h-56 font-mono text-xs bg-background border rounded-lg px-3 py-2.5
                     focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
                      placeholder="services:
  myapp:
    image: myapp:latest
    ports:
      - &quot;${PORT}:8080&quot;"
                      spellcheck="false" />
          </div>
        </div>

        <div class="p-4 sm:p-6 pt-0 flex gap-2">
          <Button class="flex-1 gap-2" :disabled="customSaving" @click="saveCustom">
            <Loader2 v-if="customSaving" class="h-4 w-4 animate-spin" />
            {{ editingCustomId ? 'Save changes' : 'Create template' }}
          </Button>
          <Button variant="outline" @click="showCustom = false">Cancel</Button>
        </div>
      </div>
    </div>
  </Transition>
</template>