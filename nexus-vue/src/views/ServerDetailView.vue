<script setup lang="ts">
import {verifySession, can as socketCan} from '@/lib/auth'
import {can} from '@/lib/auth'
import VaultTab from '@/components/VaultTab.vue'
import InventoryTab from '@/components/InventoryTab.vue'
import {nextTick, onMounted, onUnmounted, ref, watch} from 'vue'
import {useRoute, useRouter} from 'vue-router'
import {useI18n} from 'vue-i18n'
import {toast} from 'vue-sonner'
import {
  ArrowLeft, BarChart3, Bell, BellOff, ChevronDown, ChevronLeft, ChevronUp,
  Container as ContainerIcon, Copy, Database, FileCode, FolderOpen, FolderOpen as FolderOpenIcon,
  Globe, Loader2, Package, Play, Plus, RefreshCw, RotateCcw, ScrollText, ShieldCheck, Square,
  Terminal as TerminalIcon, Trash2, Upload, X, Clock, Timer,
} from '@lucide/vue'
import {Terminal} from '@xterm/xterm'
import {FitAddon} from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import {api} from '@/lib/api'
import type {Container} from '@/lib/api'
import {useServersStore} from '@/stores/servers'
import {useConfirm} from '@/composables/useConfirm'
import AppLayout from '@/components/AppLayout.vue'
import Button from '@/components/ui/Button.vue'
import LogsPanel from '@/components/LogsPanel.vue'
import TagEditor from '@/components/TagEditor.vue'
import FilesTab from '@/components/FilesTab.vue'
import MetricsTab from '@/components/MetricsTab.vue'
import ProxyTab from '@/components/ProxyTab.vue'
import AppsTab from '@/components/AppsTab.vue'
import CronTab from '@/components/CronTab.vue'
import ScheduledTasksTab from '@/components/ScheduledTasksTab.vue'
import FirewallTab from '@/components/FirewallTab.vue'
import DbExecModal from '@/components/DbExecModal.vue'

const route = useRoute()
const router = useRouter()
const {t} = useI18n()
const store = useServersStore()
const {confirm} = useConfirm()
const serverId = route.params.id as string

interface TermSession {
  id: string
  term: Terminal | null;
  fitAddon: FitAddon | null;
  inputSubscription?:{dispose():void}
  resizeSubscription?:{dispose():void}
  connectEpoch?:number
  ws: WebSocket | null
  dead: boolean;
  themeObs: MutationObserver | null;
  ro: ResizeObserver | null
}

const tabs = [
  {key:'vault',label:'Vault',icon:ShieldCheck},
  {key:'inventory',label:'Inventory',icon:BarChart3},
  {key: 'terminal', label: t('server.tabs.terminal'), icon: TerminalIcon},
  {key: 'containers', label: t('server.tabs.containers'), icon: ContainerIcon},
  {key: 'compose', label: t('server.tabs.compose'), icon: FileCode},
  {key: 'metrics', label: t('server.tabs.metrics'), icon: BarChart3},
  {key: 'files', label: 'Files', icon: FolderOpenIcon},
  {key: 'proxy', label: 'Proxy', icon: Globe},
  {key: 'apps', label: 'Apps', icon: Package},
  {key: 'cron', label: 'Cron', icon: Clock},
  {key: 'tasks', label: 'Tasks', icon: Timer},
  {key: 'firewall', label: 'Firewall', icon: ShieldCheck},
] as const

const tabPermissions: Record<string,string[]> = {vault:['integrations.manage','servers.read'],inventory:['inventory.read'],terminal:['servers.terminal','servers.execute'],containers:['docker.read'],compose:['compose.read'],metrics:['metrics.read'],files:['files.list'],proxy:['proxy.read','proxy.manage'],apps:['deployments.read','templates.read'],cron:['jobs.read','logs.read'],tasks:['jobs.read','logs.read'],firewall:['firewall.read','network.read']}
const inventoryEnabled=ref(false)
const vaultEnabled=ref(false)
const visibleTabs = tabs.filter(tab => tabPermissions[tab.key]!.every(permission => can(permission,serverId)))
const activeTab = ref<'vault' | 'inventory' | 'terminal' | 'containers' | 'compose' | 'metrics' | 'files' | 'proxy' | 'apps' | 'cron' | 'tasks' | 'firewall'>(visibleTabs.find(tab=>tab.key!=='inventory' && tab.key!=='vault')?.key ?? 'containers')
const server = ref(store.list.find(s => s.id === serverId))
const tagSaving = ref(false)
const monitoredContainerIds = ref<Set<string>>(new Set())

const termSessions = ref<TermSession[]>([])
const activeTermId = ref<string>('')
const termDivs = ref<Record<string, HTMLDivElement | null>>({})
let sessionCounter = 0

const containers = ref<Container[]>([])
const containersLoading = ref(false)
const containersError = ref('')
const actionLoading = ref<Record<string, boolean>>({})
const expandedContainerId = ref<string | null>(null)
const logsOpen = ref(false)
const logsContainer = ref<Container | null>(null)
const dbExecContainer = ref<Container | null>(null)

const composePath = ref('/root/docker-compose.yml')
const composeContent = ref('')
const composeLoading = ref(false)
const composeSaving = ref(false)
const composeOutput = ref('')
const composeOutputVisible = ref(false)
const composeActing = ref<'up' | 'down' | null>(null)

const proxyPrefillTarget = ref('')
const proxyPrefillDomain = ref('')

const termButtons = [
  {label: '↑', seq: '\x1b[A'},
  {label: '↓', seq: '\x1b[B'},
  {label: '←', seq: '\x1b[D'},
  {label: '→', seq: '\x1b[C'},
  {label: 'Tab', seq: '\t'},
  {label: 'Esc', seq: '\x1b'},
  {label: 'Ctrl+C', seq: '\x03'},
  {label: 'Ctrl+D', seq: '\x04'},
  {label: 'Ctrl+Z', seq: '\x1a'},
  {label: 'Ctrl+L', seq: '\x0c'},
  {label: 'Ctrl+A', seq: '\x01'},
  {label: 'Ctrl+E', seq: '\x05'},
  {label: 'Ctrl+W', seq: '\x17'},
  {label: 'Ctrl+K', seq: '\x0b'},
  {label: 'Ctrl+O', seq: '\x0f'},
  {label: 'Ctrl+X', seq: '\x18'},
  {label: 'Ctrl+R', seq: '\x12'},
]

function sendToActiveTerm(data: string) {
  const s = termSessions.value.find(s => s.id === activeTermId.value)
  if (s?.ws?.readyState === WebSocket.OPEN) {
    s.ws.send(JSON.stringify({type: 'input', data}))
  }
}

function isDark() {
  return document.documentElement.classList.contains('dark')
}

function termTheme(dark: boolean) {
  if (dark) return {
    background: '#0d1117', foreground: '#e6edf3', cursor: '#58a6ff',
    selectionBackground: '#264f78', black: '#484f58', red: '#ff7b72',
    green: '#3fb950', yellow: '#d29922', blue: '#58a6ff',
    magenta: '#bc8cff', cyan: '#39c5cf', white: '#b1bac4'
  }
  return {
    background: '#ffffff', foreground: '#24292f', cursor: '#0969da',
    selectionBackground: '#0969da26', black: '#24292f', red: '#cf222e',
    green: '#116329', yellow: '#9a6700', blue: '#0969da',
    magenta: '#8250df', cyan: '#1b7c83', white: '#6e7781'
  }
}

function genSessionId() {
  return `term_${++sessionCounter}`
}

function initFirstSession() {
  const id = genSessionId()
  termSessions.value.push({id, term: null, fitAddon: null, ws: null, dead: false, themeObs: null, ro: null})
  activeTermId.value = id
  nextTick(() => mountSession(id))
}

async function addTermSession() {
  const id = genSessionId()
  termSessions.value.push({id, term: null, fitAddon: null, ws: null, dead: false, themeObs: null, ro: null})
  activeTermId.value = id
  await nextTick()
  mountSession(id)
}

function mountSession(id: string) {
  const session = termSessions.value.find(s => s.id === id)
  const el = termDivs.value[id]
  if (!session || !el) return
  const term = new Terminal({
    cursorBlink: true, fontSize: 13, scrollback: 5000,
    fontFamily: '"JetBrains Mono","Fira Code",Menlo,Consolas,monospace',
    theme: termTheme(isDark()),
  })
  const fitAddon = new FitAddon()
  term.loadAddon(fitAddon)
  term.open(el)
  const viewport = el.querySelector('.xterm-viewport') as HTMLElement | null
  if (viewport) {
    let touchY = 0
    viewport.addEventListener('touchstart', e => {
      touchY = e.touches[0].clientY
    }, {passive: true})
    viewport.addEventListener('touchmove', e => {
      viewport.scrollTop += touchY - e.touches[0].clientY
      touchY = e.touches[0].clientY
      e.preventDefault()
    }, {passive: false})
  }
  term.attachCustomKeyEventHandler((e: KeyboardEvent) => {
    if (e.type === 'keydown' && e.ctrlKey && e.key === 'c' && !e.shiftKey) {
      const sel = term.getSelection()
      if (sel) {
        navigator.clipboard.writeText(sel).catch(() => {
        });
        return false
      }
    }
    return true
  })
  const themeObs = new MutationObserver(() => {
    if (term) term.options.theme = termTheme(isDark())
  })
  themeObs.observe(document.documentElement, {attributes: true, attributeFilter: ['class']})
  const ro = new ResizeObserver(() => requestAnimationFrame(() => fitAddon.fit()))
  ro.observe(el)
  requestAnimationFrame(() => {
    fitAddon.fit();
    openSessionWS(session, term, fitAddon)
  })
  session.term = term;
  session.fitAddon = fitAddon;
  session.themeObs = themeObs;
  session.ro = ro
}

function dropSocket(session:TermSession){
 session.connectEpoch=(session.connectEpoch??0)+1
 session.inputSubscription?.dispose();session.resizeSubscription?.dispose()
 const socket=session.ws
 if(socket){socket.onopen=null;socket.onclose=null;socket.onerror=null;socket.onmessage=null;socket.close()}
 session.ws=null
}

async function openSessionWS(session: TermSession, term: Terminal, fitAddon: FitAddon) {
  const epoch=session.connectEpoch=(session.connectEpoch??0)+1
  if (!await verifySession() || !socketCan('servers.terminal',serverId) || !socketCan('servers.execute',serverId) || !termSessions.value.includes(session) || session.term !== term || session.connectEpoch!==epoch) {session.dead=true; return}
  const socket = new WebSocket(api.ws.terminal(serverId))
  session.ws = socket
  socket.binaryType = 'arraybuffer'
  let started = false
  socket.onopen = () => {
    started = true;
    socket.send(JSON.stringify({type: 'resize', cols: term.cols, rows: term.rows}))
  }
  socket.onmessage = (e) => term.write(e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : e.data)
  socket.onclose = () => {
    if (socket !== session.ws) return
    session.dead=true
    if (!started) {
      term.write('\r\n\x1b[31m[connection failed]\x1b[0m\r\n');
      return
    }
    term.write('\r\n\x1b[2m[session ended]\x1b[0m\r\n')
    session.dead = true
  }
  socket.onerror = () => {
    if (socket !== session.ws || started) return;
    term.write('\r\n\x1b[31m[connection error]\x1b[0m\r\n')
  }
  session.inputSubscription?.dispose()
  session.inputSubscription=term.onData(d => socket.readyState === WebSocket.OPEN && socket.send(JSON.stringify({type: 'input', data: d})))
  session.resizeSubscription?.dispose()
  session.resizeSubscription=term.onResize(({cols, rows}) => socket.readyState === WebSocket.OPEN && socket.send(JSON.stringify({
    type: 'resize',
    cols,
    rows
  })))
}

async function switchTermSession(id: string) {
  activeTermId.value = id
  await nextTick()
  const s = termSessions.value.find(s => s.id === id)
  if (s?.fitAddon) requestAnimationFrame(() => s.fitAddon!.fit())
}

function closeTermSession(id: string) {
  const s = termSessions.value.find(s => s.id === id)
  if (s) {
    s.themeObs?.disconnect();
    s.ro?.disconnect();
    dropSocket(s);
    s.term?.dispose()
  }
  termSessions.value = termSessions.value.filter(s => s.id !== id)
  delete termDivs.value[id]
  if (activeTermId.value === id && termSessions.value.length > 0) {
    switchTermSession(termSessions.value[termSessions.value.length - 1].id)
  }
}

function reconnectSession(session: TermSession) {
  session.dead = false;
  session.term?.clear();
  dropSocket(session)
  openSessionWS(session, session.term!, session.fitAddon!)
}

function destroyAllSessions() {
  for (const s of termSessions.value) {
    s.themeObs?.disconnect();
    s.ro?.disconnect();
    dropSocket(s);
    s.term?.dispose()
  }
  termSessions.value = []
}

function copyTerminal() {
  const s = termSessions.value.find(s => s.id === activeTermId.value)
  if (!s?.term) return
  const sel = s.term.getSelection()
  if (sel) {
    navigator.clipboard.writeText(sel).catch(() => {
    })
    return
  }
  s.term.selectAll()
  navigator.clipboard.writeText(s.term.getSelection()).catch(() => {
  })
  setTimeout(() => s.term?.clearSelection(), 400)
}

async function saveTags(tags: string) {
  if (!server.value) return
  tagSaving.value = true
  try {
    await store.updateTags(server.value.id, tags)
    if (server.value) server.value.tags = tags
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to save tags')
  } finally {
    tagSaving.value = false
  }
}

function getDbType(image: string) {
  const i = image.toLowerCase()
  if (i.includes('postgres')) return 'postgres'
  if (i.includes('mariadb') || i.includes('mysql')) return 'mysql'
  if (i.includes('redis')) return 'redis'
  if (i.includes('mongo')) return 'mongo'
  return null
}

function stateColor(s: string) {
  return s === 'running' ? 'text-green-500' : s === 'paused' ? 'text-yellow-500' : 'text-muted-foreground'
}

function openLogs(c: Container) {
  logsContainer.value = c;
  logsOpen.value = true
}

function exposeContainer(c: Container) {
  const match = c.ports?.match(/\d+\.\d+\.\d+\.\d+:(\d+)->/)
  proxyPrefillTarget.value = match ? `localhost:${match[1]}` : ''
  proxyPrefillDomain.value = ''
  activeTab.value = 'proxy'
}

async function fetchContainers() {
  containersLoading.value = true
  containersError.value = ''
  try {
    containers.value = await api.containers.list(serverId)
    const monitored = await api.monitor.listMonitored(serverId)
    monitoredContainerIds.value = new Set(monitored.map(m => m.name))
  } catch (e) {
    containersError.value = e instanceof Error ? e.message : 'Failed to load containers'
  } finally {
    containersLoading.value = false
  }
}

async function containerAction(cid: string, action: 'start' | 'stop' | 'restart' | 'remove', label: string) {
  if (['stop','restart','remove'].includes(action)) {
    const ok = await confirm({
      title: `${label} container`,
      message: `${label} "${containers.value.find(c => c.id === cid)?.name || cid}" on ${server.value?.name || serverId}? ${action === 'remove' ? 'Writable container data is deleted; named volumes are retained.' : 'This can interrupt services.'} Inspect uncertain prior operations before retrying.`,
      confirmText: label, destructive: true,
    })
    if (!ok) return
  }
  actionLoading.value[cid] = true
  try {
    await api.containers[action](serverId, cid);
    toast.success(`${label} — done`);
    await fetchContainers()
  } catch (e) {
    toast.error(e instanceof Error ? e.message : `${label} failed`)
  } finally {
    actionLoading.value[cid] = false
  }
}

async function toggleMonitor(c: Container) {
  const isMonitored = monitoredContainerIds.value.has(c.name)
  try {
    if (isMonitored) {
      await api.monitor.removeMonitored(serverId, c.name)
      monitoredContainerIds.value.delete(c.name)
      toast.success(`Stopped monitoring ${c.name || c.id}`)
    } else {
      await api.monitor.addMonitored(serverId, c.id, c.name || c.id)
      monitoredContainerIds.value.add(c.name)
      toast.success(`Now monitoring ${c.name || c.id}`)
    }
    monitoredContainerIds.value = new Set(monitoredContainerIds.value)
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed')
  }
}

async function loadCompose() {
  composeLoading.value = true;
  composeOutput.value = ''
  try {
    const res = await api.compose.read(serverId, composePath.value);
    composeContent.value = res.content;
    toast.success('File loaded')
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to load file')
  } finally {
    composeLoading.value = false
  }
}

async function saveCompose() {
  if (!can('compose.write',serverId)) return
  if(!await confirm({title:'Replace Compose recipe?',message:`Replace ${composePath.value} on ${server.value?.name || serverId}? Save a recovery copy before changing a live deployment.`,confirmText:'Save recipe',destructive:true}))return
  composeSaving.value = true
  try {
    await api.compose.write(serverId, composePath.value, composeContent.value);
    toast.success('File saved')
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to save file')
  } finally {
    composeSaving.value = false
  }
}

async function composeUp() {
  if(!can('deployments.execute',serverId))return
  if(!await confirm({title:'Apply Compose deployment?',message:`Apply the saved recipe ${composePath.value} on ${server.value?.name || serverId}? Services may be recreated. Unsaved edits are not deployed. Inspect an uncertain prior result before retrying.`,confirmText:'Apply',destructive:true}))return
  composeActing.value = 'up'
  try {
    const res = await api.compose.up(serverId, composePath.value);
    composeOutput.value = (res as any).output ?? '';
    composeOutputVisible.value = true;
    toast.success('docker compose up — done')
  } catch (e) {
    composeOutput.value = e instanceof Error ? e.message : 'Failed';
    composeOutputVisible.value = true;
    toast.error('docker compose up failed')
  } finally {
    composeActing.value = null
  }
}

async function composeDown() {
  if(!can('deployments.execute',serverId))return
  if(!await confirm({title:'Stop Compose deployment?',message:`Stop and remove containers for ${composePath.value} on ${server.value?.name || serverId}? Named volumes and recipe files are retained.`,confirmText:'Stop deployment',destructive:true}))return
  composeActing.value = 'down'
  try {
    const res = await api.compose.down(serverId, composePath.value);
    composeOutput.value = (res as any).output ?? '';
    composeOutputVisible.value = true;
    toast.success('docker compose down — done')
  } catch (e) {
    composeOutput.value = e instanceof Error ? e.message : 'Failed';
    composeOutputVisible.value = true;
    toast.error('docker compose down failed')
  } finally {
    composeActing.value = null
  }
}

onMounted(async () => {
  try{const features=await api.features();inventoryEnabled.value=features.inventory;vaultEnabled.value=features.vault}catch{}
  if (!server.value) {
    try {
      const s = await api.servers.get(serverId)
      server.value = {...s, status: 'unknown', os: '—', uptime: '—'}
    } catch {
      toast.error('Server not found')
    }
  }
  if (can('servers.terminal',serverId) && can('servers.execute',serverId)) nextTick(() => initFirstSession())
  if (activeTab.value === 'containers') fetchContainers()
})

onUnmounted(() => destroyAllSessions())

watch(activeTab, tab => {
  if (tab === 'terminal') nextTick(() => {
    const s = termSessions.value.find(s => s.id === activeTermId.value)
    if (s?.fitAddon) requestAnimationFrame(() => s.fitAddon!.fit())
  })
  if (tab === 'containers') fetchContainers()
})
</script>

<template>
  <AppLayout>
    <div :class="['max-w-7xl mx-auto', activeTab === 'terminal' ? 'space-y-2 sm:space-y-6' : 'space-y-6']">

      <div class="flex items-start gap-3">
        <RouterLink to="/servers" class="shrink-0 mt-1">
          <Button size="icon" variant="ghost" class="h-8 w-8">
            <ArrowLeft class="h-4 w-4"/>
          </Button>
        </RouterLink>
        <div class="flex-1 min-w-0">
          <h1 class="text-lg sm:text-2xl font-semibold tracking-tight truncate">{{ server?.name ?? '…' }}</h1>
          <p :class="['text-sm text-muted-foreground font-mono truncate', activeTab === 'terminal' ? 'hidden sm:block' : '']">
            {{ server?.username }}@{{ server?.host }}:{{ server?.port }}</p>
          <div :class="['mt-2', activeTab === 'terminal' ? 'hidden sm:block' : '']">
            <TagEditor v-if="server && can('servers.update',serverId)" :model-value="server.tags ?? ''" :disabled="tagSaving" @save="saveTags"/>
          </div>
        </div>
      </div>

      <div class="flex border-b overflow-x-auto scrollbar-none">
        <div v-if="visibleTabs.some(tab => tab.key === 'terminal')" class="flex items-center shrink-0">
          <button :class="['flex items-center gap-1.5 px-3 sm:px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors',
            activeTab === 'terminal' ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground']"
                  @click="activeTab = 'terminal'">
            <TerminalIcon class="h-4 w-4"/>
            <span class="hidden sm:inline">{{ t('server.tabs.terminal') }}</span>
          </button>

          <template v-if="termSessions.length > 1">
            <div v-for="(s, idx) in termSessions" :key="s.id"
                 :class="['flex items-center gap-1 px-3 py-2.5 text-xs font-medium border-b-2 -mb-px cursor-pointer transition-colors',
                activeTab === 'terminal' && activeTermId === s.id
                  ? 'border-primary text-foreground bg-muted/20'
                  : 'border-transparent text-muted-foreground hover:text-foreground']"
                 @click="activeTab = 'terminal'; switchTermSession(s.id)">
              <span class="h-1.5 w-1.5 rounded-full shrink-0" :class="s.dead ? 'bg-red-500' : 'bg-green-500'"/>
              {{ idx + 1 }}
              <button class="ml-0.5 hover:text-foreground" @click.stop="closeTermSession(s.id)">
                <X class="h-2.5 w-2.5"/>
              </button>
            </div>
          </template>

          <button
              class="flex items-center justify-center h-7 w-7 mb-px text-muted-foreground hover:text-foreground hover:bg-muted rounded transition-colors"
              @click="activeTab = 'terminal'; addTermSession()">
            <Plus class="h-3.5 w-3.5"/>
          </button>
        </div>

        <button v-for="tab in visibleTabs.filter(t => t.key !== 'terminal' && (t.key !== 'inventory' || inventoryEnabled) && (t.key !== 'vault' || vaultEnabled))" :key="tab.key"
                :class="['flex items-center gap-1.5 px-3 sm:px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors shrink-0',
            activeTab === tab.key ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground']"
                @click="activeTab = tab.key">
          <component :is="tab.icon" class="h-4 w-4"/>
          <span class="hidden sm:inline">{{ tab.label }}</span>
        </button>
      </div>

      <div v-show="activeTab === 'terminal'">
        <div v-for="s in termSessions" :key="s.id">
          <div v-show="activeTermId === s.id">
            <div v-show="!s.dead"
                 class="h-[calc(100dvh-210px)] min-h-[220px] sm:h-[62dvh] sm:min-h-[300px] sm:max-h-[580px] rounded-xl border overflow-hidden"
                 :style="{ background: isDark() ? '#0d1117' : '#ffffff', borderColor: isDark() ? '#30363d' : '#d0d7de' }">
              <div :ref="(el) => { if (el) termDivs[s.id] = el as HTMLDivElement }"
                   class="h-full w-full p-2"
                   :style="{ background: isDark() ? '#0d1117' : '#ffffff' }"/>
            </div>
            <div v-if="s.dead"
                 class="h-[calc(100dvh-210px)] min-h-[220px] sm:h-[62dvh] sm:min-h-[300px] sm:max-h-[580px] rounded-xl border flex flex-col items-center justify-center gap-4"
                 :style="{ background: isDark() ? '#0d1117' : '#f6f8fa', borderColor: isDark() ? '#30363d' : '#d0d7de' }">
              <p class="text-sm" :class="isDark() ? 'text-white/50' : 'text-muted-foreground'">Session ended</p>
              <div class="flex flex-col sm:flex-row gap-3">
                <Button variant="outline"
                        :class="isDark() ? 'gap-2 bg-transparent border-white/20 text-white hover:bg-white/10 hover:text-white' : 'gap-2'"
                        @click="router.push('/servers')">
                  <ChevronLeft class="h-4 w-4"/>
                  Back to servers
                </Button>
                <Button class="gap-2" @click="reconnectSession(s)">
                  <RefreshCw class="h-4 w-4"/>
                  Reconnect
                </Button>
              </div>
            </div>
            <div v-if="!s.dead"
                 class="sm:hidden flex items-center gap-1 px-2 py-1.5 border border-t-0 rounded-b-xl overflow-x-auto"
                 :style="{ background: isDark() ? '#161b22' : '#f6f8fa', borderColor: isDark() ? '#30363d' : '#d0d7de' }">
              <button v-for="btn in termButtons" :key="btn.label"
                      class="px-2.5 py-1 rounded text-xs font-mono font-medium shrink-0 select-none active:opacity-60 transition-opacity"
                      :style="{ background: isDark() ? '#21262d' : '#eaeef2', color: isDark() ? '#e6edf3' : '#24292f' }"
                      @click="sendToActiveTerm(btn.seq)">
                {{ btn.label }}
              </button>
              <div class="w-px h-4 mx-1 shrink-0" :style="{ background: isDark() ? '#30363d' : '#d0d7de' }"/>
              <button
                  class="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium shrink-0 select-none active:opacity-60 transition-opacity"
                  :style="{ background: isDark() ? '#21262d' : '#eaeef2', color: isDark() ? '#e6edf3' : '#24292f' }"
                  @click="copyTerminal">
                <Copy class="h-3 w-3"/>
                Copy
              </button>
            </div>
          </div>
        </div>
      </div>

      <VaultTab v-if="vaultEnabled && activeTab==='vault'" :server-id="serverId"/>
      <InventoryTab v-if="inventoryEnabled && activeTab==='inventory'" :server-id="serverId"/>
      <div v-if="activeTab === 'containers'" class="space-y-4">
        <div class="flex items-center justify-between">
          <h2 class="text-sm font-medium">Containers</h2>
          <Button size="sm" variant="outline" class="gap-1.5" :disabled="containersLoading" @click="fetchContainers">
            <Loader2 v-if="containersLoading" class="h-3.5 w-3.5 animate-spin"/>
            <RotateCcw v-else class="h-3.5 w-3.5"/>
            Refresh
          </Button>
        </div>
        <div v-if="containersError" class="text-sm text-destructive bg-destructive/10 rounded-lg px-4 py-3">
          {{ containersError }}
        </div>
        <div v-if="containersLoading && !containers.length" class="grid gap-2">
          <div v-for="i in 4" :key="i" class="h-12 rounded-lg bg-muted animate-pulse"/>
        </div>
        <div v-else-if="!containers.length && !containersLoading"
             class="text-center py-12 text-muted-foreground text-sm">
          No containers found. Is Docker running on this server?
        </div>
        <div v-else class="containers-scroll border rounded-xl overflow-hidden">
          <table class="w-full text-sm">
            <thead class="sticky top-0 z-10 bg-card">
            <tr class="border-b bg-muted/40">
              <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">Name
              </th>
              <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide hidden sm:table-cell">
                Image
              </th>
              <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">
                Status
              </th>
              <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide hidden md:table-cell">
                Ports
              </th>
              <th class="w-10"/>
            </tr>
            </thead>
            <tbody>
            <template v-for="c in containers" :key="c.id">
              <tr class="border-b hover:bg-muted/20 transition-colors cursor-pointer"
                  :class="expandedContainerId === c.id ? 'bg-muted/10' : ''"
                  @click="expandedContainerId = expandedContainerId === c.id ? null : c.id">
                <td class="px-4 py-3 font-medium max-w-0 w-full truncate">{{ c.name || c.id }}</td>
                <td class="px-4 py-3 font-mono text-xs text-muted-foreground max-w-[160px] truncate hidden sm:table-cell">
                  {{ c.image }}
                </td>
                <td class="px-4 py-3"><span
                    :class="['text-xs font-medium whitespace-nowrap', stateColor((c as any).state)]">● {{
                    c.status
                  }}</span></td>
                <td class="px-4 py-3 font-mono text-xs text-muted-foreground hidden md:table-cell">{{
                    c.ports || '—'
                  }}
                </td>
                <td class="px-4 py-3 text-right">
                  <Button size="icon" variant="ghost" class="h-7 w-7"
                          @click.stop="expandedContainerId = expandedContainerId === c.id ? null : c.id">
                    <ChevronDown v-if="expandedContainerId !== c.id" class="h-3.5 w-3.5"/>
                    <ChevronUp v-else class="h-3.5 w-3.5"/>
                  </Button>
                </td>
              </tr>
              <tr v-if="expandedContainerId === c.id" class="border-b bg-muted/5">
                <td colspan="5" class="px-4 py-3">
                  <div class="flex flex-wrap items-center gap-2">
                    <Button v-if="getDbType(c.image) && can('docker.exec',serverId)" size="sm" variant="outline"
                            class="gap-1.5 h-7 text-xs text-violet-500" @click="dbExecContainer = c">
                      <Database class="h-3.5 w-3.5"/>
                      DB Query
                    </Button>
                    <Button v-if="can('settings.manage',serverId)" size="sm" variant="outline" class="gap-1.5 h-7 text-xs"
                            :class="monitoredContainerIds.has(c.name) ? 'text-primary' : ''" @click="toggleMonitor(c)">
                      <Bell v-if="monitoredContainerIds.has(c.id)" class="h-3.5 w-3.5"/>
                      <BellOff v-else class="h-3.5 w-3.5"/>
                      {{ monitoredContainerIds.has(c.id) ? 'Unmonitor' : 'Monitor' }}
                    </Button>
                    <Button v-if="can('logs.read',serverId)" size="sm" variant="outline" class="gap-1.5 h-7 text-xs" @click="openLogs(c)">
                      <ScrollText class="h-3.5 w-3.5"/>
                      Logs
                    </Button>
                    <Button v-if="can('proxy.manage',serverId)" size="sm" variant="outline" class="gap-1.5 h-7 text-xs text-blue-600"
                            @click="exposeContainer(c)">
                      <Globe class="h-3.5 w-3.5"/>
                      Expose
                    </Button>
                    <Button v-if="(c as any).state !== 'running' && can('docker.manage',serverId)" size="sm" variant="outline"
                            class="gap-1.5 h-7 text-xs text-green-600" :disabled="actionLoading[c.id]"
                            @click="containerAction(c.id, 'start', 'Start')">
                      <Play class="h-3.5 w-3.5"/>
                      Start
                    </Button>
                    <Button v-if="(c as any).state === 'running' && can('docker.manage',serverId)" size="sm" variant="outline"
                            class="gap-1.5 h-7 text-xs text-yellow-600" :disabled="actionLoading[c.id]"
                            @click="containerAction(c.id, 'stop', 'Stop')">
                      <Square class="h-3.5 w-3.5"/>
                      Stop
                    </Button>
                    <Button v-if="can('docker.manage',serverId)" size="sm" variant="outline" class="gap-1.5 h-7 text-xs" :disabled="actionLoading[c.id]"
                            @click="containerAction(c.id, 'restart', 'Restart')">
                      <RotateCcw class="h-3.5 w-3.5"/>
                      Restart
                    </Button>
                    <Button v-if="can('docker.remove',serverId)" size="sm" variant="outline"
                            class="gap-1.5 h-7 text-xs text-destructive border-destructive/30"
                            :disabled="actionLoading[c.id]" @click="containerAction(c.id, 'remove', 'Remove')">
                      <Trash2 class="h-3.5 w-3.5"/>
                      Remove
                    </Button>
                  </div>
                </td>
              </tr>
            </template>
            </tbody>
          </table>
        </div>
      </div>

      <div v-if="activeTab === 'compose'" class="space-y-4">
        <div class="flex gap-2 flex-wrap sm:flex-nowrap">
          <div class="relative flex-1 min-w-0">
            <FolderOpen class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground"/>
            <input v-model="composePath"
                   class="w-full h-9 pl-9 pr-3 rounded-md border bg-background text-sm font-mono focus:outline-none focus:ring-2 focus:ring-primary/50"
                   placeholder="/root/docker-compose.yml" @keydown.enter="loadCompose"/>
          </div>
          <Button variant="outline" class="gap-1.5 shrink-0" :disabled="composeLoading" @click="loadCompose">
            <Loader2 v-if="composeLoading" class="h-3.5 w-3.5 animate-spin"/>
            <FolderOpen v-else class="h-3.5 w-3.5"/>
            Load
          </Button>
        </div>
        <div class="border rounded-xl overflow-hidden">
          <div class="flex items-center justify-between px-3 py-2 border-b bg-muted/30 flex-wrap gap-2">
            <span class="text-xs text-muted-foreground font-mono truncate">{{ composePath }}</span>
            <div class="flex items-center gap-2 shrink-0">
              <Button v-if="can('deployments.execute',serverId)" size="sm" variant="outline"
                      class="gap-1.5 h-7 text-xs text-green-600 border-green-600/30 hover:bg-green-600/10"
                      :disabled="!composeContent || composeActing !== null" @click="composeUp">
                <Loader2 v-if="composeActing === 'up'" class="h-3 w-3 animate-spin"/>
                <ChevronUp v-else class="h-3 w-3"/>
                up -d
              </Button>
              <Button v-if="can('deployments.execute',serverId)" size="sm" variant="outline"
                      class="gap-1.5 h-7 text-xs text-yellow-600 border-yellow-600/30 hover:bg-yellow-600/10"
                      :disabled="!composeContent || composeActing !== null" @click="composeDown">
                <Loader2 v-if="composeActing === 'down'" class="h-3 w-3 animate-spin"/>
                <ChevronDown v-else class="h-3 w-3"/>
                down
              </Button>
              <Button v-if="can('compose.write',serverId)" size="sm" class="gap-1.5 h-7 text-xs" :disabled="!composeContent || composeSaving"
                      @click="saveCompose">
                <Loader2 v-if="composeSaving" class="h-3 w-3 animate-spin"/>
                <Upload v-else class="h-3 w-3"/>
                Save
              </Button>
            </div>
          </div>
          <textarea v-model="composeContent" :readonly="!can('compose.write',serverId)"
                    class="compose-editor w-full font-mono text-sm bg-card text-foreground px-4 py-3 resize-none focus:outline-none"
                    placeholder="Load a docker-compose.yml file to edit it…" spellcheck="false"/>
        </div>
        <div v-if="composeOutputVisible && composeOutput" class="border rounded-xl overflow-hidden">
          <div class="flex items-center justify-between px-3 py-2 border-b bg-muted/30">
            <span class="text-xs font-medium">Command output</span>
            <button class="text-xs text-muted-foreground hover:text-foreground" @click="composeOutputVisible = false">
              dismiss
            </button>
          </div>
          <pre class="px-4 py-3 text-xs font-mono text-foreground whitespace-pre-wrap max-h-48 overflow-y-auto">{{
              composeOutput
            }}</pre>
        </div>
      </div>

      <div v-if="activeTab === 'metrics'">
        <MetricsTab :server-id="serverId"/>
      </div>
      <div v-if="activeTab === 'files'">
        <FilesTab :server-id="serverId"/>
      </div>
      <div v-if="activeTab === 'proxy'">
        <ProxyTab :server-id="serverId" :prefill-target="proxyPrefillTarget" :prefill-domain="proxyPrefillDomain"
                  @prefill-consumed="proxyPrefillTarget = ''; proxyPrefillDomain = ''"/>
      </div>
      <div v-if="activeTab === 'apps'">
        <AppsTab :server-id="serverId"/>
      </div>
      <div v-if="activeTab === 'cron'">
        <CronTab :server-id="serverId"/>
      </div>
      <div v-if="activeTab === 'tasks'">
        <ScheduledTasksTab :server-id="serverId"/>
      </div>
      <div v-if="activeTab === 'firewall'">
        <FirewallTab :server-id="serverId"/>
      </div>

    </div>

    <LogsPanel v-if="logsContainer" v-model:open="logsOpen" :server-id="serverId"
               :container-id="logsContainer.id" :container-name="logsContainer.name || logsContainer.id"/>
    <DbExecModal v-if="dbExecContainer" :server-id="serverId" :container="dbExecContainer"
                 @close="dbExecContainer = null"/>
  </AppLayout>
</template>

<style scoped>
.containers-scroll {
  overflow: hidden;
}

.compose-editor {
  min-height: 420px;
  max-height: calc(100vh - 320px);
}
</style>