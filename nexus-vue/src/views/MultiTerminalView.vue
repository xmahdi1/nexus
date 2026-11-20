<script setup lang="ts">
import {verifySession, can as socketCan} from '@/lib/auth'
import {ref, nextTick, onUnmounted, computed} from 'vue'
import {Plus, X, RefreshCw, Server, Copy} from '@lucide/vue'
import {Terminal} from '@xterm/xterm'
import {FitAddon} from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import {api} from '@/lib/api'
import {useServersStore} from '@/stores/servers'
import AppLayout from '@/components/AppLayout.vue'
import Button from '@/components/ui/Button.vue'

const store = useServersStore()

interface Session {
  id: string
  serverId: string
  serverName: string
  term: Terminal | null
  fitAddon: FitAddon | null
  inputSubscription?:{dispose():void}
  resizeSubscription?:{dispose():void}
  connectEpoch?:number
  ws: WebSocket | null
  dead: boolean
  themeObs: MutationObserver | null
}

const sessions = ref<Session[]>([])
const activeId = ref<string | null>(null)
const showPicker = ref(false)
const termDivs = ref<Record<string, HTMLDivElement | null>>({})

const activeSession = computed(() => sessions.value.find(s => s.id === activeId.value))

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

function sendToActive(data: string) {
  const s = activeSession.value
  if (s?.ws?.readyState === WebSocket.OPEN) {
    s.ws.send(JSON.stringify({type: 'input', data}))
  }
}

function copyOutput() {
  const term = activeSession.value?.term
  if (!term) return
  const sel = term.getSelection()
  if (sel) {
    navigator.clipboard.writeText(sel).catch(() => {
    })
    return
  }
  term.selectAll()
  navigator.clipboard.writeText(term.getSelection()).catch(() => {
  })
  setTimeout(() => term.clearSelection(), 400)
}

function isDark() {
  return document.documentElement.classList.contains('dark')
}

function termTheme(dark: boolean) {
  if (dark) return {background: '#0d1117', foreground: '#e6edf3', cursor: '#58a6ff', selectionBackground: '#264f78'}
  return {background: '#ffffff', foreground: '#24292f', cursor: '#0969da', selectionBackground: '#0969da26'}
}

function genId() {
  return Math.random().toString(36).slice(2, 9)
}

function sessionLabel(session: Session): string {
  const same = sessions.value.filter(s => s.serverId === session.serverId)
  if (same.length <= 1) return session.serverName
  return `${session.serverName} ${same.findIndex(s => s.id === session.id) + 1}`
}

async function addSession(serverId: string) {
  showPicker.value = false
  const server = store.list.find(s => s.id === serverId)
  if (!server) return
  const id = genId()
  const session: Session = {
    id, serverId, serverName: server.name,
    term: null, fitAddon: null, ws: null, dead: false, themeObs: null
  }
  sessions.value.push(session)
  activeId.value = id
  await nextTick()
  initSession(session)
}

function initSession(session: Session) {
  const el = termDivs.value[session.id]
  if (!el) return

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
        })
        return false
      }
    }
    return true
  })

  const themeObs = new MutationObserver(() => {
    term.options.theme = termTheme(isDark())
  })
  themeObs.observe(document.documentElement, {attributes: true, attributeFilter: ['class']})

  const ro = new ResizeObserver(() => requestAnimationFrame(() => fitAddon.fit()))
  ro.observe(el)

  requestAnimationFrame(() => {
    fitAddon.fit();
    openWS(session, term, fitAddon)
  })

  session.term = term
  session.fitAddon = fitAddon
  session.themeObs = themeObs
}

function dropSocket(session:Session){
 session.connectEpoch=(session.connectEpoch??0)+1
 session.inputSubscription?.dispose();session.resizeSubscription?.dispose()
 const socket=session.ws
 if(socket){socket.onopen=null;socket.onclose=null;socket.onerror=null;socket.onmessage=null;socket.close()}
 session.ws=null
}

async function openWS(session: Session, term: Terminal, fitAddon: FitAddon) {
  const epoch=session.connectEpoch=(session.connectEpoch??0)+1
  if (!await verifySession() || !socketCan('servers.terminal',session.serverId) || !socketCan('servers.execute',session.serverId) || !sessions.value.includes(session) || session.term !== term || session.connectEpoch!==epoch) {session.dead=true; return}
  const ws = new WebSocket(api.ws.terminal(session.serverId))
  session.ws = ws
  ws.binaryType = 'arraybuffer'
  let started = false

  ws.onopen = () => {
    started = true
    ws.send(JSON.stringify({type: 'resize', cols: term.cols, rows: term.rows}))
  }
  ws.onmessage = (e) => term.write(e.data instanceof ArrayBuffer ? new Uint8Array(e.data) : e.data)
  ws.onclose = () => {
    if(ws!==session.ws)return
    session.dead=true
    if (!started) {
      term.write('\r\n\x1b[31m[connection failed]\x1b[0m\r\n');
      return
    }
    term.write('\r\n\x1b[2m[session ended]\x1b[0m\r\n')
    session.dead = true
  }
  ws.onerror = () => {
    if(ws!==session.ws)return
    if (!started) term.write('\r\n\x1b[31m[connection error]\x1b[0m\r\n')
  }
  session.inputSubscription?.dispose()
  session.inputSubscription=term.onData(d => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify({type: 'input', data: d})))
  session.resizeSubscription?.dispose()
  session.resizeSubscription=term.onResize(({cols, rows}) => ws.readyState === WebSocket.OPEN && ws.send(JSON.stringify({
    type: 'resize',
    cols,
    rows
  })))
}

function closeSession(id: string) {
  const s = sessions.value.find(s => s.id === id)
  if (s) {
    s.themeObs?.disconnect();
    dropSocket(s);
    s.term?.dispose()
  }
  sessions.value = sessions.value.filter(s => s.id !== id)
  delete termDivs.value[id]
  if (activeId.value === id) activeId.value = sessions.value[sessions.value.length - 1]?.id ?? null
}

function reconnect(session: Session) {
  session.dead = false
  session.term?.clear()
  dropSocket(session)
  openWS(session, session.term!, session.fitAddon!)
}

async function switchTo(id: string) {
  activeId.value = id
  await nextTick()
  const s = sessions.value.find(s => s.id === id)
  if (s?.fitAddon) requestAnimationFrame(() => s.fitAddon!.fit())
}

onUnmounted(() => {
  for (const s of sessions.value) {
    s.themeObs?.disconnect();
    dropSocket(s);
    s.term?.dispose()
  }
  sessions.value=[]
})

store.fetchAll().catch(() => {
})
</script>

<template>
  <AppLayout>
    <div class="flex flex-col" style="height: calc(100vh - 64px)">

      <div class="flex items-center gap-0 border-b bg-card shrink-0 overflow-x-auto">
        <div v-for="s in sessions" :key="s.id"
             :class="['flex items-center gap-1.5 px-4 py-2.5 text-sm border-b-2 -mb-px cursor-pointer shrink-0 transition-colors select-none',
            activeId === s.id
              ? 'border-primary text-foreground bg-muted/20'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/10']"
             @click="switchTo(s.id)">
          <Server class="h-3.5 w-3.5 shrink-0"/>
          <span class="max-w-[120px] truncate">{{ sessionLabel(s) }}</span>
          <span v-if="s.dead" class="h-1.5 w-1.5 rounded-full bg-red-500 shrink-0"/>
          <button class="ml-1 text-muted-foreground hover:text-foreground shrink-0" @click.stop="closeSession(s.id)">
            <X class="h-3 w-3"/>
          </button>
        </div>
        <button
            class="flex items-center gap-1.5 px-4 py-2.5 text-sm text-muted-foreground hover:text-foreground hover:bg-muted/10 shrink-0 transition-colors"
            @click="showPicker = !showPicker">
          <Plus class="h-4 w-4"/>
          <span v-if="sessions.length === 0">Open terminal</span>
        </button>
      </div>

      <div v-if="showPicker" class="absolute z-50 mt-10 ml-2 bg-card border rounded-xl shadow-xl w-72 overflow-hidden">
        <div class="px-3 py-2 border-b text-xs font-medium text-muted-foreground uppercase tracking-wide">Pick a
          server
        </div>
        <div class="max-h-64 overflow-y-auto">
          <button v-for="srv in store.list" :key="srv.id"
                  class="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm hover:bg-muted/50 text-left transition-colors"
                  @click="addSession(srv.id)">
            <div class="h-2 w-2 rounded-full bg-primary shrink-0"/>
            <div class="min-w-0">
              <p class="font-medium truncate">{{ srv.name }}</p>
              <p class="text-xs text-muted-foreground font-mono truncate">{{ srv.host }}</p>
            </div>
          </button>
          <div v-if="!store.list.length" class="px-4 py-6 text-center text-sm text-muted-foreground">
            No servers added yet
          </div>
        </div>
        <div class="px-3 py-2 border-t">
          <button class="text-xs text-muted-foreground hover:text-foreground" @click="showPicker = false">Cancel
          </button>
        </div>
      </div>
      <div v-if="showPicker" class="fixed inset-0 z-40" @click="showPicker = false"/>

      <div v-if="sessions.length === 0"
           class="flex-1 flex flex-col items-center justify-center text-center text-muted-foreground px-4">
        <Server class="h-12 w-12 opacity-20 mb-4"/>
        <p class="font-medium">No open terminals</p>
        <p class="text-sm mt-1 mb-4">Click the + button above to open a terminal</p>
        <Button class="gap-2" @click="showPicker = true">
          <Plus class="h-4 w-4"/>
          Open terminal
        </Button>
      </div>

      <div v-show="sessions.length > 0" class="flex-1 flex flex-col overflow-hidden">
        <div class="flex-1 relative overflow-hidden">
          <div v-for="s in sessions" :key="s.id"
               v-show="activeId === s.id"
               :ref="(el) => { if (el) termDivs[s.id] = el as HTMLDivElement }"
               class="absolute inset-0"
               :style="{ background: isDark() ? '#0d1117' : '#ffffff' }"/>

          <div v-if="activeSession?.dead"
               class="absolute inset-0 flex flex-col items-center justify-center gap-4 z-10"
               :style="{ background: isDark() ? 'rgba(13,17,23,0.85)' : 'rgba(246,248,250,0.85)' }">
            <p class="text-sm text-muted-foreground">Session ended</p>
            <Button class="gap-2" @click="activeSession && reconnect(activeSession)">
              <RefreshCw class="h-4 w-4"/>
              Reconnect
            </Button>
          </div>
        </div>

        <div v-if="!activeSession?.dead"
             class="flex items-center gap-1 px-2 py-1.5 overflow-x-auto shrink-0"
             :style="{ background: isDark() ? '#161b22' : '#f6f8fa', borderTop: isDark() ? '1px solid #30363d' : '1px solid #d0d7de' }">
          <button v-for="btn in termButtons" :key="btn.label"
                  class="px-2.5 py-1 rounded text-xs font-mono font-medium shrink-0 select-none active:opacity-60 transition-opacity"
                  :style="{ background: isDark() ? '#21262d' : '#eaeef2', color: isDark() ? '#e6edf3' : '#24292f' }"
                  @click="sendToActive(btn.seq)">
            {{ btn.label }}
          </button>
          <div class="w-px h-4 mx-1 shrink-0" :style="{ background: isDark() ? '#30363d' : '#d0d7de' }"/>
          <button
              class="flex items-center gap-1 px-2.5 py-1 rounded text-xs font-medium shrink-0 select-none active:opacity-60 transition-opacity"
              :style="{ background: isDark() ? '#21262d' : '#eaeef2', color: isDark() ? '#e6edf3' : '#24292f' }"
              @click="copyOutput">
            <Copy class="h-3 w-3"/>
            Copy
          </button>
        </div>
      </div>

    </div>
  </AppLayout>
</template>