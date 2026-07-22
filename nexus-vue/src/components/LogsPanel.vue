<script setup lang="ts">
import {ref, watch, onUnmounted, nextTick, computed} from 'vue'
import {X, Loader2, FileX} from '@lucide/vue'
import {api} from '@/lib/api'
import Button from './ui/Button.vue'

const props = defineProps<{
  open: boolean
  serverId: string
  containerId: string
  containerName: string
}>()

const emit = defineEmits<{ 'update:open': [boolean] }>()

const logEl = ref<HTMLDivElement>()
const rawLines = ref<string[]>([])
const connecting = ref(false)
const connected = ref(false)
let ws: WebSocket | null = null
let lineBuffer = ''

interface LogLine {
  timestamp: string;
  text: string;
  raw: string
}

function stripAnsi(str: string): string {
  return str
      .replace(/\x1b\[[0-9;]*[A-Za-z]/g, '')
      .replace(/\x1b[()][AB012]/g, '')
      .replace(/\x1b[ABCDHJ]/g, '')
}

function formatTs(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleTimeString(undefined, {hour12: false}) + '.' + String(d.getMilliseconds()).padStart(3, '0')
  } catch {
    return iso.slice(11, 23)
  }
}

const lines = computed<LogLine[]>(() =>
    rawLines.value.map((raw) => {
      const m = raw.match(/^(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+(.*)$/)
      return m ? {timestamp: formatTs(m[1]), text: m[2], raw} : {timestamp: '', text: raw, raw}
    }),
)

function connect() {
  if (ws) return
  connecting.value = true
  connected.value = false
  rawLines.value = []
  lineBuffer = ''

  ws = new WebSocket(api.ws.logs(props.serverId, props.containerId))

  ws.onopen = () => {
    connecting.value = false;
    connected.value = true
  }

  ws.onmessage = (e) => {
    const chunk = typeof e.data === 'string' ? e.data : new TextDecoder().decode(e.data as ArrayBuffer)
    const text = stripAnsi(lineBuffer + chunk)
    const parts = text.split('\n')
    lineBuffer = parts.pop() ?? ''
    const newLines = parts.filter(l => l.trimEnd() !== '')
    if (newLines.length) {
      rawLines.value.push(...newLines)
      if (rawLines.value.length > 2000) rawLines.value = rawLines.value.slice(-2000)
      nextTick(scrollToBottom)
    }
  }

  ws.onclose = () => {
    connecting.value = false
    if (lineBuffer.trim()) {
      rawLines.value.push(stripAnsi(lineBuffer));
      lineBuffer = ''
    }
    ws = null
  }

  ws.onerror = () => {
    connecting.value = false;
    rawLines.value.push('[connection error]');
    ws = null
  }
}

function disconnect() {
  ws?.close();
  ws = null
}

function scrollToBottom() {
  if (logEl.value) logEl.value.scrollTop = logEl.value.scrollHeight
}

watch(() => props.open, (open) => {
  if (open) connect(); else disconnect()
}, {immediate: true})
onUnmounted(() => disconnect())
</script>

<template>
  <Transition enter-active-class="transition-opacity duration-200" enter-from-class="opacity-0"
              leave-active-class="transition-opacity duration-150" leave-to-class="opacity-0">
    <div v-if="open" class="fixed inset-0 bg-black/60 z-40" @click="$emit('update:open', false)"/>
  </Transition>

  <Transition enter-active-class="transition-transform duration-200 ease-out" enter-from-class="translate-x-full"
              enter-to-class="translate-x-0" leave-active-class="transition-transform duration-150 ease-in"
              leave-from-class="translate-x-0" leave-to-class="translate-x-full">
    <div v-if="open"
         class="fixed inset-y-0 right-0 w-full sm:w-[680px] max-w-full bg-[#0d1117] border-l border-white/10 flex flex-col z-50 shadow-2xl">

      <div class="flex items-center justify-between px-4 py-3 border-b border-white/10 shrink-0">
        <div class="min-w-0">
          <p class="text-sm font-semibold text-white truncate">{{ containerName }}</p>
          <p class="text-xs text-white/40 font-mono truncate">{{ containerId }}</p>
        </div>
        <Button size="icon" variant="ghost"
                class="h-7 w-7 shrink-0 ml-2 text-white/50 hover:text-white hover:bg-white/10"
                @click="$emit('update:open', false)">
          <X class="h-4 w-4"/>
        </Button>
      </div>

      <div class="flex-1 overflow-hidden relative">
        <div v-if="connecting" class="absolute inset-0 flex items-center justify-center">
          <div class="flex flex-col items-center gap-3">
            <Loader2 class="h-5 w-5 text-white/40 animate-spin"/>
            <p class="text-xs text-white/30">Connecting…</p>
          </div>
        </div>

        <div v-else-if="connected && lines.length === 0" class="absolute inset-0 flex items-center justify-center">
          <div class="flex flex-col items-center gap-3">
            <FileX class="h-8 w-8 text-white/20"/>
            <p class="text-xs text-white/30">No log output yet</p>
          </div>
        </div>

        <div ref="logEl" class="h-full overflow-y-auto px-3 sm:px-4 py-3 space-y-0.5">
          <div v-for="(line, i) in lines" :key="i"
               class="flex gap-2 sm:gap-3 text-xs font-mono leading-5 hover:bg-white/5 rounded px-1 -mx-1">
            <span v-if="line.timestamp" class="shrink-0 text-white/30 select-none tabular-nums hidden sm:inline">
              {{ line.timestamp }}
            </span>
            <span class="text-[#e6edf3] break-all">{{ line.text }}</span>
          </div>
        </div>
      </div>

      <div class="shrink-0 px-4 py-2 border-t border-white/10 flex items-center justify-between">
        <span class="text-xs text-white/25 font-mono">{{ lines.length }} lines</span>
        <button class="text-xs text-white/30 hover:text-white/60 transition-colors" @click="scrollToBottom">
          ↓ scroll to bottom
        </button>
      </div>
    </div>
  </Transition>
</template>