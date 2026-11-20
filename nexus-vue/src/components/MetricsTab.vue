<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { Clock, Cpu, MemoryStick, HardDrive, ArrowDown, ArrowUp, Activity, Server, Bell, Loader2 } from '@lucide/vue'
import { toast } from 'vue-sonner'
import { api } from '@/lib/api'
import {managedSocket} from '@/lib/socket'
import { can, verifySession } from '@/lib/auth'
import type { Metrics, ServerAlertConfig } from '@/lib/api'
import SparkLine from './SparkLine.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps<{ serverId: string }>()

const data  = ref<Metrics | null>(null)
const error = ref('')
const MAX   = 90

type Snap = { t: number; cpu: number; mem: number; rx: number; tx: number; load: number }

const history = ref<Snap[]>([])
const dCpu    = ref(0)
const dMem    = ref(0)
const dDisk   = ref(0)
const dSwap   = ref(0)
const dRx     = ref(0)
const dTx     = ref(0)

const alerts      = ref<ServerAlertConfig | null>(null)
const alertSaving = ref(false)

const hCpu  = computed(() => history.value.map(s => s.cpu))
const hMem  = computed(() => history.value.map(s => s.mem))
const hRx   = computed(() => history.value.map(s => s.rx))
const hTx   = computed(() => history.value.map(s => s.tx))
const hLoad = computed(() => history.value.map(s => s.load))

function fmt(b: number) {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB'
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b.toFixed(0) + ' B'
}

function fmtRate(b: number) { return fmt(b) + '/s' }

function barColor(p: number) {
  return p >= 90 ? 'bg-red-500' : p >= 70 ? 'bg-yellow-500' : 'bg-primary'
}

function chartColor(p: number) {
  return p >= 90 ? '#ef4444' : p >= 70 ? '#eab308' : '#3b82f6'
}

function animateTo(current: { value: number }, target: number, ms = 600) {
  const start = current.value
  const t0    = performance.now()
  function step(now: number) {
    const p = Math.min((now - t0) / ms, 1)
    const e = 1 - Math.pow(1 - p, 3)
    current.value = start + (target - start) * e
    if (p < 1) requestAnimationFrame(step)
  }
  requestAnimationFrame(step)
}

async function saveAlerts() {
  if (!alerts.value) return
  alertSaving.value = true
  try {
    alerts.value = await api.serverAlerts.update(props.serverId, alerts.value)
    toast.success('Alert thresholds saved')
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to save')
  } finally {
    alertSaving.value = false
  }
}

let disposed = false
const stream=managedSocket({
 authorize:async()=>await verifySession() && can('metrics.read',props.serverId) && can('secrets.use',props.serverId),
 url:()=>api.ws.metrics(props.serverId),maxRetries:6,
 status:state=>{if(['denied','closed','error'].includes(state))error.value=state==='denied'?'Session or permission expired. Sign in again.':'Connection closed. Reload to reconnect.'},
 message:e=>{try{
    const m: Metrics = JSON.parse(e.data)
    if ((m as any).error) { error.value = (m as any).error; return }
    error.value = ''
    data.value  = m
    const memPct  = m.memTotal  ? (m.memUsed  / m.memTotal)  * 100 : 0
    const diskPct = m.diskTotal ? (m.diskUsed / m.diskTotal) * 100 : 0
    const swapPct = m.swapTotal ? (m.swapUsed / m.swapTotal) * 100 : 0
    animateTo(dCpu,  m.cpu,        500)
    animateTo(dMem,  memPct,       500)
    animateTo(dDisk, diskPct,      500)
    animateTo(dSwap, swapPct,      500)
    animateTo(dRx,   m.netRxRate,  500)
    animateTo(dTx,   m.netTxRate,  500)
    history.value.push({ t: Date.now(), cpu: m.cpu, mem: memPct, rx: m.netRxRate, tx: m.netTxRate, load: m.load1 })
    if (history.value.length > MAX) history.value.shift()

 }catch{error.value='Invalid metrics response'}},
})
function connect(){if(!disposed)void stream.connect()}

onMounted(async () => {
  try {
    alerts.value = await api.serverAlerts.get(props.serverId)
  } catch {
    alerts.value = {
      id: props.serverId,
      cpuEnabled: false, cpuThreshold: 90,
      ramEnabled: false, ramThreshold: 90,
      diskEnabled: false, diskThreshold: 85,
      sslEnabled: false, sslDaysBefore: 14,
      updatedAt: '',
    }
  }
  connect()
})

onUnmounted(() => { disposed = true; stream.dispose() })
</script>

<template>
  <div class="space-y-4">

    <div v-if="error" class="text-sm text-destructive bg-destructive/10 rounded-lg px-4 py-3">{{ error }}</div>

    <template v-if="!data && !error">
      <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div v-for="i in 4" :key="i" class="h-32 rounded-xl bg-muted animate-pulse" />
      </div>
      <div v-for="i in 3" :key="'c' + i" class="h-40 rounded-xl bg-muted animate-pulse" />
    </template>

    <template v-else-if="data">

      <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div class="bg-card border rounded-xl p-4 space-y-2 overflow-hidden">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-1.5 text-xs text-muted-foreground font-medium uppercase tracking-wide">
              <Cpu class="h-3.5 w-3.5" />CPU
            </div>
            <span class="text-2xl font-bold tabular-nums" :style="{ color: chartColor(dCpu) }">
              {{ dCpu.toFixed(1) }}%
            </span>
          </div>
          <SparkLine :data="hCpu" :min="0" :max="100" :height="48" :color="chartColor(dCpu)" />
          <div class="h-1.5 rounded-full bg-muted overflow-hidden">
            <div :class="['h-full rounded-full', barColor(dCpu)]"
                 :style="{ width: `${Math.min(dCpu, 100)}%`, transition: 'width 500ms cubic-bezier(0.4,0,0.2,1)' }" />
          </div>
        </div>

        <div class="bg-card border rounded-xl p-4 space-y-2 overflow-hidden">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-1.5 text-xs text-muted-foreground font-medium uppercase tracking-wide">
              <MemoryStick class="h-3.5 w-3.5" />RAM
            </div>
            <div class="text-right">
              <span class="text-2xl font-bold tabular-nums" :style="{ color: chartColor(dMem) }">{{ dMem.toFixed(1) }}%</span>
              <p class="text-[11px] text-muted-foreground">{{ fmt(data.memUsed) }} / {{ fmt(data.memTotal) }}</p>
            </div>
          </div>
          <SparkLine :data="hMem" :min="0" :max="100" :height="48" :color="chartColor(dMem)" />
          <div class="h-1.5 rounded-full bg-muted overflow-hidden">
            <div :class="['h-full rounded-full', barColor(dMem)]"
                 :style="{ width: `${dMem}%`, transition: 'width 500ms cubic-bezier(0.4,0,0.2,1)' }" />
          </div>
        </div>

        <div class="bg-card border rounded-xl p-4 space-y-2 overflow-hidden">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-1.5 text-xs text-muted-foreground font-medium uppercase tracking-wide">
              <HardDrive class="h-3.5 w-3.5" />Disk
            </div>
            <div class="text-right">
              <span class="text-2xl font-bold tabular-nums" :style="{ color: chartColor(dDisk) }">{{ dDisk.toFixed(1) }}%</span>
              <p class="text-[11px] text-muted-foreground">{{ fmt(data.diskUsed) }} / {{ fmt(data.diskTotal) }}</p>
            </div>
          </div>
          <div class="h-12 flex items-center justify-center">
            <svg viewBox="0 0 80 80" class="h-12 w-12">
              <circle cx="40" cy="40" r="30" fill="none" stroke="currentColor" stroke-width="10" class="text-muted" />
              <circle cx="40" cy="40" r="30" fill="none" :stroke="chartColor(dDisk)" stroke-width="10"
                      stroke-linecap="round" stroke-dasharray="188.5"
                      :stroke-dashoffset="188.5 - (188.5 * Math.min(dDisk, 100) / 100)"
                      transform="rotate(-90 40 40)"
                      style="transition: stroke-dashoffset 500ms cubic-bezier(0.4,0,0.2,1)" />
            </svg>
          </div>
          <div class="h-1.5 rounded-full bg-muted overflow-hidden">
            <div :class="['h-full rounded-full', barColor(dDisk)]"
                 :style="{ width: `${dDisk}%`, transition: 'width 500ms cubic-bezier(0.4,0,0.2,1)' }" />
          </div>
        </div>

        <div class="bg-card border rounded-xl p-4 space-y-3">
          <div class="flex items-center gap-1.5 text-xs text-muted-foreground font-medium uppercase tracking-wide">
            <Clock class="h-3.5 w-3.5" />System
          </div>
          <div class="space-y-2.5">
            <div>
              <p class="text-xs text-muted-foreground">Uptime</p>
              <p class="text-lg font-semibold">{{ data.uptime }}</p>
            </div>
            <div v-if="data.swapTotal > 0">
              <div class="flex items-center justify-between text-xs mb-1">
                <span class="text-muted-foreground">Swap</span>
                <span class="font-medium">{{ dSwap.toFixed(1) }}%</span>
              </div>
              <div class="h-1.5 rounded-full bg-muted overflow-hidden">
                <div :class="['h-full rounded-full', barColor(dSwap)]"
                     :style="{ width: `${dSwap}%`, transition: 'width 500ms cubic-bezier(0.4,0,0.2,1)' }" />
              </div>
              <p class="text-[11px] text-muted-foreground mt-0.5">{{ fmt(data.swapUsed) }} / {{ fmt(data.swapTotal) }}</p>
            </div>
            <div v-else class="text-xs text-muted-foreground">No swap configured</div>
          </div>
        </div>
      </div>

      <div class="bg-card border rounded-xl p-4 space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-1.5 text-sm font-medium">
            <Activity class="h-4 w-4 text-muted-foreground" />Load Average
          </div>
          <div class="flex items-center gap-3 sm:gap-4 text-xs text-muted-foreground flex-wrap">
            <span class="flex items-center gap-1">
              <span class="h-2 w-2 rounded-full bg-blue-500 inline-block" />
              1m: <strong class="text-foreground">{{ (data.load1 ?? 0).toFixed(2) }}</strong>
            </span>
            <span class="flex items-center gap-1">
              <span class="h-2 w-2 rounded-full bg-violet-500 inline-block" />
              5m: <strong class="text-foreground">{{ (data.load5 ?? 0).toFixed(2) }}</strong>
            </span>
            <span class="flex items-center gap-1">
              <span class="h-2 w-2 rounded-full bg-slate-400 inline-block" />
              15m: <strong class="text-foreground">{{ (data.load15 ?? 0).toFixed(2) }}</strong>
            </span>
          </div>
        </div>
        <SparkLine :data="hLoad" :min="0" :height="64" color="#3b82f6" />
      </div>

      <div class="bg-card border rounded-xl p-4 space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div class="flex items-center gap-1.5 text-sm font-medium">
            <Server class="h-4 w-4 text-muted-foreground" />Network I/O
          </div>
          <div class="flex items-center gap-3 sm:gap-4 text-xs text-muted-foreground">
            <span class="flex items-center gap-1">
              <ArrowDown class="h-3 w-3 text-emerald-500" />
              RX: <strong class="text-foreground">{{ fmtRate(dRx) }}</strong>
            </span>
            <span class="flex items-center gap-1">
              <ArrowUp class="h-3 w-3 text-orange-500" />
              TX: <strong class="text-foreground">{{ fmtRate(dTx) }}</strong>
            </span>
          </div>
        </div>
        <div class="relative">
          <SparkLine :data="hRx" :height="64" color="#10b981" />
          <div class="absolute inset-0 pointer-events-none">
            <SparkLine :data="hTx" :height="64" color="#f97316" />
          </div>
        </div>
        <div class="flex gap-3 text-xs text-muted-foreground">
          <span class="flex items-center gap-1"><span class="h-2 w-2 rounded-full bg-emerald-500 inline-block" />Download</span>
          <span class="flex items-center gap-1"><span class="h-2 w-2 rounded-full bg-orange-500 inline-block" />Upload</span>
        </div>
      </div>

      <div v-if="data.processes?.length" class="bg-card border rounded-xl overflow-x-auto">
        <div class="px-4 py-3 border-b bg-muted/30 flex items-center gap-1.5">
          <Cpu class="h-4 w-4 text-muted-foreground" />
          <span class="text-sm font-medium">Top Processes</span>
        </div>
        <table class="w-full text-sm min-w-[400px]">
          <thead>
          <tr class="border-b bg-muted/20">
            <th class="text-left px-4 py-2 text-xs text-muted-foreground font-medium uppercase tracking-wide">Process</th>
            <th class="text-left px-4 py-2 text-xs text-muted-foreground font-medium uppercase tracking-wide hidden sm:table-cell">PID</th>
            <th class="text-right px-4 py-2 text-xs text-muted-foreground font-medium uppercase tracking-wide">CPU</th>
            <th class="text-right px-4 py-2 text-xs text-muted-foreground font-medium uppercase tracking-wide">MEM</th>
            <th class="px-4 py-2 w-28 hidden sm:table-cell" />
          </tr>
          </thead>
          <tbody>
          <tr v-for="p in data.processes" :key="p.pid"
              class="border-b last:border-0 hover:bg-muted/10 transition-colors">
            <td class="px-4 py-2.5 font-mono text-xs font-medium">{{ p.name }}</td>
            <td class="px-4 py-2.5 text-xs text-muted-foreground hidden sm:table-cell">{{ p.pid }}</td>
            <td class="px-4 py-2.5 text-right">
                <span class="text-xs font-medium tabular-nums" :style="{ color: chartColor(p.cpu ?? 0) }">
                  {{ (p.cpu ?? 0).toFixed(1) }}%
                </span>
            </td>
            <td class="px-4 py-2.5 text-right">
              <span class="text-xs text-muted-foreground tabular-nums">{{ (p.memory ?? 0).toFixed(1) }}%</span>
            </td>
            <td class="px-4 py-2.5 hidden sm:table-cell">
              <div class="h-1.5 rounded-full bg-muted overflow-hidden">
                <div class="h-full rounded-full bg-primary"
                     :style="{ width: `${Math.min(p.cpu ?? 0, 100)}%`, transition: 'width 500ms cubic-bezier(0.4,0,0.2,1)' }" />
              </div>
            </td>
          </tr>
          </tbody>
        </table>
      </div>

      <div v-if="data.os || data.kernel"
           class="flex flex-wrap items-center gap-4 sm:gap-6 px-4 py-3 bg-card border rounded-xl text-xs text-muted-foreground">
        <span v-if="data.os" class="flex items-center gap-1.5"><Server class="h-3.5 w-3.5" />{{ data.os }}</span>
        <span v-if="data.kernel">Kernel {{ data.kernel }}</span>
        <span class="ml-auto">Live · updates every 2s</span>
      </div>

      <div v-if="alerts" class="bg-card border rounded-xl p-4 sm:p-5 space-y-4">
        <div class="flex items-start sm:items-center gap-2 flex-wrap">
          <Bell class="h-4 w-4 text-muted-foreground shrink-0 mt-0.5 sm:mt-0" />
          <h3 class="text-sm font-semibold">Alert Thresholds</h3>
          <span class="text-xs text-muted-foreground">— Telegram notification when exceeded (1h cooldown)</span>
        </div>

        <div class="space-y-3">
          <div v-for="item in [
            { key: 'cpu',  label: 'CPU',  icon: Cpu,        enabled: 'cpuEnabled',  threshold: 'cpuThreshold',  min: 50, max: 99, suffix: '%'      },
            { key: 'ram',  label: 'RAM',  icon: MemoryStick, enabled: 'ramEnabled',  threshold: 'ramThreshold',  min: 50, max: 99, suffix: '%'      },
            { key: 'disk', label: 'Disk', icon: HardDrive,  enabled: 'diskEnabled', threshold: 'diskThreshold', min: 50, max: 99, suffix: '%'      },
          ]" :key="item.key" class="flex items-center gap-3">
            <label class="flex items-center gap-2 w-24 sm:w-28 cursor-pointer select-none shrink-0">
              <input type="checkbox" v-model="(alerts as any)[item.enabled]" class="rounded" />
              <span class="text-sm font-medium flex items-center gap-1.5">
                <component :is="item.icon" class="h-3.5 w-3.5 text-muted-foreground" />{{ item.label }}
              </span>
            </label>
            <div class="flex items-center gap-2 flex-1 min-w-0">
              <input type="range" v-model.number="(alerts as any)[item.threshold]"
                     :min="item.min" :max="item.max" step="1"
                     :disabled="!(alerts as any)[item.enabled]"
                     class="flex-1 accent-primary disabled:opacity-40" />
              <span class="text-sm font-mono w-12 text-right shrink-0"
                    :class="(alerts as any)[item.enabled] ? 'text-foreground' : 'text-muted-foreground'">
                {{ (alerts as any)[item.threshold] }}{{ item.suffix }}
              </span>
            </div>
          </div>

          <div class="flex items-center gap-3">
            <label class="flex items-center gap-2 w-24 sm:w-28 cursor-pointer select-none shrink-0">
              <input type="checkbox" v-model="alerts.sslEnabled" class="rounded" />
              <span class="text-sm font-medium">SSL expiry</span>
            </label>
            <div class="flex items-center gap-2 flex-1 min-w-0">
              <input type="range" v-model.number="alerts.sslDaysBefore" min="3" max="60" step="1"
                     :disabled="!alerts.sslEnabled" class="flex-1 accent-primary disabled:opacity-40" />
              <span class="text-sm font-mono w-16 text-right shrink-0"
                    :class="alerts.sslEnabled ? 'text-foreground' : 'text-muted-foreground'">
                {{ alerts.sslDaysBefore }}d before
              </span>
            </div>
          </div>
        </div>

        <Button size="sm" class="gap-2" :disabled="alertSaving" @click="saveAlerts">
          <Loader2 v-if="alertSaving" class="h-3.5 w-3.5 animate-spin" />
          Save thresholds
        </Button>
      </div>

    </template>
  </div>
</template>