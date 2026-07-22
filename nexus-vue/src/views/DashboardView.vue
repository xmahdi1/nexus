<script setup lang="ts">
import {ref, computed, onMounted, onUnmounted} from 'vue'
import {useRouter} from 'vue-router'
import {toast} from 'vue-sonner'
import {
  Server, Wifi, WifiOff, Plus, ChevronRight, Clock,
  Activity, Bell, ChevronDown, ChevronUp, RotateCcw, Square, Loader2,
} from '@lucide/vue'
import {api} from '@/lib/api'
import type {ServerStatus, Container} from '@/lib/api'
import {useServersStore} from '@/stores/servers'
import AppLayout from '@/components/AppLayout.vue'
import Button from '@/components/ui/Button.vue'

const router = useRouter()
const store = useServersStore()

const statuses = ref<ServerStatus[]>([])
const loading = ref(true)
const expandedId = ref<string | null>(null)
const serverContainers = ref<Record<string, Container[]>>({})
const containersFetching = ref<Record<string, boolean>>({})
const quickActing = ref<Record<string, boolean>>({})
const prevOnline = new Map<string, boolean>()
let interval: ReturnType<typeof setInterval> | null = null

const totalServers = computed(() => statuses.value.length || store.list.length)
const onlineCount = computed(() => statuses.value.filter(s => s.online).length)
const offlineCount = computed(() => statuses.value.filter(s => !s.online).length)
const avgLatency = computed(() => {
  const online = statuses.value.filter(s => s.online && s.latencyMs > 0)
  if (!online.length) return null
  return Math.round(online.reduce((a, s) => a + s.latencyMs, 0) / online.length)
})
const notificationsBlocked = computed(() =>
    typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'denied'
)

function getStatus(serverId: string): ServerStatus | null {
  return statuses.value.find(s => s.serverId === serverId) ?? null
}

function runningContainers(serverId: string) {
  return (serverContainers.value[serverId] || []).filter(c => (c as any).state === 'running')
}

function timeSince(t: string | null) {
  if (!t) return 'never'
  const m = Math.floor((Date.now() - new Date(t).getTime()) / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

function browserNotify(title: string, body: string) {
  if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'granted') {
    new Notification(title, {body})
  }
}

async function loadStatuses() {
  try {
    const fresh = await api.monitor.status()
    for (const s of fresh) {
      const was = prevOnline.get(s.serverId)
      if (was === true && !s.online) {
        browserNotify('Server Down', `${s.name} (${s.host}) is unreachable`)
        toast.error(`${s.name} went offline`)
      } else if (was === false && s.online) {
        browserNotify('Server Online', `${s.name} (${s.host}) is back online`)
        toast.success(`${s.name} is back online`)
      }
      prevOnline.set(s.serverId, s.online)
    }
    statuses.value = fresh
  } catch {
  } finally {
    loading.value = false
  }
}

async function toggleExpand(e: Event, serverId: string) {
  e.stopPropagation()
  if (expandedId.value === serverId) {
    expandedId.value = null;
    return
  }
  expandedId.value = serverId
  if (!serverContainers.value[serverId]) {
    containersFetching.value[serverId] = true
    try {
      serverContainers.value[serverId] = await api.containers.list(serverId)
    } catch {
      serverContainers.value[serverId] = []
    } finally {
      containersFetching.value[serverId] = false
    }
  }
}

async function quickAction(e: Event, serverId: string, cid: string, action: 'restart' | 'stop' | 'start') {
  e.stopPropagation()
  const key = `${serverId}:${cid}`
  quickActing.value[key] = true
  try {
    await api.containers[action](serverId, cid)
    toast.success(`${action} — done`)
    serverContainers.value[serverId] = await api.containers.list(serverId)
  } catch (err) {
    toast.error(err instanceof Error ? err.message : `${action} failed`)
  } finally {
    delete quickActing.value[key]
    quickActing.value = {...quickActing.value}
  }
}

onMounted(async () => {
  await store.fetchAll().catch(() => {
  })
  if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'default') {
    await Notification.requestPermission()
  }
  await loadStatuses()
  interval = setInterval(loadStatuses, 30_000)
})

onUnmounted(() => {
  if (interval) clearInterval(interval)
})
</script>

<template>
  <AppLayout>
    <div class="max-w-7xl mx-auto space-y-6">

      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-xl sm:text-2xl font-semibold tracking-tight">Dashboard</h1>
          <p class="text-sm text-muted-foreground mt-0.5">
            Monitoring {{ totalServers }} server{{ totalServers !== 1 ? 's' : '' }}
          </p>
        </div>
        <Button class="gap-2" @click="router.push('/servers')">
          <Plus class="h-4 w-4"/>
          <span class="hidden sm:inline">Add server</span>
        </Button>
      </div>

      <div class="grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4">
        <div class="bg-card border rounded-xl p-4 space-y-1">
          <p class="text-xs text-muted-foreground font-medium uppercase tracking-wide">Total</p>
          <p class="text-3xl font-bold tabular-nums">{{ totalServers }}</p>
          <p class="text-xs text-muted-foreground">servers</p>
        </div>
        <div class="bg-card border rounded-xl p-4 space-y-1">
          <p class="text-xs text-muted-foreground font-medium uppercase tracking-wide">Online</p>
          <p class="text-3xl font-bold tabular-nums text-green-500">{{ onlineCount }}</p>
          <p class="text-xs text-muted-foreground">reachable</p>
        </div>
        <div class="bg-card border rounded-xl p-4 space-y-1">
          <p class="text-xs text-muted-foreground font-medium uppercase tracking-wide">Offline</p>
          <p class="text-3xl font-bold tabular-nums"
             :class="offlineCount > 0 ? 'text-red-500' : 'text-muted-foreground'">
            {{ offlineCount }}
          </p>
          <p class="text-xs text-muted-foreground">unreachable</p>
        </div>
        <div class="bg-card border rounded-xl p-4 space-y-1">
          <p class="text-xs text-muted-foreground font-medium uppercase tracking-wide">Avg latency</p>
          <p class="text-3xl font-bold tabular-nums">{{ avgLatency !== null ? avgLatency : '—' }}</p>
          <p class="text-xs text-muted-foreground">ms (online)</p>
        </div>
      </div>

      <div v-if="loading" class="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <div v-for="i in 3" :key="i" class="h-36 rounded-xl bg-muted animate-pulse"/>
      </div>

      <div v-else-if="!store.list.length"
           class="flex flex-col items-center justify-center py-16 sm:py-24 border rounded-2xl text-center px-4">
        <Server class="h-12 w-12 text-muted-foreground/30 mb-4"/>
        <p class="font-medium">No servers yet</p>
        <p class="text-sm text-muted-foreground mt-1 mb-4">Add a server to start monitoring</p>
        <Button class="gap-2" @click="router.push('/servers')">
          <Plus class="h-4 w-4"/>
          Add server
        </Button>
      </div>

      <div v-else class="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <div v-for="server in store.list" :key="server.id"
             class="group bg-card border rounded-xl overflow-hidden cursor-pointer hover:shadow-md
                 transition-all duration-200 hover:-translate-y-0.5"
             @click="router.push(`/servers/${server.id}`)">

          <div class="p-4 sm:p-5 space-y-4">
            <div class="flex items-start justify-between gap-2">
              <div class="flex items-center gap-2.5 min-w-0">
                <div class="relative shrink-0">
                  <div :class="['h-3 w-3 rounded-full',
                    getStatus(server.id) === null ? 'bg-muted-foreground/40' :
                    getStatus(server.id)!.online   ? 'bg-green-500' : 'bg-red-500']"/>
                  <div v-if="getStatus(server.id)?.online"
                       class="absolute inset-0 h-3 w-3 rounded-full bg-green-500 animate-ping opacity-60"/>
                </div>
                <div class="min-w-0">
                  <p class="font-semibold text-sm truncate">{{ server.name }}</p>
                  <p class="text-xs text-muted-foreground font-mono truncate">{{ server.host }}:{{ server.port }}</p>
                </div>
              </div>
              <div v-if="getStatus(server.id)" class="shrink-0">
                <span v-if="getStatus(server.id)!.online"
                      class="flex items-center gap-1 text-xs font-medium text-green-600 bg-green-500/10 px-2 py-0.5 rounded-full">
                  <Wifi class="h-3 w-3"/>Online
                </span>
                <span v-else
                      class="flex items-center gap-1 text-xs font-medium text-red-600 bg-red-500/10 px-2 py-0.5 rounded-full">
                  <WifiOff class="h-3 w-3"/>Offline
                </span>
              </div>
              <span v-else class="text-xs text-muted-foreground shrink-0">Checking…</span>
            </div>

            <div class="flex items-center gap-4 text-xs text-muted-foreground">
              <span v-if="getStatus(server.id)?.online && getStatus(server.id)!.latencyMs > 0"
                    class="flex items-center gap-1">
                <Activity class="h-3 w-3"/>{{ getStatus(server.id)!.latencyMs }}ms
              </span>
              <span v-if="getStatus(server.id) && !getStatus(server.id)!.online"
                    class="flex items-center gap-1">
                <Clock class="h-3 w-3"/>Last seen {{ timeSince(getStatus(server.id)!.lastOnline) }}
              </span>
            </div>

            <div class="flex items-center justify-between">
              <div class="flex flex-wrap gap-1">
                <span v-for="tag in (server.tags || '').split(',').filter(Boolean)" :key="tag"
                      class="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-medium">
                  {{ tag.trim() }}
                </span>
              </div>
              <ChevronRight class="h-4 w-4 text-muted-foreground/50 group-hover:text-foreground transition-colors"/>
            </div>
          </div>

          <div v-if="getStatus(server.id)?.online" class="border-t">
            <button
                class="w-full flex items-center justify-between px-5 py-2 text-xs text-muted-foreground hover:bg-muted/30 transition-colors"
                @click="toggleExpand($event, server.id)">
              <span class="flex items-center gap-1.5">
                <span class="h-1.5 w-1.5 rounded-full bg-green-500"/>Quick actions
              </span>
              <ChevronDown v-if="expandedId !== server.id" class="h-3.5 w-3.5"/>
              <ChevronUp v-else class="h-3.5 w-3.5"/>
            </button>

            <div v-if="expandedId === server.id" class="border-t bg-muted/10">
              <div v-if="containersFetching[server.id]"
                   class="px-5 py-3 flex items-center gap-2 text-xs text-muted-foreground">
                <Loader2 class="h-3.5 w-3.5 animate-spin"/>
                Loading containers…
              </div>
              <div v-else-if="!runningContainers(server.id).length"
                   class="px-5 py-3 text-xs text-muted-foreground">
                No running containers
              </div>
              <div v-else>
                <div v-for="c in runningContainers(server.id)" :key="c.id"
                     class="flex items-center justify-between px-5 py-2.5 border-b last:border-0 hover:bg-muted/20">
                  <div class="min-w-0 flex-1">
                    <p class="text-xs font-medium truncate">{{ c.name || c.id.slice(0, 12) }}</p>
                    <p class="text-[10px] text-muted-foreground font-mono truncate">{{ c.image }}</p>
                  </div>
                  <div class="flex items-center gap-1 shrink-0 ml-2">
                    <Button size="icon" variant="ghost" class="h-6 w-6"
                            :disabled="!!quickActing[`${server.id}:${c.id}`]"
                            @click="quickAction($event, server.id, c.id, 'restart')">
                      <Loader2 v-if="quickActing[`${server.id}:${c.id}`]" class="h-3 w-3 animate-spin"/>
                      <RotateCcw v-else class="h-3 w-3"/>
                    </Button>
                    <Button size="icon" variant="ghost" class="h-6 w-6 text-yellow-600"
                            :disabled="!!quickActing[`${server.id}:${c.id}`]"
                            @click="quickAction($event, server.id, c.id, 'stop')">
                      <Square class="h-3 w-3"/>
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </div>

        </div>
      </div>

      <div v-if="notificationsBlocked"
           class="flex items-center gap-3 px-4 py-3 bg-yellow-500/10 border border-yellow-500/20 rounded-xl text-sm text-yellow-700 dark:text-yellow-400">
        <Bell class="h-4 w-4 shrink-0"/>
        Browser notifications are blocked. Enable them in your browser settings to get alerts when servers go offline.
      </div>

    </div>
  </AppLayout>
</template>