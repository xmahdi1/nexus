<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { Plus, Trash2, Loader2, RefreshCw, Play, Clock, CheckCircle2, XCircle } from '@lucide/vue'
import { api } from '@/lib/api'
import type { ScheduledTask } from '@/lib/api'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
import Label from '@/components/ui/Label.vue'
import { useConfirm } from '@/composables/useConfirm'

const props = defineProps<{ serverId: string }>()
const { confirm } = useConfirm()

const INTERVALS = [
  { label: 'Every 5 minutes',  value: 5    },
  { label: 'Every 15 minutes', value: 15   },
  { label: 'Every 30 minutes', value: 30   },
  { label: 'Every hour',       value: 60   },
  { label: 'Every 6 hours',    value: 360  },
  { label: 'Every 12 hours',   value: 720  },
  { label: 'Daily',            value: 1440 },
  { label: 'Custom',           value: 0    },
]

const STATUS_COLOR: Record<string, string> = {
  ok:      'text-green-600',
  failed:  'text-destructive',
  running: 'text-blue-500',
  denied: 'text-destructive',
  cancelled: 'text-yellow-600',
  interrupted: 'text-destructive',
  pending: 'text-muted-foreground',
}

const tasks   = ref<ScheduledTask[]>([])
const loading = ref(true)
const saving  = ref(false)
const showAdd = ref(false)
const running = ref<Record<string, boolean>>({})
const form    = ref({ name: '', command: '', intervalMinutes: 60, customInterval: 60 })

function fmtInterval(m: number) {
  if (m < 60)   return `Every ${m}m`
  if (m < 1440) return `Every ${m / 60}h`
  return 'Daily'
}

function fmtDate(s: string | null | undefined) {
  return s ? new Date(s).toLocaleString() : 'Never'
}

async function load() {
  loading.value = true
  try   { tasks.value = await api.tasks.list(props.serverId) }
  catch { toast.error('Failed to load tasks') }
  finally { loading.value = false }
}

onMounted(load)

async function addTask() {
  if (!form.value.command) { toast.error('Command is required'); return }
  const interval = form.value.intervalMinutes === 0 ? form.value.customInterval : form.value.intervalMinutes
  saving.value = true
  try {
    await api.tasks.create(props.serverId, {
      name:            form.value.name || form.value.command.slice(0, 40),
      command:         form.value.command,
      intervalMinutes: interval,
    })
    toast.success('Task scheduled')
    form.value    = { name: '', command: '', intervalMinutes: 60, customInterval: 60 }
    showAdd.value = false
    await load()
  } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
  finally { saving.value = false }
}

async function toggleEnabled(task: ScheduledTask) {
  try { await api.tasks.update(props.serverId, task.id, { enabled: !task.enabled }); await load() }
  catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
}

async function runNow(task: ScheduledTask) {
  running.value[task.id] = true
  try {
    await api.tasks.runNow(props.serverId, task.id)
    toast.success('Task triggered — will run within 30 seconds')
    setTimeout(load, 5000)
  } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
  finally {
    setTimeout(() => { delete running.value[task.id]; running.value = { ...running.value } }, 3000)
  }
}

async function deleteTask(task: ScheduledTask) {
  const ok = await confirm({ title: 'Delete task', message: `Delete "${task.name}"?`, confirmText: 'Delete', destructive: true })
  if (!ok) return
  try { await api.tasks.delete(props.serverId, task.id); toast.success('Deleted'); await load() }
  catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
}
</script>

<template>
  <div class="space-y-4">

    <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:justify-between">
      <div>
        <h2 class="text-sm font-medium">Scheduled Tasks</h2>
        <p class="text-xs text-muted-foreground mt-0.5">Commands run automatically by Nexus on a schedule</p>
      </div>
      <div class="flex gap-2 shrink-0">
        <Button size="sm" variant="outline" class="gap-1.5" :disabled="loading" @click="load">
          <Loader2 v-if="loading" class="h-3.5 w-3.5 animate-spin" />
          <RefreshCw v-else class="h-3.5 w-3.5" />Refresh
        </Button>
        <Button size="sm" class="gap-1.5" @click="showAdd = !showAdd">
          <Plus class="h-3.5 w-3.5" />Add task
        </Button>
      </div>
    </div>

    <div v-if="showAdd" class="border rounded-xl p-4 space-y-4 bg-muted/20">
      <p class="text-sm font-medium">New scheduled task</p>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div class="space-y-1.5">
          <Label>Name <span class="text-muted-foreground text-xs">(optional)</span></Label>
          <Input v-model="form.name" placeholder="Daily backup" />
        </div>
        <div class="space-y-1.5">
          <Label>Interval</Label>
          <select v-model.number="form.intervalMinutes"
                  class="w-full h-9 px-3 rounded-md border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/50">
            <option v-for="i in INTERVALS" :key="i.value" :value="i.value">{{ i.label }}</option>
          </select>
        </div>
      </div>
      <div v-if="form.intervalMinutes === 0" class="space-y-1.5">
        <Label>Custom interval (minutes)</Label>
        <Input v-model.number="form.customInterval" type="number" min="1" placeholder="60" />
      </div>
      <div class="space-y-1.5">
        <Label>Command</Label>
        <Input v-model="form.command" class="font-mono text-sm" placeholder="/usr/bin/backup.sh >> /var/log/backup.log 2>&1" />
      </div>
      <div class="flex flex-col-reverse sm:flex-row gap-2">
        <Button variant="outline" class="sm:w-auto" @click="showAdd = false">Cancel</Button>
        <Button class="gap-2 sm:w-auto" :disabled="saving" @click="addTask">
          <Loader2 v-if="saving" class="h-4 w-4 animate-spin" />Add task
        </Button>
      </div>
    </div>

    <div v-if="loading && !tasks.length" class="space-y-2">
      <div v-for="i in 3" :key="i" class="h-16 rounded-lg bg-muted animate-pulse" />
    </div>

    <div v-else-if="!loading && !tasks.length"
         class="text-center py-12 text-muted-foreground text-sm border rounded-xl">
      <Clock class="h-8 w-8 mx-auto mb-2 opacity-30" />
      No scheduled tasks yet
    </div>

    <div v-else class="space-y-2">
      <div v-for="task in tasks" :key="task.id"
           class="border rounded-xl p-4 bg-card hover:bg-muted/10 transition-colors">
        <div class="flex items-start gap-3">

          <label class="mt-0.5 cursor-pointer shrink-0" @click.stop="toggleEnabled(task)">
            <div :class="['h-5 w-5 rounded-full border-2 flex items-center justify-center transition-colors',
              task.enabled ? 'bg-primary border-primary' : 'border-muted-foreground/40']">
              <div v-if="task.enabled" class="h-2 w-2 rounded-full bg-white" />
            </div>
          </label>

          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2 flex-wrap">
              <p class="text-sm font-medium">{{ task.name }}</p>
              <span class="text-[10px] px-2 py-0.5 rounded-full bg-muted text-muted-foreground font-medium">
                {{ fmtInterval(task.intervalMinutes) }}
              </span>
              <span v-if="!task.enabled"
                    class="text-[10px] px-2 py-0.5 rounded-full bg-yellow-500/10 text-yellow-600 font-medium">
                Paused
              </span>
            </div>
            <p class="text-xs font-mono text-muted-foreground mt-0.5 truncate">{{ task.command }}</p>
            <p class="text-xs text-muted-foreground mt-1">Executes as {{ task.actorId }}</p>
            <div class="flex flex-wrap items-center gap-3 mt-2 text-xs text-muted-foreground">
              <span class="flex items-center gap-1">
                <CheckCircle2 v-if="task.lastStatus === 'ok'"      class="h-3 w-3 text-green-500" />
                <XCircle      v-else-if="task.lastStatus === 'failed'"  class="h-3 w-3 text-destructive" />
                <Loader2      v-else-if="task.lastStatus === 'running'" class="h-3 w-3 animate-spin text-blue-500" />
                <Clock v-else class="h-3 w-3" />
                <span :class="STATUS_COLOR[task.lastStatus] ?? 'text-muted-foreground'">{{ task.lastStatus }}</span>
              </span>
              <span>Last: {{ fmtDate(task.lastRunAt) }}</span>
              <span v-if="task.enabled && task.nextRunAt" class="hidden sm:inline">Next: {{ fmtDate(task.nextRunAt) }}</span>
            </div>
            <details v-if="task.lastOutput" class="mt-2">
              <summary class="text-xs text-muted-foreground cursor-pointer hover:text-foreground">Last output</summary>
              <pre class="mt-1 text-[10px] font-mono bg-muted rounded-lg px-3 py-2 max-h-32 overflow-y-auto whitespace-pre-wrap">{{ task.lastOutput }}</pre>
            </details>
          </div>

          <div class="flex items-center gap-1 shrink-0">
            <Button size="icon" variant="ghost" class="h-7 w-7" :disabled="!!running[task.id] || task.lastStatus === 'running'" @click="runNow(task)">
              <Loader2 v-if="running[task.id]" class="h-3.5 w-3.5 animate-spin" />
              <Play v-else class="h-3.5 w-3.5" />
            </Button>
            <Button size="icon" variant="ghost" class="h-7 w-7 text-destructive hover:text-destructive" @click="deleteTask(task)">
              <Trash2 class="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </div>
    </div>

  </div>
</template>