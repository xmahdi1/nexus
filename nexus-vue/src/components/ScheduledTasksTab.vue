<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue'
import { toast } from 'vue-sonner'
import { Plus, Trash2, Loader2, RefreshCw, Play, Clock, CheckCircle2, XCircle } from '@lucide/vue'
import { api } from '@/lib/api'
import type { ScheduledTask, SupervisedRun, RunObservation } from '@/lib/api'
import { can } from '@/lib/auth'
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
const form    = ref({ name: '', command: '', intervalMinutes: 60, customInterval: 60, supervised: false })
const supervisionEnabled = ref(false)
const selectedTask = ref<ScheduledTask | null>(null)
const runs = ref<SupervisedRun[]>([])
const observation = ref<RunObservation | null>(null)
const runBusy = ref(false)
let alive = true
const timers: ReturnType<typeof setTimeout>[] = []
onUnmounted(() => { alive = false; timers.forEach(clearTimeout) })
watch(() => props.serverId, () => { selectedTask.value = null; observation.value = null; runs.value = []; void load() })
function allowed(...permissions: string[]) { return permissions.every(permission => can(permission, props.serverId)) }
function blocked(task: ScheduledTask) { return task.lastStatus === 'running' || (task.supervised && task.lastStatus === 'remote_unknown') }

function fmtInterval(m: number) {
  if (m < 60)   return `Every ${m}m`
  if (m < 1440) return `Every ${m / 60}h`
  return 'Daily'
}

function fmtDate(s: string | null | undefined) {
  return s ? new Date(s).toLocaleString() : 'Never'
}

async function load() {
  const server = props.serverId
  loading.value = true
  try   { const result = await api.tasks.list(server); if (alive && server === props.serverId) tasks.value = result }
  catch { toast.error('Failed to load tasks') }
  finally { loading.value = false }
}

onMounted(async () => { await Promise.all([load(), api.features().then(features => { supervisionEnabled.value = !!features.jobSupervision }).catch(() => {})]) })

async function loadRuns(task: ScheduledTask) {
  const server = props.serverId
  if (selectedTask.value?.id !== task.id) runs.value = []
  selectedTask.value = task
  observation.value = null
  try { const result = await api.tasks.runs(server, task.id); if (alive && server === props.serverId && selectedTask.value?.id === task.id) runs.value = result }
  catch (error) { toast.error(error instanceof Error ? error.message : 'Could not load run history') }
}
async function runAction(run: SupervisedRun, action: 'read' | 'inspect' | 'cancel' | 'release') {
  const server = props.serverId
  if (runBusy.value) return
  if (action === 'cancel' && !await confirm({title: 'Cancel supervised run?', message: 'Stop this run and pause its task schedule? Completed side effects are not rolled back. Work handed off to Docker or other services may continue.', confirmText: 'Cancel run', destructive: true})) return
  if (action === 'release' && !await confirm({title: 'Remove remote run artifacts?', message: 'Remove this completed run’s private remote files? Its encrypted output remains in Nexus.', confirmText: 'Remove artifacts', destructive: true})) return
  if (!alive || server !== props.serverId || selectedTask.value?.id !== run.taskId) return
  runBusy.value = true
  try {
    const invoke = {read: api.tasks.readRun, inspect: api.tasks.inspectRun, cancel: api.tasks.cancelRun, release: api.tasks.releaseRun}[action]
    const result = await invoke(server, run.taskId, run.id)
    if (alive && server === props.serverId && selectedTask.value?.id === run.taskId) observation.value = result
    const history = await api.tasks.runs(server, run.taskId)
    if (alive && server === props.serverId && selectedTask.value?.id === run.taskId) runs.value = history
    if (alive && server === props.serverId) await load()
  } catch (error) { toast.error(error instanceof Error ? error.message : 'Run state could not be verified') }
  finally { runBusy.value = false }
}

async function addTask() {
  if (!form.value.command) { toast.error('Command is required'); return }
  const interval = form.value.intervalMinutes === 0 ? form.value.customInterval : form.value.intervalMinutes
  saving.value = true
  try {
    await api.tasks.create(props.serverId, {
      name:            form.value.name || form.value.command.slice(0, 40),
      command:         form.value.command,
      intervalMinutes: interval,
      supervised: form.value.supervised,
    })
    toast.success('Task scheduled')
    form.value    = { name: '', command: '', intervalMinutes: 60, customInterval: 60, supervised: false }
    showAdd.value = false
    await load()
  } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
  finally { saving.value = false }
}

async function toggleEnabled(task: ScheduledTask) {
  if (blocked(task) || !allowed('jobs.manage', 'jobs.execute', 'servers.execute', 'secrets.use')) return
  try { await api.tasks.update(props.serverId, task.id, { enabled: !task.enabled }); await load() }
  catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
}

async function runNow(task: ScheduledTask) {
  running.value[task.id] = true
  try {
    await api.tasks.runNow(props.serverId, task.id)
    toast.success('Task triggered — will run within 30 seconds')
    timers.push(setTimeout(load, 5000))
  } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
  finally {
    timers.push(setTimeout(() => { delete running.value[task.id]; running.value = { ...running.value } }, 3000))
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
        <Button v-if="allowed('jobs.create','jobs.execute','servers.execute','secrets.use')" size="sm" class="gap-1.5" @click="showAdd = !showAdd">
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
      <label v-if="supervisionEnabled" class="flex items-start gap-2 text-sm">
        <input v-model="form.supervised" type="checkbox" class="mt-1" />
        <span>Track remotely and allow cancellation
          <span class="block text-xs text-muted-foreground">Requires root SSH, systemd, cgroup v2 and Python 3. Runs for at most 10 minutes, starting in /. Use cd explicitly when needed. Output is bounded and encrypted.</span>
          <span class="block text-xs text-muted-foreground">Cancellation controls this service’s processes. Work delegated to Docker or another service may continue.</span>
        </span>
      </label>
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

          <button v-if="allowed('jobs.manage','jobs.execute','servers.execute','secrets.use')" type="button" role="switch" :aria-checked="task.enabled" :aria-label="`Enable task ${task.name}`" :disabled="blocked(task)" class="mt-0.5 shrink-0 disabled:opacity-50" @click.stop="toggleEnabled(task)">
            <div :class="['h-5 w-5 rounded-full border-2 flex items-center justify-center transition-colors',
              task.enabled ? 'bg-primary border-primary' : 'border-muted-foreground/40']">
              <div v-if="task.enabled" class="h-2 w-2 rounded-full bg-white" />
            </div>
          </button>

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
              <span v-if="task.supervised" class="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-600">Supervised</span>
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
            <Button v-if="task.supervised" size="sm" variant="ghost" :aria-label="`Run history for ${task.name}`" @click="loadRuns(task)">Runs</Button>
            <Button v-if="allowed('jobs.execute','servers.execute','secrets.use')" size="icon" variant="ghost" class="h-7 w-7" :aria-label="`Run ${task.name} now`" :disabled="!!running[task.id] || blocked(task)" @click="runNow(task)">
              <Loader2 v-if="running[task.id]" class="h-3.5 w-3.5 animate-spin" />
              <Play v-else class="h-3.5 w-3.5" />
            </Button>
            <Button v-if="allowed('jobs.manage')" size="icon" variant="ghost" class="h-7 w-7 text-destructive hover:text-destructive" :aria-label="`Delete task ${task.name}`" :disabled="blocked(task)" @click="deleteTask(task)">
              <Trash2 class="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </div>
    </div>

    <section v-if="selectedTask" class="border rounded-xl p-4 space-y-3" aria-label="Supervised run history">
      <div class="flex justify-between items-center"><h3 class="text-sm font-medium">Runs for {{ selectedTask.name }}</h3><Button variant="ghost" size="sm" @click="selectedTask = null; observation = null">Close history</Button></div>
      <p class="text-xs text-muted-foreground">Unknown runs are never replayed automatically. Cancelling does not undo completed side effects.</p>
      <p v-if="!runs.length" class="text-xs text-muted-foreground">No supervised runs yet.</p>
      <div v-for="run in runs" :key="run.id" class="border rounded-lg p-3 space-y-2">
        <p class="text-xs font-mono break-all">{{ run.id }}</p>
        <p class="text-xs">{{ run.state }} · {{ fmtDate(run.createdAt) }}<span v-if="run.exitCode !== null"> · exit {{ run.exitCode }}</span></p>
        <p v-if="run.cancelRequestedAt && !run.finishedAt" class="text-xs text-amber-600">Cancellation requested; waiting for verified termination.</p>
        <p class="text-xs text-muted-foreground">Last verified: {{ fmtDate(run.verifiedAt) }}<span v-if="run.truncated"> · output truncated</span></p>
        <div class="flex flex-wrap gap-2">
          <Button v-if="allowed('jobs.read','logs.read','secrets.use')" size="sm" variant="outline" :disabled="runBusy" @click="runAction(run,'read')">View output</Button>
          <Button v-if="allowed('jobs.read','logs.read','servers.execute','secrets.use')" size="sm" variant="outline" :disabled="runBusy" @click="runAction(run,'inspect')">Inspect remote state</Button>
          <Button v-if="!run.finishedAt && allowed('jobs.cancel','servers.execute','secrets.use')" size="sm" variant="destructive" :disabled="runBusy" @click="runAction(run,'cancel')">Cancel run</Button>
          <Button v-if="run.finishedAt && run.verifiedAt && !run.artifactsRemoved && allowed('jobs.manage','logs.read','servers.execute','secrets.use')" size="sm" variant="outline" :disabled="runBusy" @click="runAction(run,'release')">Remove artifacts</Button>
        </div>
      </div>
      <div v-if="observation" class="space-y-2" role="status">
        <p class="text-sm">Observed: {{ observation.observation.state }} · verified: {{ observation.observation.verified ? 'yes' : 'no' }}</p>
        <p v-if="!observation.observation.verified && !observation.observation.noDispatch" class="text-xs text-amber-600">State is unverified. Inspect the target before retrying. Automatic retry is disabled.</p>
        <p v-if="observation.observation.noDispatch" class="text-xs">The command was not dispatched.</p>
        <p v-if="observation.observation.state === 'interrupted'" class="text-xs text-amber-600">The managed processes stopped without a complete command result. Inspect side effects before starting another run.</p>
        <pre v-if="observation.observation.output" class="text-xs font-mono bg-muted rounded-lg p-3 max-h-64 overflow-auto whitespace-pre-wrap">{{ observation.observation.output }}</pre>
      </div>
    </section>

  </div>
</template>
