<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { toast } from 'vue-sonner'
import { Clock, Loader2, Plus, RefreshCw, Trash2 } from '@lucide/vue'
import { api } from '@/lib/api'
import type { CronJob } from '@/lib/api'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
import Label from '@/components/ui/Label.vue'
import { useConfirm } from '@/composables/useConfirm'

const props = defineProps<{ serverId: string }>()
const { confirm } = useConfirm()

const PRESETS = [
  { label: 'Every minute',      value: '* * * * *' },
  { label: 'Every hour',        value: '0 * * * *' },
  { label: 'Daily at midnight', value: '0 0 * * *' },
  { label: 'Every Sunday',      value: '0 0 * * 0' },
  { label: 'On reboot',         value: '@reboot'   },
  { label: 'Custom',            value: ''          },
]

const HINTS: Record<string, string> = {
  '* * * * *': 'Every minute',
  '0 * * * *': 'Every hour',
  '0 0 * * *': 'Daily at midnight',
  '0 0 * * 0': 'Every Sunday',
  '@reboot':   'On system reboot',
  '@daily':    'Daily',
  '@weekly':   'Weekly',
  '@monthly':  'Monthly',
  '@hourly':   'Every hour',
}

const jobs    = ref<CronJob[]>([])
const loading = ref(true)
const saving  = ref(false)
const showAdd = ref(false)
const form    = ref({ schedule: '0 * * * *', command: '', preset: '0 * * * *' })

function applyPreset(val: string) {
  form.value.preset   = val
  form.value.schedule = val
}

async function load() {
  loading.value = true
  try   { jobs.value = await api.cron.list(props.serverId) }
  catch { toast.error('Failed to load cron jobs') }
  finally { loading.value = false }
}

onMounted(load)

async function addJob() {
  if (!form.value.schedule || !form.value.command) {
    toast.error('Schedule and command are required'); return
  }
  saving.value = true
  try {
    await api.cron.add(props.serverId, { schedule: form.value.schedule, command: form.value.command })
    toast.success('Cron job added')
    form.value.command = ''
    showAdd.value = false
    await load()
  } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
  finally { saving.value = false }
}

async function deleteJob(job: CronJob) {
  const ok = await confirm({
    title: 'Delete cron job', message: `Remove: ${job.raw}?`,
    confirmText: 'Delete', destructive: true,
  })
  if (!ok) return
  try {
    await api.cron.delete(props.serverId, job.raw)
    toast.success('Deleted')
    await load()
  } catch (e) { toast.error(e instanceof Error ? e.message : 'Failed') }
}
</script>

<template>
  <div class="space-y-4">

    <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:justify-between">
      <div>
        <h2 class="text-sm font-medium">Cron Jobs</h2>
        <p class="text-xs text-muted-foreground mt-0.5">Scheduled tasks on this server via crontab</p>
      </div>
      <div class="flex gap-2 shrink-0">
        <Button size="sm" variant="outline" class="gap-1.5" :disabled="loading" @click="load">
          <Loader2 v-if="loading" class="h-3.5 w-3.5 animate-spin" />
          <RefreshCw v-else class="h-3.5 w-3.5" />
          Refresh
        </Button>
        <Button size="sm" class="gap-1.5" @click="showAdd = !showAdd">
          <Plus class="h-3.5 w-3.5" />Add job
        </Button>
      </div>
    </div>

    <div v-if="showAdd" class="border rounded-xl p-4 space-y-4 bg-muted/20">
      <p class="text-sm font-medium">New cron job</p>
      <div class="space-y-1.5">
        <Label>Schedule preset</Label>
        <div class="flex flex-wrap gap-2">
          <button v-for="p in PRESETS" :key="p.label"
                  :class="['px-3 py-1 rounded-lg text-xs font-medium border transition-colors',
              form.preset === p.value && p.value !== ''
                ? 'bg-primary text-primary-foreground border-primary'
                : 'bg-background border-border hover:bg-muted']"
                  @click="applyPreset(p.value)">
            {{ p.label }}
          </button>
        </div>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div class="space-y-1.5">
          <Label>Cron expression</Label>
          <Input v-model="form.schedule" class="font-mono text-sm" placeholder="0 * * * *" />
          <p class="text-xs text-muted-foreground">min hour dom month dow</p>
        </div>
        <div class="space-y-1.5">
          <Label>Command</Label>
          <Input v-model="form.command" class="font-mono text-sm" placeholder="/usr/bin/backup.sh" />
        </div>
      </div>
      <div v-if="form.schedule && form.command"
           class="text-xs font-mono bg-muted rounded-lg px-3 py-2 text-muted-foreground">
        {{ form.schedule }} {{ form.command }}
      </div>
      <div class="flex flex-col-reverse sm:flex-row gap-2">
        <Button variant="outline" class="sm:w-auto" @click="showAdd = false">Cancel</Button>
        <Button class="gap-2 sm:w-auto" :disabled="saving" @click="addJob">
          <Loader2 v-if="saving" class="h-4 w-4 animate-spin" />Add job
        </Button>
      </div>
    </div>

    <div v-if="loading && !jobs.length" class="space-y-2">
      <div v-for="i in 3" :key="i" class="h-12 rounded-lg bg-muted animate-pulse" />
    </div>

    <div v-else-if="!loading && !jobs.length"
         class="text-center py-12 text-muted-foreground text-sm border rounded-xl">
      <Clock class="h-8 w-8 mx-auto mb-2 opacity-30" />
      No cron jobs configured
    </div>

    <div v-else class="border rounded-xl overflow-x-auto">
      <table class="w-full text-sm min-w-[400px]">
        <thead>
        <tr class="border-b bg-muted/40">
          <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">Schedule</th>
          <th class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide">Command</th>
          <th class="text-right px-4 py-2.5 w-12" />
        </tr>
        </thead>
        <tbody>
        <tr v-for="job in jobs" :key="job.index" class="border-b last:border-0 hover:bg-muted/10 transition-colors">
          <td class="px-4 py-3">
            <p class="font-mono text-xs font-medium">{{ job.schedule }}</p>
            <p v-if="HINTS[job.schedule]" class="text-[10px] text-muted-foreground mt-0.5">{{ HINTS[job.schedule] }}</p>
          </td>
          <td class="px-4 py-3 font-mono text-xs text-muted-foreground max-w-[200px] truncate">{{ job.command }}</td>
          <td class="px-4 py-3 text-right">
            <Button size="icon" variant="ghost" class="h-7 w-7 text-destructive hover:text-destructive"
                    @click="deleteJob(job)">
              <Trash2 class="h-3.5 w-3.5" />
            </Button>
          </td>
        </tr>
        </tbody>
      </table>
    </div>

  </div>
</template>