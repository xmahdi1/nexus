<script setup lang="ts">
import {ref, computed, onMounted} from 'vue'
import {toast} from 'vue-sonner'
import {Plus, Pencil, Trash2, ExternalLink, Loader2, Bookmark} from '@lucide/vue'
import {api} from '@/lib/api'
import type {Service} from '@/lib/api'
import {useConfirm} from '@/composables/useConfirm'
import AppLayout from '@/components/AppLayout.vue'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
import Label from '@/components/ui/Label.vue'

const {confirm} = useConfirm()

const COLORS = ['#3b82f6', '#8b5cf6', '#ec4899', '#f97316', '#10b981', '#14b8a6', '#f59e0b', '#ef4444', '#6366f1', '#84cc16']
const CATEGORIES = ['Infrastructure', 'Media', 'Monitoring', 'Development', 'Networking', 'Other']

const services = ref<Service[]>([])
const loading = ref(false)
const showForm = ref(false)
const editingId = ref<string | null>(null)
const saving = ref(false)
const form = ref({name: '', url: '', icon: '🔗', description: '', category: '', color: COLORS[0]})

const grouped = computed(() => {
  const map = new Map<string, Service[]>()
  for (const s of services.value) {
    const cat = s.category || 'Other'
    if (!map.has(cat)) map.set(cat, [])
    map.get(cat)!.push(s)
  }
  return map
})

function isImageUrl(s: string) {
  return s?.startsWith('http') || s?.startsWith('/')
}

function openURL(url: string) {
  window.open(url.startsWith('http') ? url : 'https://' + url, '_blank', 'noopener')
}

function openCreate() {
  editingId.value = null
  form.value = {name: '', url: '', icon: '🔗', description: '', category: '', color: COLORS[0]}
  showForm.value = true
}

function openEdit(svc: Service) {
  editingId.value = svc.id
  form.value = {
    name: svc.name, url: svc.url, icon: svc.icon || '🔗',
    description: svc.description || '', category: svc.category || '', color: svc.color || COLORS[0],
  }
  showForm.value = true
}

function closeForm() {
  showForm.value = false;
  editingId.value = null
}

async function loadServices() {
  loading.value = true
  try {
    services.value = await api.services.list()
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to load services')
  } finally {
    loading.value = false
  }
}

async function saveService() {
  if (!form.value.name || !form.value.url) {
    toast.error('Name and URL are required');
    return
  }
  saving.value = true
  try {
    if (editingId.value) {
      const updated = await api.services.update(editingId.value, form.value)
      const idx = services.value.findIndex(s => s.id === editingId.value)
      if (idx >= 0) services.value[idx] = updated
      toast.success('Service updated')
    } else {
      const svc = await api.services.create(form.value)
      services.value.push(svc)
      toast.success(`${svc.name} added`)
    }
    closeForm()
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to save')
  } finally {
    saving.value = false
  }
}

async function deleteService(svc: Service) {
  const ok = await confirm({
    title: 'Remove service',
    message: `Remove "${svc.name}"?`,
    confirmText: 'Remove',
    destructive: true
  })
  if (!ok) return
  try {
    await api.services.delete(svc.id)
    services.value = services.value.filter(s => s.id !== svc.id)
    toast.success('Removed')
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed')
  }
}

onMounted(loadServices)
</script>

<template>
  <AppLayout>
    <div class="max-w-7xl mx-auto space-y-6">

      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-xl sm:text-2xl font-semibold tracking-tight">Services</h1>
          <p class="text-sm text-muted-foreground mt-0.5">Your self-hosted services and dashboards</p>
        </div>
        <Button class="gap-2" @click="openCreate">
          <Plus class="h-4 w-4"/>
          <span class="hidden sm:inline">Add service</span>
        </Button>
      </div>

      <div v-if="loading" class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
        <div v-for="i in 8" :key="i" class="h-32 rounded-xl bg-muted animate-pulse"/>
      </div>

      <div v-else-if="!services.length"
           class="flex flex-col items-center justify-center py-16 sm:py-24 text-center border rounded-2xl px-4">
        <div class="h-16 w-16 rounded-2xl bg-muted flex items-center justify-center mb-4">
          <Bookmark class="h-8 w-8 text-muted-foreground/50"/>
        </div>
        <p class="text-base font-medium">No services yet</p>
        <p class="text-sm text-muted-foreground mt-1 mb-4">Add your self-hosted services to access them quickly</p>
        <Button class="gap-2" @click="openCreate">
          <Plus class="h-4 w-4"/>
          Add your first service
        </Button>
      </div>

      <template v-else>
        <div v-for="[category, items] in grouped" :key="category" class="space-y-3">
          <div class="flex items-center gap-2">
            <h2 class="text-xs font-semibold uppercase tracking-widest text-muted-foreground">{{ category }}</h2>
            <div class="flex-1 h-px bg-border"/>
            <span class="text-xs text-muted-foreground">{{ items.length }}</span>
          </div>
          <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
            <div v-for="svc in items" :key="svc.id"
                 class="group relative bg-card border rounded-xl p-4 cursor-pointer hover:shadow-md
                     transition-all duration-200 hover:-translate-y-0.5 overflow-hidden"
                 @click="openURL(svc.url)">
              <div class="absolute left-0 top-0 bottom-0 w-1 rounded-l-xl"
                   :style="{ background: svc.color || '#3b82f6' }"/>
              <div class="absolute top-2 right-2 hidden group-hover:flex items-center gap-1 z-10" @click.stop>
                <button
                    class="h-6 w-6 rounded-md bg-background/80 backdrop-blur flex items-center justify-center hover:bg-muted"
                    @click="openEdit(svc)">
                  <Pencil class="h-3 w-3"/>
                </button>
                <button
                    class="h-6 w-6 rounded-md bg-background/80 backdrop-blur flex items-center justify-center hover:bg-destructive/10 text-destructive"
                    @click="deleteService(svc)">
                  <Trash2 class="h-3 w-3"/>
                </button>
              </div>
              <div class="pl-2 space-y-2">
                <div class="text-2xl leading-none">
                  <img v-if="isImageUrl(svc.icon)" :src="svc.icon" class="h-7 w-7 rounded object-cover"/>
                  <span v-else>{{ svc.icon || '🔗' }}</span>
                </div>
                <div>
                  <p class="font-semibold text-sm leading-tight truncate">{{ svc.name }}</p>
                  <p v-if="svc.description" class="text-xs text-muted-foreground mt-0.5 line-clamp-2">{{
                      svc.description
                    }}</p>
                </div>
                <div class="flex items-center gap-1 text-xs text-muted-foreground/70">
                  <ExternalLink class="h-2.5 w-2.5 shrink-0"/>
                  <span class="truncate">{{ svc.url }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </template>

    </div>

    <Transition enter-active-class="transition-opacity duration-150" enter-from-class="opacity-0"
                leave-active-class="transition-opacity duration-100" leave-to-class="opacity-0">
      <div v-if="showForm" class="fixed inset-0 z-[200] flex items-end sm:items-center justify-center sm:p-4">
        <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" @click="closeForm"/>
        <div
            class="relative z-10 w-full sm:max-w-lg bg-card border sm:rounded-2xl rounded-t-2xl shadow-2xl p-5 sm:p-6 space-y-4 max-h-[85dvh] overflow-y-auto sm:max-h-none sm:overflow-visible"
            @click.stop>
          <h3 class="font-semibold">{{ editingId ? 'Edit service' : 'Add service' }}</h3>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div class="space-y-1.5 sm:col-span-2">
              <Label>Name</Label>
              <Input v-model="form.name" placeholder="Portainer"/>
            </div>
            <div class="space-y-1.5 sm:col-span-2">
              <Label>URL</Label>
              <Input v-model="form.url" placeholder="192.168.1.50:9000" class="font-mono text-sm"/>
            </div>
            <div class="space-y-1.5">
              <Label>Icon (emoji or image URL)</Label>
              <Input v-model="form.icon" placeholder="🐋"/>
            </div>
            <div class="space-y-1.5">
              <Label>Category</Label>
              <select v-model="form.category"
                      class="w-full h-9 px-3 rounded-md border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/50">
                <option value="">None</option>
                <option v-for="c in CATEGORIES" :key="c" :value="c">{{ c }}</option>
              </select>
            </div>
            <div class="space-y-1.5 sm:col-span-2">
              <Label>Description (optional)</Label>
              <Input v-model="form.description" placeholder="Container management dashboard"/>
            </div>
            <div class="space-y-2 sm:col-span-2">
              <Label>Accent color</Label>
              <div class="flex gap-2 flex-wrap">
                <button v-for="c in COLORS" :key="c"
                        :class="['h-7 w-7 rounded-lg transition-transform border-2',
                    form.color === c ? 'scale-110 border-foreground' : 'border-transparent hover:scale-105']"
                        :style="{ background: c }" @click="form.color = c"/>
              </div>
            </div>
          </div>
          <div class="border rounded-xl p-3 bg-muted/30">
            <p class="text-xs text-muted-foreground mb-2 font-medium">Preview</p>
            <div class="bg-card border rounded-xl p-4 overflow-hidden relative w-48">
              <div class="absolute left-0 top-0 bottom-0 w-1 rounded-l-xl" :style="{ background: form.color }"/>
              <div class="pl-2 space-y-2">
                <div class="text-2xl leading-none">
                  <img v-if="isImageUrl(form.icon)" :src="form.icon" class="h-7 w-7 rounded object-cover"/>
                  <span v-else>{{ form.icon || '🔗' }}</span>
                </div>
                <div>
                  <p class="font-semibold text-sm truncate">{{ form.name || 'Service name' }}</p>
                  <p class="text-xs text-muted-foreground mt-0.5 truncate">{{ form.description || 'Description' }}</p>
                </div>
                <div class="flex items-center gap-1 text-xs text-muted-foreground/70">
                  <ExternalLink class="h-2.5 w-2.5"/>
                  <span class="truncate">{{ form.url || 'url' }}</span>
                </div>
              </div>
            </div>
          </div>
          <div class="flex flex-col-reverse sm:flex-row gap-2 pt-1">
            <Button variant="outline" class="sm:w-auto" @click="closeForm">Cancel</Button>
            <Button class="flex-1 gap-2" :disabled="saving" @click="saveService">
              <Loader2 v-if="saving" class="h-4 w-4 animate-spin"/>
              {{ editingId ? 'Save changes' : 'Add service' }}
            </Button>
          </div>
        </div>
      </div>
    </Transition>
  </AppLayout>
</template>