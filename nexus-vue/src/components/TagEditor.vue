<script setup lang="ts">
import { ref, computed } from 'vue'
import { Plus, X } from '@lucide/vue'

const props = defineProps<{ modelValue: string; disabled?: boolean }>()
const emit  = defineEmits<{ 'update:modelValue': [string]; save: [string] }>()

const editing = ref(false)
const input   = ref('')

const COLORS = [
  'bg-blue-500/15   text-blue-600   border-blue-500/25   dark:text-blue-400',
  'bg-green-500/15  text-green-600  border-green-500/25  dark:text-green-400',
  'bg-purple-500/15 text-purple-600 border-purple-500/25 dark:text-purple-400',
  'bg-orange-500/15 text-orange-600 border-orange-500/25 dark:text-orange-400',
  'bg-pink-500/15   text-pink-600   border-pink-500/25   dark:text-pink-400',
  'bg-cyan-500/15   text-cyan-600   border-cyan-500/25   dark:text-cyan-400',
  'bg-yellow-500/15 text-yellow-600 border-yellow-500/25 dark:text-yellow-400',
  'bg-red-500/15    text-red-600    border-red-500/25    dark:text-red-400',
]

const tags = computed(() =>
    props.modelValue ? props.modelValue.split(',').map(t => t.trim()).filter(Boolean) : [],
)

function tagColor(t: string): string {
  let h = 0
  for (let i = 0; i < t.length; i++) h = (h * 31 + t.charCodeAt(i)) | 0
  return COLORS[Math.abs(h) % COLORS.length]
}

function commit(newTags: string[]) {
  const val = newTags.join(',')
  emit('update:modelValue', val)
  emit('save', val)
}

function removeTag(tag: string) { commit(tags.value.filter(t => t !== tag)) }

function addTag() {
  const val = input.value.trim().toLowerCase()
  editing.value = false
  input.value   = ''
  if (!val || tags.value.includes(val)) return
  commit([...tags.value, val])
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Enter')  { e.preventDefault(); addTag() }
  if (e.key === 'Escape') { editing.value = false; input.value = '' }
}
</script>

<template>
  <div class="flex items-center gap-1.5 flex-wrap min-h-[1.5rem]">
    <span v-for="tag in tags" :key="tag"
          :class="['inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-medium border', tagColor(tag)]">
      {{ tag }}
      <button v-if="!disabled" class="opacity-60 hover:opacity-100 hover:text-destructive transition-opacity"
              @click.stop="removeTag(tag)">
        <X class="h-3 w-3" />
      </button>
    </span>

    <input v-if="editing" v-model="input"
           class="h-6 w-24 px-2 rounded-md border bg-background text-xs font-mono focus:outline-none focus:ring-1 focus:ring-primary"
           placeholder="tag…" autofocus @keydown="onKeydown" @blur="addTag" />

    <button v-else-if="!disabled"
            class="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs border border-dashed
             text-muted-foreground hover:text-foreground hover:border-foreground/40 transition-colors"
            @click="editing = true">
      <Plus class="h-3 w-3" />tag
    </button>
  </div>
</template>