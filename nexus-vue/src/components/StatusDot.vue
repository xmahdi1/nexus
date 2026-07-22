<script setup lang="ts">
import { computed } from 'vue'
import { cn } from '@/lib/utils'

const props = defineProps<{
  status: 'online' | 'offline' | 'connecting' | 'running' | 'exited' | 'paused'
  class?: string
}>()

const color = computed(() => {
  if (props.status === 'online' || props.status === 'running')
    return 'bg-[var(--color-success)] shadow-[0_0_0_3px_color-mix(in_oklab,var(--color-success)_25%,transparent)]'
  if (props.status === 'connecting' || props.status === 'paused')
    return 'bg-[var(--color-warning)] shadow-[0_0_0_3px_color-mix(in_oklab,var(--color-warning)_25%,transparent)] animate-pulse'
  return 'bg-[var(--color-destructive)] shadow-[0_0_0_3px_color-mix(in_oklab,var(--color-destructive)_25%,transparent)]'
})
</script>

<template>
  <span :class="cn('inline-block h-2 w-2 rounded-full', color, props.class)" />
</template>