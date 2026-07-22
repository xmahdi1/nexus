<script setup lang="ts">
import { cn } from '@/lib/utils'
const props = withDefaults(defineProps<{ variant?: 'default' | 'secondary'; class?: string }>(), { variant: 'default' })
</script>
<template>
  <span :class="cn(
    'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold transition-colors',
    props.variant === 'secondary' ? 'bg-secondary text-secondary-foreground border-transparent' : 'bg-primary text-primary-foreground border-transparent',
    props.class
  )">
    <slot />
  </span>
</template>
