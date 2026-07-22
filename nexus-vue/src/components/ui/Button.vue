<script setup lang="ts">
import { computed } from 'vue'
import { cn } from '@/lib/utils'

const props = withDefaults(
  defineProps<{
    variant?: 'default' | 'outline' | 'ghost' | 'secondary' | 'destructive'
    size?: 'default' | 'sm' | 'icon'
    disabled?: boolean
    type?: 'button' | 'submit' | 'reset'
    class?: string
  }>(),
  { variant: 'default', size: 'default', type: 'button' },
)

const classes = computed(() =>
  cn(
    'inline-flex items-center justify-center font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 cursor-pointer',
    {
      'bg-primary text-primary-foreground hover:opacity-90': props.variant === 'default',
      'border border-input bg-transparent hover:bg-accent hover:text-accent-foreground': props.variant === 'outline',
      'hover:bg-accent hover:text-accent-foreground': props.variant === 'ghost',
      'bg-secondary text-secondary-foreground hover:bg-secondary/80': props.variant === 'secondary',
      'bg-destructive text-destructive-foreground hover:opacity-90': props.variant === 'destructive',
      'h-9 px-4 py-2 rounded-md text-sm gap-2': props.size === 'default',
      'h-8 px-3 rounded-md text-xs gap-1.5': props.size === 'sm',
      'h-9 w-9 rounded-md': props.size === 'icon',
    },
    props.class,
  ),
)
</script>

<template>
  <button :type="type" :disabled="disabled" :class="classes">
    <slot />
  </button>
</template>
