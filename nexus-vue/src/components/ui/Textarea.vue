<script setup lang="ts">
import { cn } from '@/lib/utils'
const props = defineProps<{ modelValue?: string; readOnly?: boolean; class?: string }>()
defineEmits<{ 'update:modelValue': [string] }>()
</script>
<template>
  <textarea
    :value="props.modelValue"
    :readonly="props.readOnly"
    :class="cn('flex min-h-[60px] w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 resize-none', props.class)"
    @input="$emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"
  />
</template>
