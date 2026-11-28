<script setup lang="ts">
import type { ClassValue } from 'clsx';
import { cn } from '@/lib/utils';

const props = defineProps<{
  id?: string;
  type?: string;
  placeholder?: string;
  required?: boolean;
  class?: ClassValue;
  modelValue?: string | number;
  readOnly?: boolean;
}>();

defineEmits<{ 'update:modelValue': [string] }>();
</script>

<template>
  <input
    :id="id"
    :type="props.type ?? 'text'"
    :value="props.modelValue"
    :placeholder="props.placeholder"
    :required="props.required"
    :readonly="props.readOnly"
    :class="
      cn(
        'flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50',
        props.class,
      )
    "
    @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
  />
</template>
