<script setup lang="ts">
import { ref, computed } from 'vue';
import { ChevronDown } from '@lucide/vue';
import { cn } from '@/lib/utils';
import { onClickOutside } from '@vueuse/core';

const props = defineProps<{
  modelValue: string;
  options: Array<{ value: string; label: string }>;
  class?: string;
}>();
const emit = defineEmits<{ 'update:modelValue': [string] }>();

const open = ref(false);
const container = ref<HTMLElement | null>(null);
const selected = computed(() => props.options.find((o) => o.value === props.modelValue)?.label ?? '');

onClickOutside(container, () => {
  open.value = false;
});

function select(v: string) {
  emit('update:modelValue', v);
  open.value = false;
}
</script>

<template>
  <div ref="container" :class="cn('relative w-full', props.class)">
    <button
      type="button"
      class="flex h-9 w-full items-center justify-between rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring cursor-pointer"
      @click="open = !open"
    >
      <span>{{ selected }}</span>
      <ChevronDown class="h-4 w-4 opacity-50" />
    </button>
    <Transition
      enter-active-class="transition duration-100 ease-out"
      enter-from-class="opacity-0 scale-95"
      enter-to-class="opacity-100 scale-100"
      leave-active-class="transition duration-75 ease-in"
      leave-from-class="opacity-100 scale-100"
      leave-to-class="opacity-0 scale-95"
    >
      <div
        v-if="open"
        class="absolute z-50 top-full mt-1 w-full rounded-md border bg-popover shadow-md overflow-hidden"
      >
        <button
          v-for="opt in options"
          :key="opt.value"
          type="button"
          class="flex w-full items-center px-3 py-2 text-sm hover:bg-accent hover:text-accent-foreground cursor-pointer"
          :class="{ 'font-medium': opt.value === modelValue }"
          @click="select(opt.value)"
        >
          {{ opt.label }}
        </button>
      </div>
    </Transition>
  </div>
</template>
