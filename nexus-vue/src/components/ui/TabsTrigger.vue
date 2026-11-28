<script setup lang="ts">
import { inject, computed } from 'vue';
import type { Ref } from 'vue';

const props = defineProps<{ value: string }>();
const active = inject<Ref<string>>('tabs-active')!;
const isActive = computed(() => active.value === props.value);
function activate() {
  active.value = props.value;
}
</script>

<template>
  <button
    type="button"
    :class="[
      'inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1 text-sm font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring cursor-pointer',
      isActive ? 'bg-background text-foreground shadow' : 'hover:bg-background/50',
    ]"
    @click="activate"
  >
    <slot />
  </button>
</template>
