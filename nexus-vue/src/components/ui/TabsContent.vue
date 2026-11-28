<script setup lang="ts">
import { inject, computed } from 'vue';
import type { Ref } from 'vue';

const props = defineProps<{ value: string }>();
const active = inject<Ref<string>>('tabs-active')!;
const isActive = computed(() => active.value === props.value);
</script>

<template>
  <div v-if="isActive" class="mt-4 focus-visible:outline-none">
    <slot />
  </div>
</template>
