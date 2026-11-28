<script setup lang="ts">
import { ref, provide } from 'vue';

const props = defineProps<{ defaultValue: string }>();
const active = ref(props.defaultValue);
provide('tabs-active', active);
</script>

<template>
  <div class="w-full">
    <slot />
  </div>
</template>
