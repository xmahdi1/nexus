<script setup lang="ts">
defineProps<{ content: string }>()
</script>

<template>
  <div class="relative inline-flex group">
    <slot />
    <div
      class="pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-1.5 z-50 opacity-0 group-hover:opacity-100 transition-opacity duration-100"
    >
      <div class="bg-popover text-popover-foreground border text-xs px-2 py-1 rounded-md shadow-sm whitespace-nowrap">
        {{ content }}
      </div>
    </div>
  </div>
</template>
