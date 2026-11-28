<script setup lang="ts">
import { toolCatalog, toolEnabled, setToolEnabled, resetTools } from '@/lib/tool-preferences';
import Button from '@/components/ui/Button.vue';
</script>
<template>
  <section
    id="tools"
    aria-label="Tool visibility"
    class="bg-card border rounded-xl p-5 sm:p-6 space-y-4 scroll-mt-4"
  >
    <div class="flex justify-between items-center">
      <h2 class="text-sm font-semibold uppercase tracking-wide text-muted-foreground">Tools</h2>
      <Button variant="outline" @click="resetTools">Show all tools</Button>
    </div>
    <p class="text-sm text-muted-foreground">
      Choose which tools appear in navigation and server tabs. Saved for your account in this browser. Hiding
      a tool does not change permissions, stop running work or disable its backend integration.
    </p>
    <div class="grid sm:grid-cols-2 gap-3">
      <label v-for="tool in toolCatalog" :key="tool.id" class="flex items-start gap-3 border rounded p-3"
        ><input
          type="checkbox"
          :checked="toolEnabled(tool.id)"
          :aria-label="'Show ' + tool.label"
          @change="setToolEnabled(tool.id, ($event.target as HTMLInputElement).checked)"
        /><span
          ><span class="block text-sm font-medium">{{ tool.label }}</span
          ><span class="block text-xs text-muted-foreground">{{ tool.description }}</span></span
        ></label
      >
    </div>
  </section>
</template>
