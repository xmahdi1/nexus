<script setup lang="ts">
import { ref } from 'vue';
import Button from './ui/Button.vue';
defineProps<{ codes: string[] }>();
const copied = ref(false);
async function copy(codes: string[]) {
  try {
    await navigator.clipboard.writeText(codes.join('\n'));
    copied.value = true;
  } catch {
    copied.value = false;
  }
}
</script>
<template>
  <div class="border rounded-lg p-4 space-y-3">
    <h3 class="font-medium">Save your recovery codes</h3>
    <p class="text-sm text-muted-foreground">
      Each code works once. Store them privately; Nexus cannot show them again. New codes replace any previous
      unused codes.
    </p>
    <pre class="text-xs sm:text-sm font-mono bg-muted p-3 rounded-md overflow-x-auto select-all">{{
      codes.join('\n')
    }}</pre>
    <Button variant="outline" size="sm" @click="copy(codes)">{{ copied ? 'Copied' : 'Copy codes' }}</Button>
  </div>
</template>
