<script setup lang="ts">
import { Toaster } from 'vue-sonner';
import ConfirmDialog from '@/components/ConfirmDialog.vue';
</script>

<template>
  <RouterView :key="$route.path" />
  <Toaster position="bottom-right" rich-colors />
  <ConfirmDialog />
</template>
