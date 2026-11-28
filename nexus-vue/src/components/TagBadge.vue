<script setup lang="ts">
defineProps<{ tag: string }>();

const COLORS = [
  'bg-blue-500/15   text-blue-600   border border-blue-500/25   dark:text-blue-400',
  'bg-green-500/15  text-green-600  border border-green-500/25  dark:text-green-400',
  'bg-purple-500/15 text-purple-600 border border-purple-500/25 dark:text-purple-400',
  'bg-orange-500/15 text-orange-600 border border-orange-500/25 dark:text-orange-400',
  'bg-pink-500/15   text-pink-600   border border-pink-500/25   dark:text-pink-400',
  'bg-cyan-500/15   text-cyan-600   border border-cyan-500/25   dark:text-cyan-400',
  'bg-yellow-500/15 text-yellow-600 border border-yellow-500/25 dark:text-yellow-400',
  'bg-red-500/15    text-red-600    border border-red-500/25    dark:text-red-400',
];

function tagColor(t: string): string {
  let h = 0;
  for (let i = 0; i < t.length; i++) h = (h * 31 + t.charCodeAt(i)) | 0;
  return COLORS[Math.abs(h) % COLORS.length];
}
</script>

<template>
  <span :class="['inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium', tagColor(tag)]">
    {{ tag }}
  </span>
</template>
