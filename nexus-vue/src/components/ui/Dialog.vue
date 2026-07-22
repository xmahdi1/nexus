<script setup lang="ts">
defineProps<{ open: boolean; maxWidth?: string }>()
defineEmits<{ 'update:open': [boolean] }>()
</script>

<template>
  <Teleport to="body">
    <Transition
      enter-active-class="transition duration-150 ease-out"
      enter-from-class="opacity-0"
      enter-to-class="opacity-100"
      leave-active-class="transition duration-100 ease-in"
      leave-from-class="opacity-100"
      leave-to-class="opacity-0"
    >
      <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div
          class="fixed inset-0 bg-black/50 backdrop-blur-sm"
          @click="$emit('update:open', false)"
        />
        <div
          :class="['relative z-10 w-full bg-card border rounded-xl shadow-xl', maxWidth ?? 'max-w-lg']"
        >
          <slot />
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
