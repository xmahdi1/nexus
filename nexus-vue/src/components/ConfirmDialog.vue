<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { AlertTriangle } from '@lucide/vue'
import { useConfirm } from '@/composables/useConfirm'
import Button from './ui/Button.vue'

const { visible, opts, _confirm, _cancel } = useConfirm()

function onKey(e: KeyboardEvent) {
  if (!visible.value) return
  if (e.key === 'Enter')  { e.preventDefault(); _confirm() }
  if (e.key === 'Escape') { e.preventDefault(); _cancel()  }
}

onMounted(() => window.addEventListener('keydown', onKey))
onUnmounted(() => window.removeEventListener('keydown', onKey))
</script>

<template>
  <Transition enter-active-class="transition-opacity duration-150" enter-from-class="opacity-0"
              leave-active-class="transition-opacity duration-100" leave-to-class="opacity-0">
    <div v-if="visible" class="fixed inset-0 z-[200] flex items-center justify-center p-4">
      <div class="absolute inset-0 bg-black/60 backdrop-blur-sm" @click="_cancel" />

      <Transition enter-active-class="transition-all duration-150" enter-from-class="opacity-0 scale-95"
                  enter-to-class="opacity-100 scale-100" leave-active-class="transition-all duration-100"
                  leave-to-class="opacity-0 scale-95">
        <div v-if="visible"
             class="relative z-10 w-full max-w-sm bg-card border rounded-2xl shadow-2xl p-6 space-y-4">
          <div class="flex items-start gap-3">
            <div :class="['h-10 w-10 rounded-full flex items-center justify-center shrink-0',
              opts.destructive ? 'bg-destructive/10 text-destructive' : 'bg-muted text-muted-foreground']">
              <AlertTriangle class="h-5 w-5" />
            </div>
            <div class="min-w-0">
              <p class="font-semibold text-sm leading-tight">{{ opts.title ?? 'Are you sure?' }}</p>
              <p class="text-sm text-muted-foreground mt-1">{{ opts.message }}</p>
            </div>
          </div>
          <div class="flex flex-col-reverse sm:flex-row sm:justify-end gap-2 pt-1">
            <Button variant="outline" class="w-full sm:w-auto" @click="_cancel">
              {{ opts.cancelText ?? 'Cancel' }}
            </Button>
            <Button :variant="opts.destructive ? 'destructive' : 'default'" class="w-full sm:w-auto" @click="_confirm">
              {{ opts.confirmText ?? 'Confirm' }}
            </Button>
          </div>
        </div>
      </Transition>
    </div>
  </Transition>
</template>