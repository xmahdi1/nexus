<script setup lang="ts">
import {ref, provide} from 'vue'
import {useRouter} from 'vue-router'
import {Menu} from '@lucide/vue'
import {isAuthed} from '@/lib/auth'
import AppSidebar from './AppSidebar.vue'

const router = useRouter()
if (!isAuthed()) router.push('/login')

const collapsed = ref(false)
const mobileOpen = ref(false)

provide('sidebarCollapsed', collapsed)

function toggleSidebar() {
  if (window.innerWidth < 768) {
    mobileOpen.value = !mobileOpen.value
  } else {
    collapsed.value = !collapsed.value
  }
}
</script>

<template>
  <div class="flex h-screen overflow-hidden w-full bg-background">
    <div v-if="mobileOpen"
         class="fixed inset-0 z-20 bg-black/50 md:hidden"
         @click="mobileOpen = false"/>

    <div :class="[
      'fixed inset-y-0 left-0 z-30 transition-transform duration-200 md:relative md:translate-x-0 md:z-auto',
      mobileOpen ? 'translate-x-0' : '-translate-x-full',
    ]">
      <AppSidebar @close="mobileOpen = false"/>
    </div>

    <div class="flex-1 flex flex-col min-w-0">
      <header class="h-12 flex items-center border-b px-3 gap-2 bg-background/80 backdrop-blur sticky top-0 z-10">
        <button type="button"
                class="h-8 w-8 inline-flex items-center justify-center rounded-md hover:bg-accent transition-colors"
                @click="toggleSidebar">
          <Menu class="h-4 w-4"/>
        </button>
      </header>

      <main class="flex-1 overflow-y-auto p-4 sm:p-6">
        <slot/>
      </main>
    </div>
  </div>
</template>