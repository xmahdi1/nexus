<script setup lang="ts">
import type {Ref} from 'vue'
import {computed, inject, ref} from 'vue'
import {useRoute, useRouter} from 'vue-router'
import {useI18n} from 'vue-i18n'
import {Bookmark, LayoutDashboard, LogOut, Moon, Server, Settings as SettingsIcon, Sun} from '@lucide/vue'
import {can, canAny, signOut} from '@/lib/auth'
import {toast} from 'vue-sonner'
import {applyTheme, getTheme, type Theme} from '@/lib/theme'

const emit = defineEmits<{ close: [] }>()

const {t} = useI18n()
const router = useRouter()
const route = useRoute()
const collapsed = inject<Ref<boolean>>('sidebarCollapsed')!

const theme = ref<Theme>(getTheme())

const navItems = computed(() => [
  {to: '/dashboard', label: t('nav.dashboard'), icon: LayoutDashboard},
  {to: '/servers', label: t('nav.servers'), icon: Server},
  ...(can('services.read') ? [{to: '/services', label: 'Services', icon: Bookmark}] : []),
  ...(canAny('ansible.inventory.read') ? [{to: '/automation', label: 'Automation', icon: Server}] : []),
  {to: '/settings', label: t('nav.settings'), icon: SettingsIcon},
])

function isActive(to: string) {
  return to === '/dashboard' ? route.path === '/dashboard' : route.path.startsWith(to)
}

function toggleTheme() {
  const next: Theme = theme.value === 'dark' ? 'light' : 'dark'
  theme.value = next
  applyTheme(next)
}

async function handleLogout() {
  try { await signOut(); router.push('/login') }
  catch { toast.error('Could not revoke this session. Check the connection and try signing out again.') }
}

function handleNav() {
  emit('close')
}
</script>

<template>
  <aside :class="[
    'flex flex-col h-dvh bg-sidebar border-r transition-all duration-200 shrink-0',
    collapsed ? 'w-14' : 'w-56',
  ]">
    <div class="flex items-center gap-2 px-3 py-3 border-b h-12">
      <img src="/icons/icon.png" alt="Nexus" class="h-8 w-8 shrink-0 rounded-xl object-cover"/>
      <div v-if="!collapsed" class="flex flex-col leading-tight overflow-hidden">
        <span class="text-sm font-semibold truncate">{{ t('app.name') }}</span>
        <span class="text-[10px] text-muted-foreground truncate">{{ t('app.tagline') }}</span>
      </div>
    </div>

    <nav class="flex-1 px-2 py-2 space-y-0.5 overflow-y-auto">
      <RouterLink v-for="item in navItems" :key="item.to" :to="item.to"
                  :class="[
          'flex items-center gap-2 rounded-md px-2 py-2 text-sm font-medium transition-colors',
          isActive(item.to)
            ? 'bg-sidebar-accent text-sidebar-accent-foreground'
            : 'text-sidebar-foreground hover:bg-sidebar-accent/50 hover:text-sidebar-accent-foreground',
        ]"
                  @click="handleNav">
        <component :is="item.icon" class="h-4 w-4 shrink-0"/>
        <span v-if="!collapsed" class="truncate">{{ item.label }}</span>
      </RouterLink>
    </nav>

    <div class="border-t px-2 py-2 space-y-0.5 shrink-0">
      <button type="button"
              class="flex w-full items-center gap-2 rounded-md px-2 py-2 text-sm text-sidebar-foreground hover:bg-sidebar-accent/50 transition-colors"
              @click="toggleTheme">
        <Sun v-if="theme === 'dark'" class="h-4 w-4 shrink-0"/>
        <Moon v-else class="h-4 w-4 shrink-0"/>
        <span v-if="!collapsed">{{ theme === 'dark' ? t('settings.themeLight') : t('settings.themeDark') }}</span>
      </button>
      <button type="button"
              class="flex w-full items-center gap-2 rounded-md px-2 py-2 text-sm text-sidebar-foreground hover:bg-sidebar-accent/50 transition-colors"
              @click="handleLogout">
        <LogOut class="h-4 w-4 shrink-0"/>
        <span v-if="!collapsed">{{ t('nav.logout') }}</span>
      </button>
    </div>
  </aside>
</template>
