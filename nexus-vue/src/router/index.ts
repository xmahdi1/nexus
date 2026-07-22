import {createRouter, createWebHistory} from 'vue-router'
import {isAuthed} from '@/lib/auth'

const router = createRouter({
    history: createWebHistory(),
    routes: [
        {path: '/', redirect: () => (isAuthed() ? '/dashboard' : '/login')},
        {path: '/login', component: () => import('@/views/LoginView.vue')},
        {path: '/dashboard', component: () => import('@/views/DashboardView.vue'), meta: {requiresAuth: true}},
        {path: '/servers', component: () => import('@/views/ServersView.vue'), meta: {requiresAuth: true}},
        {path: '/servers/:id', component: () => import('@/views/ServerDetailView.vue'), meta: {requiresAuth: true}},
        {path: '/services', component: () => import('@/views/ServicesView.vue'), meta: {requiresAuth: true}},
        {path: '/settings', component: () => import('@/views/SettingsView.vue'), meta: {requiresAuth: true}},
        {path: '/:pathMatch(.*)*', component: () => import('@/views/NotFoundView.vue')},
    ],
})

router.beforeEach((to) => {
    if (to.meta.requiresAuth && !isAuthed()) return '/login'
    if (to.path === '/login' && isAuthed()) return '/dashboard'
})

export default router