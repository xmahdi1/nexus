import {createRouter, createWebHistory} from 'vue-router'
import {verifySession, can} from '@/lib/auth'

const router = createRouter({
    history: createWebHistory(),
    routes: [
        {path: '/', redirect: '/dashboard'},
        {path: '/join', component: () => import('@/views/AccountFlowView.vue')},
        {path: '/recover', component: () => import('@/views/AccountFlowView.vue')},
        {path: '/login', component: () => import('@/views/LoginView.vue')},
        {path: '/dashboard', component: () => import('@/views/DashboardView.vue'), meta: {requiresAuth: true}},
        {path: '/servers', component: () => import('@/views/ServersView.vue'), meta: {requiresAuth: true}},
        {path: '/servers/:id', component: () => import('@/views/ServerDetailView.vue'), meta: {requiresAuth: true}},
        {path: '/services', component: () => import('@/views/ServicesView.vue'), meta: {requiresAuth: true}},
        {path: '/settings', component: () => import('@/views/SettingsView.vue'), meta: {requiresAuth: true}},
        {path: '/:pathMatch(.*)*', component: () => import('@/views/NotFoundView.vue')},
    ],
})

router.beforeEach(async (to) => {
    if (!to.meta.requiresAuth && to.path !== '/login') return
    const authenticated = await verifySession()
    if (to.meta.requiresAuth && !authenticated) return '/login'
    if (to.path === '/services' && authenticated && !can('services.read')) return '/dashboard'
    if (to.path === '/login' && authenticated) return '/dashboard'
})

export default router