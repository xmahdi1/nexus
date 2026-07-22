import {defineStore} from 'pinia'
import {ref} from 'vue'
import {api} from '@/lib/api'
import type {Server} from '@/lib/api'

export interface ServerVM extends Server {
    status: 'online' | 'offline' | 'connecting' | 'unknown'
    os: string
    uptime: string
    tags: string
}

export const useServersStore = defineStore('servers', () => {
    const list = ref<ServerVM[]>([])
    const loading = ref(false)
    const error = ref('')

    function toVM(s: Server): ServerVM {
        return {...s, status: 'unknown', os: '—', uptime: '—', tags: (s as any).tags ?? ''}
    }

    function setStatus(id: string, status: ServerVM['status']) {
        const s = list.value.find(s => s.id === id)
        if (s) s.status = status
    }

    async function fetchAll() {
        loading.value = true;
        error.value = ''
        try {
            const servers = await api.servers.list()
            list.value = servers.map(toVM)
            list.value.forEach(s => testConnection(s.id))
        } catch (e) {
            error.value = e instanceof Error ? e.message : 'Failed to load servers'
        } finally {
            loading.value = false
        }
    }

    async function addServer(data: {
        name: string;
        host: string;
        port: number;
        username: string;
        publicKey: string;
        privateKey: string
    }) {
        const server = await api.servers.create(data)
        list.value.unshift(toVM(server))
        testConnection(server.id)
        return server
    }

    async function removeServer(id: string) {
        await api.servers.delete(id)
        list.value = list.value.filter(s => s.id !== id)
    }

    async function testConnection(id: string) {
        setStatus(id, 'connecting')
        try {
            const result = await api.servers.test(id)
            setStatus(id, result.ok ? 'online' : 'offline')
            return result
        } catch {
            setStatus(id, 'offline')
            return {ok: false, latencyMs: 0, error: 'Request failed'}
        }
    }

    async function updateTags(id: string, tags: string) {
        const server = await api.servers.updateTags(id, tags)
        const vm = list.value.find(s => s.id === id)
        if (vm) vm.tags = (server as any).tags ?? tags
        return server
    }

    return {list, loading, error, fetchAll, addServer, removeServer, testConnection, updateTags}
})