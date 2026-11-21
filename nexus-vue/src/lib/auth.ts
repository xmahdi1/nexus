import {api} from './api'
import {shallowRef} from 'vue'

let authenticated = false
const capabilities = shallowRef<{global:Record<string,boolean>;servers:Record<string,string[]>}>({global:{},servers:{}})
let generation = 0
export function can(permission:string,serverId=''):boolean { return !!capabilities.value.global[permission] || !!(serverId && capabilities.value.servers[serverId]?.includes(permission)) }
export function canAny(permission:string):boolean { return can(permission) || Object.values(capabilities.value.servers).some(values=>values.includes(permission)) }
// Remove the obsolete hint; it is never used to decide authentication.
try { if (typeof localStorage !== 'undefined') localStorage.removeItem('nexus_authed') } catch { /* Storage is optional. */ }
export function isAuthed(): boolean { return authenticated }
export async function verifySession(): Promise<boolean> {
    const current=++generation
    try {
        await api.auth.me()
        const next=await api.auth.permissions()
        if(current!==generation)return false
        capabilities.value=next;authenticated=true;return true
    } catch {
        if(current===generation){authenticated=false;capabilities.value={global:{},servers:{}}}
        return false
    }
}
export async function markAuthed(): Promise<void> {
    if (!await verifySession()) throw new Error('Could not confirm the server session. Sign in again.')
}
export async function signOut(): Promise<void> {
    ++generation;authenticated=false;capabilities.value={global:{},servers:{}}
    await api.auth.logout()
}
