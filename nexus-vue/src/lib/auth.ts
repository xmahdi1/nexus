import {api} from './api'

let authenticated = false
let capabilities: {global:Record<string,boolean>;servers:Record<string,string[]>} = {global:{},servers:{}}
export function can(permission:string,serverId=''):boolean { return !!capabilities.global[permission] || !!(serverId && capabilities.servers[serverId]?.includes(permission)) }
// Remove the obsolete hint; it is never used to decide authentication.
try { if (typeof localStorage !== 'undefined') localStorage.removeItem('nexus_authed') } catch { /* Storage is optional. */ }
export function isAuthed(): boolean { return authenticated }
export async function verifySession(): Promise<boolean> {
    try { await api.auth.me(); capabilities = await api.auth.permissions(); authenticated = true; return true }
    catch { authenticated = false; capabilities = {global:{},servers:{}}; return false }
}
export async function markAuthed(): Promise<void> {
    if (!await verifySession()) throw new Error('Could not confirm the server session. Sign in again.')
}
export async function signOut(): Promise<void> {
    try { await api.auth.logout() } finally { authenticated = false; capabilities = {global:{},servers:{}} }
}
