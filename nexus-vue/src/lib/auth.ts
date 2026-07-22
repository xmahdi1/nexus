import {api} from './api'

const SESSION_KEY = 'nexus_authed'

export function isAuthed(): boolean {
    return typeof window !== 'undefined' && localStorage.getItem(SESSION_KEY) === '1'
}

export function markAuthed(): void {
    localStorage.setItem(SESSION_KEY, '1')
}

export async function signIn(password: string): Promise<void> {
    await api.auth.login(password)
    localStorage.setItem(SESSION_KEY, '1')
}

export async function signOut(): Promise<void> {
    localStorage.removeItem(SESSION_KEY)
    try {
        await api.auth.logout()
    } catch {
    }
}

export async function verifySession(): Promise<boolean> {
    try {
        await api.auth.me()
        localStorage.setItem(SESSION_KEY, '1')
        return true
    } catch {
        localStorage.removeItem(SESSION_KEY)
        return false
    }
}