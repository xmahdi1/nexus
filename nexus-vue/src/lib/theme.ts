export type Theme = 'light' | 'dark'

export function getTheme(): Theme {
    if (typeof window === 'undefined') return 'dark'
    return (localStorage.getItem('nexus_theme') as Theme) || 'dark'
}

export function applyTheme(theme: Theme) {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('nexus_theme', theme)
}