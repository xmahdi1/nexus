const BASE = '/api'

export interface ApiError {
    error: string;
    code: string
}

export interface GeneratedKey {
    publicKey: string;
    privateKey: string
}

export interface ConnectionTestResult {
    ok: boolean;
    latencyMs: number;
    error?: string
}

export interface Server {
    id: string;
    name: string;
    host: string;
    port: number
    username: string;
    publicKey: string;
    fingerprint: string;
    tags: string
    createdAt: string;
    updatedAt: string
}

export interface CreateServerInput {
    name: string;
    host: string;
    port: number
    username: string;
    publicKey: string;
    privateKey: string
}

export interface Process {
    pid: number;
    name: string;
    cpu: number;
    memory: number
}

export interface Metrics {
    cpu: number
    memTotal: number;
    memUsed: number
    swapTotal: number;
    swapUsed: number
    diskTotal: number;
    diskUsed: number
    load1: number;
    load5: number;
    load15: number
    netRxRate: number;
    netTxRate: number
    uptime: string;
    os: string;
    kernel: string
    processes: Process[]
}

export interface Container {
    id: string;
    name: string;
    image: string
    status: 'running' | 'exited' | 'paused'
    state: string;
    ports: string;
    cpu: number;
    mem: string
}

export interface FileEntry {
    name: string;
    path: string;
    isDir: boolean
    size: number;
    modTime: string;
    mode: string
}

export interface ProxyRule {
    id: string;
    serverId: string;
    domain: string;
    target: string
    proxyType: 'nginx' | 'caddy';
    sslEnabled: boolean;
    createdAt: string
}

export interface Service {
    id: string;
    name: string;
    url: string;
    icon: string
    description: string;
    category: string;
    color: string
    sortOrder: number;
    createdAt: string
}

export interface ServerStatus {
    serverId: string;
    name: string;
    host: string;
    tags: string
    online: boolean;
    latencyMs: number;
    checkedAt: string;
    lastOnline: string
}

export interface AlertConfig {
    id: string
    telegramEnabled: boolean;
    telegramToken: string;
    telegramChatId: string
    notifyServerDown: boolean;
    notifyServerUp: boolean;
    notifyContainer: boolean
}

export interface ServerAlertConfig {
    id: string
    cpuEnabled: boolean;
    cpuThreshold: number
    ramEnabled: boolean;
    ramThreshold: number
    diskEnabled: boolean;
    diskThreshold: number
    sslEnabled: boolean;
    sslDaysBefore: number
    updatedAt: string
}

export interface TemplateVar {
    name: string;
    label: string;
    description: string;
    default: string
    required: boolean;
    type: 'string' | 'password' | 'number' | 'select'
    options?: string[]
}

export interface AppTemplate {
    id: string;
    name: string;
    description: string;
    icon: string
    iconLight?: string;
    category: string;
    docUrl?: string;
    postDeploy?: string
    vars: TemplateVar[];
    builtIn: boolean;
    compose?: string
}

export interface DeployedApp {
    id: string;
    serverId: string;
    templateId: string;
    name: string
    composePath: string;
    status: string;
    deployedAt: string
}

export interface LoginEvent {
    id: number;
    ip: string;
    success: boolean;
    reason: string;
    createdAt: string
}

export interface CronJob {
    index: number;
    schedule: string;
    command: string;
    raw: string
}

export interface FirewallRule {
    number: number
    to: string
    action: string
    from: string
}

export interface OpenPort {
    protocol: string
    port: string
    address: string
    process: string
    cmdline?: string
}

export interface FirewallStatus {
    status: string
    available: boolean
    rules: FirewallRule[]
    ports: OpenPort[]
}

export interface ScheduledTask {
    id: string;
    serverId: string;
    name: string;
    command: string
    intervalMinutes: number;
    enabled: boolean
    lastRunAt: string | null;
    nextRunAt: string | null
    lastOutput: string;
    lastStatus: string;
    createdAt: string
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${BASE}${path}`, {
        method,
        credentials: 'include',
        headers: body ? {'Content-Type': 'application/json'} : {},
        body: body ? JSON.stringify(body) : undefined,
    })
    if ((res.headers.get('content-type') ?? '').includes('text/html')) {
        window.dispatchEvent(new CustomEvent('nexus:connection-lost'))
        return new Promise<T>(() => {
        })
    }
    if (!res.ok) {
        let json: any = {}
        try {
            json = await res.json()
        } catch {
        }
        if (res.status === 401 && !['/auth/login', '/auth/password', '/auth/mfa/verify'].includes(path)) {
            localStorage.removeItem('nexus_authed')
            window.location.href = '/login'
        }
        throw Object.assign(new Error(json.error ?? `HTTP ${res.status}`), json)
    }

    if (res.status === 204) return undefined as T
    return res.json() as Promise<T>
}

export const api = {
    auth: {
        login: (password: string) =>
            request<{ ok: boolean }>('POST', '/auth/login', {password}),
        logout: () => request<{ ok: boolean }>('POST', '/auth/logout'),
        me: () => request<{ ok: boolean }>('GET', '/auth/me'),
        changePassword: (currentPassword: string, newPassword: string) =>
            request<{ ok: boolean }>('POST', '/auth/password', {currentPassword, newPassword}),
        auditLog: (limit?: number) =>
            request<LoginEvent[]>('GET', limit ? `/auth/audit?limit=${limit}` : '/auth/audit'),
        mfaVerify: (pendingToken: string, code: string) =>
            request<{ ok: boolean }>('POST', '/auth/mfa/verify', {pendingToken, code}),
        mfaStatus: () => request<{ enabled: boolean }>('GET', '/auth/mfa/status'),
        mfaSetup: () => request<{ secret: string; uri: string }>('POST', '/auth/mfa/setup'),
        mfaEnable: (secret: string, code: string) =>
            request<{ ok: boolean }>('POST', '/auth/mfa/enable', {secret, code}),
        mfaDisable: (code: string) =>
            request<{ ok: boolean }>('POST', '/auth/mfa/disable', {code}),
    },

    keys: {
        generate: () => request<GeneratedKey>('POST', '/keys/generate'),
    },

    servers: {
        list: () => request<Server[]>('GET', '/servers'),
        get: (id: string) => request<Server>('GET', `/servers/${id}`),
        create: (data: CreateServerInput) => request<Server>('POST', '/servers', data),
        delete: (id: string) => request<void>('DELETE', `/servers/${id}`),
        test: (id: string) => request<ConnectionTestResult>('POST', `/servers/${id}/test`),
        updateTags: (id: string, tags: string) => request<Server>('PATCH', `/servers/${id}/tags`, {tags}),
    },

    containers: {
        list: (sid: string) => request<Container[]>('GET', `/servers/${sid}/containers`),
        start: (sid: string, cid: string) => request<void>('POST', `/servers/${sid}/containers/${cid}/start`),
        stop: (sid: string, cid: string) => request<void>('POST', `/servers/${sid}/containers/${cid}/stop`),
        restart: (sid: string, cid: string) => request<void>('POST', `/servers/${sid}/containers/${cid}/restart`),
        remove: (sid: string, cid: string) => request<void>('DELETE', `/servers/${sid}/containers/${cid}`),
        exec: (sid: string, cid: string, d: { query: string; dbUser?: string; dbPassword?: string }) =>
            request<{ output: string }>('POST', `/servers/${sid}/containers/${cid}/exec`, d),
    },

    compose: {
        read: (sid: string, path: string) =>
            request<{
                content: string;
                path: string
            }>('GET', `/servers/${sid}/compose?path=${encodeURIComponent(path)}`),
        write: (sid: string, path: string, content: string) =>
            request<{ ok: boolean }>('PUT', `/servers/${sid}/compose?path=${encodeURIComponent(path)}`, {content}),
        up: (sid: string, path: string) =>
            request<{
                ok: boolean;
                output: string
            }>('POST', `/servers/${sid}/compose/up?path=${encodeURIComponent(path)}`),
        down: (sid: string, path: string) =>
            request<{
                ok: boolean;
                output: string
            }>('POST', `/servers/${sid}/compose/down?path=${encodeURIComponent(path)}`),
    },

    files: {
        list: (sid: string, path: string) =>
            request<{
                path: string;
                entries: FileEntry[]
            }>('GET', `/servers/${sid}/files?path=${encodeURIComponent(path)}`),
        preview: (sid: string, path: string) =>
            request<{
                content: string;
                truncated: boolean;
                binary: boolean
            }>('GET', `/servers/${sid}/files/preview?path=${encodeURIComponent(path)}`),
        write: (sid: string, path: string, content: string) =>
            request<{ ok: boolean }>('PUT', `/servers/${sid}/files`, {path, content}),
        download: (_sid: string, path: string) =>
            `/api/servers/${_sid}/files/download?path=${encodeURIComponent(path)}`,
        upload: (sid: string, dirPath: string, file: File) => {
            const form = new FormData()
            form.append('file', file)
            return fetch(`/api/servers/${sid}/files/upload?path=${encodeURIComponent(dirPath)}`, {
                method: 'POST', credentials: 'include', body: form,
            }).then(async res => {
                if (!res.ok) {
                    const json = await res.json().catch(() => ({}))
                    throw new Error(json.error ?? `Upload failed (${res.status})`)
                }
                return res.json()
            })
        },
        delete: (sid: string, path: string) =>
            request<void>('DELETE', `/servers/${sid}/files?path=${encodeURIComponent(path)}`),
        mkdir: (sid: string, path: string) =>
            request<{ ok: boolean }>('POST', `/servers/${sid}/files/mkdir`, {path}),
    },

    proxy: {
        detect: (sid: string) =>
            request<{ proxyType: string; version: string }>('GET', `/servers/${sid}/proxy/detect`),
        list: (sid: string) => request<ProxyRule[]>('GET', `/servers/${sid}/proxy`),
        create: (sid: string, data: { domain: string; target: string; proxyType: string; ssl: boolean }) =>
            request<ProxyRule>('POST', `/servers/${sid}/proxy`, data),
        update: (sid: string, ruleId: string, data: {
            domain: string;
            target: string;
            proxyType: string;
            ssl: boolean
        }) =>
            request<ProxyRule>('PUT', `/servers/${sid}/proxy/${ruleId}`, data),
        delete: (sid: string, ruleId: string) =>
            request<void>('DELETE', `/servers/${sid}/proxy/${ruleId}`),
        enableSSL: (sid: string, ruleId: string, data: { email: string; wildcard: boolean; cfToken: string }) =>
            request<{ rule: ProxyRule; output: string }>('POST', `/servers/${sid}/proxy/${ruleId}/ssl`, data),
    },

    services: {
        list: () => request<Service[]>('GET', '/services'),
        create: (data: Partial<Service>) => request<Service>('POST', '/services', data),
        update: (id: string, data: Partial<Service>) => request<Service>('PUT', `/services/${id}`, data),
        delete: (id: string) => request<void>('DELETE', `/services/${id}`),
    },

    monitor: {
        status: () => request<ServerStatus[]>('GET', '/monitor/status'),
        getConfig: () => request<AlertConfig>('GET', '/monitor/config'),
        updateConfig: (data: Partial<AlertConfig>) => request<AlertConfig>('PUT', '/monitor/config', data),
        testTelegram: () => request<{ ok: string }>('POST', '/monitor/config/test'),
        listMonitored: (sid: string) =>
            request<{ id: string; containerId: string; name: string }[]>('GET', `/servers/${sid}/monitor/containers`),
        addMonitored: (sid: string, containerId: string, name: string) =>
            request<{ id: string }>('POST', `/servers/${sid}/monitor/containers`, {containerId, name}),
        removeMonitored: (sid: string, containerId: string) =>
            request<void>('DELETE', `/servers/${sid}/monitor/containers/${containerId}`),
    },

    templates: {
        list: () => request<AppTemplate[]>('GET', '/templates'),
        createCustom: (data: Partial<AppTemplate> & { compose: string }) =>
            request<AppTemplate>('POST', '/templates/custom', data),
        updateCustom: (id: string, data: Partial<AppTemplate> & { compose: string }) =>
            request<AppTemplate>('PUT', `/templates/custom/${id}`, data),
        deleteCustom: (id: string) => request<void>('DELETE', `/templates/custom/${id}`),
        listDeployed: (sid: string) => request<DeployedApp[]>('GET', `/servers/${sid}/apps`),
        deploy: (sid: string, data: { templateId: string; appName: string; variables: Record<string, string> }) =>
            request<{
                app: DeployedApp;
                output: string;
                postDeploy: string
            }>('POST', `/servers/${sid}/apps/deploy`, data),
        remove: (sid: string, appId: string) =>
            request<{ output: string }>('DELETE', `/servers/${sid}/apps/${appId}`),
    },

    serverAlerts: {
        get: (sid: string) => request<ServerAlertConfig>('GET', `/servers/${sid}/alerts`),
        update: (sid: string, data: Partial<ServerAlertConfig>) =>
            request<ServerAlertConfig>('PUT', `/servers/${sid}/alerts`, data),
    },

    cron: {
        list: (sid: string) => request<CronJob[]>('GET', `/servers/${sid}/cron`),
        add: (sid: string, d: { schedule: string; command: string }) =>
            request<{ ok: string }>('POST', `/servers/${sid}/cron`, d),
        delete: (sid: string, raw: string) =>
            request<{ ok: string }>('DELETE', `/servers/${sid}/cron`, {raw}),
    },

    tasks: {
        list: (sid: string) => request<ScheduledTask[]>('GET', `/servers/${sid}/tasks`),
        create: (sid: string, d: { name: string; command: string; intervalMinutes: number }) =>
            request<ScheduledTask>('POST', `/servers/${sid}/tasks`, d),
        update: (sid: string, tid: string, d: Partial<ScheduledTask>) =>
            request<ScheduledTask>('PUT', `/servers/${sid}/tasks/${tid}`, d),
        delete: (sid: string, tid: string) => request<void>('DELETE', `/servers/${sid}/tasks/${tid}`),
        runNow: (sid: string, tid: string) => request<{ ok: string }>('POST', `/servers/${sid}/tasks/${tid}/run`),
    },
    firewall: {
        status: (sid: string) =>
            request<FirewallStatus>('GET', `/servers/${sid}/firewall`),

        enable: (sid: string) =>
            request<{ ok: boolean }>('POST', `/servers/${sid}/firewall/enable`),

        disable: (sid: string) =>
            request<{ ok: boolean }>('POST', `/servers/${sid}/firewall/disable`),

        addRule: (sid: string, data: { port: string; action: string; from: string }) =>
            request<{ ok: boolean }>('POST', `/servers/${sid}/firewall/rules`, data),

        deleteRule: (sid: string, n: number) =>
            request<{ ok: boolean }>('DELETE', `/servers/${sid}/firewall/rules/${n}`),
    },
    ws: {
        terminal: (sid: string) =>
            `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/terminal/${sid}`,
        logs: (sid: string, cid: string) =>
            `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/logs/${sid}/${cid}`,
    },
}