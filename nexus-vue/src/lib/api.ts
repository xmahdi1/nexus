export interface AnsibleInventoryToken {id:string;groupId:string;createdAt:string;expiresAt:string}
export interface AnsibleInventoryPreview {revision:string;groups:Record<string,string>;inventory:{_meta:{hostvars:Record<string,{ansible_host:string;ansible_port:number;ansible_user:string;nexus_server_id:string}>}}}
export interface InventoryRelationship {id:string;serverId:string;sourceId:string;targetId:string;sourceName:string;targetName:string;kind:string;source:string;dataState:string;firstSeenAt:string;lastVerifiedAt:string}
export interface InventoryChange {id:number;serverId:string;runId:string;resourceId:string;kind:string;at:string;before?:{name:string;details:unknown};after?:{name:string;details:unknown}}
export interface AccountUser {
 id:string;username:string;displayName:string;email:string|null;status:string;admitted:boolean;mfaEnabled:boolean;recoveryRequired:boolean;createdAt:string;lastLoginAt:string|null
}
export interface RecoveryResult {ok:boolean;recoveryCodes:string[]}
export interface MFAEnrollment {secret:string;uri:string;setupToken:string}
export interface InviteInput {username:string;displayName:string;email:string;roleId:string;scopeType:string;scopeId:string;expiresHours:number;currentPassword:string}
export interface DeviceSession {
    id: string; createdAt: string; lastUsedAt: string; expiresAt: string; deviceLabel: string; clientIP: string
}

export interface OperationInspection {
 id:string;state:string;action:string;actorId:string;serverId:string;resourceType:string;resourceId:string;
 startedAt:string;completedAt:string|null;remoteStateVerified:boolean;automaticRetryAllowed:boolean;guidance:string
}

export interface VaultProfile {serverId?:string;port:number;tlsName:string;caPem:string;namespace:string}
export interface VaultConnection {configured:boolean;profile?:VaultProfile}
export interface VaultAccessInput {token:string;name?:string;paths?:string[]}
export interface VaultAdminField {key:string;label:string;kind:string;required:boolean;choices?:string[]}
export interface VaultAdminOperation {id:string;group:string;label:string;notice:string;fields:VaultAdminField[];permissions:string[];mutation:boolean;sensitive:boolean}
export interface VaultAdminResult {dataJson:string;revision?:string;redacted?:boolean;automaticRetryAllowed:false}
export interface VaultAccessResult {methods?:{path:string;type:string;description:string;defaultTTL?:number;maxTTL?:number}[];policies?:string[];name?:string;policy?:string;redacted?:boolean;capabilities?:Record<string,string[]>}
export interface VaultKVInput {token:string;mount:string;path:string;version?:number;dataJson?:string}
export interface VaultKVResult {keys?:string[];metadata?:{version:number};dataJson?:string;automaticRetryAllowed:false}
export interface VaultObservation {health:{initialized:boolean;sealed:boolean;standby:boolean;status:number};mounts:{path:string;type:string;description:string;version:string}[];mountsStatus:string}

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
 storedDefault?:boolean;
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
	 supervised: boolean;
    actorId: string;
    createdBy: string;
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

export interface SupervisedRun {
    id: string; taskId: string; serverId: string; actorId: string; state: string;
    exitCode: number | null; truncated: boolean; artifactsRemoved: boolean;
    detail: string; createdAt: string; dispatchStartedAt: string | null; cancelRequestedAt: string | null;
    verifiedAt: string | null; finishedAt: string | null;
}
export interface RunObservation {
    run: SupervisedRun;
    observation: {state: string; verified: boolean; empty: boolean; exitCode: number | null; output: string; truncated: boolean; released: boolean; detail: string; noDispatch: boolean};
    automaticRetryAllowed: false;
}
export type ServerOperation = 'compose-up'|'compose-down'|'container-start'|'container-stop'|'container-restart'|'container-remove'
export interface InteractiveRun extends SupervisedRun {kind:'operation';action:ServerOperation;targetId:string}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
    let res:Response
    try {res = await fetch(`${BASE}${path}`, {
        method,
        signal: AbortSignal.timeout(60_000),
        credentials: 'include',
        headers: body ? {'Content-Type': 'application/json'} : {},
        body: body ? JSON.stringify(body) : undefined,
    })} catch(error) {
      if(!['GET','HEAD','OPTIONS'].includes(method))throw Object.assign(new Error('Request interrupted; the remote outcome may be uncertain. Inspect the target before retrying.'),{code:'remote_outcome_unknown',cause:error})
      throw error
    }
    try{return await decodeResponse<T>(res,path)}catch(error){
      if(!['GET','HEAD','OPTIONS'].includes(method)&&!(error as {status?:number})?.status){
        throw responseError(res,{error:'Response interrupted; the remote outcome may be uncertain. Inspect the target before retrying.',code:'remote_outcome_unknown'})
      }
      throw error
    }
}

async function downloadFile(path:string):Promise<Blob>{
 const response=await fetch(`${BASE}${path}`,{credentials:'include',signal:AbortSignal.timeout(60_000)})
 if(!response.ok || (response.headers.get('content-type')??'').includes('text/html'))return decodeResponse<never>(response,path)
 const max=64*1024*1024
 if(Number(response.headers.get('content-length'))>max)throw new Error('Browser downloads are limited to 64 MiB.')
 const reader=response.body?.getReader();if(!reader)return new Blob([])
 const chunks:Uint8Array[]= [];let total=0
 try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>max){await reader.cancel();throw new Error('Browser downloads are limited to 64 MiB.')}chunks.push(new Uint8Array(value))}}finally{reader.releaseLock()}
 return new Blob(chunks,{type:'application/octet-stream'})
}

async function decodeResponse<T>(res: Response,path: string): Promise<T> {
    if ((res.headers.get('content-type') ?? '').includes('text/html')) {
        window.dispatchEvent(new CustomEvent('nexus:connection-lost'))
        throw Object.assign(new Error('The access proxy returned an HTML page. Refresh the page and sign in to the proxy again.'), {
            code: 'upstream_html', status: res.status,
        })
    }
    if (!res.ok) {
        let json: any = {}
        try {
            json = await res.json()
        } catch {
        }
        if (res.status === 401 && window.location.pathname !== '/login' && !['/auth/me','/auth/permissions','/auth/invitations/accept','/auth/reset/info','/auth/reset/password','/auth/reset/mfa/setup','/auth/reset/mfa/confirm','/auth/mfa/recovery', '/auth/mfa/recovery-codes', '/auth/step-up', '/auth/login', '/auth/password', '/auth/mfa/verify', '/auth/mfa/setup', '/auth/mfa/enable', '/auth/mfa/disable'].includes(path)) {
            window.location.href = '/login'
        }
        throw responseError(res,json)
    }

    if (res.status === 204) return undefined as T
    const data=await res.json()
    if (/^\/servers\/[^/]+\/compose\/(up|down)\?/.test(path) && data?.ok === false) throw responseError(res,data)
    return data as T
}
function responseError(res:Response,data:any):Error {
 const candidate=res.headers.get('X-Operation-ID')??''
 const operationId=/^[a-f0-9]{32}$/.test(candidate)?candidate:''
 const message=String(data.error??`HTTP ${res.status}`)+(operationId?` (operation ${operationId}; inspect audit and target state before retrying)`:'')
 return Object.assign(new Error(message),data,{message,operationId,status:res.status})
}

export const api = {
 ansible: {
  groups:()=>request<Array<{id:string;name:string}>>('GET','/automation/ansible/groups'),
  preview:(groupId:string)=>request<AnsibleInventoryPreview>('GET',`/automation/ansible/preview?groupId=${encodeURIComponent(groupId)}`),
  tokens:()=>request<AnsibleInventoryToken[]>('GET','/automation/ansible/tokens'),
  issue:(groupId:string,ttlSeconds:number)=>request<AnsibleInventoryToken & {token:string}>('POST','/automation/ansible/tokens',{groupId,ttlSeconds}),
  revoke:(id:string)=>request<void>('DELETE',`/automation/ansible/tokens/${encodeURIComponent(id)}`),
 },
 operations:{
  start:(sid:string,action:ServerOperation,requestId:string,target:{path?:string;cid?:string})=>{
   const compose=action.startsWith('compose-')
   if(compose?(!target.path||!!target.cid):(!target.cid||!!target.path))throw new Error('Choose one valid operation target.')
   const suffix=compose?'compose/'+action.slice('compose-'.length):'containers/'+encodeURIComponent(target.cid!)+ '/'+action.slice('container-'.length)
   return request<{run:InteractiveRun;automaticRetryAllowed:false}>('POST',`/servers/${encodeURIComponent(sid)}/operations/${suffix}`,{requestId,...(compose?{path:target.path}:{})})
  },
  list:(sid:string)=>request<InteractiveRun[]>('GET',`/servers/${encodeURIComponent(sid)}/operations/runs`),
  read:(sid:string,id:string)=>request<RunObservation>('GET',`/servers/${encodeURIComponent(sid)}/operations/runs/${encodeURIComponent(id)}`),
  inspect:(sid:string,id:string)=>request<RunObservation>('POST',`/servers/${encodeURIComponent(sid)}/operations/runs/${encodeURIComponent(id)}/inspect`),
  cancel:(sid:string,id:string)=>request<RunObservation>('POST',`/servers/${encodeURIComponent(sid)}/operations/runs/${encodeURIComponent(id)}/cancel`),
  release:(sid:string,id:string)=>request<RunObservation>('DELETE',`/servers/${encodeURIComponent(sid)}/operations/runs/${encodeURIComponent(id)}/artifacts`),
 },
 vault: {
  operations:(id:string)=>request<{operations:VaultAdminOperation[];supportedEdition:string;namespaces:boolean}>('GET',`/servers/${encodeURIComponent(id)}/vault/admin/operations`),
  admin:(id:string,action:string,input:{token:string;params:Record<string,unknown>;confirmation?:string})=>request<VaultAdminResult>('POST',`/servers/${encodeURIComponent(id)}/vault/admin/${encodeURIComponent(action)}`,input),
  access:(id:string,action:'auth'|'policies'|'policy'|'capabilities',input:VaultAccessInput)=>request<VaultAccessResult>('POST',`/servers/${encodeURIComponent(id)}/vault/access/${action}`,input),
  kv:(id:string,action:'list'|'metadata'|'read'|'write',input:VaultKVInput)=>request<VaultKVResult>('POST',`/servers/${encodeURIComponent(id)}/vault/kv/${action}`,input),
  read:(id:string)=>request<VaultConnection>('GET',`/servers/${encodeURIComponent(id)}/vault`),
  save:(id:string,profile:VaultProfile)=>request<{ok:boolean}>('PUT',`/servers/${encodeURIComponent(id)}/vault`,profile),
  remove:(id:string)=>request<void>('DELETE',`/servers/${encodeURIComponent(id)}/vault`),
  inspect:(id:string,token:string)=>request<VaultObservation>('POST',`/servers/${encodeURIComponent(id)}/vault/inspect`,{token}),
 },
 features:()=>request<{automation:boolean;inventory:boolean;jobSupervision:boolean;operationSupervision:boolean;vault:boolean}>('GET','/features'),
 inventory:{
 read:(id:string,after='')=>request<{items:Array<{id:string;kind:string;displayName:string;source:string;dataState:string;lastVerifiedAt:string;details:unknown}>;runs:Array<{id:string;status:string;warning:string;startedAt:string}>;changes:unknown[];next:string}>('GET',`/servers/${encodeURIComponent(id)}/inventory?after=${encodeURIComponent(after)}`),
 discover:(id:string)=>request<{status:string;warning:string}>('POST',`/servers/${encodeURIComponent(id)}/inventory/discover`,{}),
 relationships:(id:string,after='')=>request<{items:InventoryRelationship[];next:string}>('GET',`/servers/${encodeURIComponent(id)}/inventory/relationships?after=${encodeURIComponent(after)}`),
 history:(id:string,resourceId='',before='')=>request<{items:InventoryChange[];next:string}>('GET',`/servers/${encodeURIComponent(id)}/inventory/history?resourceId=${encodeURIComponent(resourceId)}&before=${encodeURIComponent(before)}`),
 },
 audit: {inspect:(operationId:string)=>request<OperationInspection>('GET','/audit/operations/'+encodeURIComponent(operationId)),list:(filters:Record<string,string>={})=>request<{items:Array<{id:number;at:string;operationId:string;actorId:string;action:string;resourceId:string;outcome:string;httpStatus:number;source:string}>;next:string}>('GET','/audit/events?'+new URLSearchParams({...filters,limit:'50'}).toString())},
    auth: {
        stepUp:(currentPassword:string,code:string)=>request<{ok:boolean}>('POST','/auth/step-up',{currentPassword,code}),
        login: (password: string, username = '', deviceLabel = '') =>
            request<{ ok: boolean; mfaRequired: boolean; pendingToken?: string }>('POST', '/auth/login', {password, username, deviceLabel}),
        logout: () => request<{ ok: boolean }>('POST', '/auth/logout'),
        me: () => request<{ok: boolean; mode: string; user: {id: string; username: string; displayName: string}; session: DeviceSession}>('GET', '/auth/me'),
        sessions: () => request<DeviceSession[]>('GET','/auth/sessions'),
        revokeSession: (id: string) => request<void>('DELETE',`/auth/sessions/${encodeURIComponent(id)}`),
        permissions: () => request<{global: Record<string,boolean>; servers: Record<string,string[]>}>('GET','/auth/permissions'),
        logoutAll: () => request<{ok: boolean}>('POST','/auth/logout-all'),
        changePassword: (currentPassword: string, newPassword: string) =>
            request<{ ok: boolean }>('POST', '/auth/password', {currentPassword, newPassword}),
        auditLog: (limit?: number) =>
            request<LoginEvent[]>('GET', limit ? `/auth/audit?limit=${limit}` : '/auth/audit'),
        mfaVerify: (pendingToken: string, code: string, deviceLabel = '') =>
            request<{ ok: boolean }>('POST', '/auth/mfa/verify', {pendingToken, code, deviceLabel}),
        mfaStatus: () => request<{ enabled: boolean; recoveryCodesRemaining:number }>('GET', '/auth/mfa/status'),
        mfaSetup: (currentPassword: string) => request<{ secret: string; uri: string; setupToken: string }>('POST', '/auth/mfa/setup', {currentPassword}),
        mfaEnable: (setupToken: string, code: string) =>
            request<RecoveryResult>('POST', '/auth/mfa/enable', {setupToken, code}),
        recoveryLogin: (pendingToken:string,code:string,deviceLabel='') => request<{ok:boolean}>('POST','/auth/mfa/recovery',{pendingToken,code,deviceLabel}),
        regenerateRecovery: (currentPassword:string) => request<RecoveryResult>('POST','/auth/mfa/recovery-codes',{currentPassword}),
        mfaDisable: (code: string) =>
            request<{ ok: boolean }>('POST', '/auth/mfa/disable', {code}),
    },

    accounts: {
        users: () => request<AccountUser[]>('GET','/users'),
        invitations: () => request<Array<{id:string;userId:string;expiresAt:string;redeemedAt:string|null;revokedAt:string|null}>>('GET','/users/invitations'),
        invite: (input:InviteInput) => request<{token:string}>('POST','/users/invitations',input),
        revokeInvite: (id:string,currentPassword:string) => request<void>('DELETE',`/users/invitations/${encodeURIComponent(id)}`,{currentPassword}),
        status: (id:string,status:string,currentPassword:string) => request('PATCH',`/users/${encodeURIComponent(id)}`,{status,currentPassword}),
        unlock: (id:string,currentPassword:string) => request('POST',`/users/${encodeURIComponent(id)}/unlock`,{currentPassword}),
        requestReset: (id:string,kind:string,reason:string,currentPassword:string) => request<{token:string}>('POST',`/users/${encodeURIComponent(id)}/resets`,{kind,reason,currentPassword}),
        accept: (token:string,password:string) => request<{ok:boolean;username:string}>('POST','/auth/invitations/accept',{token,password}),
        resetInfo: (token:string) => request<{kind:string;username:string;mfaRequired:boolean}>('POST','/auth/reset/info',{token}),
        resetPassword: (token:string,password:string,code:string) => request<RecoveryResult>('POST','/auth/reset/password',{token,password,code}),
        resetMFASetup: (token:string,password:string) => request<MFAEnrollment>('POST','/auth/reset/mfa/setup',{token,password}),
        resetMFAConfirm: (setupToken:string,code:string) => request<RecoveryResult>('POST','/auth/reset/mfa/confirm',{setupToken,code}),
    },
    access: {
        roles: () => request<Array<{id: string; name: string; permissions: string[]}>>('GET','/roles'),
        grants: () => request<Array<{id: string; principalId: string; principalKind: string; roleId: string; scopeType: string; scopeId: string; createdBy: string}>>('GET','/grants'),
        groups: () => request<Array<{id: string; name: string; serverIds: string[];requireMfa:boolean}>>('GET','/server-groups'),
        addGrant: (principalId: string, roleId: string, scopeType: string, scopeId: string, currentPassword: string) => request('POST','/grants',{principalId,roleId,scopeType,scopeId,currentPassword}),
        deleteGrant: (id: string, currentPassword: string) => request<void>('DELETE',`/grants/${encodeURIComponent(id)}`,{currentPassword}),
        groupPolicy:(id:string,requireMfa:boolean,currentPassword:string)=>request('PUT',`/server-groups/${encodeURIComponent(id)}/policy`,{requireMfa,currentPassword}),
        createGroup: (name: string, currentPassword: string) => request('POST','/server-groups',{name,currentPassword}),
        deleteGroup: (id: string, currentPassword: string) => request<void>('DELETE',`/server-groups/${encodeURIComponent(id)}`,{currentPassword}),
        membership: (group: string, server: string, remove: boolean, currentPassword: string) => request(remove ? 'DELETE' : 'PUT',`/server-groups/${encodeURIComponent(group)}/servers/${encodeURIComponent(server)}`,{currentPassword}),
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
            downloadFile(`/servers/${encodeURIComponent(_sid)}/files/download?path=${encodeURIComponent(path)}`),
        upload: (sid: string, dirPath: string, file: File) => {
            const form = new FormData()
            form.append('file', file)
            return fetch(`/api/servers/${sid}/files/upload?path=${encodeURIComponent(dirPath)}`, {
                method: 'POST', credentials: 'include', body: form,
                signal: AbortSignal.timeout(60_000),
            }).then(res => decodeResponse<{ok: boolean; path: string}>(res,'/files/upload'))
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
        enableSSL: (sid: string, ruleId: string, data: { email: string; wildcard: boolean; cfToken: string; renew?: boolean }) =>
            request<{ rule: ProxyRule; output: string; warning?: string; dnsCleanupStatus?: 'unverified' | 'reported_failure' }>('POST', `/servers/${sid}/proxy/${ruleId}/ssl`, data),
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
 getCustom:(id:string)=>request<AppTemplate & {compose:string}>('GET','/templates/custom/'+encodeURIComponent(id)),
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
        create: (sid: string, d: { name: string; command: string; intervalMinutes: number; supervised?: boolean }) =>
            request<ScheduledTask>('POST', `/servers/${sid}/tasks`, d),
        update: (sid: string, tid: string, d: Partial<ScheduledTask>) =>
            request<ScheduledTask>('PUT', `/servers/${sid}/tasks/${tid}`, d),
        delete: (sid: string, tid: string) => request<void>('DELETE', `/servers/${sid}/tasks/${tid}`),
        runNow: (sid: string, tid: string) => request<{ ok: string }>('POST', `/servers/${sid}/tasks/${tid}/run`),
        runs: (sid: string,tid:string)=>request<SupervisedRun[]>('GET',`/servers/${encodeURIComponent(sid)}/tasks/${encodeURIComponent(tid)}/runs`),
        readRun: (sid:string,tid:string,rid:string)=>request<RunObservation>('GET',`/servers/${encodeURIComponent(sid)}/tasks/${encodeURIComponent(tid)}/runs/${encodeURIComponent(rid)}`),
        inspectRun:(sid:string,tid:string,rid:string)=>request<RunObservation>('POST',`/servers/${encodeURIComponent(sid)}/tasks/${encodeURIComponent(tid)}/runs/${encodeURIComponent(rid)}/inspect`),
        cancelRun:(sid:string,tid:string,rid:string)=>request<RunObservation>('POST',`/servers/${encodeURIComponent(sid)}/tasks/${encodeURIComponent(tid)}/runs/${encodeURIComponent(rid)}/cancel`),
        releaseRun:(sid:string,tid:string,rid:string)=>request<RunObservation>('DELETE',`/servers/${encodeURIComponent(sid)}/tasks/${encodeURIComponent(tid)}/runs/${encodeURIComponent(rid)}/artifacts`),
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
 metrics:(id:string)=>`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws/metrics/${encodeURIComponent(id)}`,
        terminal: (sid: string) =>
            `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/terminal/${sid}`,
        logs: (sid: string, cid: string) =>
            `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/logs/${sid}/${cid}`,
    },
}
