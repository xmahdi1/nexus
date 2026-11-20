import {test, afterEach, after} from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import ts from 'typescript'

// Load the real TypeScript client without a browser or an additional test runner.
const source = readFileSync(new URL('../src/lib/api.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, {compilerOptions: {module: ts.ModuleKind.ESNext}}).outputText
const {api} = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
const originalFetch = globalThis.fetch
const originalWindow = globalThis.window
const originalStorage = globalThis.localStorage
const originalEvent = globalThis.CustomEvent
let events = []

test('interactive operations bind request identity and never replay a lost response',async()=>{
 let calls=0
 globalThis.fetch=async(url,options)=>{calls++;assert.equal(url,'/api/servers/fixture/operations/compose/up');assert.deepEqual(JSON.parse(options.body),{requestId:'a'.repeat(32),path:'/opt/fixture.yml'});throw new TypeError('fixture response lost')}
 await assert.rejects(api.operations.start('fixture','compose-up','a'.repeat(32),{path:'/opt/fixture.yml'}),{code:'remote_outcome_unknown'})
 assert.equal(calls,1)
})
globalThis.window = {dispatchEvent: e => events.push(e.type), location: {href: ''}}
globalThis.localStorage = {removeItem() {}}
globalThis.CustomEvent = class {constructor(type) {this.type = type}}
afterEach(() => { globalThis.fetch = originalFetch; events = []; window.location.href = '' })

for (const status of [200, 401, 403, 502]) {
    test(`HTML response ${status} rejects promptly`, {timeout: 1000}, async () => {
        globalThis.fetch = async () => new Response('<html>Proxy login</html>', {status, headers: {'Content-Type': 'text/html; charset=utf-8'}})
        await assert.rejects(api.servers.list(), {code: 'upstream_html', status})
        assert.deepEqual(events, ['nexus:connection-lost'])
    })
}
test('JSON response succeeds', async () => {
    globalThis.fetch = async () => Response.json([])
    assert.deepEqual(await api.servers.list(), [])
})
test('401 redirects to login; 403 preserves session', async () => {
    for (const status of [403, 401]) {
        globalThis.fetch = async () => Response.json({error: 'Denied', code: 'denied'}, {status})
        await assert.rejects(api.servers.list(), {message: 'Denied', code: 'denied'})
        assert.equal(window.location.href, status === 401 ? '/login' : '')
    }
})
test('network failure rejects', async () => {
    globalThis.fetch = async () => {throw new TypeError('Failed to fetch')}
    await assert.rejects(api.servers.list(), /Failed to fetch/)
})
test('204 succeeds without parsing JSON', async () => {
    globalThis.fetch = async () => new Response(null, {status: 204})
    assert.equal(await api.servers.delete('fixture'), undefined)
})

after(() => {
    globalThis.fetch = originalFetch
    globalThis.window = originalWindow
    globalThis.localStorage = originalStorage
    globalThis.CustomEvent = originalEvent
})

test('uploads reject proxy HTML through the common decoder', async () => {
    globalThis.fetch = async () => new Response('<html>Proxy</html>', {headers: {'Content-Type': 'text/html'}})
    await assert.rejects(api.files.upload('fixture', '/', new File(['fixture'], 'test.txt')), {code: 'upstream_html'})
})
test('session metadata and revocation use credentialed bounded requests', async () => {
    globalThis.fetch = async (url, options) => {
        assert.equal(options.credentials, 'include')
        assert.ok(options.signal instanceof AbortSignal)
        if (options.method === 'DELETE') { assert.equal(url, '/api/auth/sessions/device'); return new Response(null, {status: 204}) }
        return Response.json([{id: 'device'}])
    }
    assert.deepEqual(await api.auth.sessions(), [{id: 'device'}])
    await api.auth.revokeSession('device')
})

test('grant and group changes carry explicit scope and credential proof', async () => {
    const calls = []
    globalThis.fetch = async (url, options) => {
        calls.push({url, method: options.method, body: JSON.parse(options.body)})
        return options.method === 'DELETE' ? new Response(null,{status:204}) : Response.json({ok:true})
    }
    await api.access.addGrant('principal','operator','server_group','development','fixture password')
    await api.access.membership('development','server',true,'fixture password')
    await api.access.deleteGrant('grant','fixture password')
    assert.deepEqual(calls[0], {url:'/api/grants', method:'POST', body:{principalId:'principal',roleId:'operator',scopeType:'server_group',scopeId:'development',currentPassword:'fixture password'}})
    assert.equal(calls[1].url,'/api/server-groups/development/servers/server')
    assert.equal(calls[1].method,'DELETE')
    assert.equal(calls[2].body.currentPassword,'fixture password')
})

test('invalid invitation and recovery proofs preserve the current form', async () => {
    globalThis.fetch = async () => Response.json({error:'Invalid proof',code:'credentials'},{status:401})
    for (const action of [
        () => api.accounts.accept('fixture-token','fixture password'),
        () => api.accounts.resetInfo('fixture-token'),
        () => api.accounts.resetPassword('fixture-token','fixture password','fixture-code'),
        () => api.accounts.resetMFASetup('fixture-token','fixture password'),
        () => api.accounts.resetMFAConfirm('fixture-setup','123456'),
        () => api.auth.recoveryLogin('fixture-pending','fixture-code'),
        () => api.auth.regenerateRecovery('wrong password'),
    ]) {
        await assert.rejects(action(),{code:'credentials'})
        assert.equal(window.location.href,'')
    }
})
test('invitation authority and reset proofs are sent in request bodies', async () => {
    const calls=[]
    globalThis.fetch = async (url,options) => {calls.push({url,body:JSON.parse(options.body)});return Response.json({token:'fixture-response'})}
    await api.accounts.invite({username:'viewer',displayName:'Viewer',email:'',roleId:'viewer',scopeType:'server',scopeId:'dev',expiresHours:24,currentPassword:'proof'})
    await api.accounts.requestReset('principal','mfa','lost device','proof')
    await api.accounts.resetInfo('private-token')
    assert.equal(calls[0].body.scopeId,'dev')
    assert.equal(calls[1].body.currentPassword,'proof')
    assert.equal(calls[1].body.reason,'lost device')
    assert.equal(calls[2].url,'/api/auth/reset/info')
    assert.equal(calls[2].body.token,'private-token')
    assert.ok(calls.every(call=>!call.url.includes('private-token')))
})

test('downloads use the common auth/proxy flow and enforce a bounded blob',async()=>{
 globalThis.fetch=async()=>new Response('<html>proxy</html>',{headers:{'content-type':'text/html'}})
 await assert.rejects(api.files.download('fixture','/private'),{code:'upstream_html'})
 globalThis.fetch=async()=>Response.json({error:'Expired',code:'invalid_session'},{status:401})
 await assert.rejects(api.files.download('fixture','/private'),{code:'invalid_session'})
 assert.equal(window.location.href,'/login')
 globalThis.fetch=async()=>new Response('fixture',{headers:{'content-type':'application/octet-stream'}})
 assert.equal(await (await api.files.download('fixture','/private')).text(),'fixture')
 globalThis.fetch=async()=>new Response('fixture',{headers:{'content-length':String(65*1024*1024)}})
 await assert.rejects(api.files.download('fixture','/private'),/64 MiB/)
})

test('session probes return control to route guards without hard-reloading login',async()=>{
 globalThis.fetch=async()=>Response.json({error:'Expired',code:'invalid_session'},{status:401})
 await assert.rejects(api.auth.me(),{code:'invalid_session'});assert.equal(window.location.href,'')
 await assert.rejects(api.auth.permissions(),{code:'invalid_session'});assert.equal(window.location.href,'')
})

test('Compose 200 ok:false rejects and preserves the server operation ID',async()=>{
 const operationId='a'.repeat(32)
 globalThis.fetch=async()=>Response.json({ok:false,error:'Deployment failed',output:'fixture'},{headers:{'X-Operation-ID':operationId}})
 await assert.rejects(api.compose.up('dev','/tmp/recipe.yml'),error=>error.operationId===operationId&&error.message.includes('Deployment failed')&&error.message.includes(operationId))
})
test('A lost mutation response warns of uncertain state without retrying',async()=>{
 let calls=0;globalThis.fetch=async()=>{calls++;throw new TypeError('Failed to fetch')}
 await assert.rejects(api.containers.restart('dev','aaaaaaaaaaaa'),{code:'remote_outcome_unknown'})
 assert.equal(calls,1)
})
test('Operation inspection is an encoded read-only bounded request',async()=>{
 globalThis.fetch=async(url,options)=>{assert.equal(options.method,'GET');assert.equal(url,'/api/audit/operations/fixture%3Aoperation');assert.ok(options.signal);return Response.json({state:'pending',automaticRetryAllowed:false})}
 assert.equal((await api.audit.inspect('fixture:operation')).state,'pending')
})

test('A truncated mutation response retains its operation ID and uncertain outcome',async()=>{
 const operationId='b'.repeat(32)
 globalThis.fetch=async()=>new Response('{"ok":',{headers:{'Content-Type':'application/json','X-Operation-ID':operationId}})
 await assert.rejects(api.containers.restart('dev','aaaaaaaaaaaa'),error=>error.code==='remote_outcome_unknown'&&error.operationId===operationId)
})
