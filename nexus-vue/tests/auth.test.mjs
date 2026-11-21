import {test} from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import ts from 'typescript'
import {shallowRef,computed} from 'vue'

let valid = false
let checks = 0
let grants=['servers.read']
globalThis.__authApi = {auth: {
    me: async () => { checks++; if (!valid) throw new Error('401'); return {ok: true} },
    logout: async () => { valid = false },
    permissions: async () => ({global:{}, servers:{dev:grants}}),
}}
// Even a forged legacy hint must not grant frontend authentication.
globalThis.localStorage = {getItem: () => '1', removeItem() {}}
const stub = `data:text/javascript;base64,${Buffer.from('export const api = globalThis.__authApi').toString('base64')}`
globalThis.__authVue={shallowRef}
const vueStub=`data:text/javascript;base64,${Buffer.from('export const {shallowRef}=globalThis.__authVue').toString('base64')}`
const source = readFileSync(new URL('../src/lib/auth.ts', import.meta.url),'utf8').replace("'./api'", JSON.stringify(stub)).replace("'vue'",JSON.stringify(vueStub))
const compiled = ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
const auth = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
test('authentication is confirmed by the server and cleared on revocation/logout', async () => {
    assert.equal(auth.isAuthed(),false)
    await assert.rejects(auth.markAuthed(), /confirm the server session/)
    valid = true
    await auth.markAuthed()
    assert.equal(auth.isAuthed(),true)
    assert.equal(auth.can('servers.read','dev'),true)
    assert.equal(auth.can('servers.read','prod'),false)
    assert.equal(auth.can('docker.manage','dev'),false)
    const permission=computed(()=>auth.can('servers.read','dev'))
    assert.equal(permission.value,true)
    grants=[]
    await auth.verifySession()
    assert.equal(permission.value,false,'refreshed capabilities must invalidate Vue consumers')
    grants=['servers.read']
    valid = false
    assert.equal(await auth.verifySession(),false)
    assert.equal(auth.isAuthed(),false)
    valid = true
    await auth.markAuthed()
    await auth.signOut()
    assert.equal(auth.isAuthed(),false)
    assert.ok(checks >= 4)
})
test('a pending permission response cannot restore access after logout',async()=>{
 valid=true
 const original=globalThis.__authApi.auth.permissions
 let finish
 globalThis.__authApi.auth.permissions=()=>new Promise(resolve=>{finish=resolve})
 try {
  const pending=auth.verifySession()
  await Promise.resolve()
  assert.equal(typeof finish,'function')
  await auth.signOut()
  finish({global:{'servers.read':true},servers:{}})
  assert.equal(await pending,false)
  assert.equal(auth.can('servers.read'),false)
  assert.equal(auth.isAuthed(),false)
 } finally {globalThis.__authApi.auth.permissions=original}
})
