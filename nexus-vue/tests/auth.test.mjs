import {test} from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import ts from 'typescript'

let valid = false
let checks = 0
globalThis.__authApi = {auth: {
    me: async () => { checks++; if (!valid) throw new Error('401'); return {ok: true} },
    logout: async () => { valid = false },
    permissions: async () => ({global:{}, servers:{dev:['servers.read']}}),
}}
// Even a forged legacy hint must not grant frontend authentication.
globalThis.localStorage = {getItem: () => '1', removeItem() {}}
const stub = `data:text/javascript;base64,${Buffer.from('export const api = globalThis.__authApi').toString('base64')}`
const source = readFileSync(new URL('../src/lib/auth.ts', import.meta.url),'utf8').replace("'./api'", JSON.stringify(stub))
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
    valid = false
    assert.equal(await auth.verifySession(),false)
    assert.equal(auth.isAuthed(),false)
    valid = true
    await auth.markAuthed()
    await auth.signOut()
    assert.equal(auth.isAuthed(),false)
    assert.ok(checks >= 4)
})
