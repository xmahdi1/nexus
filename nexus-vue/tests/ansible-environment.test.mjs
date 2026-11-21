import {test} from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {parse,compileScript} from '@vue/compiler-sfc'
import * as vue from 'vue'
import ts from 'typescript'

test('environment submission retains identity without retry and discards revoked results',async()=>{
 const grants=vue.ref(new Set(['ansible.environment.read','ansible.environment.manage','servers.execute','secrets.use','jobs.read','logs.read']))
 let finish, calls=0
 const cleanup=[]
 globalThis.__environmentFixture={
  vue:{...vue,onUnmounted(fn){cleanup.push(fn)}},can:permission=>grants.value.has(permission),useConfirm:()=>({confirm:async()=>true}),
  api:{operations:{start:()=>{calls++;return new Promise(resolve=>{finish=resolve})}}},
 }
 const stub=code=>`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`
 const modules={
  vue:stub('export const {defineComponent,computed,onUnmounted,ref,watch}=globalThis.__environmentFixture.vue'),
  '@/lib/api':stub('export const api=globalThis.__environmentFixture.api'),
  '@/lib/auth':stub('export const can=globalThis.__environmentFixture.can'),
  '@/composables/useConfirm':stub('export const useConfirm=globalThis.__environmentFixture.useConfirm'),
  '@/components/ui/Button.vue':stub('export default {}'),
 }
 const {descriptor}=parse(readFileSync(new URL('../src/components/AnsibleEnvironmentTab.vue',import.meta.url),'utf8'))
 const script=compileScript(descriptor,{id:'environment-fixture'}).content
 let compiled=ts.transpileModule(script,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
 for(const [name,value] of Object.entries(modules))compiled=compiled.replaceAll(`'${name}'`,JSON.stringify(value))
 const component=(await import(stub(compiled))).default
 const scope=vue.effectScope()
 try {
  const emitted=[]
  const state=scope.run(()=>component.setup({serverId:'dev',enabled:true},{expose(){},emit:(name,id)=>emitted.push([name,id])}))
  const pending=state.start('ansible-environment-install')
  await Promise.resolve()
  assert.equal(calls,1)
  const id=state.runId.value
  assert.match(id,/^[a-f0-9]{32}$/)
  assert.deepEqual(emitted,[['submitted',id]])
  grants.value.delete('ansible.environment.read');await vue.nextTick()
  finish({run:{id,state:'running'}})
  await pending
  assert.equal(state.result.value,null)
  assert.equal(state.submittedState.value,'')
  assert.equal(state.runId.value,id,'uncertain identity must remain available for history')
  await state.start('ansible-environment-install')
  assert.equal(calls,1,'revoked or unresolved work must never be resubmitted')
 }finally{for(const dispose of cleanup)dispose();scope.stop();delete globalThis.__environmentFixture}
})
