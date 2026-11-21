import {test} from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {parse, compileScript} from '@vue/compiler-sfc'
import * as vue from 'vue'
import ts from 'typescript'

test('inventory screen discards stale previews and credentials, and clears revoked access', async () => {
 const cleanup=[]
 let permitted=true, finishPreview, finishIssue, issues=0
 const preview={revision:'revision',groups:{},inventory:{_meta:{hostvars:{}}}}
 globalThis.__automationFixture={
  vue:{...vue,onMounted(){},onUnmounted(fn){cleanup.push(fn)}},
  verifySession:async()=>true, canAny:()=>permitted,
  api:{features:async()=>({automation:true}),ansible:{
   groups:async()=>[{id:'one',name:'One'},{id:'two',name:'Two'}],tokens:async()=>[],
   preview:()=>new Promise(resolve=>{finishPreview=resolve}),
   issue:()=>{issues++;return new Promise(resolve=>{finishIssue=resolve})},
  }},
 }
 const stub=code=>`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`
 const modules={
  vue:stub('export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__automationFixture.vue'),
  '@/lib/api':stub('export const api=globalThis.__automationFixture.api'),
  '@/lib/auth':stub('export const {verifySession,canAny}=globalThis.__automationFixture'),
  '@/components/AppLayout.vue':stub('export default {}'),
  '@/components/ui/Button.vue':stub('export default {}'),
 }
 const {descriptor}=parse(readFileSync(new URL('../src/views/AutomationView.vue',import.meta.url),'utf8'))
 const script=compileScript(descriptor,{id:'automation-fixture'}).content
 let compiled=ts.transpileModule(script,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
 for(const [name,value] of Object.entries(modules)) compiled=compiled.replaceAll(`'${name}'`,JSON.stringify(value))
 const component=(await import(stub(compiled))).default
 const scope=vue.effectScope()
 const originalDocument=globalThis.document
 globalThis.document={removeEventListener(){}}
 try {
  const state=scope.run(()=>component.setup({}, {expose(){}}))
  await state.load()
  assert.equal(state.selected.value,'one')
  const first=state.inspect()
  state.selected.value='two'
  finishPreview(preview)
  await first
  assert.equal(state.preview.value,null,'old group preview must be discarded')
  const next=state.inspect(); finishPreview(preview); await next
  assert.deepEqual(state.preview.value,preview)
  const pending=state.issue()
  state.selected.value='one'
  finishIssue({id:'token',groupId:'two',token:'sensitive',createdAt:'now',expiresAt:new Date(Date.now()+60000).toISOString()})
  await pending
  assert.equal(state.issued.value,'','old group credential must not be shown')
  assert.equal(issues,1,'credential issue must not retry automatically')
  state.issued.value='secret';state.tokens.value=[{id:'token'}]
  permitted=false
  await state.load()
  assert.equal(state.issued.value,'')
  assert.deepEqual(state.tokens.value,[])
  assert.deepEqual(state.groups.value,[])
  assert.equal(state.preview.value,null)
 } finally {
  for(const dispose of cleanup) dispose()
  scope.stop();globalThis.document=originalDocument;delete globalThis.__automationFixture
 }
})
