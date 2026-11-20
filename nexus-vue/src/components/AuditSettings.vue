<script setup lang="ts">
import {onMounted,ref,watch} from 'vue'
import {api,type OperationInspection} from '@/lib/api'
import {can} from '@/lib/auth'
import Button from './ui/Button.vue'
import Input from './ui/Input.vue'
const available=can('audit.read')
const rows=ref<Array<{id:number;at:string;operationId:string;actorId:string;action:string;resourceId:string;outcome:string;httpStatus:number;source:string}>>([])
const actor=ref(''),server=ref(''),operation=ref(''),outcome=ref(''),next=ref(''),error=ref(''),loading=ref(false)
const inspection=ref<OperationInspection|null>(null)
async function inspect(){
 const id=operation.value
 if(!id)return
 error.value='';loading.value=true;inspection.value=null
 try{const result=await api.audit.inspect(id);if(operation.value===id)inspection.value=result}catch(e){error.value=e instanceof Error?e.message:'Inspection unavailable'}finally{loading.value=false}
}

watch(operation,()=>{inspection.value=null})
async function load(more=false){
 if(!available)return
 loading.value=true;error.value=''
 try {const page=await api.audit.list({actor:actor.value,server:server.value,outcome:outcome.value,operation:operation.value,before:more?next.value:''});rows.value=more?[...rows.value,...page.items]:page.items;next.value=page.next}
 catch(e){error.value=e instanceof Error?e.message:'Could not read audit'}finally{loading.value=false}
}
async function exportPage(){
 try {const page=await api.audit.list({actor:actor.value,server:server.value,outcome:outcome.value,operation:operation.value});const url=URL.createObjectURL(new Blob([page.items.map(e=>JSON.stringify(e)).join('\n')],{type:'application/x-ndjson'}));const a=document.createElement('a');a.href=url;a.download='nexus-audit-page.jsonl';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}catch(e){error.value=e instanceof Error?e.message:'Export failed'}
}
onMounted(()=>load())
</script>
<template>
 <div v-if="available" class="border rounded-lg p-4 space-y-3">
  <h3 class="font-medium">Operation audit</h3>
  <p class="text-xs text-muted-foreground">Intent and HTTP results are separate events. A successful response is the handler's report, not independent verification of remote state. An intent without a result may be running, interrupted, or missing its final audit write. Retention is a local administrator operation.</p>
  <Input v-model="operation" aria-label="Operation ID filter" placeholder="Operation ID (optional)"/><div class="grid gap-2 sm:grid-cols-3"><Input v-model="actor" aria-label="Actor ID filter" placeholder="Actor ID"/><Input v-model="server" aria-label="Server ID filter" placeholder="Server ID"/><select v-model="outcome" aria-label="Audit outcome" class="border rounded-md p-2 bg-background"><option value="">All outcomes</option><option>started</option><option>response_succeeded</option><option>response_failed</option><option>stream_closed</option><option>interrupted</option><option>remote_unknown</option><option>allowed</option><option>denied</option><option>succeeded</option><option>success</option><option>failed</option><option>partial</option><option>cancelled</option><option>step_up_required</option><option>requested</option></select></div>
  <div class="flex gap-2"><Button variant="outline" :disabled="loading" @click="load()">Filter / refresh</Button><Button variant="outline" :disabled="loading" @click="exportPage">Export first 50 matches</Button><Button variant="outline" :disabled="loading||!operation" @click="inspect">Inspect operation</Button></div>
  <div v-if="inspection" role="status" class="border rounded-md p-3 text-sm space-y-1"><p>Operation {{inspection.id}} state: <strong>{{inspection.state}}</strong></p><p>{{inspection.action}} · {{inspection.resourceType}} {{inspection.resourceId}}</p><p>{{inspection.guidance}}</p><p v-if="inspection.state==='pending'">The operation may still be running, interrupted, or missing its final audit write.</p><p>Remote state verified: {{inspection.remoteStateVerified?'yes':'no'}} · Automatic retry allowed: {{inspection.automaticRetryAllowed?'yes':'no'}}</p></div>
  <p v-if="error" role="alert" class="text-sm text-destructive">{{error}}</p>
  <div class="overflow-x-auto"><table class="text-xs w-full"><thead><tr><th class="text-left p-2">Time / operation</th><th class="text-left p-2">Actor / target</th><th class="text-left p-2">Action</th><th class="text-left p-2">Outcome</th></tr></thead><tbody><tr v-for="row in rows" :key="row.id" class="border-t"><td class="p-2">{{new Date(row.at).toLocaleString()}}<div class="font-mono">{{row.operationId}}</div></td><td class="p-2 break-all">{{row.actorId}}<div>{{row.resourceId}}</div></td><td class="p-2">{{row.action}}</td><td class="p-2">{{row.outcome}} {{row.httpStatus||''}}</td></tr></tbody></table></div>
  <Button v-if="next" variant="outline" :disabled="loading" @click="load(true)">Load older events</Button>
 </div>
</template>
