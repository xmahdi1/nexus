<script setup lang="ts">
import {computed, onUnmounted, ref, watch} from 'vue'
import {api, type AnsibleEnvironmentAction, type RunObservation} from '@/lib/api'
import {can} from '@/lib/auth'
import {useConfirm} from '@/composables/useConfirm'
import Button from '@/components/ui/Button.vue'

const props=defineProps<{serverId:string;enabled:boolean}>()
const emit=defineEmits<{submitted:[id:string]}>()
const {confirm}=useConfirm()
const busy=ref(false), error=ref(''), runId=ref(''), result=ref<RunObservation|null>(null)
const submittedState=ref('')
let generation=0, alive=true
const viewable=computed(()=>['ansible.environment.read','jobs.read','logs.read','secrets.use','servers.execute'].every(p=>can(p,props.serverId)))
const manageable=computed(()=>viewable.value && can('ansible.environment.manage',props.serverId))
const terminal=computed(()=>!!result.value?.run.finishedAt)
watch(()=>[props.serverId,viewable.value,manageable.value].join(','),()=>{generation++;result.value=null;submittedState.value='';error.value='';busy.value=false})
watch(()=>props.serverId,()=>{runId.value=''}, {flush:'sync'})
onUnmounted(()=>{alive=false;generation++;result.value=null})
const labels:Record<AnsibleEnvironmentAction,string>={'ansible-environment-install':'Install','ansible-environment-update':'Update','ansible-environment-health':'Check health','ansible-environment-remove':'Remove environment'}
async function start(action:AnsibleEnvironmentAction) {
 if (busy.value || !props.enabled || !viewable.value || (action!=='ansible-environment-health'&&!manageable.value) || (runId.value&&!terminal.value)) return
 const current=generation, server=props.serverId
 if (action!=='ansible-environment-health') {
  const ok=await confirm({title:labels[action]+' Ansible environment?',message:action==='ansible-environment-install'?'Create a dedicated non-root controller account and install the reviewed Ansible package set on this server? Python 3.13–3.15, venv, root SSH and systemd/cgroup v2 are required.':action==='ansible-environment-remove'?'Remove only the owned Ansible environment. The controller account and home remain. Playbooks may depend on this environment.':'Install the currently reviewed package versions into the owned environment. Existing system Ansible installations are unaffected.',confirmText:labels[action],destructive:action==='ansible-environment-remove'})
  if (!ok || !alive || current!==generation || server!==props.serverId) return
 }
 busy.value=true;error.value='';result.value=null;submittedState.value=''
 const id=crypto.randomUUID().replaceAll('-','');runId.value=id;emit('submitted',id)
 try {
  const response=await api.operations.start(server,action,id,{})
  if(alive&&current===generation) submittedState.value=response.run.state
 } catch(e) {if(alive&&current===generation) error.value=(e instanceof Error?e.message:'Submission could not be confirmed.')+' Inspect this run before starting another operation.'}
 finally {if(alive&&current===generation)busy.value=false}
}
async function inspect() {
 if(busy.value||!runId.value||!viewable.value)return
 busy.value=true;error.value='';const current=generation, server=props.serverId
 try {const next=await api.operations.inspect(server,runId.value);if(alive&&current===generation)result.value=next}
 catch(e){if(alive&&current===generation)error.value=e instanceof Error?e.message:'Could not inspect the retained operation.'}
 finally{if(alive&&current===generation)busy.value=false}
}
</script>

<template>
 <section class="space-y-4" aria-label="Ansible environment">
  <h2 class="font-semibold">Managed Ansible environment</h2>
  <p class="text-sm text-muted-foreground">Install Ansible 2.22.0 and its reviewed, hash-verified packages on this controller. Ansible runs under a dedicated account with a private home, separate from Nexus SSH and CI build identities. Inventory and playbook execution permissions remain separate.</p>
  <p v-if="!enabled">Enable automation and operation supervision to submit environment actions.</p>
  <p v-if="!viewable">Environment read access, SSH execution, secret use, job read and log read grants are required to inspect these actions.</p>
  <div class="flex flex-wrap gap-2"><Button v-for="(label,action) in labels" :key="action" :disabled="busy||!enabled||!viewable||(action!=='ansible-environment-health'&&!manageable)||(!!runId&&!terminal)" @click="start(action)">{{label}}</Button></div>
  <p class="text-sm text-muted-foreground">Requires a Linux controller with Python 3.13–3.15 (GIL build), venv and OpenSSH. Supported wheels: x86_64 and aarch64. Existing installations and accounts are never adopted automatically. A health check reports missing prerequisites; it does not install system packages.</p>
  <p v-if="error" role="alert" class="text-destructive">{{error}}</p>
  <div v-if="runId" class="border rounded p-3 space-y-3"><p class="text-sm break-all">Run: <code>{{runId}}</code></p><p v-if="submittedState&&!result">Submission state: {{submittedState}}</p><Button :disabled="busy||!viewable" @click="inspect">Inspect retained run</Button><template v-if="result"><p>Supervisor state: {{result.run.state}}</p><pre v-if="result.observation.output" class="text-xs whitespace-pre-wrap break-all">{{result.observation.output}}</pre></template><p class="text-sm">Operation history has restart-safe inspection, cancellation and artifact cleanup. Cancellation cannot undo account creation or package changes already applied.</p></div>
 </section>
</template>
