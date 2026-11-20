<script setup lang="ts">
import {onMounted,ref} from 'vue'
import {api} from '@/lib/api'
import {can} from '@/lib/auth'
import Button from './ui/Button.vue'
const props=defineProps<{serverId:string}>()
const items=ref<Array<{id:string;kind:string;displayName:string;source:string;dataState:string;lastVerifiedAt:string;details:unknown}>>([])
const runs=ref<Array<{id:string;status:string;warning:string;startedAt:string}>>([])
const next=ref(''),error=ref(''),loading=ref(false),scanning=ref(false)
async function load(more=false){loading.value=true;error.value='';try{const result=await api.inventory.read(props.serverId,more?next.value:'');items.value=more?[...items.value,...result.items]:result.items;runs.value=result.runs;next.value=result.next}catch(e){error.value=e instanceof Error?e.message:'Inventory unavailable'}finally{loading.value=false}}
async function discover(){scanning.value=true;error.value='';try{await api.inventory.discover(props.serverId);await load()}catch(e){error.value=e instanceof Error?e.message:'Discovery failed'}finally{scanning.value=false}}
onMounted(()=>load())
</script>
<template>
 <div class="space-y-4">
  <div class="flex flex-wrap justify-between gap-2"><h2 class="font-semibold">Observed inventory</h2><div class="flex gap-2"><Button variant="outline" :disabled="loading||scanning" @click="load()">Refresh records</Button><Button v-if="can('inventory.discover',serverId)" :disabled="loading||scanning" @click="discover">{{scanning?'Collecting…':'Collect read-only inventory'}}</Button></div></div>
  <p class="text-sm text-muted-foreground">Opt-in preview. Collection uses fixed read-only commands on this registered host. Internal container ports, host publications and observed listeners are separate facts. No public reachability is inferred. Observations become stale after 15 minutes; unavailable collectors preserve prior data.</p>
  <p v-if="error" role="alert" class="text-sm text-destructive">{{error}}</p>
  <p v-if="!loading&&!items.length" class="text-sm">No observations yet. An authorized administrator can collect this host's inventory.</p>
  <div class="overflow-x-auto"><table class="w-full text-sm"><thead><tr><th class="p-2 text-left">Resource</th><th class="p-2 text-left">Source / state</th><th class="p-2 text-left">Last verified</th><th class="p-2 text-left">Observed properties</th></tr></thead><tbody><tr v-for="item in items" :key="item.id" class="border-t"><td class="p-2">{{item.kind}} · {{item.displayName}}</td><td class="p-2">{{item.source}} · {{item.dataState}}</td><td class="p-2">{{new Date(item.lastVerifiedAt).toLocaleString()}}</td><td class="p-2"><pre class="text-xs whitespace-pre-wrap break-all">{{JSON.stringify(item.details,null,2)}}</pre></td></tr></tbody></table></div>
  <Button v-if="next" variant="outline" :disabled="loading" @click="load(true)">Load more observations</Button>
  <div class="border rounded-md p-3 space-y-2"><h3 class="font-medium">Recent collection runs</h3><p v-for="run in runs" :key="run.id" class="text-xs">{{new Date(run.startedAt).toLocaleString()}} · {{run.status}} <span>{{run.warning}}</span></p></div>
 </div>
</template>
