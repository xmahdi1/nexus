<script setup lang="ts">
import {onMounted, ref} from 'vue'
import {api, type Server} from '@/lib/api'
import Button from './ui/Button.vue'
import Input from './ui/Input.vue'
import Label from './ui/Label.vue'

type Role = {id: string; name: string; permissions: string[]}
type Grant = {id: string; principalId: string; principalKind: string; roleId: string; scopeType: string; scopeId: string; createdBy: string}
type Group = {id: string; name: string; serverIds: string[]}
const available = ref(false)
const loading = ref(false)
const error = ref('')
const password = ref('')
const roles = ref<Role[]>([])
const grants = ref<Grant[]>([])
const groups = ref<Group[]>([])
const servers = ref<Server[]>([])
const currentPrincipal = ref('')
const principal = ref('')
const role = ref('viewer')
const scope = ref('server')
const scopeId = ref('')
const groupName = ref('')
const member = ref<Record<string,string>>({})
async function load() {
  loading.value = true; error.value = ''
  try {
    const permissions = await api.auth.permissions()
    available.value = !!permissions.global['roles.manage'] && !!permissions.global['groups.manage']
    if (!available.value) return
    const [me, r, g, collections, hosts] = await Promise.all([api.auth.me(), api.access.roles(), api.access.grants(), api.access.groups(), api.servers.list()])
    currentPrincipal.value = me.user.id
    if (!principal.value) principal.value = me.user.id
    roles.value = r; grants.value = g; groups.value = collections; servers.value = hosts
  } catch (e) { error.value = e instanceof Error ? e.message : 'Could not load access settings' }
  finally { loading.value = false }
}
async function change(action: () => Promise<unknown>, target = '') {
  if (!password.value) { error.value = 'Enter the current password to confirm access changes.'; return }
  loading.value = true; error.value = ''
  try {
    await action()
    password.value = ''
    if (target === currentPrincipal.value) { window.location.href = '/login'; return }
    await load()
  } catch (e) { error.value = e instanceof Error ? e.message : 'Access change failed' }
  finally { loading.value = false }
}
onMounted(load)
</script>

<template>
  <div v-if="available || error" class="border rounded-lg p-4 space-y-4">
    <div class="flex items-center justify-between gap-2">
      <h3 class="font-medium">Roles and server groups</h3>
      <Button variant="outline" size="sm" :disabled="loading" @click="load">Refresh</Button>
    </div>
    <p class="text-xs text-muted-foreground">Additional-user login is not available yet. These grants define access for existing identities. Host control permits broad commands and file access. The upgrade's compatibility grants are listed below.</p>
    <p v-if="error" class="text-sm text-destructive" role="alert">{{ error }}</p>
    <template v-if="available">
      <div class="space-y-1.5">
        <Label for="policy-password">Current password to confirm changes</Label>
        <Input id="policy-password" v-model="password" type="password" autocomplete="current-password"/>
        <p class="text-xs text-muted-foreground">When MFA is enabled, sign in again if your confirmation is older than five minutes. Affected devices are signed out when access changes.</p>
      </div>
      <div class="grid gap-2 sm:grid-cols-2">
        <Input v-model="groupName" aria-label="New server group name" placeholder="Development, Production, Homelab…"/>
        <Button variant="outline" :disabled="loading || !groupName.trim()" @click="change(() => api.access.createGroup(groupName, password))">Create group</Button>
      </div>
      <div v-for="group in groups" :key="group.id" class="border rounded-md p-3 space-y-2">
        <div class="flex justify-between gap-2"><p class="font-medium text-sm">{{ group.name }}</p>
          <Button variant="outline" size="sm" :disabled="loading" @click="change(() => api.access.deleteGroup(group.id, password))">Delete group</Button></div>
        <div v-for="id in group.serverIds" :key="id" class="flex justify-between items-center gap-2 text-sm">
          <span>{{ servers.find(s => s.id === id)?.name ?? id }}</span>
          <Button variant="outline" size="sm" :disabled="loading" @click="change(() => api.access.membership(group.id, id, true, password))">Remove member</Button>
        </div>
        <div class="flex gap-2">
          <select v-model="member[group.id]" :aria-label="`Add server to ${group.name}`" class="min-w-0 flex-1 border rounded-md bg-background p-2 text-sm">
            <option value="">Choose server</option><option v-for="server in servers.filter(s => !group.serverIds.includes(s.id))" :key="server.id" :value="server.id">{{ server.name }}</option>
          </select>
          <Button variant="outline" size="sm" :disabled="loading || !member[group.id]" @click="change(() => api.access.membership(group.id, member[group.id]!, false, password))">Add member</Button>
        </div>
      </div>
      <div class="space-y-2 border-t pt-3">
        <h4 class="text-sm font-medium">Assign a role</h4>
        <Input v-model="principal" aria-label="Principal ID" placeholder="Existing user or service identity ID"/>
        <div class="grid gap-2 sm:grid-cols-2">
          <select v-model="role" aria-label="Role" class="border rounded-md bg-background p-2 text-sm"><option v-for="item in roles" :key="item.id" :value="item.id">{{ item.name }}</option></select>
          <select v-model="scope" aria-label="Resource scope" class="border rounded-md bg-background p-2 text-sm" @change="scopeId = ''"><option value="server">Server</option><option value="server_group">Server group</option><option value="global">Global</option></select>
        </div>
        <select v-if="scope !== 'global'" v-model="scopeId" aria-label="Scope target" class="w-full border rounded-md bg-background p-2 text-sm">
          <option value="">Choose target</option><option v-for="item in scope === 'server' ? servers : groups" :key="item.id" :value="item.id">{{ item.name }}</option>
        </select>
        <p v-if="role === 'host-control' || role === 'log-reader' || role === 'secret-reader'" class="text-sm text-destructive">This role grants access to commands, files, logs or secrets beyond normal operator access. Verify the identity and target scope.</p>
        <Button variant="outline" :disabled="loading || !principal || (scope !== 'global' && !scopeId)" @click="change(() => api.access.addGrant(principal, role, scope, scope === 'global' ? '' : scopeId, password), principal)">Assign role</Button>
      </div>
      <div class="space-y-2 border-t pt-3">
        <h4 class="text-sm font-medium">Current grants</h4>
        <p v-if="!grants.length" class="text-sm text-muted-foreground">No grants.</p>
        <div v-for="grant in grants" :key="grant.id" class="border rounded-md p-3 flex items-center justify-between gap-2">
          <div class="min-w-0 text-xs break-all"><p class="font-medium">{{ grant.roleId }} · {{ grant.scopeType }} {{ grant.scopeId }}</p><p>{{ grant.principalId }}</p><p class="text-muted-foreground">Assigned by {{ grant.createdBy }}</p></div>
          <Button variant="outline" size="sm" :disabled="loading" @click="change(() => api.access.deleteGrant(grant.id, password), grant.principalId)">Revoke</Button>
        </div>
      </div>
    </template>
  </div>
</template>
