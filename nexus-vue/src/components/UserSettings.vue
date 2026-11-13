<script setup lang="ts">
import {onMounted, ref} from 'vue'
import {api, type AccountUser} from '@/lib/api'
import {can} from '@/lib/auth'
import Button from './ui/Button.vue'
import Input from './ui/Input.vue'
import Label from './ui/Label.vue'
const available = can('users.read') && can('users.manage') && can('roles.manage')
const users = ref<AccountUser[]>([])
const invitations = ref<Array<{id:string;userId:string;expiresAt:string;redeemedAt:string|null;revokedAt:string|null}>>([])
const hosts = ref<Array<{id:string;name:string}>>([]), groups = ref<Array<{id:string;name:string}>>([])
const password = ref(''), username = ref(''), displayName = ref(''), email = ref('')
const role = ref('viewer'), scope = ref('server'), scopeId = ref('')
const reason = ref(''), loading = ref(false), error = ref(''), link = ref(''), linkKind = ref('')
const actorMFA = ref(false)
async function load() {
  if (!available) return
  loading.value = true; error.value = ''
  try { const [u,i,s,g,m] = await Promise.all([api.accounts.users(),api.accounts.invitations(),api.servers.list(),api.access.groups(),api.auth.mfaStatus()]);users.value=u;invitations.value=i;hosts.value=s;groups.value=g;actorMFA.value=m.enabled }
  catch (e) { error.value = e instanceof Error ? e.message : 'Could not load accounts' }
  finally { loading.value = false }
}
async function perform(action:()=>Promise<unknown>) {
  if (!password.value) { error.value = 'Enter your current password to confirm this action.'; return }
  loading.value=true; error.value=''
  try { await action(); password.value=''; if (!link.value) await load() }
  catch (e) { error.value=e instanceof Error ? e.message : 'Account action failed' }
  finally { loading.value=false }
}
async function invite() {
  await perform(async () => { const result=await api.accounts.invite({username:username.value,displayName:displayName.value,email:email.value,roleId:role.value,scopeType:scope.value,scopeId:scope.value==='global'?'':scopeId.value,expiresHours:24,currentPassword:password.value});link.value=`${location.origin}/join#invite=${result.token}`;linkKind.value='Invitation (24 hours)';username.value='';displayName.value='';email.value='' })
}
async function reset(user:AccountUser,kind:'password'|'mfa') {
  await perform(async()=>{const result=await api.accounts.requestReset(user.id,kind,reason.value,password.value);link.value=`${location.origin}/recover#token=${result.token}`;linkKind.value=kind==='mfa'?'MFA recovery (30 minutes; fresh enrollment required)':'Password recovery (30 minutes; existing MFA preserved)';reason.value=''})
}
async function copied() { try { await navigator.clipboard.writeText(link.value) } catch { error.value='Select and copy the link manually.' } }
onMounted(load)
</script>
<template>
  <div v-if="available" class="border rounded-lg p-4 space-y-4">
    <div class="flex items-center justify-between gap-3"><h3 class="font-medium">Accounts and invitations</h3><Button variant="outline" size="sm" :disabled="loading || !!link" @click="load">Refresh</Button></div>
    <p class="text-xs text-muted-foreground">Invite-only access. Confirm with your password and recent MFA when enabled. MFA resets additionally require your MFA to be enabled and recently verified. Requests are audited and sign the affected account out.</p>
    <p v-if="error" class="text-sm text-destructive" role="alert">{{ error }}</p>
    <div v-if="link" class="space-y-2 border rounded-md p-3">
      <p class="text-sm font-medium">{{ linkKind }}</p><p class="text-xs">Shown once. Deliver privately to the intended person; no email is sent automatically.</p>
      <Input :model-value="link" read-only aria-label="One-time private account link"/>
      <div class="flex gap-2"><Button variant="outline" size="sm" @click="copied">Copy link</Button><Button variant="outline" size="sm" @click="link=''; load()">I saved it</Button></div>
    </div>
    <template v-else>
      <Label for="account-proof">Your current password</Label><Input id="account-proof" v-model="password" type="password" autocomplete="current-password"/>
      <div class="grid gap-2 sm:grid-cols-2"><Input v-model="username" placeholder="Username" aria-label="Invited username"/><Input v-model="displayName" placeholder="Display name (optional)" aria-label="Display name"/></div>
      <Input v-model="email" type="email" placeholder="Email for account metadata (optional)" aria-label="Email"/>
      <div class="grid gap-2 sm:grid-cols-2">
        <select v-model="role" aria-label="Invitation role" class="border rounded-md p-2 bg-background text-sm"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select>
        <select v-model="scope" aria-label="Invitation scope" class="border rounded-md p-2 bg-background text-sm" @change="scopeId=''">
          <option value="server">Server</option><option value="server_group">Server group</option><option value="global">Global</option>
        </select>
      </div>
      <select v-if="scope!=='global'" v-model="scopeId" aria-label="Invitation target" class="w-full border rounded-md p-2 bg-background text-sm"><option value="">Choose target</option><option v-for="item in scope==='server'?hosts:groups" :key="item.id" :value="item.id">{{ item.name }}</option></select>
      <Button variant="outline" :disabled="loading || !username || (scope!=='global' && !scopeId)" @click="invite">Create invitation</Button>
      <p class="text-xs text-muted-foreground">Reissuing an unaccepted username revokes its older invitation and replaces its pending role assignment. Active usernames cannot be invited again.</p>
      <div v-for="invitation in invitations.filter(i=>!i.redeemedAt && !i.revokedAt)" :key="invitation.id" class="flex items-center justify-between gap-2 text-xs border-t pt-2">
        <span>{{ users.find(u=>u.id===invitation.userId)?.username ?? invitation.userId }} · Expires {{ new Date(invitation.expiresAt).toLocaleString() }}</span>
        <Button variant="outline" size="sm" :disabled="loading" @click="perform(()=>api.accounts.revokeInvite(invitation.id,password))">Revoke invitation</Button>
      </div>
      <div class="border-t pt-3 space-y-2">
        <Label for="reset-reason">Reason for account recovery (no secrets)</Label><Input id="reset-reason" v-model="reason" maxlength="240" placeholder="Lost password or authenticator"/>
        <div v-for="user in users" :key="user.id" class="border rounded-md p-3 space-y-2">
          <p class="text-sm font-medium">{{ user.displayName }} ({{ user.username }})</p>
          <p class="text-xs text-muted-foreground">{{ user.status }} · {{ user.admitted?'Admitted':'Not admitted' }} · MFA {{ user.mfaEnabled?'enabled':'disabled' }} <span v-if="user.recoveryRequired">· Recovery pending</span></p>
          <div v-if="user.admitted" class="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" :disabled="loading" @click="perform(()=>api.accounts.status(user.id,user.status==='disabled'?'active':'disabled',password))">{{ user.status==='disabled'?'Reactivate':'Disable' }}</Button>
            <Button variant="outline" size="sm" :disabled="loading" @click="perform(()=>api.accounts.unlock(user.id,password))">Clear login lockout</Button>
            <Button v-if="user.status==='active'" variant="outline" size="sm" :disabled="loading || !reason" @click="reset(user,'password')">Request password reset</Button>
            <Button v-if="user.status==='active'" variant="outline" size="sm" :disabled="loading || !reason || !actorMFA" @click="reset(user,'mfa')">Request MFA recovery</Button>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>
