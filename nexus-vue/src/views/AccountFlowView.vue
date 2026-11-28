<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import QRCode from 'qrcode';
import { api } from '@/lib/api';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';
import Label from '@/components/ui/Label.vue';
import RecoveryCodes from '@/components/RecoveryCodes.vue';
const joining = useRoute().path === '/join';
const fragment = new URLSearchParams(window.location.hash.slice(1));
const token = fragment.get(joining ? 'invite' : 'token') ?? '';
// Keep the bearer secret out of later navigation, referers, and persisted state.
window.history.replaceState(window.history.state, '', window.location.pathname);
const password = ref(''),
  confirm = ref(''),
  code = ref('');
const loading = ref(false),
  error = ref(''),
  done = ref(false);
const kind = ref(''),
  username = ref(''),
  needsMFA = ref(false);
const setupToken = ref(''),
  secret = ref(''),
  qr = ref('');
const recoveryCodes = ref<string[]>([]);
onMounted(async () => {
  if (!token) {
    error.value = 'Open a valid invitation or recovery link from your administrator.';
    return;
  }
  if (joining) return;
  loading.value = true;
  try {
    const info = await api.accounts.resetInfo(token);
    kind.value = info.kind;
    username.value = info.username;
    needsMFA.value = info.mfaRequired;
  } catch {
    error.value =
      'This recovery link is invalid, expired, revoked, or no longer authorized. Request a new link.';
  } finally {
    loading.value = false;
  }
});
async function submit() {
  error.value = '';
  if (password.value !== confirm.value || new TextEncoder().encode(password.value).length < 12) {
    error.value = 'Enter matching passwords of at least 12 bytes.';
    return;
  }
  loading.value = true;
  try {
    if (joining) {
      const result = await api.accounts.accept(token, password.value);
      username.value = result.username;
      done.value = true;
    } else if (kind.value === 'password') {
      const result = await api.accounts.resetPassword(token, password.value, code.value);
      recoveryCodes.value = result.recoveryCodes ?? [];
      done.value = true;
    } else if (kind.value === 'mfa') {
      const enrollment = await api.accounts.resetMFASetup(token, password.value);
      setupToken.value = enrollment.setupToken;
      secret.value = enrollment.secret;
      qr.value = await QRCode.toDataURL(enrollment.uri, { width: 200, margin: 1 });
    }
    password.value = '';
    confirm.value = '';
    code.value = '';
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Account setup failed';
  } finally {
    loading.value = false;
  }
}
async function finishMFA() {
  loading.value = true;
  error.value = '';
  try {
    const result = await api.accounts.resetMFAConfirm(setupToken.value, code.value);
    recoveryCodes.value = result.recoveryCodes;
    done.value = true;
    setupToken.value = '';
    secret.value = '';
    qr.value = '';
    code.value = '';
  } catch (e) {
    setupToken.value = '';
    secret.value = '';
    qr.value = '';
    code.value = '';
    error.value = e instanceof Error ? e.message : 'Enrollment expired. Start again.';
  } finally {
    loading.value = false;
  }
}
</script>
<template>
  <main class="min-h-screen bg-background p-4 flex items-center justify-center">
    <div class="w-full max-w-md space-y-5">
      <h1 class="text-2xl font-semibold">
        {{ joining ? 'Accept your invitation' : 'Recover your account' }}
      </h1>
      <p v-if="username" class="text-sm text-muted-foreground">Account: {{ username }}</p>
      <p v-if="error" role="alert" class="text-sm text-destructive">{{ error }}</p>
      <template v-if="done">
        <p>
          Your account is ready. Sign in with your username and new password{{
            joining ? '' : ', and your authenticator if enabled'
          }}.
        </p>
        <RecoveryCodes v-if="recoveryCodes.length" :codes="recoveryCodes" />
        <p v-if="kind === 'mfa'" class="text-sm text-muted-foreground">
          Wait for the next authenticator code before signing in; the enrollment code cannot be replayed.
        </p>
        <RouterLink to="/login"><Button class="mt-3">I saved my codes — sign in</Button></RouterLink>
      </template>
      <template v-else-if="setupToken">
        <p>Enroll your new authenticator before account access is restored.</p>
        <img :src="qr" alt="Authenticator enrollment QR code" class="mx-auto rounded-lg" />
        <p class="font-mono text-xs break-all select-all">{{ secret }}</p>
        <Label for="reset-code">New authenticator code</Label>
        <Input
          id="reset-code"
          v-model="code"
          inputmode="numeric"
          maxlength="6"
          autocomplete="one-time-code"
        />
        <Button :disabled="loading" @click="finishMFA">Confirm new MFA</Button>
      </template>
      <template v-else-if="token && (joining || kind)">
        <p class="text-sm text-muted-foreground">
          {{
            joining
              ? 'Choose your password. Your administrator assigned the permitted role and servers.'
              : kind === 'mfa'
                ? 'Choose a new password, then enroll a fresh authenticator. Prior access stays blocked until confirmation.'
                : 'Choose a new password. Your existing MFA remains required.'
          }}
        </p>
        <div class="space-y-2">
          <Label for="account-password">New password</Label
          ><Input id="account-password" v-model="password" type="password" autocomplete="new-password" />
        </div>
        <div class="space-y-2">
          <Label for="account-confirm">Confirm password</Label
          ><Input id="account-confirm" v-model="confirm" type="password" autocomplete="new-password" />
        </div>
        <div v-if="!joining && kind === 'password' && needsMFA" class="space-y-2">
          <Label for="factor">Current authenticator or recovery code</Label
          ><Input id="factor" v-model="code" autocomplete="one-time-code" maxlength="40" />
        </div>
        <Button :disabled="loading" @click="submit">{{
          loading
            ? 'Working…'
            : joining
              ? 'Accept invitation'
              : kind === 'mfa'
                ? 'Set up new authenticator'
                : 'Reset password'
        }}</Button>
      </template>
      <RouterLink v-if="!done" to="/login" class="block text-sm text-muted-foreground"
        >Back to sign in</RouterLink
      >
    </div>
  </main>
</template>
