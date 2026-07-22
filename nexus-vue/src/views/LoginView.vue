<script setup lang="ts">
import {ref} from 'vue'
import {useRouter} from 'vue-router'
import {Loader2, Shield} from '@lucide/vue'
import {api} from '@/lib/api'
import {signIn, markAuthed} from '@/lib/auth'
import Button from '@/components/ui/Button.vue'
import Input from '@/components/ui/Input.vue'
import Label from '@/components/ui/Label.vue'

const router = useRouter()

const password = ref('')
const otpCode = ref('')
const loading = ref(false)
const error = ref('')
const mfaStep = ref(false)
const pendingToken = ref('')

async function submitPassword() {
  const res = await api.auth.login(password.value)
  if ((res as any).mfaRequired) {
    pendingToken.value = (res as any).pendingToken
    mfaStep.value = true
    setTimeout(() => document.getElementById('otp-input')?.focus(), 50)
    return
  }
  markAuthed()
  router.replace('/dashboard')
}

async function verifyOTP() {
  await api.auth.mfaVerify(pendingToken.value, otpCode.value)
  markAuthed()
  router.replace('/dashboard')
}

async function submit() {
  error.value = ''
  loading.value = true
  try {
    if (mfaStep.value) await verifyOTP()
    else await submitPassword()
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Something went wrong'
  } finally {
    loading.value = false
  }
}

function backToPassword() {
  mfaStep.value = false
  otpCode.value = ''
  pendingToken.value = ''
  error.value = ''
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-background p-4">
    <div class="w-full max-w-sm space-y-6">

      <div class="text-center space-y-2">
        <div class="inline-flex items-center justify-center h-16 w-16 rounded-2xl mx-auto mb-2 overflow-hidden">
          <Shield v-if="mfaStep" class="h-8 w-8 text-primary"/>
          <img v-else src="/icons/icon.png" alt="Nexus" class="h-full w-full object-cover rounded-2xl"/>
        </div>
        <h1 class="text-2xl font-semibold tracking-tight">
          {{ mfaStep ? 'Two-factor auth' : 'Nexus' }}
        </h1>
        <p class="text-sm text-muted-foreground">
          {{ mfaStep ? 'Enter the 6-digit code from your authenticator app' : 'Sign in to your server dashboard' }}
        </p>
      </div>

      <div class="space-y-4">
        <template v-if="!mfaStep">
          <div class="space-y-1.5">
            <Label for="password">Password</Label>
            <Input id="password" v-model="password" type="password" placeholder="••••••••"
                   autocomplete="current-password" @keydown.enter="submit"/>
          </div>
        </template>

        <template v-else>
          <div class="space-y-1.5">
            <Label for="otp-input">Authentication code</Label>
            <Input id="otp-input" v-model="otpCode" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="6"
                   placeholder="000000" autocomplete="one-time-code"
                   class="text-center tracking-[0.5em] text-lg font-mono"
                   @keydown.enter="submit"/>
          </div>
        </template>

        <p v-if="error" class="text-sm text-destructive">{{ error }}</p>

        <Button class="w-full gap-2" :disabled="loading" @click="submit">
          <Loader2 v-if="loading" class="h-4 w-4 animate-spin"/>
          {{ mfaStep ? 'Verify' : 'Sign in' }}
        </Button>

        <button v-if="mfaStep"
                class="w-full text-sm text-muted-foreground hover:text-foreground transition-colors"
                @click="backToPassword">
          ← Back
        </button>
      </div>

    </div>
  </div>
</template>