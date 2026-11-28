<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { useI18n } from 'vue-i18n';
import { toast } from 'vue-sonner';
import {
  Loader2,
  ShieldCheck,
  ShieldOff,
  QrCode,
  Bell,
  Send,
  History,
  CheckCircle2,
  XCircle,
  Palette,
  Shield,
  RefreshCw,
} from '@lucide/vue';
import QRCode from 'qrcode';
import { api } from '@/lib/api';
import { applyTheme, getTheme, type Theme } from '@/lib/theme';
import AppLayout from '@/components/AppLayout.vue';
import ToolSettings from '@/components/ToolSettings.vue';
import AccessSettings from '@/components/AccessSettings.vue';
import AuditSettings from '@/components/AuditSettings.vue';
import UserSettings from '@/components/UserSettings.vue';
import RecoveryCodes from '@/components/RecoveryCodes.vue';
import { can } from '@/lib/auth';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';
import Label from '@/components/ui/Label.vue';
import type { AlertConfig, LoginEvent, DeviceSession } from '@/lib/api';

const { t, locale, availableLocales } = useI18n();

const sections = [
  { id: 'appearance', label: 'Appearance', icon: Palette },
  { id: 'tools', label: 'Tools', icon: Palette },
  { id: 'security', label: 'Security', icon: Shield },
  ...(can('settings.manage') ? [{ id: 'notifications', label: 'Notifications', icon: Bell }] : []),
  ...(can('audit.read') ? [{ id: 'login-history', label: 'Login History', icon: History }] : []),
];

const activeSection = ref('appearance');
const build = ref<Awaited<ReturnType<typeof api.version>>>();

onMounted(async () => {
  build.value = await api.version().catch(() => undefined);
});
const theme = ref<Theme>(getTheme());
const langLabels: Record<string, string> = { en: 'English', de: 'Deutsch', fr: 'Français' };

const currentPw = ref('');
const newPw = ref('');
const confirmPw = ref('');
const pwLoading = ref(false);
const sessions = ref<DeviceSession[]>([]);
const currentSession = ref('');
const sessionsLoading = ref(false);
const sessionError = ref('');
async function loadSessions() {
  sessionsLoading.value = true;
  sessionError.value = '';
  try {
    const [devices, me] = await Promise.all([api.auth.sessions(), api.auth.me()]);
    sessions.value = devices;
    currentSession.value = me.session.id;
  } catch (e) {
    sessionError.value = e instanceof Error ? e.message : 'Could not load sessions';
  } finally {
    sessionsLoading.value = false;
  }
}
async function revokeDevice(id: string) {
  try {
    await api.auth.revokeSession(id);
    if (id === currentSession.value) window.location.href = '/login';
    else await loadSessions();
  } catch (e) {
    sessionError.value = e instanceof Error ? e.message : 'Could not revoke session';
  }
}
async function logoutAll() {
  try {
    await api.auth.logoutAll();
    window.location.href = '/login';
  } catch (e) {
    sessionError.value = e instanceof Error ? e.message : 'Could not revoke sessions';
  }
}
onMounted(loadSessions);

const stepUpPassword = ref(''),
  stepUpCode = ref('');
async function stepUp() {
  try {
    await api.auth.stepUp(stepUpPassword.value, stepUpCode.value);
    stepUpPassword.value = '';
    stepUpCode.value = '';
    toast.success('MFA verified for five minutes on this device.');
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Verification failed');
  }
}
const mfaEnabled = ref(false);
const recoveryCodes = ref<string[]>([]);
const recoveryRemaining = ref(0);
const recoveryPassword = ref('');
async function regenerateCodes() {
  try {
    const result = await api.auth.regenerateRecovery(recoveryPassword.value);
    recoveryPassword.value = '';
    recoveryCodes.value = result.recoveryCodes;
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Could not regenerate codes');
  }
}
const mfaPassword = ref('');
const setupToken = ref('');
const setupStep = ref<'idle' | 'scan' | 'verify'>('idle');
const setupSecret = ref('');
const setupQR = ref('');
const setupCode = ref('');
const setupLoading = ref(false);
const disableOpen = ref(false);
const disableCode = ref('');
const disableLoading = ref(false);

const alertCfg = ref<AlertConfig | null>(null);
const alertSaving = ref(false);
const alertTesting = ref(false);
const telegramTokenInput = ref('');

const auditLog = ref<LoginEvent[]>([]);
const auditLoading = ref(false);
const auditLimit = ref(10);
const AUDIT_LIMITS = [5, 10, 25, 50, 100];

const REASON_MAP: Record<string, string> = {
  ok: 'Login successful',
  bad_password: 'Wrong password',
  bad_mfa: 'Wrong MFA code',
  mfa_required: 'Password OK, MFA pending',
  session_expired: 'MFA session expired',
};

function setTheme(th: Theme) {
  theme.value = th;
  applyTheme(th);
}

function scrollTo(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  activeSection.value = id;
}

function fmtDate(s: string) {
  const d = new Date(s);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
}

function reasonLabel(r: string) {
  return REASON_MAP[r] ?? r;
}

async function changePassword() {
  if (!currentPw.value || !newPw.value || !confirmPw.value) {
    toast.error('All fields are required');
    return;
  }
  if (newPw.value !== confirmPw.value) {
    toast.error('New passwords do not match');
    return;
  }
  if (new TextEncoder().encode(newPw.value).length < 12) {
    toast.error('New password must be at least 12 bytes');
    return;
  }
  pwLoading.value = true;
  try {
    await api.auth.changePassword(currentPw.value, newPw.value);
    toast.success('Password updated. Sign in again.');
    window.location.href = '/login';
    currentPw.value = '';
    newPw.value = '';
    confirmPw.value = '';
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to update password');
  } finally {
    pwLoading.value = false;
  }
}

async function startSetup() {
  setupLoading.value = true;
  try {
    const res = await api.auth.mfaSetup(mfaPassword.value);
    mfaPassword.value = '';
    setupToken.value = res.setupToken;
    setupSecret.value = res.secret;
    setupQR.value = await QRCode.toDataURL(res.uri, { width: 200, margin: 1 });
    setupStep.value = 'scan';
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to generate QR code');
  } finally {
    setupLoading.value = false;
  }
}

async function enableMFA() {
  if (setupCode.value.length !== 6) {
    toast.error('Enter the 6-digit code');
    return;
  }
  setupLoading.value = true;
  try {
    const result = await api.auth.mfaEnable(setupToken.value, setupCode.value);
    recoveryCodes.value = result.recoveryCodes;
    mfaEnabled.value = true;
    setupStep.value = 'idle';
    setupCode.value = '';
    cancelSetup();
    toast.success('Save your recovery codes, then sign in again.');
  } catch (e) {
    cancelSetup();
    toast.error(e instanceof Error ? e.message : 'Code invalid or expired. Start setup again.');
  } finally {
    setupLoading.value = false;
  }
}

function cancelSetup() {
  setupStep.value = 'idle';
  setupCode.value = '';
  setupQR.value = '';
  setupSecret.value = '';
  setupToken.value = '';
  mfaPassword.value = '';
}

async function disableMFA() {
  if (!disableCode.value) {
    toast.error('Enter your current OTP code');
    return;
  }
  disableLoading.value = true;
  try {
    await api.auth.mfaDisable(disableCode.value);
    mfaEnabled.value = false;
    disableOpen.value = false;
    disableCode.value = '';
    toast.success('Two-factor authentication disabled. Sign in again.');
    window.location.href = '/login';
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Invalid code');
  } finally {
    disableLoading.value = false;
  }
}

async function saveAlertConfig() {
  if (!alertCfg.value) return;
  alertSaving.value = true;
  try {
    const payload: any = { ...alertCfg.value };
    if (telegramTokenInput.value) payload.telegramToken = telegramTokenInput.value;
    alertCfg.value = await api.monitor.updateConfig(payload);
    telegramTokenInput.value = '';
    toast.success('Notification settings saved');
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Failed to save');
  } finally {
    alertSaving.value = false;
  }
}

async function testTelegram() {
  alertTesting.value = true;
  try {
    await api.monitor.testTelegram();
    toast.success('Test message sent — check your Telegram!');
  } catch (e) {
    toast.error(e instanceof Error ? e.message : 'Test failed');
  } finally {
    alertTesting.value = false;
  }
}

async function refreshAudit() {
  auditLoading.value = true;
  if (can('settings.manage')) {
    try {
      alertCfg.value = await api.monitor.getConfig();
    } catch {
      alertCfg.value = null;
    }
  }
  try {
    if (can('audit.read')) auditLog.value = await api.auth.auditLog(auditLimit.value);
  } catch {
    auditLog.value = [];
  } finally {
    auditLoading.value = false;
  }
}

let observer: IntersectionObserver | null = null;

onMounted(async () => {
  try {
    const mfaRes = await api.auth.mfaStatus();
    mfaEnabled.value = mfaRes.enabled;
    recoveryRemaining.value = mfaRes.recoveryCodesRemaining;
  } catch {
    // Personal MFA status can be unavailable after session revocation.
  }
  if (can('settings.manage')) {
    try {
      alertCfg.value = await api.monitor.getConfig();
    } catch {
      alertCfg.value = null;
    }
  }
  try {
    if (can('audit.read')) auditLog.value = await api.auth.auditLog(auditLimit.value);
  } catch {
    auditLog.value = [];
  }

  observer = new IntersectionObserver(
    (entries) => {
      for (const e of entries) {
        if (e.isIntersecting) activeSection.value = e.target.id;
      }
    },
    { threshold: 0.3 },
  );
  sections.forEach((s) => {
    const el = document.getElementById(s.id);
    if (el) observer!.observe(el);
  });
});

onUnmounted(() => observer?.disconnect());
</script>

<template>
  <AppLayout>
    <div class="max-w-5xl mx-auto">
      <div class="mb-6">
        <h1 class="text-xl sm:text-2xl font-semibold tracking-tight">{{ t('settings.title') }}</h1>
        <p class="text-sm text-muted-foreground mt-1">{{ t('settings.subtitle') }}</p>
      </div>

      <div class="flex gap-8 items-start">
        <nav class="hidden md:flex flex-col gap-1 w-44 shrink-0 sticky top-6">
          <button
            v-for="s in sections"
            :key="s.id"
            :class="[
              'flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors text-left w-full',
              activeSection === s.id
                ? 'bg-primary/10 text-primary'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted',
            ]"
            @click="scrollTo(s.id)"
          >
            <component :is="s.icon" class="h-4 w-4 shrink-0" />
            {{ s.label }}
          </button>
        </nav>

        <div class="flex-1 space-y-8 min-w-0">
          <section id="appearance" class="bg-card border rounded-xl p-5 sm:p-6 space-y-4 scroll-mt-4">
            <div v-if="build" class="text-xs text-muted-foreground sm:text-right">
              Nexus {{ build.version }} · {{ build.os }}/{{ build.arch }}
              <span v-if="build.commit" class="font-mono" :title="build.commit">
                · {{ build.commit.slice(0, 12) }}
              </span>
              <span v-if="build.built"> · {{ build.built }}</span>
            </div>
            <h2 class="text-sm font-semibold uppercase tracking-wide text-muted-foreground">Appearance</h2>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p class="text-sm font-medium">{{ t('settings.theme') }}</p>
                <p class="text-xs text-muted-foreground">Choose your preferred color scheme</p>
              </div>
              <div class="flex gap-2">
                <Button
                  :variant="theme === 'light' ? 'default' : 'outline'"
                  size="sm"
                  @click="setTheme('light')"
                >
                  {{ t('settings.themeLight') }}
                </Button>
                <Button
                  :variant="theme === 'dark' ? 'default' : 'outline'"
                  size="sm"
                  @click="setTheme('dark')"
                >
                  {{ t('settings.themeDark') }}
                </Button>
              </div>
            </div>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p class="text-sm font-medium">{{ t('settings.language') }}</p>
                <p class="text-xs text-muted-foreground">Interface language</p>
              </div>
              <div class="flex gap-2">
                <Button
                  v-for="lang in availableLocales"
                  :key="lang"
                  :variant="locale === lang ? 'default' : 'outline'"
                  size="sm"
                  @click="locale = lang"
                >
                  {{ langLabels[lang] ?? lang }}
                </Button>
              </div>
            </div>
          </section>

          <ToolSettings />
          <section id="security" class="bg-card border rounded-xl p-5 sm:p-6 space-y-4 scroll-mt-4">
            <h2 class="text-sm font-semibold uppercase tracking-wide text-muted-foreground">Security</h2>
            <div v-if="mfaEnabled" class="border rounded-lg p-4 space-y-2">
              <h3 class="font-medium">Verify a protected operation</h3>
              <p class="text-xs">
                Confirm your current password and a fresh authenticator or unused recovery code. Verification
                lasts five minutes on this device; return to the intended target afterwards.
              </p>
              <Input
                v-model="stepUpPassword"
                type="password"
                autocomplete="current-password"
                placeholder="Current password"
              /><Input
                v-model="stepUpCode"
                autocomplete="one-time-code"
                maxlength="40"
                placeholder="Authenticator or recovery code"
              /><Button @click="stepUp">Verify MFA</Button>
            </div>
            <UserSettings />
            <AccessSettings />
            <AuditSettings />
            <div v-if="recoveryCodes.length" class="space-y-3">
              <RecoveryCodes :codes="recoveryCodes" /><a href="/login" class="underline"
                >I saved my codes — sign in again</a
              >
            </div>
            <div class="border rounded-lg p-4 space-y-3">
              <div class="flex items-center justify-between gap-2">
                <h3 class="font-medium">Signed-in devices</h3>
                <Button variant="outline" size="sm" :disabled="sessionsLoading" @click="loadSessions"
                  >Refresh</Button
                >
              </div>
              <p v-if="sessionsLoading" class="text-sm">Loading sessions…</p>
              <p v-if="sessionError" class="text-sm text-destructive">{{ sessionError }}</p>
              <p v-if="!sessionsLoading && !sessions.length && !sessionError" class="text-sm">
                No active sessions.
              </p>
              <div
                v-for="device in sessions"
                :key="device.id"
                class="flex items-center justify-between gap-3 border-t pt-2"
              >
                <div class="text-sm">
                  <p>
                    {{ device.deviceLabel }} <span v-if="device.id === currentSession">(this device)</span>
                  </p>
                  <p class="text-xs text-muted-foreground">
                    {{ device.clientIP }} · Last used {{ fmtDate(device.lastUsedAt) }}
                  </p>
                </div>
                <Button variant="outline" size="sm" @click="revokeDevice(device.id)">Sign out</Button>
              </div>
              <Button variant="outline" size="sm" @click="logoutAll">Sign out all devices</Button>
            </div>
            <div class="grid gap-3">
              <div class="grid gap-1.5">
                <Label for="cur">Current password</Label>
                <Input id="cur" v-model="currentPw" type="password" autocomplete="current-password" />
              </div>
              <div class="grid gap-1.5">
                <Label for="new">New password</Label>
                <Input id="new" v-model="newPw" type="password" autocomplete="new-password" />
              </div>
              <div class="grid gap-1.5">
                <Label for="confirm">Confirm new password</Label>
                <Input id="confirm" v-model="confirmPw" type="password" autocomplete="new-password" />
              </div>
              <Button class="w-fit gap-2 mt-1" :disabled="pwLoading" @click="changePassword">
                <Loader2 v-if="pwLoading" class="h-4 w-4 animate-spin" />
                Update password
              </Button>
            </div>

            <div class="border-t pt-4 space-y-3">
              <div class="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p class="text-sm font-medium flex items-center gap-2">
                    Two-factor authentication
                    <span
                      v-if="mfaEnabled"
                      class="text-xs font-medium text-green-600 bg-green-500/10 border border-green-500/20 px-2 py-0.5 rounded-full"
                    >
                      Enabled
                    </span>
                    <span
                      v-else
                      class="text-xs font-medium text-muted-foreground bg-muted border px-2 py-0.5 rounded-full"
                    >
                      Disabled
                    </span>
                  </p>
                  <p class="text-xs text-muted-foreground mt-0.5">
                    {{
                      mfaEnabled
                        ? 'Your account is protected with an authenticator app'
                        : 'Add a second factor using any TOTP authenticator app'
                    }}
                  </p>
                </div>
                <Input
                  v-if="!mfaEnabled && setupStep === 'idle'"
                  v-model="mfaPassword"
                  type="password"
                  autocomplete="current-password"
                  aria-label="Current password for MFA enrollment"
                  placeholder="Current password to enroll MFA"
                />
                <Button
                  v-if="!mfaEnabled && setupStep === 'idle'"
                  variant="outline"
                  size="sm"
                  class="gap-2 shrink-0"
                  :disabled="setupLoading"
                  @click="startSetup"
                >
                  <Loader2 v-if="setupLoading" class="h-3.5 w-3.5 animate-spin" />
                  <QrCode v-else class="h-3.5 w-3.5" />
                  Set up
                </Button>
                <Button
                  v-if="mfaEnabled && !disableOpen"
                  variant="outline"
                  size="sm"
                  class="gap-2 shrink-0 text-destructive border-destructive/30 hover:bg-destructive/10"
                  @click="disableOpen = true"
                >
                  <ShieldOff class="h-3.5 w-3.5" />
                  Disable
                </Button>
              </div>

              <div v-if="setupStep === 'scan'" class="border rounded-xl p-5 space-y-4 bg-muted/20">
                <p class="text-sm font-medium">Scan with your authenticator app</p>
                <p class="text-xs text-muted-foreground">
                  Use Google Authenticator, Authy, Bitwarden, or any TOTP app to scan this QR code.
                </p>
                <div class="flex justify-center">
                  <img :src="setupQR" alt="TOTP QR code" class="rounded-lg border" width="200" height="200" />
                </div>
                <p class="text-xs text-center text-muted-foreground font-mono break-all">
                  Manual key: {{ setupSecret }}
                </p>
                <div class="space-y-2">
                  <Label for="setup-code">Enter the 6-digit code to confirm</Label>
                  <Input
                    id="setup-code"
                    v-model="setupCode"
                    type="text"
                    inputmode="numeric"
                    maxlength="6"
                    placeholder="000000"
                    class="text-center tracking-[0.5em] font-mono text-lg"
                    @keydown.enter="enableMFA"
                  />
                </div>
                <div class="flex gap-2">
                  <Button class="flex-1 gap-2" :disabled="setupLoading" @click="enableMFA">
                    <Loader2 v-if="setupLoading" class="h-4 w-4 animate-spin" />
                    <ShieldCheck v-else class="h-4 w-4" />
                    Activate
                  </Button>
                  <Button variant="outline" @click="cancelSetup">Cancel</Button>
                </div>
              </div>

              <div v-if="mfaEnabled && !recoveryCodes.length" class="space-y-2">
                <p class="text-sm">
                  {{ recoveryRemaining }} recovery codes remaining. Regenerating signs out all devices.
                </p>
                <Input
                  v-model="recoveryPassword"
                  type="password"
                  autocomplete="current-password"
                  placeholder="Current password"
                /><Button variant="outline" @click="regenerateCodes">Regenerate recovery codes</Button>
              </div>
              <div v-if="disableOpen" class="border rounded-xl p-5 space-y-3 bg-muted/20">
                <p class="text-sm font-medium">Confirm with your authenticator app or a recovery code</p>
                <Input
                  v-model="disableCode"
                  type="text"
                  maxlength="40"
                  placeholder="000000"
                  class="text-center tracking-[0.5em] font-mono text-lg"
                  @keydown.enter="disableMFA"
                />
                <div class="flex gap-2">
                  <Button
                    variant="destructive"
                    class="flex-1 gap-2"
                    :disabled="disableLoading"
                    @click="disableMFA"
                  >
                    <Loader2 v-if="disableLoading" class="h-4 w-4 animate-spin" />
                    Disable MFA
                  </Button>
                  <Button
                    variant="outline"
                    @click="
                      disableOpen = false;
                      disableCode = '';
                    "
                    >Cancel</Button
                  >
                </div>
              </div>
            </div>
          </section>

          <section
            v-if="alertCfg"
            id="notifications"
            class="bg-card border rounded-xl p-5 sm:p-6 space-y-5 scroll-mt-4"
          >
            <div class="flex items-center gap-2">
              <Bell class="h-5 w-5 text-muted-foreground" />
              <h2 class="text-base font-semibold">Notifications</h2>
            </div>
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p class="text-sm font-medium">Telegram Bot</p>
                <p class="text-xs text-muted-foreground mt-0.5">
                  Get alerts via Telegram when servers or containers go down
                </p>
              </div>
              <label class="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" v-model="alertCfg!.telegramEnabled" class="sr-only peer" />
                <div
                  class="w-11 h-6 bg-muted rounded-full peer peer-checked:bg-primary after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:after:translate-x-5"
                />
              </label>
            </div>
            <template v-if="alertCfg?.telegramEnabled">
              <div class="space-y-4 border-t pt-4">
                <div class="space-y-1.5">
                  <Label>Bot Token</Label>
                  <Input
                    v-model="telegramTokenInput"
                    :placeholder="alertCfg.telegramToken || 'Enter new token (from @BotFather)'"
                    type="password"
                    class="font-mono text-sm"
                  />
                  <p class="text-xs text-muted-foreground">
                    Create a bot at <span class="font-mono">@BotFather</span> on Telegram → /newbot
                  </p>
                </div>
                <div class="space-y-1.5">
                  <Label>Chat ID</Label>
                  <Input
                    v-model="alertCfg.telegramChatId"
                    placeholder="123456789"
                    class="font-mono text-sm"
                  />
                  <p class="text-xs text-muted-foreground">
                    Send any message to your bot, then visit
                    <span class="font-mono">https://api.telegram.org/bot{TOKEN}/getUpdates</span>
                    to find your chat ID
                  </p>
                </div>
                <div class="space-y-2">
                  <p class="text-sm font-medium">Notify when</p>
                  <label class="flex items-center gap-2 text-sm cursor-pointer">
                    <input type="checkbox" v-model="alertCfg.notifyServerDown" class="rounded" />Server goes
                    offline
                  </label>
                  <label class="flex items-center gap-2 text-sm cursor-pointer">
                    <input type="checkbox" v-model="alertCfg.notifyServerUp" class="rounded" />Server comes
                    back online
                  </label>
                  <label class="flex items-center gap-2 text-sm cursor-pointer">
                    <input type="checkbox" v-model="alertCfg.notifyContainer" class="rounded" />Monitored
                    container stops
                  </label>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  class="gap-2"
                  :disabled="alertTesting"
                  @click="testTelegram"
                >
                  <Loader2 v-if="alertTesting" class="h-3.5 w-3.5 animate-spin" />
                  <Send v-else class="h-3.5 w-3.5" />
                  Send test message
                </Button>
              </div>
            </template>
            <Button class="gap-2" :disabled="alertSaving" @click="saveAlertConfig">
              <Loader2 v-if="alertSaving" class="h-4 w-4 animate-spin" />
              Save notification settings
            </Button>
          </section>

          <section
            v-if="can('audit.read')"
            id="login-history"
            class="bg-card border rounded-xl p-5 sm:p-6 space-y-4 scroll-mt-4"
          >
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="flex items-center gap-2">
                <History class="h-5 w-5 text-muted-foreground" />
                <h2 class="text-base font-semibold">Login History</h2>
              </div>
              <div class="flex items-center gap-2">
                <div class="flex items-center rounded-lg border p-0.5">
                  <button
                    v-for="n in AUDIT_LIMITS"
                    :key="n"
                    :class="[
                      'px-2.5 py-1 text-xs font-medium rounded-md transition-colors',
                      auditLimit === n
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground hover:text-foreground',
                    ]"
                    @click="
                      auditLimit = n;
                      refreshAudit();
                    "
                  >
                    {{ n }}
                  </button>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  class="gap-1.5"
                  :disabled="auditLoading"
                  @click="refreshAudit"
                >
                  <Loader2 v-if="auditLoading" class="h-3.5 w-3.5 animate-spin" />
                  <RefreshCw v-else class="h-3.5 w-3.5" />
                  <span class="hidden sm:inline">Refresh</span>
                </Button>
              </div>
            </div>
            <div v-if="!auditLog.length" class="text-sm text-muted-foreground text-center py-8">
              No login events yet
            </div>
            <div v-else class="border rounded-xl overflow-x-auto">
              <table class="w-full text-sm min-w-[480px]">
                <thead>
                  <tr class="border-b bg-muted/40">
                    <th
                      class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide"
                    >
                      Time
                    </th>
                    <th
                      class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide"
                    >
                      IP
                    </th>
                    <th
                      class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide"
                    >
                      Result
                    </th>
                    <th
                      class="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground uppercase tracking-wide hidden sm:table-cell"
                    >
                      Detail
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="e in auditLog"
                    :key="e.id"
                    class="border-b last:border-0 hover:bg-muted/10 transition-colors"
                  >
                    <td class="px-4 py-2.5 text-xs text-muted-foreground font-mono whitespace-nowrap">
                      {{ fmtDate(e.createdAt) }}
                    </td>
                    <td class="px-4 py-2.5 text-xs font-mono">{{ e.ip }}</td>
                    <td class="px-4 py-2.5">
                      <span
                        class="flex items-center gap-1.5 text-xs font-medium"
                        :class="e.success ? 'text-green-600' : 'text-destructive'"
                      >
                        <CheckCircle2 v-if="e.success" class="h-3.5 w-3.5" />
                        <XCircle v-else class="h-3.5 w-3.5" />
                        {{ e.success ? 'Success' : 'Failed' }}
                      </span>
                    </td>
                    <td class="px-4 py-2.5 text-xs text-muted-foreground hidden sm:table-cell">
                      {{ reasonLabel(e.reason) }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </div>
    </div>
  </AppLayout>
</template>
