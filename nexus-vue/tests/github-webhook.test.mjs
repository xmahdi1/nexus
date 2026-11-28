import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('webhook configuration clears secrets and ignores replies after scope or permission changes', async () => {
  const permissions = vue.ref(
    new Set(['github.actions.read', 'github.webhooks.manage', 'secrets.create', 'secrets.reveal']),
  );
  const props = vue.reactive({ serverId: 'build', connectionId: 'first' });
  let finish,
    confirm = async () => true,
    writes = 0;
  const cleanup = [];
  globalThis.__webhookFixture = {
    vue: {
      ...vue,
      onMounted() {},
      onUnmounted(fn) {
        cleanup.push(fn);
      },
    },
    can: (p) => permissions.value.has(p),
    useConfirm: () => ({ confirm: (...args) => confirm(...args) }),
    api: {
      githubActions: {
        webhookEvents: async () => [{ runId: 71, status: 'completed' }],
        webhook: async () => ({ configured: true, path: '/first', disabled: false }),
        rotateWebhook: async () => {
          writes++;
          return new Promise((resolve) => {
            finish = resolve;
          });
        },
        disableWebhook: async () => {},
      },
    },
  };
  const module = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const stubs = {
    vue: module(
      'export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__webhookFixture.vue',
    ),
    '@/lib/api': module('export const api=globalThis.__webhookFixture.api'),
    '@/lib/auth': module('export const can=globalThis.__webhookFixture.can'),
    '@/composables/useConfirm': module('export const useConfirm=globalThis.__webhookFixture.useConfirm'),
    './ui/Button.vue': module('export default {}'),
  };
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/GitHubWebhookPanel.vue', import.meta.url), 'utf8'),
  );
  let code = ts.transpileModule(compileScript(descriptor, { id: 'webhooks' }).content, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(stubs))
    code = code.replaceAll(`'${name}'`, JSON.stringify(value));
  const component = (await import(module(code))).default,
    scope = vue.effectScope();
  try {
    const state = scope.run(() => component.setup(props, { expose() {}, emit() {} }));
    await state.load();
    assert.equal(state.runs.value.length, 1);
    const saving = state.rotate();
    await Promise.resolve();
    await Promise.resolve();
    props.connectionId = 'second';
    finish({ webhook: { configured: true, path: '/first' }, secret: 'private-fixture' });
    await saving;
    assert.equal(state.secret.value, '');
    assert.equal(state.info.value, undefined);
    const next = state.rotate();
    await Promise.resolve();
    await Promise.resolve();
    finish({ webhook: { configured: true, path: '/second' }, secret: 'private-fixture' });
    await next;
    assert.equal(state.secret.value, 'private-fixture');
    permissions.value = new Set(['github.actions.read']);
    assert.equal(state.secret.value, '');
    assert.equal(state.info.value, undefined);
    permissions.value = new Set([
      'github.actions.read',
      'github.webhooks.manage',
      'secrets.create',
      'secrets.reveal',
    ]);
    let approve;
    confirm = () =>
      new Promise((resolve) => {
        approve = resolve;
      });
    const before = writes,
      prompt = state.rotate();
    props.connectionId = 'third';
    approve(true);
    await prompt;
    assert.equal(writes, before, 'scope changed during confirmation but write was sent');
    permissions.value = new Set();
    assert.equal(state.runs.value.length, 0);
  } finally {
    cleanup.forEach((fn) => fn());
    scope.stop();
    delete globalThis.__webhookFixture;
  }
});
