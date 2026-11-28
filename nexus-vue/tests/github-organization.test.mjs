import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('organization credentials clear, lost replies block new requests and permissions suppress late disclosures', async () => {
  const permissions = vue.ref(
    new Set([
      'github.organizations.read',
      'github.organizations.connections.manage',
      'github.organizations.runners.manage',
      'github.organizations.runners.register',
      'secrets.use',
      'secrets.create',
      'secrets.reveal',
    ]),
  );
  const props = vue.reactive({ serverId: 'build' });
  let finish,
    reject,
    writes = 0,
    confirmed = async () => true;
  const cleanup = [];
  globalThis.__orgFixture = {
    vue: {
      ...vue,
      onMounted() {},
      onUnmounted(fn) {
        cleanup.push(fn);
      },
    },
    can: (p) => permissions.value.has(p),
    confirm: (...args) => confirmed(...args),
    api: {
      githubOrganizations: {
        list: async () => [{ id: 'org', login: 'fixture-org', disabled: false }],
        history: async () => [],
        create: async (_sid, input) => {
          assert.equal(input.privateKey, 'private-key');
          return new Promise((resolve) => (finish = resolve));
        },
        registration: async () => {
          writes++;
          return new Promise((resolve, rejectFn) => {
            finish = resolve;
            reject = rejectFn;
          });
        },
      },
    },
  };
  const mod = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const stubs = {
    vue: mod(
      'export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__orgFixture.vue',
    ),
    '@/lib/auth': mod('export const can=globalThis.__orgFixture.can'),
    '@/lib/api': mod('export const api=globalThis.__orgFixture.api'),
    '@/composables/useConfirm': mod(
      'export const useConfirm=()=>({confirm:globalThis.__orgFixture.confirm})',
    ),
    './ui/Button.vue': mod('export default {}'),
    './ui/Input.vue': mod('export default {}'),
  };
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/GitHubOrganizations.vue', import.meta.url), 'utf8'),
  );
  let code = ts.transpileModule(compileScript(descriptor, { id: 'organization' }).content, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(stubs))
    code = code.replaceAll(`'${name}'`, JSON.stringify(value));
  const scope = vue.effectScope(),
    component = (await import(mod(code))).default;
  try {
    const state = scope.run(() => component.setup(props, { expose() {} }));
    await state.load();
    state.privateKey.value = 'private-key';
    const saving = state.create();
    assert.equal(state.privateKey.value, '');
    finish({ id: 'second', login: 'fixture-two', disabled: false });
    await saving;
    state.selected.value = 'org';
    const first = state.change('registration');
    await Promise.resolve();
    await Promise.resolve();
    reject(new Error('reply lost'));
    await first;
    assert.equal(writes, 1);
    assert.equal(state.blocked.value, true);
    state.selected.value = 'second';
    assert.equal(state.blocked.value, true, 'selection lost an unconfirmed request');
    await state.change('registration');
    assert.equal(writes, 1);
    await state.acknowledge();
    assert.equal(state.pending.value, '');
    const late = state.change('registration');
    await Promise.resolve();
    await Promise.resolve();
    permissions.value = new Set(['github.organizations.read']);
    finish({
      change: { id: 'request', kind: 'registration', state: 'applied', connectionId: 'second' },
      credential: { token: 'private-token', expiresAt: new Date(Date.now() + 3600_000).toISOString() },
    });
    await late;
    assert.equal(state.credential.value, '');
    assert.equal(state.history.value.length, 0);
    permissions.value = new Set([
      'github.organizations.read',
      'github.organizations.runners.register',
      'secrets.use',
      'secrets.reveal',
    ]);
    await state.load();
    state.selected.value = 'org';
    let approve;
    confirmed = () => new Promise((resolve) => (approve = resolve));
    const before = writes,
      prompt = state.change('registration');
    props.serverId = 'other';
    approve(true);
    await prompt;
    assert.equal(writes, before, 'changed scope sent a token request');
  } finally {
    cleanup.forEach((fn) => fn());
    scope.stop();
    delete globalThis.__orgFixture;
  }
});
