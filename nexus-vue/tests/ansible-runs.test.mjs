import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('approved execution clears Vault tokens and never retries an unknown submission', async () => {
  const grants = vue.ref(
    new Set([
      'ansible.projects.read',
      'ansible.playbooks.execute',
      'jobs.read',
      'jobs.execute',
      'logs.read',
      'secrets.use',
    ]),
  );
  let rejectRun,
    calls = 0;
  const cleanup = [];
  globalThis.__ansibleRunFixture = {
    vue: {
      ...vue,
      onMounted() {},
      onUnmounted(fn) {
        cleanup.push(fn);
      },
    },
    can: (p) => grants.value.has(p),
    useConfirm: () => ({ confirm: async () => true }),
    api: {
      features: async () => ({ automation: true, operationSupervision: true }),
      playbooks: {
        runs: async () => [],
        run: (_server, _plan, id, tokens) => {
          calls++;
          assert.match(id, /^[a-f0-9]{32}$/);
          assert.equal(tokens.dev, 'fixture-transient-token');
          return new Promise((_resolve, reject) => {
            rejectRun = reject;
          });
        },
      },
    },
  };
  const stub = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: stub(
      'export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__ansibleRunFixture.vue',
    ),
    '@/lib/api': stub('export const api=globalThis.__ansibleRunFixture.api'),
    '@/lib/auth': stub('export const can=globalThis.__ansibleRunFixture.can'),
    '@/composables/useConfirm': stub('export const useConfirm=globalThis.__ansibleRunFixture.useConfirm'),
  };
  for (const name of ['ui/Button', 'ui/Input'])
    modules[`@/components/${name}.vue`] = stub('export default {}');
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/AnsibleRunsPanel.vue', import.meta.url), 'utf8'),
  );
  let compiled = ts.transpileModule(compileScript(descriptor, { id: 'ansible-run-fixture' }).content, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    compiled = compiled.replaceAll(`'${name}'`, JSON.stringify(value));
  const component = (await import(stub(compiled))).default,
    scope = vue.effectScope();
  try {
    const plan = {
      id: 'plan',
      state: 'approved',
      actorId: 'owner',
      targets: [{ serverId: 'dev' }],
      options: { mode: 'check', vaultPassword: { serverId: 'dev' } },
      variables: {},
    };
    const state = scope.run(() =>
      component.setup({ serverId: 'controller', actorId: 'owner', plan }, { expose() {} }),
    );
    await state.load();
    state.tokens.value.dev = 'fixture-transient-token';
    const pending = state.start();
    await Promise.resolve();
    assert.equal(calls, 1);
    assert.deepEqual(state.tokens.value, {});
    rejectRun(new Error('unknown acknowledgement'));
    await pending;
    await state.start();
    assert.equal(calls, 1, 'unknown execution was submitted twice');
    state.tokens.value.dev = 'another-token';
    state.output.value = 'previous recap';
    state.runs.value = [{ id: 'old' }];
    grants.value.delete('jobs.read');
    await vue.nextTick();
    assert.deepEqual(state.tokens.value, {});
    assert.equal(state.output.value, '');
    assert.deepEqual(state.runs.value, []);
  } finally {
    for (const dispose of cleanup) dispose();
    scope.stop();
    delete globalThis.__ansibleRunFixture;
  }
});
