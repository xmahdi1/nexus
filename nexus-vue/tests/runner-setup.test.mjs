import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('runner credentials clear on submission and permission loss; unknown enrollment never retries', async () => {
  const grants = vue.ref(
    new Set([
      'github.runners.read',
      'github.runners.manage',
      'jobs.read',
      'jobs.cancel',
      'jobs.manage',
      'logs.read',
      'servers.execute',
      'secrets.use',
    ]),
  );
  let calls = 0,
    rejectStart;
  const cleanup = [];
  globalThis.__runnerFixture = {
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
      runners: {
        list: async () => [],
        start: async (sid, input) => {
          calls++;
          assert.equal(sid, 'dev');
          assert.equal(input.registrationToken, 'private-token-fixture');
          return new Promise((resolve, reject) => {
            rejectStart = reject;
          });
        },
      },
    },
  };
  const stub = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: stub(
      'export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__runnerFixture.vue',
    ),
    '@/lib/api': stub('export const api=globalThis.__runnerFixture.api'),
    '@/lib/auth': stub('export const can=globalThis.__runnerFixture.can'),
    '@/composables/useConfirm': stub('export const useConfirm=globalThis.__runnerFixture.useConfirm'),
  };
  for (const path of ['Dialog', 'Button', 'Input'])
    modules[`@/components/ui/${path}.vue`] = stub('export default {}');
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/RunnerSetup.vue', import.meta.url), 'utf8'),
  );
  let compiled = ts.transpileModule(compileScript(descriptor, { id: 'runner-fixture' }).content, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    compiled = compiled.replaceAll(`'${name}'`, JSON.stringify(value));
  const component = (await import(stub(compiled))).default,
    scope = vue.effectScope();
  try {
    const state = scope.run(() => component.setup({ serverId: 'dev' }, { expose() {}, emit() {} }));
    await state.load();
    state.token.value = 'private-token-fixture';
    state.dedicated.value = true;
    state.url.value = 'https://github.com/example/repository';
    const pending = state.start();
    await Promise.resolve();
    assert.equal(calls, 1);
    assert.equal(state.token.value, '');
    assert.match(state.pending.value, /^[a-f0-9]{32}$/);
    rejectStart(new Error('outcome unknown'));
    await pending;
    await state.start();
    assert.equal(calls, 1, 'uncertain enrollment must not retry');
    state.token.value = 'another-secret';
    state.inspection.value = 'old result';
    state.runners.value = [{ run: { id: 'old' } }];
    grants.value.delete('github.runners.read');
    await vue.nextTick();
    assert.equal(state.token.value, '');
    assert.equal(state.inspection.value, '');
    assert.deepEqual(state.runners.value, []);
  } finally {
    for (const dispose of cleanup) dispose();
    scope.stop();
    delete globalThis.__runnerFixture;
  }
});
