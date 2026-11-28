import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('revoking history access clears output and rejects a pending saved result', async () => {
  const grants = vue.ref(new Set(['jobs.read', 'logs.read', 'secrets.use', 'compose.read']));
  const run = { id: 'a'.repeat(32), action: 'compose-up', state: 'exited' };
  let reads = 0,
    lists = 0,
    finishRead;
  const cleanup = [];
  globalThis.__operationFixture = {
    vue: {
      ...vue,
      onMounted() {},
      onUnmounted(fn) {
        cleanup.push(fn);
      },
    },
    api: {
      operations: {
        list: async () => {
          lists++;
          return [run];
        },
        read: () => {
          reads++;
          return new Promise((resolve) => {
            finishRead = resolve;
          });
        },
      },
    },
    can: (permission) => grants.value.has(permission),
    useConfirm: () => ({ confirm: async () => true }),
  };
  const stub = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: stub(
      'export const {defineComponent,onMounted,onUnmounted,ref,watch}=globalThis.__operationFixture.vue',
    ),
    '@/lib/api': stub('export const api=globalThis.__operationFixture.api'),
    '@/lib/auth': stub('export const can=globalThis.__operationFixture.can'),
    '@/composables/useConfirm': stub('export const useConfirm=globalThis.__operationFixture.useConfirm'),
    '@/components/ui/Button.vue': stub('export default {}'),
  };
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/OperationsTab.vue', import.meta.url), 'utf8'),
  );
  const script = compileScript(descriptor, { id: 'operations-fixture' }).content;
  let compiled = ts.transpileModule(script, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    compiled = compiled.replaceAll(`'${name}'`, JSON.stringify(value));
  const component = (await import(stub(compiled))).default;
  const scope = vue.effectScope();
  try {
    const state = scope.run(() => component.setup({ serverId: 'dev', enabled: true }, { expose() {} }));
    await state.load();
    assert.equal(state.runs.value.length, 1);
    const revealed = state.act('read', run);
    assert.equal(reads, 1);
    finishRead({ run, observation: { output: 'private saved result' } });
    await revealed;
    assert.equal(state.result.value.observation.output, 'private saved result');
    grants.value.delete('jobs.read');
    await vue.nextTick();
    assert.deepEqual(state.runs.value, []);
    assert.equal(state.result.value, null);
    assert.equal(state.viewable(run), false);
    await state.load();
    assert.equal(lists, 2, 'history must not refetch while access is revoked');
    grants.value.add('jobs.read');
    await vue.nextTick();
    assert.equal(lists, 3);
    assert.equal(reads, 1, 'restoring access must not reveal saved output automatically');
    const pending = state.act('read', run);
    grants.value.delete('jobs.read');
    await vue.nextTick();
    finishRead({ run, observation: { output: 'late private saved result' } });
    await pending;
    assert.equal(state.result.value, null);
    assert.equal(lists, 3, 'a stale result must not trigger another history request');
  } finally {
    for (const dispose of cleanup) dispose();
    scope.stop();
    delete globalThis.__operationFixture;
  }
});
