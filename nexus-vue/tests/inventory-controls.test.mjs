import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('collection controls save a revision once and discard old-host or revoked replies', async () => {
  const cleanup = [],
    calls = [],
    events = [];
  const grants = vue.ref(new Set(['inventory.read', 'inventory.edit', 'inventory.discover', 'secrets.use']));
  const props = vue.reactive({ serverId: 'one' });
  const initial = {
    enabled: false,
    intervalMinutes: 60,
    freshnessMinutes: 15,
    retentionDays: 0,
    revision: 0,
    actorId: '',
    nextRunAt: '',
    lastStatus: '',
    failureCount: 0,
    updatedAt: '',
  };
  let deferred = false,
    finishLoad,
    finishSave;
  globalThis.__inventoryControls = {
    vue: {
      ...vue,
      onMounted() {},
      onUnmounted(fn) {
        cleanup.push(fn);
      },
    },
    can: (p) => grants.value.has(p),
    api: {
      inventory: {
        policy: async () =>
          deferred
            ? new Promise((resolve) => {
                finishLoad = resolve;
              })
            : initial,
        savePolicy: (server, input) => {
          calls.push([server, input]);
          return new Promise((resolve) => {
            finishSave = resolve;
          });
        },
      },
    },
  };
  const mod = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: mod(
      'export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__inventoryControls.vue',
    ),
    '@/lib/api': mod('export const api=globalThis.__inventoryControls.api'),
    '@/lib/auth': mod('export const {can}=globalThis.__inventoryControls'),
    './ui/Button.vue': mod('export default {}'),
  };
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/InventoryControls.vue', import.meta.url), 'utf8'),
  );
  let code = ts.transpileModule(compileScript(descriptor, { id: 'controls-fixture' }).content, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    code = code.replaceAll(`'${name}'`, JSON.stringify(value));
  const scope = vue.effectScope(),
    component = (await import(mod(code))).default;
  try {
    const state = scope.run(() =>
      component.setup(props, { expose() {}, emit: (...args) => events.push(args) }),
    );
    await state.load();
    assert.equal(state.policy.value.enabled, false);
    state.draft.value.enabled = true;
    state.draft.value.retentionDays = 30;
    const saving = state.save();
    await state.save();
    assert.equal(calls.length, 1, 'an in-flight save must not be replayed');
    assert.deepEqual(calls[0], [
      'one',
      { enabled: true, intervalMinutes: 60, freshnessMinutes: 15, retentionDays: 30, revision: 0 },
    ]);
    finishSave({ ...initial, ...calls[0][1], revision: 1 });
    await saving;
    assert.equal(state.policy.value.revision, 1);
    assert.deepEqual(events, [['saved']]);
    deferred = true;
    const loading = state.load();
    const oldFinish = finishLoad;
    props.serverId = 'two';
    oldFinish({ ...initial, actorId: 'old-host' });
    await loading;
    assert.equal(state.policy.value, null, 'old-host result must be discarded');
    finishLoad({ ...initial, revision: 3 });
    await vue.nextTick();
    await Promise.resolve();
    assert.equal(state.policy.value.revision, 3);
    const pending = state.save();
    grants.value.delete('inventory.edit');
    await vue.nextTick();
    finishSave({ ...initial, revision: 4 });
    await pending;
    assert.equal(state.policy.value, null, 'revoked save reply must be discarded');
    assert.equal(events.length, 1, 'revoked response must not emit a refresh');
    grants.value.delete('inventory.read');
    await vue.nextTick();
    assert.equal(state.draft.value, null);
  } finally {
    cleanup.forEach((fn) => fn());
    scope.stop();
    delete globalThis.__inventoryControls;
  }
});
