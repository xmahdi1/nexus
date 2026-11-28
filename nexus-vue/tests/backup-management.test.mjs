import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('retention confirmation follows its target and an unknown cleanup is not repeated', async () => {
  const grants = vue.ref(
    new Set(['backups.read', 'backups.manage', 'backups.prune', 'secrets.use', 'jobs.execute']),
  );
  const props = vue.reactive({
    serverId: 'one',
    supervised: true,
    runs: [],
    inspection: {
      runId: 'preview',
      policyId: 'policy',
      data: {
        state: 'retention_preview',
        verified: true,
        retention: {
          keepLast: 1,
          inventoryDigest: 'd'.repeat(64),
          removeIds: ['a'.repeat(64)],
          keptCount: 1,
          unclassifiedCount: 0,
        },
      },
    },
  });
  let confirm = async () => true,
    resolve,
    calls = 0,
    captured,
    failure = new Error('Acknowledgement lost');
  const cleanup = [];
  globalThis.__backupManagement = {
    vue: {
      ...vue,
      onMounted() {},
      onUnmounted(fn) {
        cleanup.push(fn);
      },
    },
    can: (p) => grants.value.has(p),
    useConfirm: () => ({ confirm: (...args) => confirm(...args) }),
    api: {
      backups: {
        health: async () => ({
          observedAt: new Date().toISOString(),
          policies: [
            {
              policyId: 'policy',
              name: 'Fixture',
              state: 'completed',
              settings: { keepLast: 1, maxAgeMinutes: 0, verifyAfterDays: 30 },
              issues: [],
            },
          ],
          alerts: [],
        }),
        retention: async (...args) => {
          calls++;
          captured = args;
          if (failure) throw failure;
          return { id: args[2] };
        },
      },
    },
  };
  const mod = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: mod(
      'export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__backupManagement.vue',
    ),
    '@/lib/api': mod('export const api=globalThis.__backupManagement.api'),
    '@/lib/auth': mod('export const can=globalThis.__backupManagement.can'),
    '@/composables/useConfirm': mod('export const useConfirm=globalThis.__backupManagement.useConfirm'),
  };
  for (const name of ['Button', 'Input']) modules[`@/components/ui/${name}.vue`] = mod('export default {}');
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/BackupManagementPanel.vue', import.meta.url), 'utf8'),
  );
  let code = ts.transpileModule(compileScript(descriptor, { id: 'management-fixture' }).content, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    code = code.replaceAll(`'${name}'`, JSON.stringify(value)).replaceAll(`"${name}"`, JSON.stringify(value));
  const scope = vue.effectScope(),
    component = (await import(mod(code))).default;
  try {
    const state = scope.run(() => component.setup(props, { expose() {}, emit() {} }));
    await state.load();
    confirm = () =>
      new Promise((done) => {
        resolve = done;
      });
    const switching = state.retention('retention-apply');
    props.serverId = 'two';
    resolve(true);
    await switching;
    await vue.nextTick();
    assert.equal(calls, 0, 'old target confirmation dispatched cleanup');
    await state.load();
    confirm = async () => true;
    props.inspection = { ...props.inspection, runId: 'new-preview' };
    await state.retention('retention-apply');
    assert.equal(calls, 1);
    assert.equal(captured[0], 'two');
    assert.equal(captured[4], 'new-preview');
    assert.match(state.pending.value, /^[a-f0-9]{32}$/);
    await state.retention('retention-apply');
    assert.equal(calls, 1, 'unknown cleanup was submitted twice');
    grants.value = new Set([...grants.value].filter((p) => p !== 'backups.prune'));
    await vue.nextTick();
    assert.equal(state.applyAllowed.value, false, 'cleanup survived lost permission');
    await state.load();
    for (const code of ['backup_busy', 'backup_conflict', 'feature_disabled']) {
      failure = Object.assign(new Error('Request rejected'), { status: 409, code });
      const before = calls;
      await state.retention('retention-preview');
      assert.equal(calls, before + 1);
      assert.equal(state.pending.value, '', 'known rejection stranded the request');
    }
    failure = null;
    await state.retention('retention-preview');
    await state.load();
    assert.match(state.notice.value, /Operation saved/, 'refresh erased the operation confirmation');
  } finally {
    cleanup.forEach((fn) => fn());
    scope.stop();
    delete globalThis.__backupManagement;
  }
});
