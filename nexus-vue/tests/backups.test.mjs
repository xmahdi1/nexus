import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('backup setup clones reactive settings, clears submitted secrets, and retains an unknown request', async () => {
  const grants = vue.ref(
    new Set([
      'backups.read',
      'backups.manage',
      'backups.execute',
      'backups.restore',
      'backups.schedule',
      'jobs.read',
      'jobs.execute',
      'secrets.create',
      'secrets.use',
    ]),
  );
  const props = vue.reactive({ serverId: 'one', serverName: 'Fixture server' });
  const cleanup = [];
  let confirm = async () => true,
    finish,
    calls = 0,
    captured,
    policies = [];
  const oldDocument = globalThis.document;
  globalThis.document = { hidden: false, addEventListener() {}, removeEventListener() {} };
  globalThis.__backupFixture = {
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
      features: async () => ({ backups: true, operationSupervision: true }),
      backups: {
        policies: async () => policies,
        runs: async () => [],
        create: async (scope, id, definition) => {
          calls++;
          captured = { scope, id, definition: JSON.parse(JSON.stringify(definition)) };
          throw new Error('Lost acknowledgement');
        },
      },
    },
  };
  const mod = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: mod(
      'export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__backupFixture.vue',
    ),
    '@/lib/api': mod('export const api=globalThis.__backupFixture.api'),
    '@/lib/auth': mod('export const can=globalThis.__backupFixture.can'),
    '@/composables/useConfirm': mod('export const useConfirm=globalThis.__backupFixture.useConfirm'),
  };
  for (const name of ['ui/Button', 'ui/Input', 'BackupSourceFields', 'BackupManagementPanel'])
    modules[`@/components/${name}.vue`] = mod('export default {}');
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/BackupsWorkspace.vue', import.meta.url), 'utf8'),
  );
  let code = ts.transpileModule(compileScript(descriptor, { id: 'backup-fixture' }).content, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    code = code.replaceAll(`'${name}'`, JSON.stringify(value));
  const scope = vue.effectScope(),
    component = (await import(mod(code))).default;
  try {
    const state = scope.run(() => component.setup(props, { expose() {} }));
    await state.load();
    const fill = () => {
      state.name.value = 'Files';
      state.chosen.value = [{ key: 'source', source: { kind: 'files', label: 'App', path: '/srv/app' } }];
      state.repository.value = {
        kind: 'local',
        location: '/mnt/backup',
        password: 'private-fixture-password',
      };
      state.liveFiles.value = true;
    };
    fill();
    assert.equal(state.definition().repository.password, 'private-fixture-password');
    await state.save();
    assert.equal(calls, 1);
    assert.equal(captured.definition.repository.password, 'private-fixture-password');
    assert.equal(state.repository.value.password, '');
    assert.match(state.pending.value.id, /^[a-f0-9]{32}$/);
    fill();
    await state.save();
    assert.equal(calls, 1, 'unknown creation was repeated');
    policies = [{ id: captured.id }];
    await state.load();
    assert.equal(state.pending.value, null);
    fill();
    confirm = () =>
      new Promise((resolve) => {
        finish = resolve;
      });
    const changing = state.save();
    props.serverId = 'two';
    finish(true);
    await changing;
    assert.equal(calls, 1, 'old confirmation created on a different server');
    state.result.value = {
      runId: 'old',
      policyId: 'policy',
      data: { state: 'restored', restorePath: '/private/old' },
    };
    state.repository.value.password = 'private-to-clear';
    grants.value = new Set([...grants.value].filter((p) => p !== 'secrets.use'));
    assert.equal(state.result.value, null, 'result survived loss of secret access');
    assert.equal(state.repository.value.password, '', 'form secret survived lost access');
  } finally {
    cleanup.forEach((fn) => fn());
    scope.stop();
    delete globalThis.__backupFixture;
    globalThis.document = oldDocument;
  }
});
