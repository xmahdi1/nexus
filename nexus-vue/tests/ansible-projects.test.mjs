import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('revoked project reveal discards pending content and integer variables stay typed', async () => {
  const grants = vue.ref(
    new Set([
      'ansible.projects.read',
      'ansible.projects.manage',
      'secrets.reveal',
      'ansible.playbooks.execute',
    ]),
  );
  let finish;
  const cleanup = [];
  globalThis.__projectFixture = {
    vue: {
      ...vue,
      onMounted() {},
      onUnmounted(fn) {
        cleanup.push(fn);
      },
    },
    can: (p) => grants.value.has(p),
    canAny: () => false,
    useConfirm: () => ({ confirm: async () => true }),
    api: {
      auth: { me: async () => ({ user: { id: 'owner' } }) },
      playbooks: {
        presets: async () => [],
        projects: async () => [],
        plans: async () => [],
        content: () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      },
    },
  };
  const stub = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: stub(
      'export const {defineComponent,computed,nextTick,onMounted,onUnmounted,ref,watch}=globalThis.__projectFixture.vue',
    ),
    '@/lib/api': stub('export const api=globalThis.__projectFixture.api'),
    '@/lib/auth': stub('export const {can,canAny}=globalThis.__projectFixture'),
    '@/composables/useConfirm': stub('export const useConfirm=globalThis.__projectFixture.useConfirm'),
  };
  for (const name of [
    'ui/Button',
    'ui/Input',
    'AnsibleVaultReference',
    'AnsibleRunsPanel',
    'AnsibleOrchestrationPanel',
    'AnsibleAuthoringTools',
  ])
    modules[`@/components/${name}.vue`] = stub('export default {}');
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/AnsibleProjectsPanel.vue', import.meta.url), 'utf8'),
  );
  let compiled = ts.transpileModule(compileScript(descriptor, { id: 'project-fixture' }).content, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    compiled = compiled.replaceAll(`'${name}'`, JSON.stringify(value));
  const component = (await import(stub(compiled))).default,
    scope = vue.effectScope();
  try {
    const state = scope.run(() =>
      component.setup({ serverId: 'controller', servers: [], vaultEnabled: true }, { expose() {} }),
    );
    await state.load();
    state.projectId.value = 'p';
    state.revisionId.value = 'r';
    state.revisions.value = [{ id: 'r' }];
    const pending = state.revealRevision();
    await Promise.resolve();
    assert.equal(typeof finish, 'function');
    grants.value.delete('secrets.reveal');
    await vue.nextTick();
    finish({ main: 'main.yml', files: { 'main.yml': 'private playbook' }, variables: [] });
    await pending;
    assert.deepEqual(state.files.value, {});
    assert.equal(state.loaded.value, null);
    assert.equal(state.review.value, null);
    state.loaded.value = {
      main: 'main.yml',
      files: {},
      variables: [{ name: 'count', kind: 'integer', required: true }],
    };
    state.strings.value.count = '';
    assert.throws(() => state.variables(), /Enter an integer/);
    state.strings.value.count = '3';
    assert.deepEqual(state.variables(), { count: 3 });
  } finally {
    for (const dispose of cleanup) dispose();
    scope.stop();
    delete globalThis.__projectFixture;
  }
});
