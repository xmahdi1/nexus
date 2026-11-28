import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('execution presets reset values, prepare through the saved selection, and discard revoked replies', async () => {
  const grants = vue.ref(
    new Set([
      'ansible.projects.read',
      'ansible.projects.manage',
      'secrets.reveal',
      'ansible.playbooks.execute',
    ]),
  );
  const cleanup = [];
  let deferred = false,
    finish;
  const calls = [];
  const selection = {
    name: 'Checks',
    projectId: 'project',
    revisionId: 'revision',
    revisionDigest: 'digest',
    groupId: 'targets',
    serverIds: ['dev'],
    options: { mode: 'check', tags: [], skipTags: [], verbosity: 0, timeoutSeconds: 60 },
  };
  const bundle = {
    main: 'main.yml',
    files: { 'main.yml': '- hosts: all\n  tasks: []' },
    variables: [{ name: 'message', kind: 'string', required: true }],
  };
  globalThis.__presetFixture = {
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
      ansible: {
        preview: async () => ({
          inventory: {
            _meta: {
              hostvars: {
                dev: {
                  nexus_server_id: 'dev',
                  ansible_host: '192.0.2.1',
                  ansible_user: 'fixture',
                  ansible_port: 22,
                },
              },
            },
          },
        }),
      },
      playbooks: {
        projects: async () => [{ id: 'project' }],
        plans: async () => [],
        presets: async () => [{ id: 'preset', name: 'Checks' }],
        presetContent: async () => selection,
        revisions: async () => [{ id: 'revision', digest: 'digest' }],
        content: async () =>
          deferred
            ? new Promise((resolve) => {
                finish = resolve;
              })
            : bundle,
        preparePreset: async (...args) => {
          calls.push(args);
          return { id: 'fresh', state: 'prepared', presetId: 'preset' };
        },
      },
    },
  };
  const mod = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: mod(
      'export const {defineComponent,computed,nextTick,onMounted,onUnmounted,ref,watch}=globalThis.__presetFixture.vue',
    ),
    '@/lib/api': mod('export const api=globalThis.__presetFixture.api'),
    '@/lib/auth': mod('export const {can,canAny}=globalThis.__presetFixture'),
    '@/composables/useConfirm': mod('export const useConfirm=globalThis.__presetFixture.useConfirm'),
  };
  for (const name of [
    'ui/Button',
    'ui/Input',
    'AnsibleVaultReference',
    'AnsibleRunsPanel',
    'AnsibleOrchestrationPanel',
    'AnsibleAuthoringTools',
  ])
    modules[`@/components/${name}.vue`] = mod('export default {}');
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/AnsibleProjectsPanel.vue', import.meta.url), 'utf8'),
  );
  let code = ts.transpileModule(compileScript(descriptor, { id: 'preset-fixture' }).content, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    code = code.replaceAll(`'${name}'`, JSON.stringify(value));
  const scope = vue.effectScope(),
    component = (await import(mod(code))).default;
  try {
    const state = scope.run(() =>
      component.setup({ serverId: 'controller', servers: [], vaultEnabled: true }, { expose() {} }),
    );
    await state.load();
    state.presetId.value = 'preset';
    state.strings.value = { message: 'old-private-value' };
    state.useVaultPassword.value = true;
    await state.loadPreset();
    assert.equal(state.activePresetId.value, 'preset');
    assert.deepEqual(state.selected.value, ['dev']);
    assert.equal(state.strings.value.message, '');
    assert.equal(state.useVaultPassword.value, false);
    state.strings.value.message = 'fresh-value';
    await state.prepare();
    assert.deepEqual(calls, [['controller', 'preset', { message: 'fresh-value' }, undefined]]);
    assert.equal(state.plans.value[0].state, 'prepared');
    deferred = true;
    const loading = state.loadPreset();
    for (let i = 0; i < 8 && !finish; i++) await Promise.resolve();
    assert.equal(typeof finish, 'function');
    grants.value.delete('secrets.reveal');
    await vue.nextTick();
    finish(bundle);
    await loading;
    assert.equal(state.loaded.value, null);
    assert.deepEqual(state.files.value, {});
    assert.equal(state.activePresetId.value, '');
  } finally {
    cleanup.forEach((fn) => fn());
    scope.stop();
    delete globalThis.__presetFixture;
  }
});
