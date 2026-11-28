import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('GitHub keys clear on submission; unknown dispatch never replays and revoked access discards data', async () => {
  const grants = vue.ref(
    new Set([
      'github.actions.read',
      'github.connections.manage',
      'github.actions.dispatch',
      'secrets.create',
      'secrets.use',
    ]),
  );
  let finishCreate,
    rejectDispatch,
    writes = 0,
    submissions = [];
  const cleanup = [];
  globalThis.__githubPanel = {
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
      githubActions: {
        connections: async () => [{ id: 'connection', owner: 'fixture', name: 'repo', disabled: false }],
        history: async () => submissions,
        runs: async () => ({ total_count: 0, workflow_runs: [] }),
        create: (_server, input) => {
          assert.equal(input.privateKey, 'fixture-private-key');
          return new Promise((resolve) => {
            finishCreate = resolve;
          });
        },
        dispatch: () => {
          writes++;
          return new Promise((_resolve, reject) => {
            rejectDispatch = reject;
          });
        },
      },
    },
  };
  const stub = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: stub(
      'export const {defineComponent,defineAsyncComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__githubPanel.vue',
    ),
    '@/lib/tool-preferences': stub('export const toolEnabled=()=>true'),
    '@/lib/api': stub('export const api=globalThis.__githubPanel.api'),
    '@/lib/auth': stub('export const can=globalThis.__githubPanel.can'),
    '@/composables/useConfirm': stub('export const useConfirm=globalThis.__githubPanel.useConfirm'),
  };
  for (const name of [
    'ui/Button',
    'ui/Input',
    'GitHubRunPanel',
    'GitHubProviderRunners',
    'GitHubWorkflowEditor',
  ])
    modules[`@/components/${name}.vue`] = stub('export default {}');
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/GitHubConnectionPanel.vue', import.meta.url), 'utf8'),
  );
  let compiled = ts.transpileModule(compileScript(descriptor, { id: 'github-fixture' }).content, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    compiled = compiled.replaceAll(`'${name}'`, JSON.stringify(value));
  const component = (await import(stub(compiled))).default,
    scope = vue.effectScope();
  try {
    const state = scope.run(() => component.setup({ serverId: 'build' }, { expose() {} }));
    state.privateKey.value = 'fixture-private-key';
    const saving = state.create();
    assert.equal(state.privateKey.value, '');
    finishCreate({
      id: 'connection',
      owner: 'fixture',
      name: 'repo',
      disabled: false,
    });
    await saving;
    state.selected.value = 'connection';
    state.workflows.value = [
      {
        id: 7,
        name: 'Fixture',
        path: '.github/workflows/build.yml',
        state: 'active',
      },
    ];
    state.workflow.value = 7;
    state.editingPath.value = '.github/workflows/build.yml';
    await state.browse('runs', 1);
    assert.equal(
      state.editingPath.value,
      '.github/workflows/build.yml',
      'listing runs must preserve the open workflow draft',
    );
    state.inputs.value = '{"enabled":true}';
    const pending = state.dispatch();
    await Promise.resolve();
    assert.equal(writes, 1);
    assert.equal(state.inputs.value, '{}');
    rejectDispatch(new Error('lost acknowledgement'));
    await pending;
    await state.dispatch();
    assert.equal(writes, 1);
    const retained = state.pending.value;
    submissions = [{ id: retained, state: 'unknown' }];
    state.pending.value = '';
    await state.load();
    assert.equal(state.pending.value, retained, 'reload must restore unresolved requests');
    await state.dispatch();
    assert.equal(writes, 1);
    submissions = [{ id: retained, state: 'submitted', runId: 99 }];
    await state.load();
    assert.equal(state.pending.value, '');
    state.privateKey.value = 'another-private-value';
    state.runs.value = [{ id: 9 }];
    grants.value.delete('github.actions.read');
    await vue.nextTick();
    assert.equal(state.privateKey.value, '');
    assert.deepEqual(state.connections.value, []);
    assert.deepEqual(state.runs.value, []);
  } finally {
    for (const dispose of cleanup) dispose();
    scope.stop();
    delete globalThis.__githubPanel;
  }
});
