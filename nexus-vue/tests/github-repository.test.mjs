import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';
const module = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
const transpile = (source) =>
  ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
const diffModule = module(
  transpile(readFileSync(new URL('../src/lib/workflow-diff.ts', import.meta.url), 'utf8')),
);
const { workflowDiff } = await import(diffModule);
async function component(name, key, fixture) {
  const cleanup = [];
  fixture.vue = {
    ...vue,
    onMounted() {},
    onUnmounted(fn) {
      cleanup.push(fn);
    },
  };
  globalThis[key] = fixture;
  const base = `globalThis.${key}`;
  const modules = {
    vue: module(`export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=${base}.vue`),
    '@/lib/api': module(`export const api=${base}.api`),
    '@/lib/auth': module(`export const can=${base}.can`),
    '@/composables/useConfirm': module(`export const useConfirm=${base}.useConfirm`),
    '@/lib/yaml-assist': module('export const yamlIssues=()=>[]'),
    '@/lib/workflow-diff': diffModule,
  };
  for (const name of ['ui/Button', 'ui/Input', 'YamlTextEditor'])
    modules[`@/components/${name}.vue`] = module('export default {}');
  const { descriptor } = parse(
    readFileSync(new URL(`../src/components/${name}.vue`, import.meta.url), 'utf8'),
  );
  let compiled = transpile(compileScript(descriptor, { id: key }).content);
  for (const [path, url] of Object.entries(modules))
    compiled = compiled.replaceAll(`'${path}'`, JSON.stringify(url));
  const object = (await import(module(compiled))).default,
    scope = vue.effectScope();
  const state = scope.run(() =>
    object.setup(
      {
        serverId: 'build',
        connectionId: 'connection',
        repository: 'fixture/repository',
        workflowPath: '.github/workflows/build.yml',
      },
      { expose() {} },
    ),
  );
  return {
    state,
    close() {
      for (const fn of cleanup) fn();
      scope.stop();
      delete globalThis[key];
    },
  };
}
test('workflow diff is plain text and reports edits and final newline changes', () => {
  const diff = workflowDiff('name: Old\non: [push]\n', 'name: New\non: [push]\n');
  assert.match(diff, /-name: Old/);
  assert.match(diff, /\+name: New/);
  assert.equal(workflowDiff('a', 'a'), '');
  assert.match(workflowDiff('a', 'a\n'), /final newline/);
});
test('repository workflow review retains unknown writes and discards late file reads', async () => {
  const grants = vue.ref(new Set(['github.workflows.read', 'github.workflows.write', 'secrets.use']));
  let writes = 0,
    rejectWrite,
    finishRead,
    deferRead = false,
    history = [];
  const file = {
    baseBranch: 'main',
    baseSha: 'a'.repeat(40),
    blobSha: 'b'.repeat(40),
    path: '.github/workflows/build.yml',
    content: 'name: Old\non: [push]\njobs: {}\n',
  };
  const fixture = {
    can: (p) => grants.value.has(p),
    useConfirm: () => ({ confirm: async () => true }),
    api: {
      githubActions: {
        changes: async () => history,
        workflowFile: () =>
          deferRead
            ? new Promise((resolve) => {
                finishRead = resolve;
              })
            : Promise.resolve({ ...file }),
        publishWorkflow: (_s, _id, input) => {
          writes++;
          assert.equal(input.baseSha, file.baseSha);
          assert.equal(input.blobSha, file.blobSha);
          assert.match(input.content, /name: Edited/);
          return new Promise((_resolve, reject) => {
            rejectWrite = reject;
          });
        },
      },
    },
  };
  const view = await component('GitHubWorkflowEditor', '__workflowReview', fixture),
    state = view.state;
  try {
    await state.open();
    state.content.value = 'name: Edited\non: [push]\njobs: {}\n';
    await vue.nextTick();
    assert.equal(state.ready.value, false);
    state.reviewed.value = true;
    assert.equal(state.ready.value, true);
    const writing = state.publish();
    await Promise.resolve();
    assert.equal(writes, 1);
    rejectWrite(new Error('lost acknowledgement'));
    await writing;
    const retained = state.pending.value;
    assert.ok(retained);
    await state.publish();
    assert.equal(writes, 1);
    history = [
      {
        id: retained,
        connectionId: 'connection',
        kind: 'workflow_edit',
        state: 'unknown',
        phase: 'file_write',
      },
    ];
    state.pending.value = '';
    await state.historyOnly();
    assert.equal(state.pending.value, retained);
    deferRead = true;
    const opening = state.open();
    await Promise.resolve();
    assert.equal(typeof finishRead, 'function');
    grants.value.delete('github.workflows.read');
    await vue.nextTick();
    finishRead({ ...file, content: 'private fixture file' });
    await opening;
    assert.equal(state.content.value, '');
    assert.equal(state.snapshot.value, undefined);
  } finally {
    view.close();
  }
});
test('runner removal is explicit, offline-only and never replays unknown results', async () => {
  const grants = vue.ref(
    new Set(['github.runners.provider.read', 'github.runners.provider.manage', 'secrets.use']),
  );
  let writes = 0,
    history = [];
  const runner = {
    id: 9,
    name: 'fixture',
    status: 'offline',
    busy: false,
    labels: [],
  };
  const fixture = {
    can: (p) => grants.value.has(p),
    useConfirm: () => ({ confirm: async () => true }),
    api: {
      githubActions: {
        providerRunners: async () => ({ total_count: 1, runners: [runner] }),
        changes: async () => history,
        removeProviderRunner: async (_s, _c, id) => {
          writes++;
          return {
            change: {
              id,
              connectionId: 'connection',
              kind: 'runner_remove',
              state: 'unknown',
              resourceId: 9,
            },
          };
        },
      },
    },
  };
  const view = await component('GitHubProviderRunners', '__repositoryRunners', fixture),
    state = view.state;
  try {
    await state.refresh(1);
    await state.remove({ ...runner, status: 'online' });
    assert.equal(writes, 0);
    await state.remove({ ...runner, busy: true });
    assert.equal(writes, 0);
    await state.remove(runner);
    assert.equal(writes, 1);
    const retained = state.pending.value;
    assert.ok(retained);
    history = [
      {
        id: retained,
        connectionId: 'connection',
        kind: 'runner_remove',
        state: 'unknown',
      },
    ];
    state.pending.value = '';
    await state.refresh();
    assert.equal(state.pending.value, retained);
    await state.remove(runner);
    assert.equal(writes, 1);
    grants.value.delete('github.runners.provider.read');
    await vue.nextTick();
    assert.deepEqual(state.rows.value, []);
    assert.deepEqual(state.history.value, []);
  } finally {
    view.close();
  }
});
