import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('run controls retain unknown cancellation and discard logs when permission changes', async () => {
  const grants = vue.ref(
    new Set(['github.actions.read', 'github.actions.cancel', 'github.actions.logs.read', 'secrets.use']),
  );
  let writes = 0,
    rejectCancel,
    finishLog,
    history = [];
  const cleanups = [];
  globalThis.__githubRun = {
    vue: {
      ...vue,
      onMounted() {},
      onUnmounted(fn) {
        cleanups.push(fn);
      },
    },
    can: (p) => grants.value.has(p),
    useConfirm: () => ({ confirm: async () => true }),
    api: {
      githubActions: {
        run: async () => ({ id: 99, run_attempt: 1, status: 'in_progress' }),
        cancellations: async () => history,
        cancelRun: () => {
          writes++;
          return new Promise((_resolve, reject) => {
            rejectCancel = reject;
          });
        },
        jobLog: () =>
          new Promise((resolve) => {
            finishLog = resolve;
          }),
      },
    },
  };
  const module = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: module(
      'export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__githubRun.vue',
    ),
    '@/lib/api': module('export const api=globalThis.__githubRun.api'),
    '@/lib/auth': module('export const can=globalThis.__githubRun.can'),
    '@/composables/useConfirm': module('export const useConfirm=globalThis.__githubRun.useConfirm'),
    '@/components/ui/Button.vue': module('export default {}'),
  };
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/GitHubRunPanel.vue', import.meta.url), 'utf8'),
  );
  let compiled = ts.transpileModule(compileScript(descriptor, { id: 'github-run' }).content, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    compiled = compiled.replaceAll(`'${name}'`, JSON.stringify(value));
  const component = (await import(module(compiled))).default,
    scope = vue.effectScope();
  try {
    const state = scope.run(() =>
      component.setup({ serverId: 'build', connectionId: 'connection', runId: 99 }, { expose() {} }),
    );
    await state.refresh();
    const request = state.cancelRun();
    await Promise.resolve();
    assert.equal(writes, 1);
    rejectCancel(new Error('lost acknowledgement'));
    await request;
    assert.ok(state.pending.value);
    const retained = state.pending.value;
    history = [
      {
        id: retained,
        connectionId: 'connection',
        runId: 99,
        runAttempt: 1,
        state: 'unknown',
      },
    ];
    state.pending.value = '';
    await state.refresh();
    assert.equal(state.pending.value, retained);
    await state.cancelRun();
    assert.equal(writes, 1, 'refresh must not replay unknown cancellation');
    const reading = state.revealLog(101);
    await Promise.resolve();
    assert.equal(typeof finishLog, 'function');
    grants.value.delete('github.actions.logs.read');
    await vue.nextTick();
    finishLog({ content: 'private fixture log', redacted: false });
    await reading;
    assert.equal(state.log.value, '');
    assert.equal(state.logJob.value, 0);
    assert.equal(state.run.value, undefined);
  } finally {
    for (const cleanup of cleanups) cleanup();
    scope.stop();
    delete globalThis.__githubRun;
  }
});
