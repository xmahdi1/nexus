import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('queue UI retains an unknown request and rejects changed plan or permission after confirmation', async () => {
  const grants = vue.ref(
    new Set([
      'ansible.projects.read',
      'jobs.read',
      'ansible.playbooks.execute',
      'jobs.execute',
      'ansible.schedules.manage',
      'secrets.create',
      'secrets.use',
    ]),
  );
  const props = vue.reactive({
    serverId: 'controller',
    actorId: 'owner',
    plan: {
      id: 'plan',
      actorId: 'owner',
      state: 'approved',
      presetId: 'preset',
      options: { mode: 'check' },
      variables: {},
    },
  });
  const cleanup = [];
  let confirm = async () => true,
    finish,
    calls = 0;
  globalThis.__orchestrationFixture = {
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
      features: async () => ({ automation: true, operationSupervision: true }),
      playbooks: {
        queue: async () => [],
        schedules: async () => [],
        enqueue: async (_server, _plan, input) => {
          calls++;
          assert.match(input.requestId, /^[a-f0-9]{32}$/);
          throw new Error('Lost acknowledgement');
        },
      },
    },
  };
  const mod = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: mod(
      'export const {defineComponent,computed,onMounted,onUnmounted,ref,watch}=globalThis.__orchestrationFixture.vue',
    ),
    '@/lib/api': mod('export const api=globalThis.__orchestrationFixture.api'),
    '@/lib/auth': mod('export const can=globalThis.__orchestrationFixture.can'),
    '@/composables/useConfirm': mod('export const useConfirm=globalThis.__orchestrationFixture.useConfirm'),
  };
  for (const name of ['ui/Button', 'ui/Input'])
    modules[`@/components/${name}.vue`] = mod('export default {}');
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/AnsibleOrchestrationPanel.vue', import.meta.url), 'utf8'),
  );
  let code = ts.transpileModule(compileScript(descriptor, { id: 'orchestration-fixture' }).content, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  for (const [name, value] of Object.entries(modules))
    code = code.replaceAll(`'${name}'`, JSON.stringify(value));
  const scope = vue.effectScope(),
    component = (await import(mod(code))).default;
  try {
    const state = scope.run(() => component.setup(props, { expose() {}, emit() {} }));
    await state.load();
    await state.enqueue();
    assert.equal(calls, 1);
    assert.match(state.pending.value, /^[a-f0-9]{32}$/);
    await state.enqueue();
    assert.equal(calls, 1, 'unknown enqueue repeated automatically');
    state.pending.value = '';
    confirm = () =>
      new Promise((resolve) => {
        finish = resolve;
      });
    const changed = state.enqueue();
    props.plan = { ...props.plan, id: 'another' };
    finish(true);
    await changed;
    assert.equal(calls, 1, 'changed plan passed old confirmation');
    const revoked = state.enqueue();
    grants.value.delete('jobs.execute');
    await vue.nextTick();
    finish(true);
    await revoked;
    assert.equal(calls, 1, 'revoked execution passed confirmation');
  } finally {
    cleanup.forEach((fn) => fn());
    scope.stop();
    delete globalThis.__orchestrationFixture;
  }
});
