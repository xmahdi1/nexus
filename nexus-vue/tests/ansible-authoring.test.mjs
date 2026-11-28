import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';

test('authoring helpers preserve concurrent edits and discard content after authority or project changes', async () => {
  const grants = vue.ref(
    new Set([
      'ansible.projects.manage',
      'ansible.projects.read',
      'github.projects.read',
      'secrets.use',
      'secrets.create',
      'secrets.reveal',
    ]),
  );
  const props = vue.reactive({
    serverId: 'controller',
    projectId: 'first',
    bundle: { main: 'main.yml', files: { 'main.yml': '- hosts: all' }, variables: [] },
  });
  const events = [],
    cleanup = [];
  let finish,
    approve,
    imports = 0,
    confirm = async () => true;
  globalThis.__authoringFixture = {
    vue: {
      ...vue,
      onUnmounted(fn) {
        cleanup.push(fn);
      },
    },
    can: (p) => grants.value.has(p),
    confirm: (...args) => confirm(...args),
    api: {
      playbooks: {
        templates: async () => [{ id: 'template', name: 'Reusable' }],
        templateContent: async () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
        importRevision: async () => {
          imports++;
          return { id: 'imported' };
        },
      },
    },
  };
  const mod = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: mod(
      'export const {defineComponent,computed,onUnmounted,ref,watch}=globalThis.__authoringFixture.vue',
    ),
    '@/lib/auth': mod('export const can=globalThis.__authoringFixture.can'),
    '@/lib/api': mod('export const api=globalThis.__authoringFixture.api'),
    '@/lib/ansible-checks': mod('export const checkAnsibleBundle=()=>[]'),
    '@/composables/useConfirm': mod(
      'export const useConfirm=()=>({confirm:globalThis.__authoringFixture.confirm})',
    ),
    './ui/Button.vue': mod('export default {}'),
    './ui/Input.vue': mod('export default {}'),
  };
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/AnsibleAuthoringTools.vue', import.meta.url), 'utf8'),
  );
  let code = ts.transpileModule(compileScript(descriptor, { id: 'authoring' }).content, {
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
    await state.listTemplates();
    state.templateId.value = 'template';
    const loading = state.loadTemplate();
    await Promise.resolve();
    await Promise.resolve();
    props.bundle.files['main.yml'] = '- hosts: edited';
    finish({ main: 'main.yml', files: { 'main.yml': 'private-template' }, variables: [] });
    await loading;
    assert.equal(events.length, 0);
    assert.match(state.notice.value, /draft changed/i);
    const next = state.loadTemplate();
    await Promise.resolve();
    await Promise.resolve();
    grants.value = new Set(['ansible.projects.manage', 'ansible.projects.read']);
    finish({ main: 'main.yml', files: { 'main.yml': 'private-template' }, variables: [] });
    await next;
    assert.equal(events.length, 0, 'revoked content was emitted');
    grants.value = new Set([
      'ansible.projects.manage',
      'ansible.projects.read',
      'github.projects.read',
      'secrets.use',
      'secrets.create',
    ]);
    state.connectionId.value = 'repository';
    confirm = () =>
      new Promise((resolve) => {
        approve = resolve;
      });
    const importing = state.importRevision();
    props.projectId = 'second';
    approve(true);
    await importing;
    assert.equal(imports, 0, 'changed project received an import');
  } finally {
    cleanup.forEach((fn) => fn());
    scope.stop();
    delete globalThis.__authoringFixture;
  }
});
