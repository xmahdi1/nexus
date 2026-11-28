import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse, compileScript } from '@vue/compiler-sfc';
import * as vue from 'vue';
import ts from 'typescript';
test('YAML editor rejects truncated data and prevents stale reveals after read revocation', async () => {
  const grants = vue.ref(
    new Set(['compose.read', 'compose.write', 'files.read', 'files.write', 'secrets.use', 'secrets.reveal']),
  );
  let finish;
  const cleanup = [];
  globalThis.__yamlFile = {
    vue: {
      ...vue,
      onUnmounted(fn) {
        cleanup.push(fn);
      },
    },
    can: (p) => grants.value.has(p),
    useConfirm: () => ({ confirm: async () => true }),
    assist: {
      profiles: { yaml: 'YAML', compose: 'Compose' },
      detectYamlProfile: (path, content = '') =>
        path.includes('compose') || content.includes('services:') ? 'compose' : 'yaml',
      isComposeDocument: () => true,
      yamlIssues: () => [],
    },
    api: {
      compose: {
        read: () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      },
      files: {
        preview: async () => ({
          content: 'incomplete',
          truncated: true,
          binary: false,
        }),
      },
    },
  };
  const stub = (code) => `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`;
  const modules = {
    vue: stub('export const {defineComponent,computed,onUnmounted,ref,watch}=globalThis.__yamlFile.vue'),
    '@/lib/api': stub('export const api=globalThis.__yamlFile.api'),
    '@/lib/auth': stub('export const can=globalThis.__yamlFile.can'),
    '@/composables/useConfirm': stub('export const useConfirm=globalThis.__yamlFile.useConfirm'),
    '@/lib/yaml-assist': stub(
      'export const {profiles,detectYamlProfile,isComposeDocument,yamlIssues}=globalThis.__yamlFile.assist',
    ),
  };
  for (const name of ['ui/Button', 'ui/Input', 'YamlTextEditor'])
    modules[`@/components/${name}.vue`] = stub('export default {}');
  const { descriptor } = parse(
    readFileSync(new URL('../src/components/YamlFileTab.vue', import.meta.url), 'utf8'),
  );
  let compiled = ts.transpileModule(compileScript(descriptor, { id: 'yaml-file-fixture' }).content, {
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
    const state = scope.run(() =>
      component.setup({ serverId: 'build', supervision: false, operate: async () => {} }, { expose() {} }),
    );
    const loading = state.open();
    await Promise.resolve();
    assert.equal(typeof finish, 'function');
    grants.value.delete('compose.read');
    await vue.nextTick();
    finish({ content: 'private: value' });
    await loading;
    assert.equal(state.content.value, '');
    assert.equal(state.loadedPath.value, '');
    state.path.value = '/opt/config.yaml';
    await state.open();
    assert.match(state.error.value, /Truncated/);
    assert.equal(state.loadedPath.value, '');
    grants.value.add('compose.read');
    await vue.nextTick();
    let composeReads = 0,
      fileReads = 0;
    globalThis.__yamlFile.api.compose.read = async () => {
      composeReads++;
      return { content: 'services:\n  app:\n    image: nginx\n' };
    };
    globalThis.__yamlFile.api.files.preview = async () => {
      fileReads++;
      return {
        content: 'apiVersion: apps/v1\nkind: Deployment\n',
        truncated: false,
        binary: false,
      };
    };
    state.path.value = '/opt/compose.yml';
    await state.open();
    assert.equal(composeReads, 1);
    state.path.value = '/opt/deployment.yaml';
    await state.open();
    assert.equal(composeReads, 1, 'old Compose contents must not choose transport for a new path');
    assert.equal(fileReads, 1);
    assert.equal(state.loadedTransport.value, 'files');
    assert.equal(state.loadedPath.value, '/opt/deployment.yaml');
    let writes = 0;
    globalThis.__yamlFile.api.files.write = async () => {
      writes++;
      throw new Error('Lost write acknowledgement');
    };
    state.content.value += 'metadata: {name: api}\n';
    await state.save();
    assert.equal(writes, 1);
    assert.equal(state.writeUnconfirmed.value, true);
    await state.save();
    assert.equal(writes, 1, 'uncertain save must require reopening');
    await state.open();
    assert.equal(state.writeUnconfirmed.value, false);
    state.content.value += 'metadata: {name: api}\n';
    globalThis.__yamlFile.api.files.preview = async () => ({
      content: 'changed: elsewhere\n',
      truncated: false,
      binary: false,
    });
    await state.save();
    assert.equal(writes, 1, 'remote change must prevent overwrite');
    assert.match(state.error.value, /remote file changed/);
  } finally {
    for (const dispose of cleanup) dispose();
    scope.stop();
    delete globalThis.__yamlFile;
  }
});
