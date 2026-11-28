import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
async function load(name) {
  let source = ts.transpileModule(
    readFileSync(new URL('../src/lib/' + name + '.ts', import.meta.url), 'utf8'),
    {
      compilerOptions: {
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ES2022,
      },
    },
  ).outputText;
  for (const module of ['vue'])
    source = source.replaceAll(`from '${module}'`, `from ${JSON.stringify(import.meta.resolve(module))}`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
test('tool visibility remains per-user browser preference and rejects unknown IDs', async () => {
  const data = new Map();
  globalThis.localStorage = {
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, value),
    removeItem: (key) => data.delete(key),
  };
  const prefs = await load('tool-preferences');
  prefs.setToolPreferenceUser('alice');
  prefs.setToolEnabled('github', false);
  assert.equal(prefs.toolEnabled('github'), false);
  assert.deepEqual(JSON.parse(data.get('nexus:tools:v1:alice')), ['github']);
  prefs.setToolPreferenceUser('bob');
  assert.equal(prefs.toolEnabled('github'), true);
  prefs.setToolEnabled('yaml', false);
  prefs.setToolPreferenceUser('alice');
  assert.equal(prefs.toolEnabled('github'), false);
  assert.equal(prefs.toolEnabled('yaml'), true);
  prefs.resetTools();
  assert.equal(prefs.toolEnabled('github'), true);
  data.set('nexus:tools:v1:bob', '["yaml","unknown-tool"]');
  prefs.setToolPreferenceUser('bob');
  assert.equal(prefs.toolEnabled('yaml'), false);
  prefs.setToolPreferenceUser('');
  assert.equal(prefs.toolEnabled('yaml'), true);
  delete globalThis.localStorage;
});
