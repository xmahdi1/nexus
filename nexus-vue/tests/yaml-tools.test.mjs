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
  for (const module of ['vue', 'yaml'])
    source = source.replaceAll(`from '${module}'`, `from ${JSON.stringify(import.meta.resolve(module))}`);
  return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}
const assist = await load('yaml-assist');
test('YAML assistance distinguishes profiles and validates safe saved Compose documents', () => {
  assert.equal(assist.detectYamlProfile('/opt/app/docker-compose.yml', ''), 'compose');
  assert.equal(assist.detectYamlProfile('/opt/project/.github/workflows/build.yml', ''), 'github');
  assert.equal(
    assist.detectYamlProfile('/opt/deployment.yaml', 'apiVersion: apps/v1\nkind: Deployment\n'),
    'kubernetes',
  );
  assert.equal(assist.isComposeDocument('services: {}'), true);
  assert.equal(assist.isComposeDocument('apiVersion: v1\nkind: ConfigMap\n'), false);
  assert.equal(assist.isComposeDocument('services: {}\n---\nservices: {}'), false);
  assert.ok(assist.yamlIssues('services: [').some((issue) => issue.severity === 'error'));
  assert.ok(assist.yamlIssues('name: one\nname: two').some((issue) => issue.severity === 'error'));
  assert.ok(assist.yamlIssues('x'.repeat(262145)).some((issue) => issue.message.includes('256 KiB')));
  assert.equal(
    assist.yamlIssues(
      Array.from({ length: 55 }, (_, i) => `key${i}: !unknown value`).join('\n') + '\n---\nbroken: [',
    )[0].severity,
    'error',
  );
  assert.deepEqual(assist.yamlIssues('name: Build\non: [push]\njobs: {}'), []);
  assert.ok(assist.yamlKeys('compose', 'services:\n  web:\n    im').includes('image'));
  assert.ok(assist.yamlKeys('compose', 'services:\n  web:\n    healthcheck:\n      ret').includes('retries'));
  assert.ok(assist.yamlKeys('github', 'jobs:\n  build:\n    steps:\n      - us').includes('uses'));
  assert.ok(
    assist
      .yamlKeys(
        'kubernetes',
        'spec:\n  template:\n    spec:\n      containers:\n        - name: api\n          im',
      )
      .includes('image'),
  );
  assert.ok(assist.yamlValues('kubernetes', 'kind: Dep').includes('Deployment'));
});
