import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const source = readFileSync(new URL('../src/lib/ansible-checks.ts', import.meta.url), 'utf8');
const code = ts
  .transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  })
  .outputText.replace("from 'yaml'", `from ${JSON.stringify(import.meta.resolve('yaml'))}`);
const { checkAnsibleBundle } = await import(
  `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`
);
const bundle = (source) => ({ main: 'main.yml', files: { 'main.yml': source }, variables: [] });
test('project checks identify invalid YAML and command/delegation risks without quoting values', () => {
  assert(checkAnsibleBundle(bundle('tasks: []')).some((i) => i.code === 'playbook'));
  assert(checkAnsibleBundle(bundle('- hosts: all\n  hosts: duplicate\n')).some((i) => i.code === 'yaml'));
  const issues = checkAnsibleBundle(
    bundle(
      '- hosts: all\n  tasks:\n    - shell: echo private-value\n      delegate_to: localhost\n      become: true\n',
    ),
  );
  for (const code of ['command', 'fqcn', 'delegation', 'privilege'])
    assert(
      issues.some((i) => i.code === code),
      code,
    );
  assert(!JSON.stringify(issues).includes('private-value'));
  assert.equal(checkAnsibleBundle(bundle('$ANSIBLE_VAULT;1.1;AES256\nopaque')).length, 0);
  assert.equal(
    checkAnsibleBundle(bundle('- hosts: all\n  gather_facts: false\n  tasks:\n    - ansible.builtin.ping:\n'))
      .length,
    0,
  );
});
