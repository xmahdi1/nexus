import { isMap, isScalar, isSeq, LineCounter, parseDocument, type Node } from 'yaml';
import type { AnsibleBundle } from './api';
export interface AnsibleCheck {
  file: string;
  line: number;
  level: 'error' | 'warning';
  code: string;
  message: string;
}
// Local authoring checks only. Never render source excerpts or evaluate Jinja,
// YAML aliases, lookups, modules or plugins. Runtime syntax/approval stay separate.
export function checkAnsibleBundle(bundle: AnsibleBundle): AnsibleCheck[] {
  const issues: AnsibleCheck[] = [];
  const add = (file: string, line: number, level: AnsibleCheck['level'], code: string, message: string) => {
    if (issues.length < 100) issues.push({ file, line, level, code, message });
  };
  let visited = 0;
  for (const [file, source] of Object.entries(bundle.files)) {
    if (!/\.ya?ml$/.test(file) || source.startsWith('$ANSIBLE_VAULT;')) continue;
    if (source.length > 16_384) {
      add(file, 1, 'error', 'size', 'File exceeds the project size limit.');
      continue;
    }
    const lines = new LineCounter();
    const doc = parseDocument(source, { lineCounter: lines, prettyErrors: false, uniqueKeys: true });
    if (doc.errors.length) {
      add(
        file,
        lines.linePos(doc.errors[0]!.pos[0]).line,
        'error',
        'yaml',
        'Invalid YAML. Check indentation, duplicate keys and document structure.',
      );
      continue;
    }
    if (file === bundle.main && !isSeq(doc.contents))
      add(file, 1, 'error', 'playbook', 'The main playbook must be a list of plays or playbook imports.');
    const walk = (node: Node | null | undefined, depth: number) => {
      if (!node || issues.length >= 100) return;
      visited++;
      if (depth > 32 || visited > 10_000) {
        add(
          file,
          1,
          'warning',
          'complexity',
          'Document is too complex for these local checks. Review it with Ansible.',
        );
        return;
      }
      if (isSeq(node)) {
        for (const item of node.items) walk(item as Node, depth + 1);
        return;
      }
      if (!isMap(node)) return;
      const line = lines.linePos(node.range?.[0] ?? 0).line;
      for (const pair of node.items) {
        const key = isScalar(pair.key) ? String(pair.key.value) : '';
        if (
          [
            'shell',
            'ansible.builtin.shell',
            'command',
            'ansible.builtin.command',
            'raw',
            'ansible.builtin.raw',
          ].includes(key)
        )
          add(file, line, 'warning', 'command', 'Review command execution and check-mode behavior.');
        if (key === 'delegate_to' || key === 'local_action')
          add(
            file,
            line,
            'warning',
            'delegation',
            'Delegation can execute on another host or the controller. Review its scope.',
          );
        if (
          key === 'become' &&
          isScalar(pair.value) &&
          [true, 'yes', 'true'].includes(pair.value.value as boolean | string)
        )
          add(file, line, 'warning', 'privilege', 'Review privilege escalation on the selected targets.');
        if (
          [
            'shell',
            'command',
            'raw',
            'copy',
            'template',
            'file',
            'service',
            'apt',
            'dnf',
            'yum',
            'user',
            'group',
            'set_fact',
            'debug',
            'assert',
            'ping',
            'include_tasks',
            'import_tasks',
          ].includes(key)
        )
          add(file, line, 'warning', 'fqcn', 'Use a fully qualified module name to make its source clear.');
        walk(pair.value as Node, depth + 1);
      }
    };
    walk(doc.contents as Node, 0);
  }
  for (const lock of bundle.collections ?? []) {
    if (
      !/^[a-z][a-z0-9_]{0,63}$/.test(lock.namespace) ||
      !/^[a-z][a-z0-9_]{0,63}$/.test(lock.name) ||
      !/^(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})\.(0|[1-9]\d{0,4})$/.test(lock.version) ||
      !/^[a-f0-9]{64}$/.test(lock.sha256)
    )
      add(
        'collections',
        1,
        'error',
        'collection-lock',
        'Each collection needs a namespace, name, exact version and SHA-256 archive checksum.',
      );
  }
  return issues;
}
