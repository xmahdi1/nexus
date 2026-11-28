import { parseAllDocuments, isMap } from 'yaml';
export type YamlProfile = 'yaml' | 'compose' | 'github' | 'kubernetes';
export const profiles: Record<YamlProfile, string> = {
  yaml: 'General YAML',
  compose: 'Docker Compose',
  github: 'GitHub Actions',
  kubernetes: 'Kubernetes',
};
export interface YamlIssue {
  from: number;
  to: number;
  severity: 'error' | 'warning';
  message: string;
}
export function yamlIssues(text: string): YamlIssue[] {
  if (new TextEncoder().encode(text).length > 262144)
    return [
      {
        from: 0,
        to: Math.min(text.length, 1),
        severity: 'error',
        message: 'Editor limit: 256 KiB. Use a smaller file.',
      },
    ];
  try {
    const docs = parseAllDocuments(text, {
      prettyErrors: false,
      uniqueKeys: true,
    });
    // Keep errors ahead of warnings so the display cap never hides a syntax
    // error in a later document behind warnings from an earlier document.
    return [
      ...docs.flatMap((doc) =>
        doc.errors.map((error) => ({
          from: error.pos[0],
          to: error.pos[1],
          severity: 'error' as const,
          message: error.message,
        })),
      ),
      ...docs.flatMap((doc) =>
        doc.warnings.map((warning) => ({
          from: warning.pos[0],
          to: warning.pos[1],
          severity: 'warning' as const,
          message: warning.message,
        })),
      ),
    ].slice(0, 50);
  } catch {
    return [
      {
        from: 0,
        to: Math.min(text.length, 1),
        severity: 'error',
        message: 'YAML could not be parsed.',
      },
    ];
  }
}
export function detectYamlProfile(path: string, text: string): YamlProfile {
  if (/(?:^|\/)\.github\/workflows\//.test(path)) return 'github';
  if (/(?:^|\/)(?:docker-)?compose(?:\.[^/]*)?\.ya?ml$/i.test(path) || /^services:\s*$/m.test(text))
    return 'compose';
  if (/^apiVersion:\s*\S+/m.test(text) && /^kind:\s*\S+/m.test(text)) return 'kubernetes';
  if (/^jobs:\s*$/m.test(text) && /^on:/m.test(text)) return 'github';
  return 'yaml';
}
export function isComposeDocument(text: string): boolean {
  try {
    const docs = parseAllDocuments(text, { prettyErrors: false });
    return (
      docs.length === 1 &&
      docs[0]!.errors.length === 0 &&
      isMap(docs[0]!.contents) &&
      isMap(docs[0]!.get('services', true))
    );
  } catch {
    return false;
  }
}
const fields = {
  compose: {
    root: ['name', 'services', 'networks', 'volumes', 'secrets', 'configs', 'include'],
    service: [
      'image',
      'build',
      'ports',
      'environment',
      'env_file',
      'volumes',
      'depends_on',
      'healthcheck',
      'restart',
      'networks',
      'profiles',
      'user',
      'read_only',
      'cap_drop',
      'security_opt',
      'deploy',
      'command',
      'entrypoint',
      'labels',
      'working_dir',
      'secrets',
      'configs',
      'logging',
      'stop_grace_period',
    ],
    build: ['context', 'dockerfile', 'args', 'target', 'cache_from', 'cache_to', 'ssh', 'secrets'],
    healthcheck: ['test', 'interval', 'timeout', 'retries', 'start_period', 'start_interval'],
  },
  github: {
    root: ['name', 'run-name', 'on', 'permissions', 'concurrency', 'env', 'defaults', 'jobs'],
    job: [
      'name',
      'runs-on',
      'needs',
      'if',
      'permissions',
      'strategy',
      'steps',
      'env',
      'environment',
      'timeout-minutes',
      'concurrency',
      'container',
      'services',
      'defaults',
      'outputs',
      'uses',
      'with',
      'secrets',
    ],
    step: [
      'name',
      'id',
      'uses',
      'run',
      'with',
      'env',
      'if',
      'shell',
      'working-directory',
      'timeout-minutes',
      'continue-on-error',
    ],
    strategy: ['matrix', 'fail-fast', 'max-parallel'],
    permissions: [
      'actions',
      'contents',
      'deployments',
      'id-token',
      'issues',
      'packages',
      'pull-requests',
      'security-events',
      'statuses',
      'checks',
      'attestations',
    ],
  },
  kubernetes: {
    root: ['apiVersion', 'kind', 'metadata', 'spec', 'data', 'stringData', 'type', 'immutable'],
    metadata: ['name', 'namespace', 'labels', 'annotations', 'generateName', 'finalizers', 'ownerReferences'],
    spec: [
      'replicas',
      'selector',
      'template',
      'containers',
      'initContainers',
      'volumes',
      'serviceAccountName',
      'securityContext',
      'restartPolicy',
      'ports',
      'type',
      'rules',
      'tls',
      'schedule',
      'jobTemplate',
      'backoffLimit',
      'completions',
      'parallelism',
    ],
    container: [
      'name',
      'image',
      'imagePullPolicy',
      'ports',
      'env',
      'envFrom',
      'resources',
      'volumeMounts',
      'command',
      'args',
      'workingDir',
      'securityContext',
      'livenessProbe',
      'readinessProbe',
      'startupProbe',
    ],
    resources: ['requests', 'limits'],
    probe: [
      'httpGet',
      'tcpSocket',
      'exec',
      'initialDelaySeconds',
      'periodSeconds',
      'timeoutSeconds',
      'failureThreshold',
      'successThreshold',
    ],
  },
};
// Block-style context suggestions complement YAML parsing. They are curated
// editing assistance, not full provider-schema certification or execution.
export function yamlKeys(profile: YamlProfile, before: string): string[] {
  const lines = before.split('\n'),
    current = lines.pop() ?? '',
    indent = current.match(/^\s*/)?.[0].length ?? 0;
  const stack: Array<{ indent: number; key: string }> = [];
  for (const line of lines) {
    const m = line.match(/^(\s*)(?:-\s+)?([A-Za-z_][\w-]*):(?:\s*#.*)?\s*$/);
    if (!m) continue;
    const depth = m[1]!.length;
    while (stack.length && stack.at(-1)!.indent >= depth) stack.pop();
    stack.push({ indent: depth, key: m[2]! });
  }
  while (stack.length && stack.at(-1)!.indent >= indent) stack.pop();
  const ancestors = stack.map((row) => row.key),
    last = ancestors.at(-1);
  if (last && ['env', 'environment', 'with', 'labels', 'annotations', 'data', 'stringData'].includes(last))
    return [];
  if (profile === 'compose') {
    if (!ancestors.length) return fields.compose.root;
    if (last === 'build') return fields.compose.build;
    if (last === 'healthcheck') return fields.compose.healthcheck;
    if (ancestors[0] === 'services' && ancestors.length >= 2) return fields.compose.service;
    if (last === 'services') return ['web', 'api', 'database'];
    return [];
  }
  if (profile === 'github') {
    if (!ancestors.length) return fields.github.root;
    if (last === 'permissions') return fields.github.permissions;
    if (last === 'strategy') return fields.github.strategy;
    if (ancestors.includes('steps')) return fields.github.step;
    if (ancestors[0] === 'jobs' && ancestors.length >= 2) return fields.github.job;
    if (last === 'jobs') return ['build', 'test', 'deploy'];
    if (last === 'on') return ['push', 'pull_request', 'workflow_dispatch', 'schedule'];
    return [];
  }
  if (profile === 'kubernetes') {
    if (!ancestors.length) return fields.kubernetes.root;
    if (last === 'metadata') return fields.kubernetes.metadata;
    if (ancestors.includes('containers') || ancestors.includes('initContainers')) {
      if (last === 'resources') return fields.kubernetes.resources;
      if (last?.endsWith('Probe')) return fields.kubernetes.probe;
      return fields.kubernetes.container;
    }
    if (last === 'spec') return fields.kubernetes.spec;
    return [];
  }
  return [];
}
export function yamlValues(profile: YamlProfile, line: string): string[] {
  const key = line.match(/([A-Za-z][\w-]*):\s*[^:]*$/)?.[1];
  if (profile === 'compose' && key === 'restart') return ['no', 'always', 'on-failure', 'unless-stopped'];
  if (profile === 'github' && key === 'runs-on')
    return ['ubuntu-latest', 'windows-latest', 'macos-latest', 'self-hosted'];
  if (profile === 'github' && key === 'shell') return ['bash', 'pwsh', 'sh', 'python'];
  if (profile === 'kubernetes' && key === 'apiVersion')
    return ['v1', 'apps/v1', 'batch/v1', 'networking.k8s.io/v1', 'rbac.authorization.k8s.io/v1'];
  if (profile === 'kubernetes' && key === 'kind')
    return [
      'Deployment',
      'Service',
      'ConfigMap',
      'Secret',
      'Ingress',
      'StatefulSet',
      'DaemonSet',
      'Job',
      'CronJob',
      'Namespace',
      'ServiceAccount',
      'Role',
      'RoleBinding',
      'PersistentVolumeClaim',
    ];
  if (profile === 'kubernetes' && key === 'restartPolicy') return ['Always', 'OnFailure', 'Never'];
  if (profile === 'kubernetes' && key === 'imagePullPolicy') return ['Always', 'IfNotPresent', 'Never'];
  return [];
}
