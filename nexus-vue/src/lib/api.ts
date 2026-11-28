export interface GitHubOrganization {
  id: string;
  serverId: string;
  login: string;
  organizationId: number;
  clientId: string;
  installationId: number;
  disabled: boolean;
  createdAt: string;
}
export interface GitHubOrganizationChange {
  id: string;
  connectionId: string;
  kind: 'registration' | 'runner_remove';
  state: string;
  resourceId: number;
  expiresAt: string | null;
  createdAt: string;
}
export interface GitHubOrganizationResult {
  change: GitHubOrganizationChange;
  credential: { token: string; expiresAt: string } | null;
  automaticRetryAllowed: false;
}
export interface GitHubWebhookInfo {
  configured: boolean;
  disabled: boolean;
  path: string;
  createdAt: string;
}
export interface GitHubRunObservation {
  connectionId: string;
  runId: number;
  runAttempt: number;
  workflowId: number;
  status: string;
  conclusion: string;
  headSha: string;
  sourceUpdatedAt: string;
  receivedAt: string;
}
export interface GitHubProviderRunner {
  id: number;
  name: string;
  os: string;
  status: 'online' | 'offline';
  busy: boolean;
  ephemeral: boolean;
  version: string;
  labels: Array<{ name: string; type: string }>;
}
export interface GitHubChange {
  id: string;
  connectionId: string;
  kind: 'runner_remove' | 'workflow_edit';
  state: string;
  phase: string;
  resourceId: number;
  branch: string;
  commitSha: string;
  pullNumber: number;
  createdAt: string;
}
export interface GitHubWorkflowFile {
  baseBranch: string;
  baseSha: string;
  blobSha: string;
  path: string;
  content: string;
}
export interface GitHubWorkflowEdit extends GitHubWorkflowFile {
  title: string;
  requestId: string;
}
export interface GitHubConnection {
  id: string;
  serverId: string;
  owner: string;
  name: string;
  repositoryId: number;
  clientId: string;
  installationId: number;
  disabled: boolean;
  createdAt: string;
}
export interface GitHubWorkflow {
  id: number;
  name: string;
  path: string;
  state: string;
}
export interface GitHubSubmission {
  id: string;
  connectionId: string;
  state: string;
  workflowId: number;
  ref: string;
  runId: number;
  createdAt: string;
}
export interface GitHubCancellation {
  id: string;
  connectionId: string;
  runId: number;
  runAttempt: number;
  state: string;
  createdAt: string;
}
export interface GitHubArtifact {
  id: number;
  name: string;
  size_in_bytes: number;
  expired: boolean;
  workflow_run: { id: number; repository_id: number };
}
export interface GitHubRun {
  run_attempt: number;
  id: number;
  workflow_id: number;
  status: string;
  conclusion: string | null;
  head_sha: string;
  head_branch: string;
  event: string;
}
export interface GitHubJob {
  id: number;
  run_id: number;
  name: string;
  status: string;
  conclusion: string | null;
}
export type BackupSourceKind =
  | 'nexus'
  | 'files'
  | 'sqlite'
  | 'docker-volume'
  | 'docker-bind'
  | 'postgres'
  | 'mysql'
  | 'mariadb'
  | 'mongodb';
export interface BackupDatabase {
  host?: string;
  port?: number;
  name?: string;
  user?: string;
  password?: string;
  containerEnvironment?: boolean;
}
export interface BackupSource {
  kind: BackupSourceKind;
  label: string;
  path?: string;
  containerId?: string;
  volume?: string;
  database?: BackupDatabase;
}
export interface BackupRepository {
  kind: 'local' | 's3';
  location: string;
  password: string;
  accessKey?: string;
  secretKey?: string;
  region?: string;
  sessionToken?: string;
  bucketLookup?: 'auto' | 'path' | 'dns';
}
export interface BackupTiming {
  mode: 'manual' | 'once' | 'interval';
  at?: string;
  intervalMinutes?: number;
}
export interface BackupDefinition {
  name: string;
  repository: BackupRepository;
  sources: BackupSource[];
  timing: BackupTiming;
  runtimeSeconds: number;
  exportLimitGiB: number;
  allowLiveFiles: boolean;
}
export interface BackupCandidate {
  id: string;
  source: BackupSource;
  consistency: string;
  state: string;
  note: string;
}
export interface BackupDiscovery {
  sources: BackupCandidate[];
  tools: Record<string, boolean>;
  truncated: boolean;
}
export interface BackupPolicy {
  id: string;
  serverId: string;
  name: string;
  actorId: string;
  mode: string;
  intervalMinutes: number;
  nextAt?: string;
  enabled: boolean;
  archived: boolean;
  lastRunId?: string;
  lastState: string;
  lastSuccessAt?: string;
  lastCheckAt?: string;
  lastRestoreAt?: string;
  createdAt: string;
  sourceKinds: string[];
  repositoryKind: string;
  repository: { kind: string; location: string; region?: string };
  sources: Array<Pick<BackupSource, 'kind' | 'label' | 'path' | 'containerId' | 'volume'>>;
}
export interface BackupRun extends SupervisedRun {
  action: string;
  policyId: string;
  stagingClean: boolean;
}
export interface BackupRetention {
  keepLast: number;
  inventoryDigest: string;
  removeIds: string[];
  keptCount: number;
  unclassifiedCount: number;
}
export interface BackupSettings {
  policyId?: string;
  keepLast: number;
  maxAgeMinutes: number;
  verifyAfterDays: number;
}
export interface BackupCoverage {
  scannedAt: string;
  truncated: boolean;
  watchGaps: boolean;
  items: Array<{
    candidate: BackupCandidate;
    state: string;
    policyIds: string[];
    lastSuccessAt?: string;
  }>;
}
export interface BackupHealth {
  observedAt: string;
  policies: Array<{
    policyId: string;
    name: string;
    state: string;
    settings: BackupSettings;
    issues: Array<{ code: string; severity: string }>;
    lastSuccessAt?: string;
    lastRestoreAt?: string;
  }>;
  alerts: Array<{
    id: string;
    policyId: string;
    code: string;
    severity: string;
    state: string;
    firstSeenAt: string;
    lastSeenAt: string;
    resolvedAt?: string;
  }>;
  coverage?: BackupCoverage;
}
export interface BackupResult {
  state: string;
  phase?: string;
  snapshotId?: string;
  files?: number;
  bytes?: number;
  snapshots?: Array<{ id: string; time: string }>;
  restorePath?: string;
  verified: boolean;
  retention?: BackupRetention;
}
export interface BackupObservation extends RunObservation {
  run: BackupRun;
  result?: BackupResult | null;
}
export type BackupAction = 'install' | 'init' | 'backup' | 'snapshots' | 'check' | 'restore' | 'verify';
export interface AnsibleProject {
  id: string;
  serverId: string;
  name: string;
  createdBy: string;
  createdAt: string;
  archived: boolean;
}
export interface AnsibleRevision {
  sourceConnectionId?: string;
  sourceRepositoryId?: number;
  sourceCommitSha?: string;
  id: string;
  projectId: string;
  serverId: string;
  digest: string;
  createdBy: string;
  createdAt: string;
}
export interface AnsibleVariable {
  name: string;
  kind: 'string' | 'integer' | 'boolean' | 'choice' | 'vault';
  required: boolean;
  choices?: string[];
}
export interface AnsibleCollectionLock {
  namespace: string;
  name: string;
  version: string;
  sha256: string;
}
export interface AnsibleProjectTemplate {
  id: string;
  serverId: string;
  name: string;
  digest: string;
  archived: boolean;
  createdAt: string;
}
export interface AnsibleBundle {
  collections?: AnsibleCollectionLock[];
  main: string;
  files: Record<string, string>;
  variables: AnsibleVariable[];
}
export interface AnsibleVaultReference {
  serverId: string;
  mount: string;
  path: string;
  field: string;
  version: number;
}
export interface AnsiblePlanOptions {
  mode: 'syntax' | 'check' | 'apply';
  tags: string[];
  skipTags: string[];
  verbosity: number;
  timeoutSeconds: number;
  vaultPassword?: AnsibleVaultReference;
}
export interface AnsiblePlan {
  presetId?: string;
  id: string;
  projectId: string;
  revisionId: string;
  serverId: string;
  actorId: string;
  digest: string;
  state: string;
  approvedBy?: string;
  createdAt: string;
  expiresAt: string;
  approvedAt?: string;
}
export interface AnsiblePlanView extends AnsiblePlan {
  groupId: string;
  revisionDigest: string;
  targets: Array<{ serverId: string; host: string; user: string; port: number }>;
  variableNames: string[];
  variables?: Record<string, unknown>;
  options: AnsiblePlanOptions;
}
export interface RunnerProfile {
  url: string;
  name: string;
  labels: string[];
  group: string;
  lifetimeSeconds: number;
}
export interface AnsibleQueueEntry {
  id: string;
  serverId: string;
  planId: string;
  actorId: string;
  state: 'waiting' | 'admitted' | 'cancelled' | 'blocked' | 'expired';
  detail: string;
  afterRunId?: string;
  notBefore: string;
  expiresAt: string;
  createdAt: string;
  admittedAt?: string;
}
export interface AnsibleSchedule {
  id: string;
  serverId: string;
  name: string;
  presetId: string;
  actorId: string;
  intervalMinutes: number;
  nextAt: string;
  enabled: boolean;
  pendingPlanId?: string;
  lastState: string;
  createdAt: string;
}
export interface AnsiblePreset {
  id: string;
  serverId: string;
  name: string;
  digest: string;
  createdBy: string;
  createdAt: string;
  archived: boolean;
}
export interface AnsiblePresetSelection {
  name: string;
  projectId: string;
  revisionId: string;
  revisionDigest: string;
  groupId: string;
  serverIds: string[];
  options: AnsiblePlanOptions;
}
export interface AnsibleTaskResult {
  task: number;
  serverId: string;
  status: 'ok' | 'changed' | 'failed' | 'ignored' | 'unreachable' | 'skipped';
  startedMs: number;
  durationMs: number;
}
export interface AnsibleExecutionResult {
  stage?: string;
  state: string;
  exitCode: number;
  version: string;
  hosts: Record<string, Record<string, number>>;
  tasks: AnsibleTaskResult[];
  tasksTruncated: boolean;
}
export interface AnsibleRunObservation extends RunObservation {
  result?: AnsibleExecutionResult | null;
}
export interface AnsibleInventoryToken {
  id: string;
  groupId: string;
  createdAt: string;
  expiresAt: string;
}
export interface AnsibleInventoryPreview {
  revision: string;
  groups: Record<string, string>;
  inventory: {
    _meta: {
      hostvars: Record<
        string,
        { ansible_host: string; ansible_port: number; ansible_user: string; nexus_server_id: string }
      >;
    };
  };
}
export interface InventoryRelationship {
  id: string;
  serverId: string;
  sourceId: string;
  targetId: string;
  sourceName: string;
  targetName: string;
  kind: string;
  source: string;
  dataState: string;
  firstSeenAt: string;
  lastVerifiedAt: string;
}
export interface InventoryChange {
  id: number;
  serverId: string;
  runId: string;
  resourceId: string;
  kind: string;
  at: string;
  before?: { name: string; details: unknown };
  after?: { name: string; details: unknown };
}
export interface InventoryPolicyInput {
  enabled: boolean;
  intervalMinutes: number;
  freshnessMinutes: number;
  retentionDays: number;
  revision: number;
}
export interface InventoryPolicy extends InventoryPolicyInput {
  actorId: string;
  nextRunAt: string;
  failureCount: number;
  lastStatus: string;
  updatedAt: string;
}
export interface InventorySourceResult {
  runId: string;
  source: string;
  status: string;
  collectedAt: string;
}
export interface InventoryDocumentNotes {
  notes: string;
  revision: number;
}
export interface InventoryDocument {
  serverName: string;
  manual: InventoryDocumentNotes;
  resources: Array<{
    id: string;
    kind: string;
    displayName: string;
    source: string;
    dataState: string;
    lastVerifiedAt: string;
    details: unknown;
  }>;
  limited: boolean;
  collectionStatus?: string;
  collectionWarning?: string;
  markdown: string;
}
export interface AccountUser {
  id: string;
  username: string;
  displayName: string;
  email: string | null;
  status: string;
  admitted: boolean;
  mfaEnabled: boolean;
  recoveryRequired: boolean;
  createdAt: string;
  lastLoginAt: string | null;
}
export interface RecoveryResult {
  ok: boolean;
  recoveryCodes: string[];
}
export interface MFAEnrollment {
  secret: string;
  uri: string;
  setupToken: string;
}
export interface InviteInput {
  username: string;
  displayName: string;
  email: string;
  roleId: string;
  scopeType: string;
  scopeId: string;
  expiresHours: number;
  currentPassword: string;
}
export interface DeviceSession {
  id: string;
  createdAt: string;
  lastUsedAt: string;
  expiresAt: string;
  deviceLabel: string;
  clientIP: string;
}

export interface OperationInspection {
  id: string;
  state: string;
  action: string;
  actorId: string;
  serverId: string;
  resourceType: string;
  resourceId: string;
  startedAt: string;
  completedAt: string | null;
  remoteStateVerified: boolean;
  automaticRetryAllowed: boolean;
  guidance: string;
}

export interface VaultProfile {
  serverId?: string;
  port: number;
  tlsName: string;
  caPem: string;
  namespace: string;
}
export interface VaultConnection {
  configured: boolean;
  profile?: VaultProfile;
}
export interface VaultAccessInput {
  token: string;
  name?: string;
  paths?: string[];
}
export interface VaultAdminField {
  key: string;
  label: string;
  kind: string;
  required: boolean;
  choices?: string[];
}
export interface VaultAdminOperation {
  id: string;
  group: string;
  label: string;
  notice: string;
  fields: VaultAdminField[];
  permissions: string[];
  mutation: boolean;
  sensitive: boolean;
}
export interface VaultAdminResult {
  dataJson: string;
  revision?: string;
  redacted?: boolean;
  automaticRetryAllowed: false;
}
export interface VaultAccessResult {
  methods?: { path: string; type: string; description: string; defaultTTL?: number; maxTTL?: number }[];
  policies?: string[];
  name?: string;
  policy?: string;
  redacted?: boolean;
  capabilities?: Record<string, string[]>;
}
export interface VaultKVInput {
  token: string;
  mount: string;
  path: string;
  version?: number;
  dataJson?: string;
}
export interface VaultKVResult {
  keys?: string[];
  metadata?: { version: number };
  dataJson?: string;
  automaticRetryAllowed: false;
}
export interface VaultObservation {
  health: { initialized: boolean; sealed: boolean; standby: boolean; status: number };
  mounts: { path: string; type: string; description: string; version: string }[];
  mountsStatus: string;
}

const BASE = '/api';

export interface ApiError {
  error: string;
  code: string;
}

export interface GeneratedKey {
  publicKey: string;
  privateKey: string;
}

export interface ConnectionTestResult {
  ok: boolean;
  latencyMs: number;
  error?: string;
}

export interface Server {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  publicKey: string;
  fingerprint: string;
  tags: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateServerInput {
  name: string;
  host: string;
  port: number;
  username: string;
  publicKey: string;
  privateKey: string;
}

export interface Process {
  pid: number;
  name: string;
  cpu: number;
  memory: number;
}

export interface Metrics {
  cpu: number;
  memTotal: number;
  memUsed: number;
  swapTotal: number;
  swapUsed: number;
  diskTotal: number;
  diskUsed: number;
  load1: number;
  load5: number;
  load15: number;
  netRxRate: number;
  netTxRate: number;
  uptime: string;
  os: string;
  kernel: string;
  processes: Process[];
}

export interface Container {
  id: string;
  name: string;
  image: string;
  status: 'running' | 'exited' | 'paused';
  state: string;
  ports: string;
  cpu: number;
  mem: string;
}

export interface FileEntry {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
  modTime: string;
  mode: string;
}

export interface ProxyRule {
  id: string;
  serverId: string;
  domain: string;
  target: string;
  proxyType: 'nginx' | 'caddy';
  sslEnabled: boolean;
  createdAt: string;
}

export interface Service {
  id: string;
  name: string;
  url: string;
  icon: string;
  description: string;
  category: string;
  color: string;
  sortOrder: number;
  createdAt: string;
}

export interface ServerStatus {
  serverId: string;
  name: string;
  host: string;
  tags: string;
  online: boolean;
  latencyMs: number;
  checkedAt: string;
  lastOnline: string;
}

export interface AlertConfig {
  id: string;
  telegramEnabled: boolean;
  telegramToken: string;
  telegramChatId: string;
  notifyServerDown: boolean;
  notifyServerUp: boolean;
  notifyContainer: boolean;
}

export interface ServerAlertConfig {
  id: string;
  cpuEnabled: boolean;
  cpuThreshold: number;
  ramEnabled: boolean;
  ramThreshold: number;
  diskEnabled: boolean;
  diskThreshold: number;
  sslEnabled: boolean;
  sslDaysBefore: number;
  updatedAt: string;
}

export interface TemplateVar {
  storedDefault?: boolean;
  name: string;
  label: string;
  description: string;
  default: string;
  required: boolean;
  type: 'string' | 'password' | 'number' | 'select';
  options?: string[];
}

export interface AppTemplate {
  setupKind?: string;
  id: string;
  name: string;
  description: string;
  icon: string;
  iconLight?: string;
  category: string;
  docUrl?: string;
  postDeploy?: string;
  vars: TemplateVar[];
  builtIn: boolean;
  compose?: string;
}

export interface DeployedApp {
  id: string;
  serverId: string;
  templateId: string;
  name: string;
  composePath: string;
  status: string;
  deployedAt: string;
}

export interface LoginEvent {
  id: number;
  ip: string;
  success: boolean;
  reason: string;
  createdAt: string;
}

export interface CronJob {
  index: number;
  schedule: string;
  command: string;
  raw: string;
}

export interface FirewallRule {
  number: number;
  to: string;
  action: string;
  from: string;
}

export interface OpenPort {
  protocol: string;
  port: string;
  address: string;
  process: string;
  cmdline?: string;
}

export interface FirewallStatus {
  status: string;
  available: boolean;
  rules: FirewallRule[];
  ports: OpenPort[];
}

export interface ScheduledTask {
  supervised: boolean;
  actorId: string;
  createdBy: string;
  id: string;
  serverId: string;
  name: string;
  command: string;
  intervalMinutes: number;
  enabled: boolean;
  lastRunAt: string | null;
  nextRunAt: string | null;
  lastOutput: string;
  lastStatus: string;
  createdAt: string;
}

export interface SupervisedRun {
  id: string;
  taskId: string;
  serverId: string;
  actorId: string;
  state: string;
  exitCode: number | null;
  truncated: boolean;
  artifactsRemoved: boolean;
  detail: string;
  createdAt: string;
  dispatchStartedAt: string | null;
  cancelRequestedAt: string | null;
  verifiedAt: string | null;
  finishedAt: string | null;
}
export interface AnsibleRun extends SupervisedRun {
  planId: string;
}
export interface RunObservation {
  run: SupervisedRun;
  observation: {
    state: string;
    verified: boolean;
    empty: boolean;
    exitCode: number | null;
    output: string;
    truncated: boolean;
    released: boolean;
    detail: string;
    noDispatch: boolean;
  };
  automaticRetryAllowed: false;
}
export type AnsibleEnvironmentAction =
  | 'ansible-environment-install'
  | 'ansible-environment-update'
  | 'ansible-environment-health'
  | 'ansible-environment-remove';
export type ServerOperation =
  | 'github-runner'
  | AnsibleEnvironmentAction
  | 'compose-up'
  | 'compose-down'
  | 'container-start'
  | 'container-stop'
  | 'container-restart'
  | 'container-remove';
export interface InteractiveRun extends SupervisedRun {
  kind: 'operation';
  action: ServerOperation;
  targetId: string;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      signal: AbortSignal.timeout(60_000),
      credentials: 'include',
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (error) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method))
      throw Object.assign(
        new Error(
          'Request interrupted; the remote outcome may be uncertain. Inspect the target before retrying.',
        ),
        { code: 'remote_outcome_unknown', cause: error },
      );
    throw error;
  }
  try {
    return await decodeResponse<T>(res, path);
  } catch (error) {
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && !(error as { status?: number })?.status) {
      throw responseError(res, {
        error:
          'Response interrupted; the remote outcome may be uncertain. Inspect the target before retrying.',
        code: 'remote_outcome_unknown',
      });
    }
    throw error;
  }
}

async function downloadFile(path: string, method: 'GET' | 'POST' = 'GET'): Promise<Blob> {
  const response = await fetch(`${BASE}${path}`, {
    credentials: 'include',
    method,
    cache: 'no-store',
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok || (response.headers.get('content-type') ?? '').includes('text/html'))
    return decodeResponse<never>(response, path);
  const max = 64 * 1024 * 1024;
  if (Number(response.headers.get('content-length')) > max)
    throw new Error('Browser downloads are limited to 64 MiB.');
  const reader = response.body?.getReader();
  if (!reader) return new Blob([]);
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) {
        await reader.cancel();
        throw new Error('Browser downloads are limited to 64 MiB.');
      }
      chunks.push(new Uint8Array(value));
    }
  } finally {
    reader.releaseLock();
  }
  return new Blob(chunks, { type: 'application/octet-stream' });
}

async function decodeResponse<T>(res: Response, path: string): Promise<T> {
  if ((res.headers.get('content-type') ?? '').includes('text/html')) {
    window.dispatchEvent(new CustomEvent('nexus:connection-lost'));
    throw Object.assign(
      new Error('The access proxy returned an HTML page. Refresh the page and sign in to the proxy again.'),
      {
        code: 'upstream_html',
        status: res.status,
      },
    );
  }
  if (!res.ok) {
    let json: any = {};
    try {
      json = await res.json();
    } catch {
      // Non-JSON failures still use the HTTP status and safe default message.
    }
    if (
      res.status === 401 &&
      window.location.pathname !== '/login' &&
      ![
        '/auth/me',
        '/auth/permissions',
        '/auth/invitations/accept',
        '/auth/reset/info',
        '/auth/reset/password',
        '/auth/reset/mfa/setup',
        '/auth/reset/mfa/confirm',
        '/auth/mfa/recovery',
        '/auth/mfa/recovery-codes',
        '/auth/step-up',
        '/auth/login',
        '/auth/password',
        '/auth/mfa/verify',
        '/auth/mfa/setup',
        '/auth/mfa/enable',
        '/auth/mfa/disable',
      ].includes(path)
    ) {
      window.location.href = '/login';
    }
    throw responseError(res, json);
  }

  if (res.status === 204) return undefined as T;
  const data = await res.json();
  if (/^\/servers\/[^/]+\/compose\/(up|down)\?/.test(path) && data?.ok === false)
    throw responseError(res, data);
  return data as T;
}
function responseError(res: Response, data: any): Error {
  const candidate = res.headers.get('X-Operation-ID') ?? '';
  const operationId = /^[a-f0-9]{32}$/.test(candidate) ? candidate : '';
  const message =
    String(data.error ?? `HTTP ${res.status}`) +
    (operationId ? ` (operation ${operationId}; inspect audit and target state before retrying)` : '');
  return Object.assign(new Error(message), data, { message, operationId, status: res.status });
}

function backupBase(scope: string) {
  return scope ? '/servers/' + encodeURIComponent(scope) + '/backups' : '/backups/nexus';
}
export const api = {
  githubOrganizations: {
    list: (sid: string) =>
      request<GitHubOrganization[]>('GET', `/servers/${encodeURIComponent(sid)}/github/organizations`),
    create: (
      sid: string,
      input: {
        login: string;
        organizationId: number;
        clientId: string;
        installationId: number;
        privateKey: string;
      },
    ) =>
      request<GitHubOrganization>('POST', `/servers/${encodeURIComponent(sid)}/github/organizations`, input),
    disable: (sid: string, id: string) =>
      request<void>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/organizations/${encodeURIComponent(id)}/disable`,
      ),
    history: (sid: string) =>
      request<GitHubOrganizationChange[]>(
        'GET',
        `/servers/${encodeURIComponent(sid)}/github/organization-changes`,
      ),
    runners: (sid: string, id: string, page = 1) =>
      request<{ total_count: number; runners: GitHubProviderRunner[] }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/organizations/${encodeURIComponent(id)}/runners?page=${page}`,
      ),
    remove: (sid: string, id: string, requestId: string, runnerId: number, name: string) =>
      request<GitHubOrganizationResult>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/organizations/${encodeURIComponent(id)}/runners/remove`,
        { requestId, runnerId, name },
      ),
    registration: (sid: string, id: string, requestId: string) =>
      request<GitHubOrganizationResult>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/organizations/${encodeURIComponent(id)}/registration-token`,
        { requestId },
      ),
  },
  githubActions: {
    webhook: (sid: string, id: string) =>
      request<GitHubWebhookInfo>(
        'GET',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/webhook`,
      ),
    rotateWebhook: (sid: string, id: string) =>
      request<{ webhook: GitHubWebhookInfo; secret: string }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/webhook`,
      ),
    disableWebhook: (sid: string, id: string) =>
      request<void>(
        'DELETE',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/webhook`,
      ),
    webhookEvents: (sid: string, id: string) =>
      request<GitHubRunObservation[]>(
        'GET',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/events`,
      ),
    changes: (sid: string) =>
      request<GitHubChange[]>('GET', `/servers/${encodeURIComponent(sid)}/github/changes`),
    providerRunners: (sid: string, id: string, page = 1) =>
      request<{ total_count: number; runners: GitHubProviderRunner[] }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/provider-runners?page=${page}`,
      ),
    removeProviderRunner: (sid: string, id: string, requestId: string, runnerId: number, name: string) =>
      request<{ change: GitHubChange; automaticRetryAllowed: false }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/provider-runners/remove`,
        { requestId, runnerId, name },
      ),
    workflowFile: (sid: string, id: string, branch: string, path: string) =>
      request<GitHubWorkflowFile>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/workflow-file`,
        { branch, path },
      ),
    publishWorkflow: (sid: string, id: string, input: GitHubWorkflowEdit) =>
      request<{ change: GitHubChange; automaticRetryAllowed: false }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/workflow-change`,
        input,
      ),
    run: (sid: string, id: string, run: number) =>
      request<GitHubRun>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/runs/${run}`,
      ),
    artifacts: (sid: string, id: string, run: number, page = 1) =>
      request<{ total_count: number; artifacts: GitHubArtifact[] }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/runs/${run}/artifacts?page=${page}`,
      ),
    jobLog: (sid: string, id: string, run: number, job: number) =>
      request<{ content: string; redacted: false }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/runs/${run}/jobs/${job}/logs`,
      ),
    artifactDownload: (sid: string, id: string, run: number, artifact: number) =>
      downloadFile(
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/runs/${run}/artifacts/${artifact}/download`,
        'POST',
      ),
    cancellations: (sid: string) =>
      request<GitHubCancellation[]>('GET', `/servers/${encodeURIComponent(sid)}/github/cancellations`),
    cancelRun: (sid: string, id: string, run: number, requestId: string, runAttempt: number) =>
      request<{ cancellation: GitHubCancellation; automaticRetryAllowed: false }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/runs/${run}/cancel`,
        { requestId, runAttempt },
      ),
    connections: (sid: string) =>
      request<GitHubConnection[]>('GET', `/servers/${encodeURIComponent(sid)}/github/connections`),
    create: (
      sid: string,
      input: {
        owner: string;
        name: string;
        repositoryId: number;
        clientId: string;
        installationId: number;
        privateKey: string;
      },
    ) => request<GitHubConnection>('POST', `/servers/${encodeURIComponent(sid)}/github/connections`, input),
    disable: (sid: string, id: string) =>
      request<void>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/disable`,
      ),
    workflows: (sid: string, id: string, page: number) =>
      request<{ total_count: number; workflows: GitHubWorkflow[] }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/workflows?page=${page}`,
      ),
    runs: (sid: string, id: string, page: number) =>
      request<{ total_count: number; workflow_runs: GitHubRun[] }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/runs?page=${page}`,
      ),
    jobs: (sid: string, id: string, run: number, page: number) =>
      request<{ total_count: number; jobs: GitHubJob[] }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/runs/${run}/jobs?page=${page}`,
      ),
    history: (sid: string) =>
      request<GitHubSubmission[]>('GET', `/servers/${encodeURIComponent(sid)}/github/dispatches`),
    dispatch: (
      sid: string,
      id: string,
      input: { requestId: string; workflowId: number; ref: string; inputs: Record<string, string | boolean> },
    ) =>
      request<{ submission: GitHubSubmission; automaticRetryAllowed: false }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/github/connections/${encodeURIComponent(id)}/dispatch`,
        input,
      ),
  },
  backups: {
    health: (scope: string) => request<BackupHealth>('GET', backupBase(scope) + '/health'),
    coverage: (scope: string, path: string, watchGaps: boolean) =>
      request<BackupCoverage>('POST', backupBase(scope) + '/coverage', { path, watchGaps }),
    saveSettings: (scope: string, id: string, settings: BackupSettings) =>
      request<void>('PUT', backupBase(scope) + '/policies/' + encodeURIComponent(id) + '/settings', {
        keepLast: settings.keepLast,
        maxAgeMinutes: settings.maxAgeMinutes,
        verifyAfterDays: settings.verifyAfterDays,
      }),
    retention: (
      scope: string,
      id: string,
      requestId: string,
      action: 'retention-preview' | 'retention-apply',
      previewRunId = '',
    ) =>
      request<BackupRun>('POST', backupBase(scope) + '/policies/' + encodeURIComponent(id) + '/runs', {
        requestId,
        action,
        previewRunId,
      }),
    policies: (scope: string) => request<BackupPolicy[]>('GET', backupBase(scope) + '/policies'),
    create: (scope: string, requestId: string, definition: BackupDefinition) =>
      request<BackupPolicy>('POST', backupBase(scope) + '/policies', { requestId, definition }),
    discover: (scope: string, path = '') =>
      request<BackupDiscovery>('POST', backupBase(scope) + '/discover', { path }),
    schedule: (scope: string, id: string, enabled: boolean) =>
      request<void>('POST', backupBase(scope) + '/policies/' + encodeURIComponent(id) + '/schedule', {
        enabled,
      }),
    archive: (scope: string, id: string) =>
      request<void>('POST', backupBase(scope) + '/policies/' + encodeURIComponent(id) + '/archive'),
    start: (scope: string, id: string, requestId: string, action: BackupAction, snapshotId = '') =>
      request<BackupRun>('POST', backupBase(scope) + '/policies/' + encodeURIComponent(id) + '/runs', {
        requestId,
        action,
        snapshotId,
      }),
    runs: (scope: string) => request<BackupRun[]>('GET', backupBase(scope) + '/runs'),
    inspect: (scope: string, id: string) =>
      request<BackupObservation>('POST', backupBase(scope) + '/runs/' + encodeURIComponent(id) + '/inspect'),
    cancel: (scope: string, id: string) =>
      request<BackupObservation>('POST', backupBase(scope) + '/runs/' + encodeURIComponent(id) + '/cancel'),
    cleanup: (scope: string, id: string) =>
      request<BackupObservation>('POST', backupBase(scope) + '/runs/' + encodeURIComponent(id) + '/cleanup'),
  },
  playbooks: {
    queue: (sid: string) =>
      request<AnsibleQueueEntry[]>('GET', `/servers/${encodeURIComponent(sid)}/ansible/queue`),
    enqueue: (
      sid: string,
      pid: string,
      input: { requestId: string; afterRunId?: string; notBefore?: string },
    ) =>
      request<AnsibleQueueEntry>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/plans/${encodeURIComponent(pid)}/queue`,
        input,
      ),
    cancelQueue: (sid: string, id: string) =>
      request<void>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/queue/${encodeURIComponent(id)}/cancel`,
      ),
    schedules: (sid: string) =>
      request<AnsibleSchedule[]>('GET', `/servers/${encodeURIComponent(sid)}/ansible/schedules`),
    createSchedule: (
      sid: string,
      input: { name: string; planId: string; intervalMinutes: number; firstAt?: string },
    ) => request<AnsibleSchedule>('POST', `/servers/${encodeURIComponent(sid)}/ansible/schedules`, input),
    setSchedule: (sid: string, id: string, enabled: boolean) =>
      request<void>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/schedules/${encodeURIComponent(id)}`,
        { enabled },
      ),
    presets: (sid: string) =>
      request<AnsiblePreset[]>('GET', `/servers/${encodeURIComponent(sid)}/ansible/presets`),
    createPreset: (sid: string, name: string, planId: string) =>
      request<AnsiblePreset>('POST', `/servers/${encodeURIComponent(sid)}/ansible/presets`, { name, planId }),
    presetContent: (sid: string, id: string) =>
      request<AnsiblePresetSelection>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/presets/${encodeURIComponent(id)}/content`,
      ),
    archivePreset: (sid: string, id: string) =>
      request<void>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/presets/${encodeURIComponent(id)}/archive`,
      ),
    preparePreset: (
      sid: string,
      id: string,
      variables: Record<string, unknown>,
      vaultPassword?: AnsibleVaultReference,
    ) =>
      request<AnsiblePlanView>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/presets/${encodeURIComponent(id)}/prepare`,
        { variables, ...(vaultPassword ? { vaultPassword } : {}) },
      ),
    templates: (sid: string) =>
      request<AnsibleProjectTemplate[]>('GET', `/servers/${encodeURIComponent(sid)}/ansible/templates`),
    createTemplate: (sid: string, name: string, bundle: AnsibleBundle) =>
      request<AnsibleProjectTemplate>('POST', `/servers/${encodeURIComponent(sid)}/ansible/templates`, {
        name,
        bundle,
      }),
    templateContent: (sid: string, id: string) =>
      request<AnsibleBundle>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/templates/${encodeURIComponent(id)}/content`,
      ),
    archiveTemplate: (sid: string, id: string) =>
      request<void>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/templates/${encodeURIComponent(id)}/archive`,
      ),
    importRevision: (
      sid: string,
      pid: string,
      input: {
        connectionId: string;
        commitSha: string;
        main: string;
        paths: string[];
        variables: AnsibleVariable[];
        collections: AnsibleCollectionLock[];
      },
    ) =>
      request<AnsibleRevision>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/projects/${encodeURIComponent(pid)}/revisions/import`,
        input,
      ),
    runs: (sid: string) => request<AnsibleRun[]>('GET', `/servers/${encodeURIComponent(sid)}/ansible/runs`),
    run: (sid: string, plan: string, requestId: string, vaultTokens: Record<string, string>) =>
      request<{ run: AnsibleRun; error?: string; automaticRetryAllowed: false }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/plans/${encodeURIComponent(plan)}/run`,
        { requestId, vaultTokens },
      ),
    inspectRun: (sid: string, id: string) =>
      request<AnsibleRunObservation>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/runs/${encodeURIComponent(id)}/inspect`,
      ),
    cancelRun: (sid: string, id: string) =>
      request<RunObservation>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/runs/${encodeURIComponent(id)}/cancel`,
      ),
    releaseRun: (sid: string, id: string) =>
      request<RunObservation>(
        'DELETE',
        `/servers/${encodeURIComponent(sid)}/ansible/runs/${encodeURIComponent(id)}/artifacts`,
      ),
    projects: (sid: string) =>
      request<AnsibleProject[]>('GET', `/servers/${encodeURIComponent(sid)}/ansible/projects`),
    create: (sid: string, name: string) =>
      request<AnsibleProject>('POST', `/servers/${encodeURIComponent(sid)}/ansible/projects`, { name }),
    archive: (sid: string, pid: string) =>
      request<void>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/projects/${encodeURIComponent(pid)}/archive`,
      ),
    revisions: (sid: string, pid: string) =>
      request<AnsibleRevision[]>(
        'GET',
        `/servers/${encodeURIComponent(sid)}/ansible/projects/${encodeURIComponent(pid)}/revisions`,
      ),
    publish: (sid: string, pid: string, bundle: AnsibleBundle) =>
      request<AnsibleRevision>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/projects/${encodeURIComponent(pid)}/revisions`,
        bundle,
      ),
    content: (sid: string, pid: string, rid: string) =>
      request<AnsibleBundle>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/projects/${encodeURIComponent(pid)}/revisions/${encodeURIComponent(rid)}/content`,
      ),
    plans: (sid: string) =>
      request<AnsiblePlan[]>('GET', `/servers/${encodeURIComponent(sid)}/ansible/plans`),
    prepare: (
      sid: string,
      pid: string,
      input: {
        revisionId: string;
        revisionDigest: string;
        groupId: string;
        serverIds: string[];
        variables: Record<string, unknown>;
        options: AnsiblePlanOptions;
      },
    ) =>
      request<AnsiblePlanView>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/projects/${encodeURIComponent(pid)}/plans`,
        input,
      ),
    reveal: (sid: string, id: string) =>
      request<AnsiblePlanView>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/plans/${encodeURIComponent(id)}/content`,
      ),
    approve: (sid: string, plan: AnsiblePlanView) =>
      request<AnsiblePlanView>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/plans/${encodeURIComponent(plan.id)}/approve`,
        { planDigest: plan.digest, revisionDigest: plan.revisionDigest },
      ),
    cancel: (sid: string, id: string) =>
      request<void>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/ansible/plans/${encodeURIComponent(id)}/cancel`,
      ),
  },

  runners: {
    list: (sid: string) =>
      request<Array<{ run: InteractiveRun; profile: RunnerProfile & { version: string } }>>(
        'GET',
        `/servers/${encodeURIComponent(sid)}/github/runners`,
      ),
    start: (sid: string, input: RunnerProfile & { requestId: string; registrationToken: string }) =>
      request<{ run: InteractiveRun; automaticRetryAllowed: false }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/operations/github/runner/start`,
        input,
      ),
  },
  ansible: {
    groups: () => request<Array<{ id: string; name: string }>>('GET', '/automation/ansible/groups'),
    preview: (groupId: string) =>
      request<AnsibleInventoryPreview>(
        'GET',
        `/automation/ansible/preview?groupId=${encodeURIComponent(groupId)}`,
      ),
    tokens: () => request<AnsibleInventoryToken[]>('GET', '/automation/ansible/tokens'),
    issue: (groupId: string, ttlSeconds: number) =>
      request<AnsibleInventoryToken & { token: string }>('POST', '/automation/ansible/tokens', {
        groupId,
        ttlSeconds,
      }),
    revoke: (id: string) => request<void>('DELETE', `/automation/ansible/tokens/${encodeURIComponent(id)}`),
  },
  operations: {
    start: (
      sid: string,
      action: ServerOperation,
      requestId: string,
      target: { path?: string; cid?: string },
    ) => {
      const compose = action.startsWith('compose-');
      const environment = action.startsWith('ansible-environment-');
      if (
        environment
          ? !!target.path || !!target.cid
          : compose
            ? !target.path || !!target.cid
            : !target.cid || !!target.path
      )
        throw new Error('Choose one valid operation target.');
      const suffix = environment
        ? 'ansible/environment/' + action.slice('ansible-environment-'.length)
        : compose
          ? 'compose/' + action.slice('compose-'.length)
          : 'containers/' + encodeURIComponent(target.cid!) + '/' + action.slice('container-'.length);
      return request<{ run: InteractiveRun; automaticRetryAllowed: false }>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/operations/${suffix}`,
        { requestId, ...(compose ? { path: target.path } : {}) },
      );
    },
    list: (sid: string) =>
      request<InteractiveRun[]>('GET', `/servers/${encodeURIComponent(sid)}/operations/runs`),
    read: (sid: string, id: string) =>
      request<RunObservation>(
        'GET',
        `/servers/${encodeURIComponent(sid)}/operations/runs/${encodeURIComponent(id)}`,
      ),
    inspect: (sid: string, id: string) =>
      request<RunObservation>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/operations/runs/${encodeURIComponent(id)}/inspect`,
      ),
    cancel: (sid: string, id: string) =>
      request<RunObservation>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/operations/runs/${encodeURIComponent(id)}/cancel`,
      ),
    release: (sid: string, id: string) =>
      request<RunObservation>(
        'DELETE',
        `/servers/${encodeURIComponent(sid)}/operations/runs/${encodeURIComponent(id)}/artifacts`,
      ),
  },
  vault: {
    operations: (id: string) =>
      request<{ operations: VaultAdminOperation[]; supportedEdition: string; namespaces: boolean }>(
        'GET',
        `/servers/${encodeURIComponent(id)}/vault/admin/operations`,
      ),
    admin: (
      id: string,
      action: string,
      input: { token: string; params: Record<string, unknown>; confirmation?: string },
    ) =>
      request<VaultAdminResult>(
        'POST',
        `/servers/${encodeURIComponent(id)}/vault/admin/${encodeURIComponent(action)}`,
        input,
      ),
    access: (id: string, action: 'auth' | 'policies' | 'policy' | 'capabilities', input: VaultAccessInput) =>
      request<VaultAccessResult>('POST', `/servers/${encodeURIComponent(id)}/vault/access/${action}`, input),
    kv: (id: string, action: 'list' | 'metadata' | 'read' | 'write', input: VaultKVInput) =>
      request<VaultKVResult>('POST', `/servers/${encodeURIComponent(id)}/vault/kv/${action}`, input),
    read: (id: string) => request<VaultConnection>('GET', `/servers/${encodeURIComponent(id)}/vault`),
    save: (id: string, profile: VaultProfile) =>
      request<{ ok: boolean }>('PUT', `/servers/${encodeURIComponent(id)}/vault`, profile),
    remove: (id: string) => request<void>('DELETE', `/servers/${encodeURIComponent(id)}/vault`),
    inspect: (id: string, token: string) =>
      request<VaultObservation>('POST', `/servers/${encodeURIComponent(id)}/vault/inspect`, { token }),
  },
  version: () =>
    request<{ version: string; commit?: string; built?: string; os: string; arch: string }>(
      'GET',
      '/version',
    ),
  features: () =>
    request<{
      backups: boolean;
      automation: boolean;
      inventory: boolean;
      jobSupervision: boolean;
      operationSupervision: boolean;
      vault: boolean;
    }>('GET', '/features'),
  inventory: {
    policy: (id: string) =>
      request<InventoryPolicy>('GET', `/servers/${encodeURIComponent(id)}/inventory/policy`),
    savePolicy: (id: string, input: InventoryPolicyInput) =>
      request<InventoryPolicy>('PUT', `/servers/${encodeURIComponent(id)}/inventory/policy`, input),
    read: (id: string, after = '') =>
      request<{
        items: Array<{
          id: string;
          kind: string;
          displayName: string;
          source: string;
          lastRunId: string;
          dataState: string;
          lastVerifiedAt: string;
          details: unknown;
        }>;
        runs: Array<{ id: string; status: string; warning: string; startedAt: string; trigger: string }>;
        sources: InventorySourceResult[];
        changes: unknown[];
        next: string;
      }>('GET', `/servers/${encodeURIComponent(id)}/inventory?after=${encodeURIComponent(after)}`),
    discover: (id: string) =>
      request<{ status: string; warning: string }>(
        'POST',
        `/servers/${encodeURIComponent(id)}/inventory/discover`,
        {},
      ),
    relationships: (id: string, after = '') =>
      request<{ items: InventoryRelationship[]; next: string }>(
        'GET',
        `/servers/${encodeURIComponent(id)}/inventory/relationships?after=${encodeURIComponent(after)}`,
      ),
    history: (id: string, resourceId = '', before = '') =>
      request<{ items: InventoryChange[]; next: string }>(
        'GET',
        `/servers/${encodeURIComponent(id)}/inventory/history?resourceId=${encodeURIComponent(resourceId)}&before=${encodeURIComponent(before)}`,
      ),
    document: (id: string) =>
      request<InventoryDocument>('GET', `/servers/${encodeURIComponent(id)}/inventory/documentation`),
    saveNotes: (id: string, notes: InventoryDocumentNotes) =>
      request<InventoryDocumentNotes>(
        'PUT',
        `/servers/${encodeURIComponent(id)}/inventory/documentation`,
        notes,
      ),
  },
  audit: {
    inspect: (operationId: string) =>
      request<OperationInspection>('GET', '/audit/operations/' + encodeURIComponent(operationId)),
    list: (filters: Record<string, string> = {}) =>
      request<{
        items: Array<{
          id: number;
          at: string;
          operationId: string;
          actorId: string;
          action: string;
          resourceId: string;
          outcome: string;
          httpStatus: number;
          source: string;
        }>;
        next: string;
      }>('GET', '/audit/events?' + new URLSearchParams({ ...filters, limit: '50' }).toString()),
  },
  auth: {
    stepUp: (currentPassword: string, code: string) =>
      request<{ ok: boolean }>('POST', '/auth/step-up', { currentPassword, code }),
    login: (password: string, username = '', deviceLabel = '') =>
      request<{ ok: boolean; mfaRequired: boolean; pendingToken?: string }>('POST', '/auth/login', {
        password,
        username,
        deviceLabel,
      }),
    logout: () => request<{ ok: boolean }>('POST', '/auth/logout'),
    me: () =>
      request<{
        ok: boolean;
        mode: string;
        user: { id: string; username: string; displayName: string };
        session: DeviceSession;
      }>('GET', '/auth/me'),
    sessions: () => request<DeviceSession[]>('GET', '/auth/sessions'),
    revokeSession: (id: string) => request<void>('DELETE', `/auth/sessions/${encodeURIComponent(id)}`),
    permissions: () =>
      request<{ global: Record<string, boolean>; servers: Record<string, string[]> }>(
        'GET',
        '/auth/permissions',
      ),
    logoutAll: () => request<{ ok: boolean }>('POST', '/auth/logout-all'),
    changePassword: (currentPassword: string, newPassword: string) =>
      request<{ ok: boolean }>('POST', '/auth/password', { currentPassword, newPassword }),
    auditLog: (limit?: number) =>
      request<LoginEvent[]>('GET', limit ? `/auth/audit?limit=${limit}` : '/auth/audit'),
    mfaVerify: (pendingToken: string, code: string, deviceLabel = '') =>
      request<{ ok: boolean }>('POST', '/auth/mfa/verify', { pendingToken, code, deviceLabel }),
    mfaStatus: () => request<{ enabled: boolean; recoveryCodesRemaining: number }>('GET', '/auth/mfa/status'),
    mfaSetup: (currentPassword: string) =>
      request<{ secret: string; uri: string; setupToken: string }>('POST', '/auth/mfa/setup', {
        currentPassword,
      }),
    mfaEnable: (setupToken: string, code: string) =>
      request<RecoveryResult>('POST', '/auth/mfa/enable', { setupToken, code }),
    recoveryLogin: (pendingToken: string, code: string, deviceLabel = '') =>
      request<{ ok: boolean }>('POST', '/auth/mfa/recovery', { pendingToken, code, deviceLabel }),
    regenerateRecovery: (currentPassword: string) =>
      request<RecoveryResult>('POST', '/auth/mfa/recovery-codes', { currentPassword }),
    mfaDisable: (code: string) => request<{ ok: boolean }>('POST', '/auth/mfa/disable', { code }),
  },

  accounts: {
    users: () => request<AccountUser[]>('GET', '/users'),
    invitations: () =>
      request<
        Array<{
          id: string;
          userId: string;
          expiresAt: string;
          redeemedAt: string | null;
          revokedAt: string | null;
        }>
      >('GET', '/users/invitations'),
    invite: (input: InviteInput) => request<{ token: string }>('POST', '/users/invitations', input),
    revokeInvite: (id: string, currentPassword: string) =>
      request<void>('DELETE', `/users/invitations/${encodeURIComponent(id)}`, { currentPassword }),
    status: (id: string, status: string, currentPassword: string) =>
      request('PATCH', `/users/${encodeURIComponent(id)}`, { status, currentPassword }),
    unlock: (id: string, currentPassword: string) =>
      request('POST', `/users/${encodeURIComponent(id)}/unlock`, { currentPassword }),
    requestReset: (id: string, kind: string, reason: string, currentPassword: string) =>
      request<{ token: string }>('POST', `/users/${encodeURIComponent(id)}/resets`, {
        kind,
        reason,
        currentPassword,
      }),
    accept: (token: string, password: string) =>
      request<{ ok: boolean; username: string }>('POST', '/auth/invitations/accept', { token, password }),
    resetInfo: (token: string) =>
      request<{ kind: string; username: string; mfaRequired: boolean }>('POST', '/auth/reset/info', {
        token,
      }),
    resetPassword: (token: string, password: string, code: string) =>
      request<RecoveryResult>('POST', '/auth/reset/password', { token, password, code }),
    resetMFASetup: (token: string, password: string) =>
      request<MFAEnrollment>('POST', '/auth/reset/mfa/setup', { token, password }),
    resetMFAConfirm: (setupToken: string, code: string) =>
      request<RecoveryResult>('POST', '/auth/reset/mfa/confirm', { setupToken, code }),
  },
  access: {
    roles: () => request<Array<{ id: string; name: string; permissions: string[] }>>('GET', '/roles'),
    grants: () =>
      request<
        Array<{
          id: string;
          principalId: string;
          principalKind: string;
          roleId: string;
          scopeType: string;
          scopeId: string;
          createdBy: string;
        }>
      >('GET', '/grants'),
    groups: () =>
      request<Array<{ id: string; name: string; serverIds: string[]; requireMfa: boolean }>>(
        'GET',
        '/server-groups',
      ),
    addGrant: (
      principalId: string,
      roleId: string,
      scopeType: string,
      scopeId: string,
      currentPassword: string,
    ) => request('POST', '/grants', { principalId, roleId, scopeType, scopeId, currentPassword }),
    deleteGrant: (id: string, currentPassword: string) =>
      request<void>('DELETE', `/grants/${encodeURIComponent(id)}`, { currentPassword }),
    groupPolicy: (id: string, requireMfa: boolean, currentPassword: string) =>
      request('PUT', `/server-groups/${encodeURIComponent(id)}/policy`, { requireMfa, currentPassword }),
    createGroup: (name: string, currentPassword: string) =>
      request('POST', '/server-groups', { name, currentPassword }),
    deleteGroup: (id: string, currentPassword: string) =>
      request<void>('DELETE', `/server-groups/${encodeURIComponent(id)}`, { currentPassword }),
    membership: (group: string, server: string, remove: boolean, currentPassword: string) =>
      request(
        remove ? 'DELETE' : 'PUT',
        `/server-groups/${encodeURIComponent(group)}/servers/${encodeURIComponent(server)}`,
        { currentPassword },
      ),
  },

  keys: {
    generate: () => request<GeneratedKey>('POST', '/keys/generate'),
  },

  servers: {
    list: () => request<Server[]>('GET', '/servers'),
    get: (id: string) => request<Server>('GET', `/servers/${id}`),
    create: (data: CreateServerInput) => request<Server>('POST', '/servers', data),
    delete: (id: string) => request<void>('DELETE', `/servers/${id}`),
    test: (id: string) => request<ConnectionTestResult>('POST', `/servers/${id}/test`),
    updateTags: (id: string, tags: string) => request<Server>('PATCH', `/servers/${id}/tags`, { tags }),
  },

  containers: {
    list: (sid: string) => request<Container[]>('GET', `/servers/${sid}/containers`),
    start: (sid: string, cid: string) => request<void>('POST', `/servers/${sid}/containers/${cid}/start`),
    stop: (sid: string, cid: string) => request<void>('POST', `/servers/${sid}/containers/${cid}/stop`),
    restart: (sid: string, cid: string) => request<void>('POST', `/servers/${sid}/containers/${cid}/restart`),
    remove: (sid: string, cid: string) => request<void>('DELETE', `/servers/${sid}/containers/${cid}`),
    exec: (sid: string, cid: string, d: { query: string; dbUser?: string; dbPassword?: string }) =>
      request<{ output: string }>('POST', `/servers/${sid}/containers/${cid}/exec`, d),
  },

  compose: {
    read: (sid: string, path: string) =>
      request<{
        content: string;
        path: string;
      }>('GET', `/servers/${sid}/compose?path=${encodeURIComponent(path)}`),
    write: (sid: string, path: string, content: string) =>
      request<{ ok: boolean }>('PUT', `/servers/${sid}/compose?path=${encodeURIComponent(path)}`, {
        content,
      }),
    up: (sid: string, path: string) =>
      request<{
        ok: boolean;
        output: string;
      }>('POST', `/servers/${sid}/compose/up?path=${encodeURIComponent(path)}`),
    down: (sid: string, path: string) =>
      request<{
        ok: boolean;
        output: string;
      }>('POST', `/servers/${sid}/compose/down?path=${encodeURIComponent(path)}`),
  },

  files: {
    list: (sid: string, path: string) =>
      request<{
        path: string;
        entries: FileEntry[];
      }>('GET', `/servers/${sid}/files?path=${encodeURIComponent(path)}`),
    preview: (sid: string, path: string) =>
      request<{
        content: string;
        truncated: boolean;
        binary: boolean;
      }>('GET', `/servers/${sid}/files/preview?path=${encodeURIComponent(path)}`),
    write: (sid: string, path: string, content: string) =>
      request<{ ok: boolean }>('PUT', `/servers/${sid}/files`, { path, content }),
    download: (_sid: string, path: string) =>
      downloadFile(`/servers/${encodeURIComponent(_sid)}/files/download?path=${encodeURIComponent(path)}`),
    upload: (sid: string, dirPath: string, file: File) => {
      const form = new FormData();
      form.append('file', file);
      return fetch(`/api/servers/${sid}/files/upload?path=${encodeURIComponent(dirPath)}`, {
        method: 'POST',
        credentials: 'include',
        body: form,
        signal: AbortSignal.timeout(60_000),
      }).then((res) => decodeResponse<{ ok: boolean; path: string }>(res, '/files/upload'));
    },
    delete: (sid: string, path: string) =>
      request<void>('DELETE', `/servers/${sid}/files?path=${encodeURIComponent(path)}`),
    mkdir: (sid: string, path: string) =>
      request<{ ok: boolean }>('POST', `/servers/${sid}/files/mkdir`, { path }),
  },

  proxy: {
    detect: (sid: string) =>
      request<{ proxyType: string; version: string }>('GET', `/servers/${sid}/proxy/detect`),
    list: (sid: string) => request<ProxyRule[]>('GET', `/servers/${sid}/proxy`),
    create: (sid: string, data: { domain: string; target: string; proxyType: string; ssl: boolean }) =>
      request<ProxyRule>('POST', `/servers/${sid}/proxy`, data),
    update: (
      sid: string,
      ruleId: string,
      data: {
        domain: string;
        target: string;
        proxyType: string;
        ssl: boolean;
      },
    ) => request<ProxyRule>('PUT', `/servers/${sid}/proxy/${ruleId}`, data),
    delete: (sid: string, ruleId: string) => request<void>('DELETE', `/servers/${sid}/proxy/${ruleId}`),
    enableSSL: (
      sid: string,
      ruleId: string,
      data: { email: string; wildcard: boolean; cfToken: string; renew?: boolean },
    ) =>
      request<{
        rule: ProxyRule;
        output: string;
        warning?: string;
        dnsCleanupStatus?: 'unverified' | 'reported_failure';
      }>('POST', `/servers/${sid}/proxy/${ruleId}/ssl`, data),
  },

  services: {
    list: () => request<Service[]>('GET', '/services'),
    create: (data: Partial<Service>) => request<Service>('POST', '/services', data),
    update: (id: string, data: Partial<Service>) => request<Service>('PUT', `/services/${id}`, data),
    delete: (id: string) => request<void>('DELETE', `/services/${id}`),
  },

  monitor: {
    status: () => request<ServerStatus[]>('GET', '/monitor/status'),
    getConfig: () => request<AlertConfig>('GET', '/monitor/config'),
    updateConfig: (data: Partial<AlertConfig>) => request<AlertConfig>('PUT', '/monitor/config', data),
    testTelegram: () => request<{ ok: string }>('POST', '/monitor/config/test'),
    listMonitored: (sid: string) =>
      request<{ id: string; containerId: string; name: string }[]>(
        'GET',
        `/servers/${sid}/monitor/containers`,
      ),
    addMonitored: (sid: string, containerId: string, name: string) =>
      request<{ id: string }>('POST', `/servers/${sid}/monitor/containers`, { containerId, name }),
    removeMonitored: (sid: string, containerId: string) =>
      request<void>('DELETE', `/servers/${sid}/monitor/containers/${containerId}`),
  },

  templates: {
    list: () => request<AppTemplate[]>('GET', '/templates'),
    getCustom: (id: string) =>
      request<AppTemplate & { compose: string }>('GET', '/templates/custom/' + encodeURIComponent(id)),
    createCustom: (data: Partial<AppTemplate> & { compose: string }) =>
      request<AppTemplate>('POST', '/templates/custom', data),
    updateCustom: (id: string, data: Partial<AppTemplate> & { compose: string }) =>
      request<AppTemplate>('PUT', `/templates/custom/${id}`, data),
    deleteCustom: (id: string) => request<void>('DELETE', `/templates/custom/${id}`),
    listDeployed: (sid: string) => request<DeployedApp[]>('GET', `/servers/${sid}/apps`),
    deploy: (sid: string, data: { templateId: string; appName: string; variables: Record<string, string> }) =>
      request<{
        app: DeployedApp;
        output: string;
        postDeploy: string;
      }>('POST', `/servers/${sid}/apps/deploy`, data),
    remove: (sid: string, appId: string) =>
      request<{ output: string }>('DELETE', `/servers/${sid}/apps/${appId}`),
  },

  serverAlerts: {
    get: (sid: string) => request<ServerAlertConfig>('GET', `/servers/${sid}/alerts`),
    update: (sid: string, data: Partial<ServerAlertConfig>) =>
      request<ServerAlertConfig>('PUT', `/servers/${sid}/alerts`, data),
  },

  cron: {
    list: (sid: string) => request<CronJob[]>('GET', `/servers/${sid}/cron`),
    add: (sid: string, d: { schedule: string; command: string }) =>
      request<{ ok: string }>('POST', `/servers/${sid}/cron`, d),
    delete: (sid: string, raw: string) => request<{ ok: string }>('DELETE', `/servers/${sid}/cron`, { raw }),
  },

  tasks: {
    list: (sid: string) => request<ScheduledTask[]>('GET', `/servers/${sid}/tasks`),
    create: (
      sid: string,
      d: { name: string; command: string; intervalMinutes: number; supervised?: boolean },
    ) => request<ScheduledTask>('POST', `/servers/${sid}/tasks`, d),
    update: (sid: string, tid: string, d: Partial<ScheduledTask>) =>
      request<ScheduledTask>('PUT', `/servers/${sid}/tasks/${tid}`, d),
    delete: (sid: string, tid: string) => request<void>('DELETE', `/servers/${sid}/tasks/${tid}`),
    runNow: (sid: string, tid: string) => request<{ ok: string }>('POST', `/servers/${sid}/tasks/${tid}/run`),
    runs: (sid: string, tid: string) =>
      request<SupervisedRun[]>(
        'GET',
        `/servers/${encodeURIComponent(sid)}/tasks/${encodeURIComponent(tid)}/runs`,
      ),
    readRun: (sid: string, tid: string, rid: string) =>
      request<RunObservation>(
        'GET',
        `/servers/${encodeURIComponent(sid)}/tasks/${encodeURIComponent(tid)}/runs/${encodeURIComponent(rid)}`,
      ),
    inspectRun: (sid: string, tid: string, rid: string) =>
      request<RunObservation>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/tasks/${encodeURIComponent(tid)}/runs/${encodeURIComponent(rid)}/inspect`,
      ),
    cancelRun: (sid: string, tid: string, rid: string) =>
      request<RunObservation>(
        'POST',
        `/servers/${encodeURIComponent(sid)}/tasks/${encodeURIComponent(tid)}/runs/${encodeURIComponent(rid)}/cancel`,
      ),
    releaseRun: (sid: string, tid: string, rid: string) =>
      request<RunObservation>(
        'DELETE',
        `/servers/${encodeURIComponent(sid)}/tasks/${encodeURIComponent(tid)}/runs/${encodeURIComponent(rid)}/artifacts`,
      ),
  },
  firewall: {
    status: (sid: string) => request<FirewallStatus>('GET', `/servers/${sid}/firewall`),

    enable: (sid: string) => request<{ ok: boolean }>('POST', `/servers/${sid}/firewall/enable`),

    disable: (sid: string) => request<{ ok: boolean }>('POST', `/servers/${sid}/firewall/disable`),

    addRule: (sid: string, data: { port: string; action: string; from: string }) =>
      request<{ ok: boolean }>('POST', `/servers/${sid}/firewall/rules`, data),

    deleteRule: (sid: string, n: number) =>
      request<{ ok: boolean }>('DELETE', `/servers/${sid}/firewall/rules/${n}`),
  },
  ws: {
    metrics: (id: string) =>
      `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/metrics/${encodeURIComponent(id)}`,
    terminal: (sid: string) =>
      `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/terminal/${sid}`,
    logs: (sid: string, cid: string) =>
      `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/logs/${sid}/${cid}`,
  },
};
