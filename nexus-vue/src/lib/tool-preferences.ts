import { shallowRef } from 'vue';
export const toolCatalog = [
  { id: 'backups', label: 'Backups', description: 'Sources, repositories, schedules and restore copies' },
  {
    id: 'ansible',
    label: 'Ansible',
    description: 'Controllers, inventory and playbook runs',
  },
  {
    id: 'github',
    label: 'GitHub Actions',
    description: 'Connections, workflows and run status',
  },
  {
    id: 'runners',
    label: 'GitHub runners',
    description: 'Marketplace runner setup and lifecycle',
  },
  {
    id: 'vault',
    label: 'HashiCorp Vault',
    description: 'Vault management and Marketplace recipe',
  },
  {
    id: 'inventory',
    label: 'Server inventory',
    description: 'Discovered resources and relationships',
  },
  {
    id: 'terminal',
    label: 'Terminal',
    description: 'Interactive server terminals',
  },
  {
    id: 'containers',
    label: 'Containers',
    description: 'Docker containers and lifecycle controls',
  },
  {
    id: 'yaml',
    label: 'YAML Editor',
    description: 'Compose, GitHub Actions and Kubernetes YAML',
  },
  { id: 'metrics', label: 'Metrics', description: 'Server monitoring charts' },
  { id: 'files', label: 'Files', description: 'Remote file browser' },
  {
    id: 'proxy',
    label: 'Proxy',
    description: 'Domains, routing and certificates',
  },
  {
    id: 'apps',
    label: 'Apps',
    description: 'Application Marketplace and deployments',
  },
  {
    id: 'cron',
    label: 'Cron',
    description: 'Cron entries and execution output',
  },
  {
    id: 'tasks',
    label: 'Scheduled tasks',
    description: 'Recurring server tasks',
  },
  {
    id: 'operations',
    label: 'Operations',
    description: 'Supervised operation history and controls',
  },
  {
    id: 'firewall',
    label: 'Firewall',
    description: 'Server networking and firewall rules',
  },
  { id: 'services', label: 'Services', description: 'Saved service bookmarks' },
] as const;
export type ToolId = (typeof toolCatalog)[number]['id'];
const hidden = shallowRef<ReadonlySet<ToolId>>(new Set());
let principal = '';
const key = () => `nexus:tools:v1:${principal}`;
function read() {
  try {
    const value = JSON.parse(localStorage.getItem(key()) ?? '[]');
    hidden.value = new Set(
      Array.isArray(value) ? value.filter((id: unknown) => toolCatalog.some((tool) => tool.id === id)) : [],
    );
  } catch {
    hidden.value = new Set();
  }
}
export function setToolPreferenceUser(id: string) {
  if (id === principal) return;
  principal = id;
  hidden.value = new Set();
  if (id) read();
}
export function toolEnabled(id: ToolId): boolean {
  return !hidden.value.has(id);
}
export function setToolEnabled(id: ToolId, enabled: boolean) {
  if (!toolCatalog.some((tool) => tool.id === id)) return;
  const next = new Set(hidden.value);
  if (enabled) next.delete(id);
  else next.add(id);
  hidden.value = next;
  try {
    if (principal) localStorage.setItem(key(), JSON.stringify([...next]));
  } catch {
    /* Preferences still work for this session. */
  }
}
export function resetTools() {
  hidden.value = new Set();
  try {
    if (principal) localStorage.removeItem(key());
  } catch {
    /* Storage is optional. */
  }
}
if (typeof window !== 'undefined' && typeof window.addEventListener === 'function')
  window.addEventListener('storage', (event) => {
    if (principal && (event.key === key() || event.key === null)) read();
  });
