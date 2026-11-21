# Nexus Ansible inventory

Enable `NEXUS_ENABLE_AUTOMATION=true`. Assign the `ansible-inventory` role to the
operator for an explicit server group in Settings. Existing admin roles do not
automatically gain this permission. Use Automation to preview that group and
issue a credential lasting at most 15 minutes. Save the credential to a file owned
by your local user with mode `0600`; never put it in a repository or command line.

```sh
export NEXUS_URL=https://nexus.example.com
export NEXUS_INVENTORY_TOKEN_FILE=/private/path/inventory-token
ansible-inventory -i ./integrations/ansible/nexus_inventory.py --list
ansible-inventory -i ./integrations/ansible/nexus_inventory.py --graph
```

The adapter supports `--list` and `--host ALIAS`, including unknown-host `{}`.
Every invocation fetches current inventory; there is no disk cache or stale-grant
fallback. `--refresh` explicitly fetches again. HTTP is permitted only on loopback;
remote endpoints require verified HTTPS. Redirects and ambient proxies are disabled.
Set `ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED=true` for commands that execute
playbooks so an inventory failure stops the command.

Inventory credentials work only on the inventory GET endpoint, for their selected
group, and depend on the issuing login session remaining valid. Logout, session
expiry, account disablement, grant removal, token revocation and offline key
rotation remove authority. Adding, updating or deleting a registered server is
visible on the next refresh. Revoking the last eligible target returns an error.
Inventory grants do not authorize playbook execution or reveal SSH credentials.

Aliases are `nexus_host_<sha256(server ID)>`; group/tag aliases use separate
`nexus_group_`/`nexus_tag_` prefixes and full hashes. Automation preview supplies
display-name mappings outside Ansible variables. Hostvars contain only the
validated address, port, user and server ID. Invalid addresses/users, templated
labels, or inventories exceeding 1,000 hosts fail closed. Credentials and verified
SSH host keys must be supplied through a separate execution context; this adapter
does not disable host-key checking or export Nexus private keys.

External playbooks can refresh inventory mid-run. This adapter alone does not
freeze a run's target set, approve a playbook, or authorize execution. Nexus-managed
revision approval, frozen target snapshots, credentials and run supervision are
separate implementation steps.

## Managed environment

The server's **Ansible** tab offers install, update, health and removal through
the existing durable operation supervisor. Enable both automation and operation
supervision. Assign `ansible-environment` explicitly alongside the existing SSH
execution, secret-use, job-read and log-read grants needed by the supervisor.
Protected groups require fresh MFA. Inventory grants remain independent.

The selected Linux controller must already have Python 3.13–3.15 (standard GIL
build), venv, OpenSSH, root SSH and systemd/cgroup v2. The package lock supports
x86_64/aarch64 Linux wheels. Nexus creates a dedicated `nexus-ansible` system user
with a private home and no login shell or supplementary groups, then runs the
reviewed installer and pip as that user. All package versions and wheel hashes
are pinned; source distributions, ambient pip settings, user Ansible plugins,
SSH agent credentials and the host Docker socket are excluded.

The environment lives at `/var/lib/nexus-ansible/environment`. Health reports
the installed version, package/config integrity, and whether OpenSSH is available;
it never installs prerequisites. Install refuses existing unowned accounts,
homes and environments. Update is explicit. Removal deletes only the owned
environment and retains the controller user/home. The supervisor retains run
identity across restart and never resubmits an uncertain operation; inspect or
cancel it through operation history. Cancellation cannot undo package/account
changes already applied.

For an independently prepared non-root controller, the same installer can run
directly from the source tree:

```sh
python3 integrations/ansible/environment.py install --root /private/controller/ansible
python3 integrations/ansible/environment.py health --root /private/controller/ansible
python3 integrations/ansible/environment.py update --root /private/controller/ansible
python3 integrations/ansible/environment.py remove --root /private/controller/ansible
```

The parent directory must exist. Use an absolute path containing only letters,
numbers, `/`, `_`, `-` and `.`; no symlinks. Failed/interrupted installations remain
owned but incomplete; inspect, remove and explicitly reinstall rather than
adopting them. The installer does not modify a system Ansible installation.

Regenerate the embedded reviewed bundle after changing the installer or lock:
`python3 scripts/generate_ansible_bundle.py`. A Go regression test verifies its
bytes against these source files. `scripts/ansible_environment_lab.py` validates
the actual dedicated-user lifecycle in a disposable container with no host mounts
or published ports. Managed project approval, credential delivery and playbook
execution are subsequent layers; installing an environment does not start a playbook.
