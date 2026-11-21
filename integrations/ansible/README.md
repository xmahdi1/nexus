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
