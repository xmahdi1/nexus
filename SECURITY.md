# Security

## Support status

Nexus is in development. The maintainers triage reports against the current
`main` branch. There is no supported release series or guaranteed response time
yet. There has been no independent security audit.

## Report privately

Use the repository's **Security → Report a vulnerability** form once private
reporting is enabled. If it is unavailable, reach out privately to the
[maintainer](https://github.com/xmahdi1) for a reporting channel before sharing
technical details. Avoid public issues or PRs for vulnerability disclosures.

Include the version or commit, affected feature, impact, and reproduction steps
using a disposable environment. Remove credentials, session cookies, keys,
and real host details. The maintainer will acknowledge the report as capacity
allows, assess impact, and coordinate a fix and disclosure with the reporter.

## Deployment boundaries

Run the dashboard on a trusted management network behind HTTPS. Use verified SSH
host keys and dedicated OS accounts. Give users and background services the
smallest scope they need. Keep the database, data key, and recovery copies private.
Controller administrators and SSH accounts with root access have substantial
power over managed infrastructure.

See the [security architecture](ARCHITECTURE.md) for trust boundaries and review
points, and [deployment](DEPLOYMENT.md) for setup and recovery.
