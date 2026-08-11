# Security Policy

NOCsmith is built for private, operator-controlled network access. Security
issues can affect controller credentials, household or organizational network
metadata, managed network configuration, and the host that runs the connector.
Please report suspected vulnerabilities privately.

## Reporting a vulnerability

Use the repository's
[private vulnerability reporting form](https://github.com/clintbnyc/NOCSmith/security/advisories/new).
Do not open a public issue for an unpatched vulnerability and do not include
real API keys, bearer tokens, private keys, client data, journal contents, or
other sensitive deployment information in a report.

Include enough information to reproduce and evaluate the issue:

- the affected revision or version;
- the deployment and authentication mode involved;
- required attacker access and trust-boundary position;
- concise reproduction steps or a minimal proof of concept;
- observed confidentiality, integrity, or availability impact; and
- any suggested mitigation or evidence that the behavior fails closed.

You should receive an acknowledgement as soon as practical. Remediation and
disclosure timing will depend on severity, reproducibility, deployment reach,
and whether coordinated upstream work is required.

For configuration help, feature requests, or behavior that does not expose a
security boundary, use a normal repository issue instead.

## Supported versions

Security fixes target the current default branch. Once stable semantic releases
are published, the latest stable release is also supported. Older revisions,
manual `sha-*` test images, locally modified builds, stale container images, and
unsupported controller/API combinations may not receive fixes. Stable GHCR
releases use exact semantic-version tags; deployments should pin the published
image digest when reproducible rollback matters.

The connector is intended for a current .NET 10 runtime and a compatible UniFi
Network Integration API. Run `doctor` after upgrades and before exposing a new
transport.

## Deployment scope

The supported security model assumes:

- a private, single-operator or small trusted-group deployment;
- validated HTTPS to the controller and any external reverse proxy;
- least-privilege UniFi Network and Site Manager API keys;
- authenticated MCP transport with no direct public Kestrel exposure;
- protected secret injection and private journal/storage paths; and
- a trusted host, container runtime, CA store, Tailscale daemon, and secret
  manager.

This is not a public multi-tenant service. One server process has one tool set
and one in-memory confirmation store; it does not provide tenant isolation,
per-principal tool authorization, or confirmation-token ownership.

## Security guarantees

The project treats these as core invariants:

1. MCP input cannot select an arbitrary origin, URL, method, header,
   filesystem path, process, or SQL statement.
2. Controller writes require an allowlisted preview, a short-lived single-use
   confirmation capability, and a matching live-state check.
3. Mutations are sent once and are never automatically retried.
4. Private UniFi reads are opt-in, fixed-resource, bounded, projected,
   redacted, and provenance-labelled; raw responses are not returned.
5. Secrets do not belong in source control, logs, tool output, previews,
   snapshots, exceptions, MCP configuration, or the client journal.
6. Partial, contradictory, malformed, stale, or unsupported upstream data
   fails closed rather than becoming a false topology or safety claim.
7. Read-only journal tools do not create, migrate, prune, recover, or change
   filesystem permissions.
8. HTTP authentication, proxy identity, `Host`, `Origin`, socket ownership,
   and transport encryption remain part of the deployment security boundary.

Redaction is defense in depth. Explicit projections and schema allowlists are
the primary controls against data leakage.

## Secrets and sensitive data

- Never commit a resolved `.env` file or credentials.
- Prefer a secret manager or protected environment file and pass it with
  `--env-file`; the loader treats it as dotenv data, not shell code.
- Use a separate read-only key for Site Manager.
- Treat controller names, notes, comments, log text, client identifiers,
  topology, ISP metrics, and journal data as untrusted and potentially
  sensitive.
- The optional SQLite journal is cleartext. Its private directory, host volume,
  backups, and retention are operator responsibilities.

If a secret may have been exposed, rotate it at the source before sharing
diagnostics. Sanitizing a later report does not revoke a disclosed credential.

## Security design and review

The full [threat model](docs/threat-model.md) documents assets, actors, trust
boundaries, attacker-controlled inputs, mitigations, review hotspots,
out-of-scope assumptions, and severity calibration.

Changes that add a transport, authentication mode, upstream API, private
resource, write category, persistent field, executable input, deployment
boundary, or secret-handling path must update that model and include focused
  adversarial tests.
