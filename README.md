<div align="center">

# UniFi MCP

**A security-first Model Context Protocol server for operating and understanding UniFi Network.**

Give AI assistants structured access to network inventory, diagnostics, history,
and carefully controlled changes—without turning your controller into an
open-ended API proxy.

![.NET 10](https://img.shields.io/badge/.NET-10-512BD4?logo=dotnet&logoColor=white)
![MCP](https://img.shields.io/badge/MCP-stdio%20%7C%20Streamable%20HTTP-6E56CF)
![UniFi Network](https://img.shields.io/badge/UniFi-Network-0559C9?logo=ubiquiti&logoColor=white)
![Security model](https://img.shields.io/badge/security-threat%20modeled-2E7D32)

</div>

## What it is

UniFi MCP connects MCP-compatible assistants to a self-hosted UniFi Network
controller. It exposes 36 purpose-built tools for reading network state,
investigating client behavior, reviewing configuration, and applying approved
changes.

The official UniFi Network Integration API remains authoritative. Optional
private reads are narrowly fixed, bounded, projected, and provenance-labelled
for the few useful fields the official contract does not expose. Callers never
receive an arbitrary URL, raw private response, controller session, or database
connection.

This project is designed for private, operator-controlled deployments. It is
not affiliated with or endorsed by Ubiquiti.

## Network superpowers

| Mission | What UniFi MCP does |
| --- | --- |
| Map the control plane | Builds source-aware snapshots across sites, devices, clients, networks, Wi-Fi, switching, firewall, ACL, DNS, VPN, WAN, vouchers, and traffic policy |
| Hunt RF ghosts | Correlates a client with its AP and radio, then exposes RSSI, SNR, noise, PHY rates, MCS/NSS, retries, channel utilization, transmit power, roaming, and DHCP/APIPA evidence |
| Reconstruct client timelines | Reconciles authoritative current state, bounded controller history, and configured groups—or records explicit observations in a local SQLite journal for later change queries |
| Audit intent versus reality | Surfaces missing fields, partial sources, configuration references, ungrouped clients, firmware state, and topology caveats without inventing certainty |
| Watch the whole fleet | Adds optional read-only Site Manager inventory, console health, firmware/update state, and historical ISP metrics |
| Execute guarded changes | Turns a proposed mutation into an exact preview, short-lived confirmation capability, live drift check, and one non-retried apply |
| Run inside your trust boundary | Speaks local stdio or authenticated stateless Streamable HTTP, including a hardened Unix-socket path behind Tailscale Serve |

## Safety by design

- **Allowlisted operations.** Normal calls must exist in a reviewed OpenAPI
  contract. Private adapters use fixed resources and explicit output fields.
- **Human-gated writes.** Every controller mutation is previewed first and
  bound to a random, single-use, five-minute confirmation capability.
- **State-drift protection.** Apply rechecks relevant live state and rejects a
  stale preview.
- **Data minimization.** Private responses are projected, bounded, recursively
  redacted, and labelled with source and observation metadata.
- **No connector-managed credential store.** Credentials can be injected from
  a protected environment file or secret manager; they do not belong in MCP
  configuration, source control, tool output, or the journal.
- **Fail-closed semantics.** Partial, contradictory, unsupported, or
  version-specific data is not silently promoted to authoritative state.
- **Hardened deployment.** The tracked container runs non-root and read-only,
  drops all Linux capabilities, and exposes no LAN port.

Read the concise [security policy](SECURITY.md) or the full
[threat model](docs/threat-model.md).

## How it fits together

```mermaid
flowchart LR
    client["MCP client"] -->|stdio or authenticated HTTP| server["UniFi MCP"]
    server --> guard["Contract validation, projection, redaction"]
    guard --> local["UniFi Network Integration API"]
    guard -.-> private["Fixed opt-in UniFi resources"]
    guard -.-> cloud["Read-only UniFi Site Manager"]
    server <--> journal["Optional local client journal"]
    preview["Preview + approval + drift check"] --> guard
```

## Quick start

### Requirements

- .NET SDK 10
- A UniFi Network Integration API key
- HTTPS access to a UniFi OS Network Integration API endpoint
- An MCP client such as Codex

Create the API key in **Network → Settings → Control Plane → Integrations**.
Provide these values through a protected environment file or secret manager:

```dotenv
UNIFI_API_KEY=replace-with-secret
UNIFI_BASE_URL=https://unifi.example.com/proxy/network/integration
UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=false
UNIFI_ENABLE_CLIENT_JOURNAL=false
```

`.env.example` documents every supported setting. Do not commit a resolved
environment file.

Build and test:

```sh
dotnet restore --locked-mode
dotnet build UnifiMcp.slnx --configuration Release --no-restore
dotnet test UnifiMcp.slnx --configuration Release --no-restore
```

Validate configuration, TLS, API access, contract selection, and enabled
features without printing secrets:

```sh
dotnet run --project src/UnifiMcp --configuration Release --no-build -- \
  --env-file=/absolute/path/to/protected.env doctor
```

Run the stdio MCP server:

```sh
dotnet run --project src/UnifiMcp --configuration Release --no-build -- \
  --env-file=/absolute/path/to/protected.env
```

For a durable local publish, Streamable HTTP, Tailscale Serve, Docker, or the
production rollback procedure, use the [operations reference](docs/operations.md).

## Tool families

The server exposes 36 tools grouped around operator intent:

- **Discover:** capabilities, site snapshots, sites, and supporting resources
- **Observe:** devices, clients, networks, Wi-Fi, switching, firewall, ACL,
  DNS, traffic lists, hotspot vouchers, and System Log alerts
- **Diagnose:** current Wi-Fi RF/DHCP diagnostics and client-group audits
- **Remember:** explicit client collection, change queries, per-client history,
  journal health, and fingerprint-bound recovery
- **See the fleet:** Site Manager inventory and ISP metrics
- **Change safely:** domain previews, a generic allowlisted preview, and one
  confirmation-bound apply tool

Use `unifi_get_capabilities` to inspect the live contract, enabled optional
features, coverage limitations, and exact operation inventory.

## Optional capabilities

Private reads, Site Manager, the client journal, and scheduled collection are
off unless configured. The main feature gates are:

```dotenv
UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true
UNIFI_SITE_API_KEY=replace-with-separate-read-only-key
UNIFI_ENABLE_CLIENT_JOURNAL=true
UNIFI_CLIENT_JOURNAL_DB_PATH=/absolute/private/path/client-journal.db
UNIFI_ENABLE_SCHEDULED_COLLECTION=true
```

The private-read gate enables only reviewed fixed resources. The journal is a
separate local data grain and is not encrypted by the connector; protect its
host volume and directory permissions. See the operations reference for exact
limits, retention, provenance, and recovery behavior.

## Compatibility

- Runtime: .NET 10
- MCP transports: stdio and stateless Streamable HTTP
- Embedded fallback contract: UniFi Network 10.4.57
- Local API: official Network Integration API over validated HTTPS
- Optional cloud API: UniFi Site Manager stable v1, read-only
- Journal: SQLite WAL on a private local filesystem

At startup the connector probes the live application and controller contract.
A controller contract is accepted only when its version matches the running
Network application; otherwise the reviewed embedded contract remains the
fail-closed fallback.

## Documentation

| Document | Purpose |
| --- | --- |
| [Operations reference](docs/operations.md) | Full configuration, private-read semantics, journal behavior, deployment, rollback, and Codex registration |
| [Security policy](SECURITY.md) | Supported versions, vulnerability reporting, and security guarantees |
| [Threat model](docs/threat-model.md) | Assets, actors, trust boundaries, attacker stories, mitigations, and severity calibration |
| [.env.example](.env.example) | Supported environment variables without resolved secrets |

## Development

The repository uses locked NuGet dependencies, warnings-as-errors, a vendored
OpenAPI contract, and complete Release tests. Before opening a pull request:

```sh
dotnet format UnifiMcp.slnx --no-restore
dotnet test UnifiMcp.slnx --configuration Release --no-restore
git diff --check
```

Security-sensitive changes should update the threat model when they add a
transport, authentication mode, upstream API, write category, persistent data
field, deployment boundary, or secret-handling path.
