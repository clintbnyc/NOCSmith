# UniFi MCP Operations Reference

This is the detailed configuration and deployment reference for the tracked
local and Pinode environments. Start with the product-facing
[README](../README.md) if you are evaluating or setting up the connector for
the first time.

Private MCP access to UniFi Network on pinode, with stdio and stateless Streamable HTTP transports plus optional read-only UniFi Site Manager fleet enrichment. The connector uses the local official Integration API as the authority for detailed state and every write. Site Manager stable-v1 reads add fleet host/site/device inventory, firmware/update state, and historical ISP metrics. Narrowly projected, opt-in private local reads remain available for documentation fields, client groups, and System Log events unavailable from the official schema. The local data plane uses the active UniFi OS Server through the Tailscale HTTPS name:

`https://unifi.nutria-newton.ts.net/proxy/network/integration`

It does not use the stopped `/srv/unifi` Docker rollback stack, controller database access, an Internet-facing listener, or insecure TLS bypasses. The Pinode HTTP origin is loopback-only and is exposed privately by Tailscale Serve. Private controller access, when explicitly enabled, permits only one fixed legacy device GET, one fixed v2 active-client GET, one fixed bounded v2 client-history GET, one fixed v2 client-group GET, and one fixed read-only System Logs query, and never returns their raw responses.

## Security model

See [`SECURITY.md`](../SECURITY.md) for the security policy and
[`threat-model.md`](threat-model.md) for the repository-scoped threat model,
trust boundaries, attacker capabilities, security invariants, and severity
calibration used during security reviews.

- Local authentication is an official Network Integration API key sent only to the configured local HTTPS endpoint as `X-API-Key`. Optional Site Manager authentication uses a separate read-only API key sent only to `https://api.ui.com`.
- The local stdio API key stays in a 1Password Environment exposed through a locally mounted `.env` file. 1Password supplies those contents on demand without storing plaintext values on the Mac.
- The unattended Pinode container uses a separately protected `0600` environment file under `/srv/unifi-mcp/secrets`. This is an explicit at-rest secret handoff on Pinode; it is excluded from Git and Docker build context, and Compose never publishes its contents.
- The connector parses the mounted file itself when launched with `--env-file`. It imports only its supported `UNIFI_*` variables, does not execute the file as shell code, and does not override variables explicitly inherited from the parent process.
- Neither transport stores the API key in the repository or Codex configuration. The connector never reads macOS Keychain directly.
- Streamable HTTP defaults to bearer authentication. The Pinode profile trusts `Tailscale-User-Login` only on a Unix socket inside a `0700` directory owned by the non-root container user. Tailscale Serve runs as root, injects the authenticated tailnet identity, and can connect to that socket; unprivileged local host processes cannot. Tailscale 1.98.9 or newer is required because it restricts Unix-socket Serve targets to root.
- HTTP requests must use the configured public `Host`; a supplied `Origin` must match the same HTTPS authority. MCP responses are marked `Cache-Control: no-store`.
- HTTPS uses the platform/.NET trust store plus hostname validation. Local stdio uses `unifi.nutria-newton.ts.net`; the Pinode container uses the LAN certificate name `unifi.webbman.nyc` and mounts Pinode's trusted CA bundle read-only. There is no certificate-validation override and no direct-IP fallback.
- Every normal API operation must exist in the loaded OpenAPI contract. Optional private access is separately constrained to GET `stat/device`, GET `v2/api/site/{site}/clients/active?includeTrafficUsage=true&includeUnifiDevices=true`, GET `v2/api/site/{site}/clients/history?onlyNonBlocked=true&includeUnifiDevices=true&withinHours={bounded-value}`, GET `v2/api/site/{site}/network-members-groups`, and an empty-body query-style POST to `v2/api/site/{site}/system-log/all`. The System Logs POST is a read operation used by Network 10.4.57 and accepts no caller-supplied body. The history GET accepts only the six time-bounded values used by the authenticated Network 10.4.57 UI. Arbitrary private URLs, methods, query keys, and writes are rejected.
- Site Manager permits only stable `/v1` host, site, device, and ISP-metric reads. Early Access, SD-WAN, Cloud Connector proxying, arbitrary URLs, and Site Manager writes are rejected.
- Responses, exceptions, snapshots, and previews are recursively redacted. Wi-Fi credentials, API keys, tokens, passwords, pre-shared keys, and hotspot voucher codes are never returned.
- Read operations retry 429, transient HTTP failures, and timeouts, including the fixed query-style System Logs POST. Mutations are sent exactly once and are never automatically retried.
- Site Manager requests share a process-local rolling ceiling of 9,000 requests per 60 seconds, 100-request rate-limit and concurrency queues, and four concurrent request slots. Discovery pages use the provider maximum of 500 records and are cached/coalesced for five minutes. A `429` establishes a process-wide cooldown from delta-seconds or HTTP-date `Retry-After`; cooldown waits occur without occupying a dispatch slot, and the permit is rechecked after a slot is acquired so no newly dispatched request bypasses the provider wait. Waits beyond five minutes return structured `rateLimited` metadata.

## Prerequisites

- .NET SDK 10.0.302 or a compatible 10.0 patch release
- 1Password for Mac with an Environment and local `.env` destination
- Docker Engine with Compose for the optional Pinode deployment
- A UniFi Network Integration API key created in **Network > Settings > Control Plane > Integrations**
- Optional: a read-only Site Manager stable-v1 API key created at **unifi.ui.com > Settings > API Keys**
- Tailscale access to `unifi.nutria-newton.ts.net`

## Configure 1Password

In 1Password, create an Environment for the connector and add these variables:

```text
UNIFI_API_KEY=<Network Integration API key>
UNIFI_BASE_URL=https://unifi.nutria-newton.ts.net/proxy/network/integration
UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=false
UNIFI_ENABLE_CLIENT_JOURNAL=false
# UNIFI_CLIENT_JOURNAL_DB_PATH=/absolute/private/path/client-journal.db
# UNIFI_CLIENT_JOURNAL_RETENTION_DAYS=90
# UNIFI_CLIENT_JOURNAL_MAX_MIB=256
UNIFI_ENABLE_SCHEDULED_COLLECTION=false
# UNIFI_SCHEDULED_COLLECTION_INTERVAL_MINUTES=60
# UNIFI_SCHEDULED_COLLECTION_SITE_ID=
# UNIFI_SCHEDULED_COLLECTION_HISTORY_HOURS=24
# UNIFI_MCP_HTTP_AUTH_MODE=bearer
# UNIFI_MCP_HTTP_BEARER_TOKEN=<32-or-more-character-token>
# UNIFI_MCP_TAILSCALE_ALLOWED_USERS=clint@example.com
# UNIFI_MCP_HTTP_PUBLIC_URL=https://unifi-mcp.example.com/mcp
# UNIFI_MCP_HTTP_LISTEN_URL=http://0.0.0.0:8080
# UNIFI_MCP_TAILSCALE_SOCKET_PATH=/absolute/private/directory/unifi-mcp.sock
UNIFI_SITE_API_KEY=<optional Site Manager API key>
UNIFI_SITE_MANAGER_LOCAL_HOST_ID=<optional explicit host ID>
```

`UNIFI_SITE_API_KEY` enables fleet tools and ISP history. `UNIFI_SITE_MANAGER_LOCAL_HOST_ID` is required only to enrich this local controller's device responses; obtain the opaque ID with `unifi_site_manager` action `hosts`. No hostname or name-based heuristic is used. Capabilities and doctor verify the configured ID against paginated Site Manager hosts and report `mapped`, `notFound`, or `notConfigured` without returning the ID. The other optional variables are `UNIFI_DEFAULT_SITE_ID` and `UNIFI_TIMEOUT_SECONDS`. The tracked `.env.example` records the supported names only and must never contain resolved secrets.

From the Environment's **Destinations** tab, configure a local `.env` file at the persistent source checkout:

```text
/Users/cbeilman/source/personal/unifi-mcp/.env
```

The path is ignored by Git. 1Password mounts it as an in-memory FIFO and prompts for authorization when the connector reads it. Do not leave the mounted file open in an editor because local Environment files are not designed for concurrent readers. There is intentionally no service-account or plaintext fallback.

Set `UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true` only when port labels, STP-related state/configuration fields, device/client notes and comments, bounded client history, client-group membership, current Wi-Fi diagnostics, or System Log events are needed. The legacy-named variable is retained for configuration compatibility and gates all five private resources. The same `X-API-Key` is used; no administrator username/password session or browser cookie is introduced. The enrichment adapter reads devices from the fixed legacy `/proxy/network/api/s/{site}/stat/device` resource and active clients from the fixed private `/proxy/network/v2/api/site/{site}/clients/active?includeTrafficUsage=true&includeUnifiDevices=true` resource, joins records by MAC address, and returns only:

- device/client IDs and MAC addresses needed to identify projected records;
- port index, custom label, controller-native STP-related state and configuration fields, uplink flag, and selected STP mode fields;
- `note`, `notes`, `comment`, and `comments` free text.

Raw private responses, VLAN/network identifiers, authentication material, device keys, traffic counters, and all other fields are discarded before tool output is built. Selected free text is passed through the connector's secret redactor, including inline password, token, API-key, PSK, and private-key patterns. Enrichment failures are reported under `_connector.legacyReadEnrichment` without failing the official read.

`unifi_clients` action `history` is a separate, opt-in read and does not change
the `list` or `get` actions. Network `10.4.57`'s authenticated client UI was
verified to issue the fixed GET:

```text
/proxy/network/v2/api/site/{site}/clients/history?onlyNonBlocked=true&includeUnifiDevices=true&withinHours={hours}
```

The action accepts only the UI's bounded `historyHours` values: `24`, `72`,
`168`, `336`, `720`, or `4320`; it deliberately rejects the UI's all-time
value. `offset` and `limit` provide connector-side pagination independently
over each returned classification, with a maximum limit of 200. The controller
history response itself is capped at 10,000 records and must match the
validated object-record contract. Official current-client pages must also
match their declared count, offset, limit, and total count; incomplete or
contradictory pagination fails closed rather than risking a false offline
classification.

The response keeps three data grains visibly separate:

- `currentlyConnectedClients` comes from the official
  `getConnectedClientOverviewPage` operation and is authoritative for current
  name, MAC address, IP address, state, and connection time when present.
- `offlineClientsWithinWindow` contains non-blocked private history records
  absent from the current official feed. It may include historical name, MAC,
  IP, and `last_seen` evidence, but never overwrites a current record.
- `groupMembersWithoutHistory` contains configured client-group MAC members
  absent from both the current official feed and the complete bounded history
  response. Group membership alone supplies no name, IP address, last-seen
  evidence, or online state.

All three classifications can include projected group IDs and redacted names
from the fixed client-group resource. Total configured memberships are capped
at 10,000, and one response page can project at most 5,000 group references.
Per-field provenance identifies the source, authority, and availability of
every projected data field, including derived and unavailable values. Metadata
reports requested and effective windows, source collections,
per-classification pagination, truncation, safety limits, online/offline
counts, missing-field counts, exact audit scope, and limitations. A missing
endpoint or unrecognized history, current-client, or group response returns
`status: notSupported` with empty client arrays and identifies the exact
failing source; raw private records are never returned.

`unifi_client_groups` separately sends a fixed GET to
`/proxy/network/v2/api/site/{site}/network-members-groups`. Network `10.4.57`
was live-verified to accept the existing Integration API key and return 12
configured groups with group ID, name, type, and member MAC addresses. The
`list` action returns projected group definitions and can optionally include
the member MAC addresses. The `audit` action joins those memberships to the
official connected-client list and reports connected clients with no group
assignment. Because the official contract exposes connected clients rather
than complete offline history, the audit explicitly does not claim to identify
ungrouped offline clients. No client-group create, update, reorder, or delete
operation is exposed.

### Current Wi-Fi diagnostics

`unifi_wifi_diagnostics` reads only the fixed active-client and `stat/device`
resources named above. It returns at most 200 clients and 100 AP-radio records
(defaults: 100 and 50), with an optional exact client-MAC filter. The response
is a fresh current-state projection; it does not read or extend the client
journal.

The explicit client allowlist covers controller-reported AP/radio association,
band, channel and width, RSSI, noise floor, SNR, signal quality and Signal
Balance classification, PHY rates, MCS/NSS/MIMO, Wi-Fi standard, bounded
retry/error counters or rates, association/roam evidence, power-save state,
and DHCP lease/failure/APIPA state. The AP-radio allowlist combines configured
`radio_table` fields with effective and operational `radio_table_stats` fields,
including transmit power, channel/width, utilization, interference, noise,
station count, and retry/error telemetry. This lets one response correlate an
associated client's signal with its AP and compare current conditions across
AP radios.

Every supported field is present with `null` when the controller or firmware
does not expose a recognized version-specific alias. Direct SNR takes
precedence; otherwise SNR is derived only when both RSSI and noise are present.
APIPA is derived from a validated `169.254.0.0/16` IPv4 address only when the
controller provides no direct APIPA field. `_connector` identifies both fixed
sources, configured-versus-operational radio provenance, derivations, limits,
redaction, and version-drift behavior. Unknown fields and raw private responses
are discarded.

This deployment currently has no adopted UniFi gateway or UniFi access points.
Clients seen through eero and the managed switch may therefore lack direct
UniFi Wi-Fi/AP association, gateway-derived network context, or other
connection telemetry. The connector reports those fields as unavailable and
does not infer a direct cable, radio, VLAN, or physical path through eero.

### Optional client observation journal

The client journal is a separate, opt-in local data grain. It does not change
`unifi_clients list`, `unifi_clients history`, or `unifi_client_groups audit`.
It is disabled by default and creates nothing at process startup unless
scheduled collection is separately enabled. Enable the journal with both:

```text
UNIFI_ENABLE_CLIENT_JOURNAL=true
UNIFI_CLIENT_JOURNAL_DB_PATH=/absolute/private/path/client-journal.db
```

`UNIFI_CLIENT_JOURNAL_RETENTION_DAYS` defaults to 90 and accepts 1–3650.
`UNIFI_CLIENT_JOURNAL_MAX_MIB` defaults to 256 and accepts 16–4096. Explicit
collection also requires `UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true`; health
and journal queries need only the journal gate and path.

The parent directory must be local, non-symlinked, and private (`0700` or
stricter). The connector creates a missing parent as `0700` and maintains the
database, WAL, and SHM files as `0600`. The journal is not encrypted: it stores
projected household metadata such as normalized lowercase MAC addresses,
normalized IP addresses, bounded redacted names, timestamps, group IDs/names,
and field provenance in cleartext. It never stores controller responses,
request bodies, credentials, tokens, controller-internal IDs, traffic
counters, arbitrary JSON, or unrelated fields.

`unifi_collect_client_observations` and `journal collect` use the same
collection service. It
fetches controller data before opening the journal transaction, records
official connected state, bounded UI history, and configured group membership
as independent sources, and atomically persists the normalized result. Each
source is `complete`, `partial`, or `failed`; records validated before a source
became partial are positive evidence, but absence from an incomplete source is
never interpreted as disconnected, offline, no longer configured, or removed.
The collection result contains identifiers, timestamps, safe per-source
status/count/error metadata, and no client rows.

The journal query tools are:

- `unifi_client_changes`: source-specific complete baselines, with matching
  windows for UI-history comparisons. Omit `sinceTimestamp` for the previous
  successful source snapshot. Results use `connectedObserved`,
  `noLongerConnected`, `enteredHistoryWindow`, `leftHistoryWindow`,
  `fieldChanged`, `groupRenamed`, `membershipAdded`, and
  `membershipNoLongerConfigured`; the term “removed” is not used. Offline
  evidence is derived only when official-current and UI-history sources are
  both complete in the same collection.
- `unifi_client_observation_history`: chronological source-grained evidence
  for one normalized MAC, including source completeness and field provenance.
  Gaps carry no inferred state.
- `unifi_client_journal_health`: a filesystem-nonmutating inspection that
  returns `disabled`, `notInitialized`, `healthy`, `migrationRequired`,
  `newerSchemaNotSupported`, `unsafePath`, `corrupt`, or `oversized`, plus schema/WAL,
  size/retention, collection success, and quarantine metadata without client
  rows.
- `unifi_recover_client_journal`: the only recovery path. It requires and
  rechecks the corruption fingerprint from health, quarantines the active
  DB/WAL/SHM set, initializes a fresh migrated journal, and restores the old
  set if initialization fails. Recovery is never automatic.

All query operations use stable ordering and bounded pagination (default 100,
maximum 200) with total, returned, offset, truncation, and next-offset
metadata. Ordered checksummed migrations run transactionally only during
explicit collection or recovery. Read-only tools never create or migrate a
database and fail closed on unknown newer schemas. SQLite runs in WAL mode
with foreign keys, `synchronous=FULL`, incremental auto-vacuum, a bounded busy
timeout, separate pooled connections, and a process-local write semaphore.
Retention and size pruning delete whole collections; the configured active
DB/WAL/SHM cap takes precedence. Before deleting a collection for size, the
store requires a successful truncating WAL checkpoint and fully reclaims
already-free pages. If an active reader pins an oversized WAL, collection
fails closed without deleting another historical collection.

The locked dependency graph uses `Microsoft.Data.Sqlite` 10.0.10 and explicitly
pins `SQLitePCLRaw.bundle_e_sqlite3` 2.1.12. The explicit native-bundle pin
avoids the vulnerable 2.1.11 native SQLite package otherwise selected by the
10.0.10 metapackage; vulnerability warnings remain errors and are not
suppressed.

#### Scheduled collection

The proposal is implemented as two explicit entrypoints:

```sh
dotnet unifi-mcp.dll --env-file=/absolute/path/.env \
  journal collect [--site-id UUID] [--history-hours HOURS]

dotnet unifi-mcp.dll --env-file=/absolute/path/.env serve-http
```

`journal collect` emits one compact, client-free JSON result. Exit code `0`
means complete, `3` means partial, `4` means all sources failed, `2` means
invalid configuration or arguments, and `1` means another operational failure.

The long-running HTTP host performs scheduled collection only when all three
gates are true:

```text
UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true
UNIFI_ENABLE_CLIENT_JOURNAL=true
UNIFI_ENABLE_SCHEDULED_COLLECTION=true
```

The interval defaults to 60 minutes and accepts 5–1440.
`UNIFI_SCHEDULED_COLLECTION_HISTORY_HOURS` accepts `24`, `72`, `168`, `336`,
`720`, or `4320`; an optional site ID must be a UUID. Startup examines the last
completed persisted collection and delays only until the next due time, so a
restart or sleep does not cause duplicate catch-up runs. A private sibling
lock file serializes CLI, tool, and scheduled collectors across processes.
Overlap is skipped safely, all operational errors are redacted, and the next
normal interval remains scheduled. Retention and size enforcement use the same
transactional journal rules described above.

`unifi_alerts` separately sends `{}` to `/proxy/network/v2/api/site/{site}/system-log/all`. Although the endpoint uses POST, it is a read-only collection query: callers cannot supply a body, path, or method. Network 10.4.57 was live-verified to accept the existing Integration API key and return up to 50 records with pagination metadata. The projection preserves controller-supplied event/key, raw description/title, severity, status, category/subcategory, type, target, timestamp, and a small allowlist from `parameters`, including IP address, affected clients, learn-more reference, object, console, count, platform, section, and administrator identifiers. Raw parameter objects and unrelated fields are discarded.

The projected STP values are controller-native evidence, not a normalized UniFi UI role. Live verification found no reliable direct field for the UI's **Edge** versus **Participant** column, and `stpState`, `isUplink`, `stpPortMode`, and `settingPreference` are not individually or collectively treated as a safe mapping. The enrichment therefore reports `normalizedUiStpRole.status` as `unavailable` and does not emit `uiStpRole`.

## Build and verify

```sh
dotnet restore --locked-mode
dotnet build UnifiMcp.slnx --configuration Release --no-restore
dotnet test UnifiMcp.slnx --configuration Release --no-restore
```

Run the live diagnostic without printing secrets:

```sh
/usr/local/share/dotnet/dotnet \
  src/UnifiMcp/bin/Release/net10.0/unifi-mcp.dll \
  --env-file=/Users/cbeilman/source/personal/unifi-mcp/.env \
  doctor
```

`--env-file /absolute/path/.env` is also accepted. The diagnostic checks configuration, successful secret injection, normal TLS validation, `/v1/info`, contract selection, site discovery, private enrichment, the fixed one-day client-history classification, the fixed client-group audit, the fixed System Logs query, non-mutating client-journal health, and—when configured—read-only Site Manager fleet access plus explicit local-host mapping. A configured host ID that is not visible to the Site Manager account makes Site Manager doctor status `degraded`.

## Pinode container deployment

The tracked Compose profile builds a multi-stage ARM64-compatible image from
digest-pinned .NET 10 SDK and ASP.NET runtime images. The runtime is non-root,
read-only, drops every Linux capability, enables `no-new-privileges`, and uses
a private Unix socket for the Tailscale Serve backend. It does not publish a
Docker port to the LAN. The container reaches UniFi
through `https://unifi.webbman.nyc` on the LAN and mounts Pinode's existing
system CA bundle read-only so normal certificate and hostname validation remain
enabled.

Prepare the state and secret paths on Pinode:

```sh
cd /srv/unifi-mcp
sudo install -d -m 0700 -o 1654 -g 1654 data
sudo install -d -m 0700 -o 1654 -g 1654 run
sudo install -d -m 0700 -o admin -g admin secrets
sudo install -m 0600 -o admin -g admin /dev/null \
  secrets/unifi-mcp.env
```

The secret file contains only values that must remain private:

```text
UNIFI_API_KEY=<Network Integration API key>
# UNIFI_SITE_API_KEY=<optional Site Manager API key>
```

All non-secret production settings are visible in `docker-compose.yml`.
Validate and deploy without printing the resolved environment:

```sh
sudo docker compose config --quiet
sudo docker compose build --pull
sudo docker compose up -d
```

The dedicated Tailscale Service is `svc:unifi-mcp`. Its policy grants
`group:network-admins` TCP 443 access and permits only `tag:pinode` to advertise
it. Pinode terminates HTTPS and proxies the Service to the private Unix socket.
Use Tailscale 1.98.9 or newer, and configure Serve as root:

```sh
sudo tailscale serve --yes --service=svc:unifi-mcp --https=443 \
  unix:/srv/unifi-mcp/run/mcp.sock
```

The production MCP URL is:

```text
https://unifi-mcp.nutria-newton.ts.net/mcp
```

The Compose profile accepts only `clint@webbman.nyc` as the authenticated
Tailscale identity. Add another identity deliberately to
`UNIFI_MCP_TAILSCALE_ALLOWED_USERS`; do not replace the allowlist with a
wildcard.

Verify the container, socket boundary, MCP handshake, scheduled journal, and
Service readiness:

```sh
sudo docker inspect unifi-mcp \
  --format 'running={{.State.Running}} status={{.State.Status}}'
sudo stat -c '%a %u:%g %F' run
sudo test -S run/mcp.sock
sudo docker compose logs --since 10m unifi-mcp
sudo tailscale serve status --json
sudo docker exec unifi-mcp \
  dotnet /app/unifi-mcp.dll journal collect --history-hours 24
```

The final command is an explicit extra collection and is therefore optional
during routine checks. Successful HTTPS MCP initialization from an allowlisted
tailnet user is the end-to-end acceptance test. A local TCP request cannot
reach the application because it has no TCP listener; a request without an
injected Tailscale identity returns `401`, and a mismatched `Host` or `Origin`
returns `403`.

Codex uses the Streamable HTTP endpoint directly:

```toml
[mcp_servers.unifi]
url = "https://unifi-mcp.nutria-newton.ts.net/mcp"
```

No API key or bearer token belongs in Codex configuration. Keep the old stdio
registration until the HTTP endpoint has passed a live initialize and tool
call, then remove the stdio command and restart Codex.

Rollback is failure-domain specific:

- Disable only remote MCP access with
  `sudo tailscale serve --service=svc:unifi-mcp --https=443 off`.
- Stop collection and HTTP together with
  `sudo docker compose down`; the journal and secret file remain.
- Restore the prior image/source bundle and run
  `sudo docker compose up -d` to roll back application code without replacing
  the journal.
- Do not copy a newer journal into older code unless that version explicitly
  supports the journal schema. Retain a pre-change DB/WAL/SHM backup when
  crossing schema versions.

## MCP tools

The server exposes 36 tools:

- Discovery, snapshots, and fleet data: `unifi_get_capabilities`, `unifi_get_site_snapshot`, `unifi_site_manager`, `unifi_isp_metrics`
- Grouped reads: `unifi_sites`, `unifi_devices`, `unifi_clients`, `unifi_client_groups`, `unifi_wifi_diagnostics`, `unifi_alerts`, `unifi_networks`, `unifi_wifi`, `unifi_hotspot`, `unifi_firewall`, `unifi_acl`, `unifi_switching`, `unifi_dns`, `unifi_traffic_lists`, `unifi_supporting_resources`
- Contract-defined read escape hatch: `unifi_read_operation`
- Client journal: `unifi_collect_client_observations`, `unifi_client_changes`, `unifi_client_observation_history`, `unifi_client_journal_health`, `unifi_recover_client_journal`
- Domain previews: `unifi_preview_device_change`, `unifi_preview_client_change`, `unifi_preview_network_change`, `unifi_preview_wifi_change`, `unifi_preview_hotspot_change`, `unifi_preview_firewall_change`, `unifi_preview_acl_change`, `unifi_preview_dns_change`, `unifi_preview_traffic_list_change`
- Contract-defined write preview: `unifi_preview_operation`
- Confirmed apply: `unifi_apply_change`

Official read tools support the contract's offset, limit, and filter parameters. Page responses include `_connector.truncated`; when true, request another page. `unifi_clients` actions `list` and `get` retain the official connected-client semantics; action `history` is the distinct bounded private classification described above and accepts `historyHours`, `offset`, and `limit`. `unifi_client_groups` supports `list` and `audit`; `includeMembers=true` includes projected configured member MAC addresses. The group audit remains connected-only and does not silently become a history audit. `unifi_wifi_diagnostics` accepts bounded client/radio limits plus an optional exact client MAC and returns nullable, version-aware RF and DHCP/APIPA projections from fixed private resources. `unifi_alerts` accepts a local 1-50 limit over the first System Logs page and reports the controller's page and total counts. Set `includeRead=false` to retain only records whose direct controller status is `NEW`; no meaning is inferred for other status values. Read responses also include observation/source metadata when their response shape can carry it. Device-detail and client responses include `_connector.contract` and `_connector.knownLimitations` when response coverage needs explanation. A site is auto-selected only if exactly one exists or `UNIFI_DEFAULT_SITE_ID` is configured.

`unifi_site_manager` actions are `hosts`, `host`, `sites`, and `devices`. List actions use `pageSize` from 1 to 500 and return an opaque `pagination.continuation`; pass it back as `nextToken` for the next call. `host` requires `hostId`; `devices` optionally filters by host. `unifi_isp_metrics` accepts interval `5m` or `1h`, duration `24h` for 5-minute metrics, duration `7d` or `30d` for hourly metrics, or explicit RFC3339 timestamps. Optional targeted queries accept an array of `{ hostId, siteId, beginTimestamp?, endTimestamp? }`.

Fleet inventory is projected before tool output. Host account profiles, email addresses, permissions, locations, UI assets, and undocumented application internals are discarded. Host identity/health/version, documented site metadata/statistics, and documented device/firmware/update fields are retained and recursively redacted.

When both `UNIFI_SITE_API_KEY` and `UNIFI_SITE_MANAGER_LOCAL_HOST_ID` are configured, local adopted-device reads add `_connector.siteManagerEnrichment`. Records are joined only by normalized MAC address and contain Site Manager cloud status, firmware/update state, note, and provider update time with explicit source/observation metadata. Local fields are never overwritten. Duplicate provider MACs are reported as ambiguous and are not joined; Site Manager failures never fail a successful local read.

Client `type` and `uplinkDeviceId` values are preserved as controller-reported observation data. The connector does not reinterpret them as proof of a direct cable, switch port, or Wi-Fi radio association when a third-party bridge such as eero may be in the path. Client responses include `_connector.topologySemantics` so callers can distinguish reported data from physical-topology inference.

Site-snapshot sections report `status` as `ok`, `notApplicable`, or `failed`, plus the source operation and observation time. The exact UniFi response code `api.firewall.zone-based-firewall-not-configured` is treated as `notApplicable` only for zone-based firewall policy and zone lists; unrelated 400 responses remain failures. The snapshot summary reports succeeded, not-applicable, and failed counts separately, and its root `_connector` object records contract status and known response limitations.

`unifi_read_operation` accepts an exact GET `operationId` plus named parameters. `unifi_preview_operation` accepts only a non-GET operation in the same allowlist. Neither tool accepts a URL or arbitrary HTTP method.

## Write workflow

All configuration changes use the same two-step protocol:

1. A preview tool performs reads only, validates the method/path/query/body, captures live state, checks known references, and returns a redacted before/proposed view with warnings and a random confirmation token.
2. After the user explicitly approves that exact preview, `unifi_apply_change` accepts only its opaque token. It re-reads state, rejects drift, consumes the token, and sends exactly one mutation.

Tokens are process-local, single-use, capped, and expire after five minutes. A failed drift check consumes the token. PUT domain tools treat the supplied body as changes over the current resource: absent fields are preserved, explicit `null` clears a field, nested objects merge, and arrays replace arrays. Network deletes with known references require an explicit preview override. Bulk voucher deletion resolves the exact matching voucher IDs and refuses previews that cannot fit into a single verified page.

The MCP metadata marks reads and previews read-only.
`unifi_collect_client_observations` is a local, non-destructive,
non-idempotent write. `unifi_recover_client_journal` and
`unifi_apply_change` are writable, destructive, and non-idempotent so Codex
can require conservative approval.

## OpenAPI contract

The repository vendors Ubiquiti Network OpenAPI `10.4.57`, matching the active Network application, with 41 GET and 32 write operations. At startup the connector reads `/v1/info` and probes controller-local contract locations. It uses a controller contract only when its version matches the live Network application; otherwise it remains restricted to the reviewed embedded contract. Capabilities, read-response metadata, snapshots, and `doctor` report the machine-readable contract status.

The official `10.4.57` adopted-device schema still does not expose custom switch-port labels or STP-related state and configuration fields. The connector detects these capabilities from response-schema paths instead of hard-coding a version. Missing fields are reported with `source`, `scope`, `resolutionStatus`, `resolvedBy`, and `stillMissing` metadata. Successful legacy enrichment resolves labels and the projected STP-related fields separately under `_connector.legacyReadEnrichment`; the normalized UniFi UI Edge/Participant role remains explicitly unresolved.

Refresh is an explicit review step:

```sh
./scripts/update-openapi.sh 10.4.57
dotnet test UnifiMcp.slnx
git diff -- contracts/unifi-network.openapi.json
```

Supply the reviewed published version to the script. Do not silently refresh the contract at runtime.

## Codex registration

### Stable local publish

A worktree build path disappears when that worktree is removed. Before cleaning up a verified worktree, publish it to the stable local connector directory:

```sh
./scripts/publish-local.sh
```

The script restores locked dependencies, runs the complete Release test suite, publishes into a new versioned directory under `~/source/personal/mcp-connectors/unifi-mcp/releases/`, and atomically switches the `current` symlink only after all prior steps succeed. It never copies `.env` or resolved secrets. Existing releases remain available for manual rollback; the script does not prune them.

An alternate absolute destination may be supplied as the first argument. The default durable entrypoint is:

```text
/Users/cbeilman/source/personal/mcp-connectors/unifi-mcp/current/unifi-mcp
```

Run the published diagnostic with the locally mounted 1Password Environment file:

```sh
/Users/cbeilman/source/personal/mcp-connectors/unifi-mcp/current/unifi-mcp \
  --env-file=/Users/cbeilman/source/personal/unifi-mcp/.env \
  doctor
```

After the published `doctor` succeeds, register the stdio server without putting the key in Codex configuration:

```sh
codex mcp add unifi -- \
  /Users/cbeilman/source/personal/mcp-connectors/unifi-mcp/current/unifi-mcp \
  --env-file=/Users/cbeilman/source/personal/unifi-mcp/.env
```

Equivalent `~/.codex/config.toml` settings are:

```toml
[mcp_servers.unifi]
command = "/Users/cbeilman/source/personal/mcp-connectors/unifi-mcp/current/unifi-mcp"
args = [
  "--env-file=/Users/cbeilman/source/personal/unifi-mcp/.env",
]
cwd = "/Users/cbeilman/source/personal/mcp-connectors/unifi-mcp/current"
startup_timeout_sec = 30
tool_timeout_sec = 90
default_tools_approval_mode = "writes"
```

Restart Codex after registration and approve the 1Password prompt when the connector first reads the mount. The durable Mac configuration and runbook should be updated only after `doctor` and representative MCP calls succeed.
