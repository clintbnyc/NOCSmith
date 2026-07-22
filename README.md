# UniFi MCP Connector

Private, stdio-only MCP access to UniFi Network on pinode. The connector uses the official Integration API by default and supports a narrowly projected, opt-in legacy read enrichment for documentation fields unavailable from the official schema. It uses the active UniFi OS Server through the Tailscale HTTPS name:

`https://unifi.nutria-newton.ts.net/proxy/network/integration`

It does not use the stopped `/srv/unifi` Docker rollback stack, controller database access, a public listener, or insecure TLS bypasses. Legacy enrichment, when explicitly enabled, permits only two fixed GET resources and never returns their raw responses.

## Security model

- Authentication is an official Network Integration API key sent only as `X-API-Key`.
- The API key stays in 1Password. A local ignored env file contains only an `op://` reference, and `op run` injects the resolved value into the connector process.
- This does not store the API key in macOS Keychain, the repository, or Codex configuration. The 1Password desktop app may authorize its CLI integration using normal macOS facilities, but the connector never reads Keychain directly.
- HTTPS uses macOS/.NET system trust plus hostname validation for `unifi.nutria-newton.ts.net`. There is no certificate-validation override and no direct-IP fallback.
- Every normal API operation must exist in the loaded OpenAPI contract. The optional legacy enrichment is separately constrained to GET `stat/device` and GET `stat/sta`; arbitrary legacy URLs, methods, and writes are rejected.
- Responses, exceptions, snapshots, and previews are recursively redacted. Wi-Fi credentials, API keys, tokens, passwords, pre-shared keys, and hotspot voucher codes are never returned.
- GET requests retry 429, transient HTTP failures, and timeouts. Mutations are sent exactly once and are never automatically retried.

## Prerequisites

- .NET SDK 10.0.302 or a compatible 10.0 patch release
- 1Password CLI (`/opt/homebrew/bin/op`) with desktop app integration enabled
- A UniFi Network Integration API key created in **Network > Settings > Control Plane > Integrations**
- Tailscale access to `unifi.nutria-newton.ts.net`

## Configure 1Password

Copy the example, then replace only its placeholder 1Password reference. Either ignored filename is supported operationally; `.env.op` is preferred:

```sh
cp .env.op.example .env.op
chmod 600 .env.op
```

The file must contain a reference, not a resolved secret:

```dotenv
UNIFI_API_KEY=op://YOUR_VAULT/YOUR_ITEM/YOUR_FIELD
UNIFI_BASE_URL=https://unifi.nutria-newton.ts.net/proxy/network/integration
UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=false
```

If 1Password is locked, desktop integration is disabled, or the reference is wrong, `op run` fails before the connector receives a key. There is intentionally no service-account or plaintext fallback.

Set `UNIFI_ENABLE_LEGACY_READ_ENRICHMENT=true` only when port labels, STP-related state/configuration fields, or device/client notes and comments are needed. The same `X-API-Key` is used; no administrator username/password session is introduced. The adapter performs fixed GETs under `/proxy/network/api/s/{site}/stat/device` and `/proxy/network/api/s/{site}/stat/sta`, joins records by MAC address, and returns only:

- device/client IDs and MAC addresses needed to identify projected records;
- port index, custom label, controller-native STP-related state and configuration fields, uplink flag, and selected STP mode fields;
- `note`, `notes`, `comment`, and `comments` free text.

Raw legacy responses, VLAN/network identifiers, authentication material, device keys, and all other fields are discarded before tool output is built. Selected free text is passed through the connector's secret redactor, including inline password, token, API-key, PSK, and private-key patterns. Enrichment failures are reported under `_connector.legacyReadEnrichment` without failing the official read.

The projected STP values are controller-native evidence, not a normalized UniFi UI role. Live verification found no reliable direct field for the UI's **Edge** versus **Participant** column, and `stpState`, `isUplink`, `stpPortMode`, and `settingPreference` are not individually or collectively treated as a safe mapping. The enrichment therefore reports `normalizedUiStpRole.status` as `unavailable` and does not emit `uiStpRole`.

## Build and verify

```sh
dotnet restore --locked-mode
dotnet build UnifiMcp.slnx --configuration Release --no-restore
dotnet test UnifiMcp.slnx --configuration Release --no-restore
```

Run the live diagnostic without printing secrets:

```sh
/opt/homebrew/bin/op --account YOUR_ACCOUNT_ID run --env-file .env.op -- \
  /usr/local/share/dotnet/dotnet \
  src/UnifiMcp/bin/Release/net10.0/unifi-mcp.dll doctor
```

Use `--env-file .env` instead if that is the ignored filename you created. If only one 1Password account is configured, `--account YOUR_ACCOUNT_ID` may be omitted. The diagnostic checks configuration, successful secret injection, normal TLS validation, `/v1/info`, contract selection, and site discovery.

## MCP tools

The server exposes 26 tools:

- Discovery and snapshots: `unifi_get_capabilities`, `unifi_get_site_snapshot`
- Grouped reads: `unifi_sites`, `unifi_devices`, `unifi_clients`, `unifi_networks`, `unifi_wifi`, `unifi_hotspot`, `unifi_firewall`, `unifi_acl`, `unifi_switching`, `unifi_dns`, `unifi_traffic_lists`, `unifi_supporting_resources`
- Contract-defined read escape hatch: `unifi_read_operation`
- Domain previews: `unifi_preview_device_change`, `unifi_preview_client_change`, `unifi_preview_network_change`, `unifi_preview_wifi_change`, `unifi_preview_hotspot_change`, `unifi_preview_firewall_change`, `unifi_preview_acl_change`, `unifi_preview_dns_change`, `unifi_preview_traffic_list_change`
- Contract-defined write preview: `unifi_preview_operation`
- Confirmed apply: `unifi_apply_change`

Read tools support the contract's offset, limit, and filter parameters. Page responses include `_connector.truncated`; when true, request another page. Read responses also include `_connector.sourceOperationId` and an ISO-8601 `_connector.observedAt` timestamp when the response shape can carry metadata. Device-detail and client responses include `_connector.contract` and `_connector.knownLimitations` when response coverage needs explanation. A site is auto-selected only if exactly one exists or `UNIFI_DEFAULT_SITE_ID` is configured.

Client `type` and `uplinkDeviceId` values are preserved as controller-reported observation data. The connector does not reinterpret them as proof of a direct cable, switch port, or Wi-Fi radio association when a third-party bridge such as eero may be in the path. Client responses include `_connector.topologySemantics` so callers can distinguish reported data from physical-topology inference.

Site-snapshot sections report `status` as `ok`, `notApplicable`, or `failed`, plus the source operation and observation time. The exact UniFi response code `api.firewall.zone-based-firewall-not-configured` is treated as `notApplicable` only for zone-based firewall policy and zone lists; unrelated 400 responses remain failures. The snapshot summary reports succeeded, not-applicable, and failed counts separately, and its root `_connector` object records contract status and known response limitations.

`unifi_read_operation` accepts an exact GET `operationId` plus named parameters. `unifi_preview_operation` accepts only a non-GET operation in the same allowlist. Neither tool accepts a URL or arbitrary HTTP method.

## Write workflow

All configuration changes use the same two-step protocol:

1. A preview tool performs reads only, validates the method/path/query/body, captures live state, checks known references, and returns a redacted before/proposed view with warnings and a random confirmation token.
2. After the user explicitly approves that exact preview, `unifi_apply_change` accepts only its opaque token. It re-reads state, rejects drift, consumes the token, and sends exactly one mutation.

Tokens are process-local, single-use, capped, and expire after five minutes. A failed drift check consumes the token. PUT domain tools treat the supplied body as changes over the current resource: absent fields are preserved, explicit `null` clears a field, nested objects merge, and arrays replace arrays. Network deletes with known references require an explicit preview override. Bulk voucher deletion resolves the exact matching voucher IDs and refuses previews that cannot fit into a single verified page.

The MCP metadata marks reads and previews read-only. `unifi_apply_change` is marked writable, destructive, and non-idempotent so Codex can require conservative approval.

## OpenAPI contract

The repository vendors Ubiquiti Network OpenAPI `10.3.58`, currently the latest published contract, with 41 GET and 32 write operations. At startup the connector reads `/v1/info` and probes controller-local contract locations. It uses a controller contract only when its version matches the live Network application; otherwise it remains restricted to the reviewed embedded contract. Capabilities, read-response metadata, snapshots, and `doctor` report a machine-readable contract status such as `embedded-fallback` alongside the version warning. When the application version is newer than Ubiquiti's latest published contract, `embedded-fallback` means the connector is intentionally using the newest reviewed contract available; it does not imply that a matching published download was missed.

The official `10.3.58` adopted-device schema does not expose custom switch-port labels or STP-related state and configuration fields. The connector reports these as limitations of the official response, with `source`, `scope`, `resolutionStatus`, `resolvedBy`, and `stillMissing` metadata. Successful legacy enrichment resolves labels and the projected STP-related fields separately under `_connector.legacyReadEnrichment`; the normalized UniFi UI Edge/Participant role remains explicitly unresolved.

Refresh is an explicit review step:

```sh
./scripts/update-openapi.sh 10.3.58
dotnet test UnifiMcp.slnx
git diff -- contracts/unifi-network.openapi.json
```

Supply the reviewed published version to the script. Do not silently refresh the contract at runtime.

## Codex registration

After a Release build and successful `doctor`, register the stdio server without putting the key or its `op://` reference in Codex configuration:

```sh
codex mcp add unifi -- \
  /opt/homebrew/bin/op --account YOUR_ACCOUNT_ID run \
  --env-file=/Users/cbeilman/source/personal/unifi-mcp/.env.op \
  -- \
  /usr/local/share/dotnet/dotnet \
  /Users/cbeilman/source/personal/unifi-mcp/src/UnifiMcp/bin/Release/net10.0/unifi-mcp.dll
```

Equivalent `~/.codex/config.toml` settings are:

```toml
[mcp_servers.unifi]
command = "/opt/homebrew/bin/op"
args = [
  "--account",
  "YOUR_ACCOUNT_ID",
  "run",
  "--env-file=/Users/cbeilman/source/personal/unifi-mcp/.env.op",
  "--",
  "/usr/local/share/dotnet/dotnet",
  "/Users/cbeilman/source/personal/unifi-mcp/src/UnifiMcp/bin/Release/net10.0/unifi-mcp.dll",
]
cwd = "/Users/cbeilman/source/personal/unifi-mcp"
startup_timeout_sec = 30
tool_timeout_sec = 90
default_tools_approval_mode = "writes"
```

Use `.env` in the path if that is your chosen ignored file. Restart Codex after registration. The durable Mac configuration and runbook should be updated only after `doctor` and representative MCP calls succeed.
