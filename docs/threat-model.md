# NOCsmith Threat Model

For supported versions and private vulnerability reporting, see the
[security policy](../SECURITY.md).

This document is the authoritative, repository-scoped threat model for
`unifi-mcp`. It is intended to be reused during security reviews of unrelated
changes. It describes security boundaries and vulnerability classes, not known
vulnerabilities in the current revision.

Last reviewed: 2026-08-01.

Update this model when a change adds a transport, authentication mode, upstream
API, write category, persistent data field, executable input, deployment
boundary, or materially different secret-handling path.

## Overview

NOCsmith, whose stable technical runtime identifier is `unifi-mcp`, is a private
.NET 10 Model Context Protocol connector for a UniFi Network controller and,
optionally, the UniFi Site Manager stable-v1 API. It turns MCP tool calls into:

- reads and writes defined by a reviewed or controller-supplied UniFi Network
  OpenAPI contract;
- narrowly fixed, opt-in private UniFi reads for data absent from the official
  contract;
- fixed read-only Site Manager inventory and ISP-metric requests; and
- local collection and queries over an opt-in SQLite client-observation
  journal.

The primary runtime surfaces are:

- a local stdio MCP server in `src/UnifiMcp/Program.cs`;
- a stateless Streamable HTTP server in
  `src/UnifiMcp/HttpServerCommand.cs`;
- explicit `doctor` and `journal collect` command-line entry points; and
- optional scheduled journal collection in the long-running HTTP host.

The intended deployment is private and single-operator or small trusted-group,
not a public multi-tenant service. The tracked Pinode deployment uses a
non-root, read-only container and a private Unix socket behind Tailscale Serve.
Portable bearer authentication is also implemented, but it depends on an
external HTTPS termination and network-exposure design appropriate to the
deployment.

### Security-relevant assets

- The UniFi Network Integration API key and optional Site Manager API key.
- The HTTP bearer token or the integrity of the Tailscale-authenticated
  identity header.
- UniFi configuration and operational state, including networks, Wi-Fi,
  firewall and ACL policy, DNS, devices, clients, vouchers, and traffic lists.
- Confidential network and household metadata returned by reads, including
  MAC/IP addresses, names, topology, events, and ISP metrics.
- The cleartext SQLite client journal, its integrity, and its availability.
- The correctness of the embedded/controller OpenAPI allowlist and the
  preview-to-apply binding for mutations.
- The integrity of release artifacts, locked dependencies, container images,
  and deployment configuration.

### Primary security objectives

1. Only an authenticated and intended MCP principal can invoke tools.
2. Tool input cannot escape an allowlisted operation into arbitrary HTTP,
   filesystem, process, or database access.
3. A controller mutation occurs only after an exact preview, through a
   short-lived single-use capability, and against unchanged relevant state.
4. Secrets do not enter source control, logs, tool output, previews, snapshots,
   exceptions, or the client journal.
5. Private API responses are projected to the minimum documented fields and
   remain separate from authoritative official data.
6. Incomplete, stale, malformed, or ambiguous upstream data fails closed and
   does not become a false security or topology claim.
7. Journal reads do not create or migrate state; collection, pruning, and
   recovery preserve path safety and database integrity.
8. Upstream failure, rate limiting, and hostile data sizes remain bounded and
   do not cause unsafe retries or uncontrolled resource use.

The private history feed can include a MAC-less `TELEPORT` pseudo-client. It is
not treated as a client identity or persisted: the connector suppresses only
that exact type, reports the count, and continues to fail closed for any other
missing or malformed MAC. This avoids inventing a join key while preserving
validated MAC-keyed observations.

## Threat Model, Trust Boundaries, and Assumptions

### Actors and capabilities

**Unauthenticated remote actor.** May reach an accidentally exposed HTTP
listener and control request paths, methods, MCP payloads, `Host`, `Origin`,
and authorization headers. This actor must not reach MCP tool execution.

**Authenticated but malicious or compromised MCP client.** Can invoke every
tool registered in its server process, choose tool arguments, read returned
data, request previews, and receive confirmation tokens. Transport
authentication is not per-tool authorization. This is the principal attacker
for request-validation, write-safety, data-exposure, and resource-exhaustion
analysis.

**Network or controller data author.** A person or compromised device may
influence controller-supplied names, notes, comments, log descriptions,
addresses, identifiers, counts, pagination, and response shapes. A compromised
controller can also influence a controller-served OpenAPI document. These
values are untrusted even though they arrive from an authenticated HTTPS
upstream.

**Local unprivileged host process.** May probe TCP listeners and accessible
files or sockets. In the Tailscale mode, it must not be able to connect to the
private MCP socket or forge `Tailscale-User-Login`.

**Operator.** Controls environment variables, the env-file path, feature
gates, base URL, site selection, listener/public URL, Tailscale allowlist,
journal path, retention, and deployment. Operator-controlled configuration is
trusted to express intent but must be syntactically constrained and must fail
closed when unsafe.

**Developer and build/release operator.** Controls source, the embedded
OpenAPI contract, dependency locks, Dockerfiles, Compose, and publishing
scripts. A malicious or compromised developer/build dependency is a supply
chain threat rather than ordinary MCP input.

### Trust boundaries and data flows

1. **MCP client to connector.** Stdio inherits the trust and identity of the
   launching process. HTTP crosses a network/proxy boundary and relies on
   bearer authentication or a Tailscale identity injected through a private
   Unix socket. All MCP arguments remain untrusted after authentication.
2. **Tailscale Serve to HTTP origin.** In Tailscale mode, the connector trusts
   `Tailscale-User-Login` only when Kestrel observes a Unix-socket connection.
   The socket parent must be a pre-existing, non-symlinked `0700` directory.
   Tailscale Serve and the host's root boundary are therefore part of the
   authentication system.
3. **Connector to local UniFi controller.** `UNIFI_BASE_URL` is
   operator-controlled but must be absolute HTTPS, contain no credentials,
   query, or fragment, and end in `/proxy/network/integration`. Normal
   certificate and hostname validation is required. The connector sends the
   Integration API key and consumes untrusted JSON responses. Contract
   discovery may also read the fixed same-origin sibling resource
   `/proxy/network/api-docs/integration.json`; caller input cannot select that
   path or another controller resource, and contract responses are capped at
   2 MiB before JSON parsing.
4. **Connector to UniFi Site Manager.** The origin is fixed to
   `https://api.ui.com`; a separate optional key is used. Only stable-v1
   inventory and ISP-metric reads are intended.
5. **Official contract to private API adapters.** Official Integration API
   operations are the authority. Opt-in private reads cross a separate
   compatibility boundary and must remain fixed, bounded, projected, redacted,
   and explicitly provenance-labelled. They must never become arbitrary proxy
   access or silently override official state.
6. **Connector to local journal.** Normalized projected client metadata moves
   from upstream responses into a cleartext local SQLite database. Filesystem
   ownership/mode, symlink resistance, local-filesystem semantics, migrations,
   checksums, WAL behavior, locks, and recovery are part of this boundary.
7. **Environment/secret injector to process.** The env file may be a
   1Password-mounted FIFO or a protected deployment file. The loader parses it
   as dotenv data, imports only supported `UNIFI_*` variables, and preserves
   explicitly inherited values. It must never execute the file as shell code
   or reveal its contents in errors.
8. **Source/build pipeline to runtime.** NuGet packages, base images, the
   embedded OpenAPI file, and publishing scripts become executable runtime
   inputs. Package locks, warning policy, digest-pinned images, and reviewed
   update scripts reduce but do not remove this trust.

### Input classification

Attacker-controlled or potentially attacker-influenced input includes:

- every MCP tool name and argument received from a client;
- HTTP request metadata and serialized MCP bodies;
- all controller and Site Manager response bodies, headers, pagination
  metadata, `Retry-After` values, and controller-served OpenAPI documents;
- user-visible UniFi names, comments, notes, descriptions, and log parameters;
- an existing journal database when its directory integrity is not assured;
  and
- dependency or image content after a supply-chain compromise.

Operator-controlled input includes environment variables, env-file and journal
paths, API endpoints permitted by configuration validation, feature gates,
site IDs, retention/size limits, authentication mode, public/listen URLs, and
Tailscale identities.

Developer-controlled input includes the embedded contract, fixed private
paths and projections, tool annotations, package locks, container digests, and
release/update scripts.

### Assumptions

- The host, container runtime, Tailscale daemon, 1Password secret injector, CA
  trust store, and root account are administered as trusted infrastructure. A
  host-root attacker can read process secrets, replace binaries, access the
  journal, or impersonate the proxy and is outside the connector's containment
  boundary.
- The UniFi API keys have no broader privilege than operationally necessary.
  The connector cannot compensate for an over-privileged upstream key.
- Tailscale identity mode is deployed only with a Tailscale version that
  restricts Unix-socket Serve targets to root, and no other process can enter
  the socket's `0700` parent.
- Bearer mode is exposed only through HTTPS or a comparably protected
  transport. `UNIFI_MCP_HTTP_PUBLIC_URL` validates public authority; it does
  not itself add TLS to a plaintext Kestrel listener.
- All authenticated users of one process share the same tool set and
  in-memory confirmation store. There is no tenant, role, or per-session
  isolation. A confirmation token is a bearer capability; explicit human
  approval is an agent/client policy, while the server enforces token
  possession, expiry, single use, and state binding.
- Redaction is defense in depth, not a reason to return raw upstream objects.
  Projections and schema allowlists are the primary data-minimization control.
- Controller-derived free text can contain prompt-injection-like instructions.
  The connector treats it as data and does not execute it, but downstream MCP
  clients and agents must not treat that content as trusted instructions.
- This model does not attempt to secure the UniFi controller, Site Manager,
  Tailscale, 1Password, Docker registry, or NuGet ecosystem themselves. Issues
  are in scope when connector behavior materially expands the impact of their
  compromise.

## Attack Surface, Mitigations, and Attacker Stories

### MCP transport and authentication

Relevant code: `Program.cs`, `HttpServerCommand.cs`,
`McpHttpSecurityMiddleware.cs`, and `UnifiConfiguration.cs`.

Realistic attacker stories include an exposed Kestrel listener, bearer-token
theft, forged proxy identity, DNS rebinding or cross-origin browser requests,
and an authenticated user invoking a tool outside the operator's intent.

Existing controls include:

- bearer mode by default, minimum token length, hashed fixed-time comparison,
  and `WWW-Authenticate` on failure;
- Tailscale identity acceptance only over a Unix socket and against an
  explicit case-insensitive allowlist;
- exact public `Host` validation, same-authority `Origin` validation when an
  Origin is supplied, and `Cache-Control: no-store`;
- stateless HTTP transport, no LAN-published Docker port in the tracked
  deployment, and a private Tailscale Serve origin; and
- a non-root, read-only container with all Linux capabilities dropped and
  `no-new-privileges`.

Security reviews should pay particular attention to middleware ordering,
alternate MCP paths, proxy/header trust, socket replacement or permission
races, listen-address changes, token disclosure in logging, and any attempt to
introduce unauthenticated health or administrative endpoints that expose
sensitive state.

The tracked container uses host networking. A runtime compromise may therefore
reach services available from the Pinode host network namespace even though
the MCP listener is a Unix socket. Non-root execution and a read-only
filesystem reduce host modification, but egress and local-service reachability
must remain part of deployment review.

### Operation allowlisting, request construction, and SSRF/injection

Relevant code: `ContractProvider.cs`, `OpenApiContract.cs`,
`UnifiClient.cs`, `SiteManagerClient.cs`, and the read-service classes.

All client-supplied operation IDs, path/query values, and JSON bodies are
untrusted. The important invariant is that validation produces a request only
for a known operation and its declared schema, with escaped parameters and no
caller-selected origin, raw path, HTTP method, or header.

Existing controls include contract-defined operations, rejection of unknown
parameters, JSON-schema validation, URI escaping, an HTTPS/suffix-constrained
local base URL, a fixed Site Manager origin, and fixed private resources. The
private System Logs POST has an empty connector-created body and is a read;
callers cannot choose its method, path, or body.

A controller-served OpenAPI document is a special trust case. It is accepted
only when parseable and version-matched to the live application, but a
compromised controller could still publish a malicious same-version contract.
Reviews should ensure such a contract cannot create arbitrary-origin requests,
inject headers, bypass preview/apply, or cause unsafe schema complexity. The
reviewed embedded contract must remain the fail-closed fallback.

The embedded update workflow may ingest an official contract downloaded from
the authenticated local documentation because the public developer download
can lag a Network release. The updater validates the exact requested version
and replaces controller-specific `servers` metadata before vendoring it, so a
live controller address is not committed. Runtime request origins continue to
come only from validated `UNIFI_BASE_URL`; OpenAPI `servers` entries are not
used for request routing.

Classic SQL injection is low relevance for upstream reads because the
connector does not build SQL from MCP values for controller access. SSRF,
path/query injection, schema-validation bypass, JSON parser exhaustion, and
unsafe dynamic contract expansion are the important classes here.

### Mutation preview and apply

Relevant code: `WritePlanner.cs`, `ConfirmationStore.cs`,
`CanonicalJson.cs`, and the preview/apply tools in `UnifiTools.cs`.

An authenticated client can ask for a preview of any allowlisted non-GET
operation. It must not be able to mutate during preview or apply a different
method, target, query, or body than the previewed request.

Existing controls include cryptographically random 256-bit tokens, a five
minute lifetime, single-use consumption before checks, a bounded pending
store, canonical hashes of readable pre-state and safety state, exact voucher
binding, reference checks for network deletion, explicit destructive MCP
metadata, and no automatic retries for mutations.

Important attacker stories are token theft from tool output, replay,
cross-client token consumption in a shared process, race/state changes between
preview and apply, partial-state reads that make a destructive operation look
safe, schema projection that drops a safety-relevant field, and a new write
tool that bypasses the planner. Explicit user approval is not enforced by a
separate identity or signature inside the connector, so deployments must not
treat transport authentication as fine-grained write authorization.

### Upstream responses, projection, redaction, and semantic integrity

Relevant code: `SecretRedactor.cs`, `ToolResponse.cs`,
`ResponseMetadata.cs`, `PrivateReadResponseParser.cs`, the enrichment/read
services (including `WifiDiagnosticsReadService.cs`), and `SnapshotService.cs`.

Upstream JSON can be malformed, contradictory, oversized, stale, or contain
secret-like or instruction-like text. The connector must preserve provenance,
bound pages and record counts, redact recursively, and fail closed rather than
invent a complete network state.

Existing controls include projection of private response fields, recursive
secret-name and inline-pattern redaction, bounded history/group/log and Wi-Fi
diagnostics reads, validated counts and pagination, per-section snapshot
failure, explicit source/authority metadata, nullable version-drift behavior,
and separation of current, historical, and group-membership grains. Wi-Fi
diagnostics combine only fixed active-client and device resources, discard
unknown fields, and distinguish configured radio state, operational radio
state, and explicitly documented derivations. Wired or transport-unknown client
records are excluded before output limits, nested radio arrays have per-device
and aggregate source ceilings, and anonymous configuration/statistics records
are not correlated by array position.

Prompt injection through device names, comments, or System Log descriptions
is not code execution in this repository, but it becomes security-relevant if
an MCP client automatically follows those strings as instructions or feeds
them into an approved write. Preserve structured provenance and do not add
language that presents upstream free text as trusted operational guidance.

### Secrets and configuration

Relevant code: `EnvironmentFileLoader.cs`, `UnifiConfiguration.cs`,
`UnifiClient.cs`, `SiteManagerClient.cs`, `.env.example`, `.gitignore`, and
deployment documentation.

Realistic failures include committing a resolved env file, shell-executing
dotenv input, accepting unresolved `op://` references, leaking request headers
or bodies through exceptions, logging a URL containing a secret query value,
or copying controller credentials into the journal.

Existing controls include a Git-ignored `.env`, an allowlist of imported
variables, inherited-value precedence, generic parser errors, rejection of
unresolved 1Password references, separate local and Site Manager keys,
redacted errors/output, and journal field minimization. The unattended
deployment secret file is outside the image/build context and must remain
mode `0600`.

Secret-redaction changes require adversarial tests for alternate casing,
nested arrays/objects, inline assignments, URLs, private keys, Wi-Fi secrets,
vouchers, and exceptions. No test or diagnostic should print resolved
credentials.

### Client journal and filesystem

Relevant code: `ClientJournalStore.cs`, `ClientJournalService.cs`,
`ClientObservationCollector.cs`, migrations, scheduled collection, and
`JournalCommand.cs`.

The journal contains cleartext household identifiers and history. An attacker
who can select or replace its path could attempt symlink traversal, unsafe
permissions, database substitution, corruption-triggered overwrite, quarantine
path abuse, disk exhaustion, lock starvation, or rollback to an incompatible
schema.

Existing controls include an absolute path, local-filesystem requirement,
non-symlinked private parent and active paths, `0700`/`0600` modes, WAL with
full synchronization and foreign keys, checksummed transactional migrations,
bounded retention/size, whole-collection pruning, write serialization, a
cross-process sibling lock, read-only health inspection, no automatic
recovery, exact corruption-fingerprint revalidation, quarantine, and rollback
if fresh initialization fails.

Reviews should preserve the invariant that read-only tools never create,
migrate, prune, recover, or chmod journal state. Incomplete source collections
must contribute positive evidence only; absence from a partial or failed
source must never become an offline/removal assertion.

Encryption at rest is not provided by the connector. Filesystem and host-volume
protection are therefore required. Adding more journal fields changes the
privacy model and requires an explicit update to this document.

### Availability, rate limits, and resource exhaustion

Authenticated clients and hostile upstreams may induce expensive snapshots,
large pages, slow responses, repeated previews, collection overlap, SQLite
growth, or provider throttling.

Existing controls include bounded configuration values and page sizes,
timeouts, limited Site Manager concurrency/queues, a process-wide rate ceiling
and cooldown, five-minute coalescing/caching for discovery, pending-preview
limits, journal size/retention caps, collection locks, and structured partial
results for appropriate read aggregation.

Reads may retry transient failures and `429`; writes are sent exactly once.
Review retry changes for amplification, retry-after overflow, slot starvation,
unbounded response buffering, and cancellation propagation. Availability
problems normally have lower severity than authorization or integrity failures
unless they prevent recovery or disrupt essential network administration.

### Build, contract update, and release

Relevant files: `packages.lock.json`, `global.json`, `Directory.Build.props`,
`Dockerfile`, `docker-compose.yml`, and `scripts/`.

The build executes NuGet package code and uses .NET container images. The
repository pins locked packages, treats warnings as errors, explicitly pins
the native SQLite bundle, and digest-pins both container stages. The OpenAPI
update script downloads over HTTPS and validates document shape and the
expected version before replacement. Publishing scripts can install a local
release or push an ARM64 image to a private registry.

Supply-chain review should cover unexpected lockfile changes, package/build
script execution, digest updates, OpenAPI semantic changes, dirty-source
publishing, registry identity, and symlink-safe activation of local releases.
Developer tooling does not process MCP attacker input, but compromise here can
replace the entire runtime and is therefore high impact.

### Out-of-scope or lower-relevance stories

- Direct compromise of UniFi, Site Manager, Tailscale, 1Password, the host root
  account, registry, or developer workstation without a connector weakness.
- Physical attacks, malicious firmware, radio attacks, and general LAN
  segmentation flaws not created or worsened by a connector operation.
- Browser-specific CSRF/XSS against a rendered UI: the repository serves MCP,
  not an HTML application. Host/Origin validation remains relevant to browser
  and proxy abuse.
- Traditional multi-tenant data isolation: the intended deployment has no
  tenants. If the service is offered to mutually untrusted users, this
  assumption is invalid and per-principal authorization, token scoping,
  journal partitioning, and confirmation ownership become required.
- Exact uptime of third-party APIs. Unsafe retries, secret leakage, corrupted
  state, or misleading success during an outage remain in scope.

## Severity Calibration (Critical, High, Medium, Low)

Severity combines realistic reachability in the intended private deployment
with confidentiality, integrity, availability, and recovery impact.

### Critical

Use Critical only for a realistic path to broad, unauthenticated compromise of
the connector host or managed network, or equivalent secret compromise with
that effect.

Examples:

- an HTTP authentication/proxy-boundary bypass reachable outside the trusted
  tailnet that permits arbitrary firewall, ACL, DNS, Wi-Fi, or network writes;
- MCP input causing arbitrary command execution or arbitrary host-file
  overwrite in the production container/host boundary; or
- exfiltration of a sufficiently privileged controller credential to an
  unauthenticated remote actor, with demonstrated broad network-control impact.

A defect requiring host root, a compromised controller, or an already
authorized operator is normally not Critical because those actors already
cross the primary trust boundary.

### High

Use High for a practical authenticated or adjacent-network path to major
network integrity loss, credential disclosure, durable privacy compromise, or
host-impacting filesystem behavior.

Examples:

- bypassing preview/apply binding to execute a materially different or stale
  destructive controller mutation;
- forging a Tailscale identity from an unprivileged local or LAN process;
- arbitrary-origin authenticated requests that disclose an API key or make the
  connector a privileged SSRF client;
- returning controller, Site Manager, bearer, Wi-Fi, voucher, or private-key
  secrets through ordinary tool output or logs; or
- journal path/recovery manipulation that overwrites unrelated files or
  exposes the full retained client-history database.

### Medium

Use Medium for bounded unauthorized disclosure or modification, meaningful
semantic-integrity failures, or repeatable authenticated denial of service
without broad host/network compromise.

Examples:

- exposing household client history, MAC/IP addresses, event details, or ISP
  metrics to an unintended but authenticated principal;
- accepting contradictory or partial source data as authoritative and using it
  to approve a destructive action;
- cross-client consumption of a preview token in a deployment that knowingly
  serves more than one mutually untrusted authenticated user;
- unbounded response, queue, preview, or collection behavior that reliably
  exhausts the private service; or
- unsafe prompt-like upstream text being presented as trusted instructions in
  a way that creates a credible downstream action path.

### Low

Use Low for limited metadata exposure, defense-in-depth gaps, low-impact
availability issues, or misleading output that does not cross a consequential
authorization or integrity boundary.

Examples:

- disclosure of non-secret version, tool-count, or coarse health metadata;
- a malformed upstream record causing one bounded read to fail safely;
- missing `no-store` or overly detailed redacted error text where no secret or
  sensitive household data is exposed; or
- stale limitation/provenance wording that may confuse an operator but cannot
  itself authorize or execute a change.

Pure code-quality issues, speculative attacks without the required attacker
control, and behavior fully contained by an explicit fail-closed check are not
security findings unless a concrete security impact is demonstrated.
