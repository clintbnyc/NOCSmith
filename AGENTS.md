# NOCsmith repository instructions

These instructions apply to the entire repository. Also follow the inherited
workspace instructions in `../AGENTS.md` and `/Users/cbeilman/source/AGENTS.md`.

## Product and compatibility

- The product name is **NOCsmith by Clint**. The tagline is **Network
  intelligence, forged safely.**
- Preserve `unifi-mcp` as the executable, assembly name, MCP server ID,
  container/image name, repository slug, deployment namespace, and local
  publish directory unless a migration is explicitly requested.
- Preserve existing `UNIFI_*` environment-variable names and public MCP tool
  names. Treat changes to these identifiers as compatibility changes.
- This project is independent of and is not endorsed by Ubiquiti. Do not imply
  otherwise in documentation or metadata.

## Architecture

- `src/UnifiMcp/` contains the .NET 10 server and command-line entry points.
- `src/UnifiMcp/Api/` contains controller and Site Manager clients. Keep
  upstream request construction inside these reviewed boundaries.
- `src/UnifiMcp/Contracts/` loads and validates the official UniFi OpenAPI
  contract. `contracts/unifi-network.openapi.json` is the reviewed embedded
  fallback, not an incidental generated artifact.
- `src/UnifiMcp/Tools/` contains MCP-facing services and response projection.
  Keep tool registration and descriptions aligned with implemented behavior.
- `src/UnifiMcp/Writes/` owns canonical previews, confirmation capabilities,
  drift checks, and mutation planning.
- `src/UnifiMcp/Journal/` owns the optional SQLite observation journal,
  migrations, collection, retention, and recovery.
- `src/UnifiMcp/Security/` and `McpHttpSecurityMiddleware.cs` contain security
  controls that must remain centralized and directly tested.
- Tests in `tests/UnifiMcp.Tests/` should mirror the production component being
  changed. Add focused regression tests for every bug fix and security boundary.

## Security invariants

Read `SECURITY.md` and `docs/threat-model.md` before changing a transport,
authentication mode, upstream API, private resource, write path, persistent
field, executable input, deployment boundary, or secret-handling path.

- Never turn the connector into an arbitrary HTTP, filesystem, process, or SQL
  proxy. Caller input must not select an unreviewed origin, URL, method, header,
  path, command, or query.
- The official Network Integration API is authoritative. Private UniFi reads
  must remain opt-in, fixed-resource, bounded, explicitly projected, redacted,
  and provenance-labelled. Never return raw private responses.
- Site Manager access is read-only. Use a separate API key and keep requests on
  the reviewed stable-v1 resources.
- Every controller mutation requires an allowlisted preview, a short-lived
  single-use confirmation capability, and a matching live-state check.
  Mutations are sent exactly once and are never automatically retried.
- Treat controller-supplied names, notes, log text, identifiers, response
  shapes, counts, and pagination as untrusted input.
- Redaction is defense in depth. Prefer explicit response projections and
  schema allowlists; do not rely on redaction to make an overbroad response safe.
- Partial, contradictory, malformed, stale, or unsupported data must fail
  closed or be reported as partial. Do not invent topology or certainty.
- Read-only journal operations must not create, migrate, prune, recover, or
  alter filesystem permissions. Keep journal path and symlink checks fail closed.
- Never print, log, commit, test with, or copy real credentials, tokens, private
  keys, controller data, or journal contents. A resolved `.env` file is secret.

## Implementation conventions

- Use C# 10 with nullable reference types enabled. Warnings are errors.
- Prefer small services with explicit interfaces, dependency injection, and
  immutable or narrowly scoped models over shared mutable state.
- Preserve cancellation tokens through async call chains. Do not introduce
  blocking waits around network or database operations.
- Bound pagination, response sizes, concurrency, retry delays, history windows,
  and persistent growth. Respect upstream rate-limit signals.
- Reads may retry only documented transient failures. Writes must not retry.
- Keep source/provenance and observation timestamps attached when combining
  official, private, cloud, or journal data.
- Avoid broad mechanical rewrites of the vendored OpenAPI contract. Update it
  with `scripts/update-openapi.sh`, inspect the semantic diff, and update tests
  and documented compatibility when accepting a new version.
- Do not silently change feature-gate defaults. Optional private reads, Site
  Manager, journaling, and scheduled collection must remain off unless enabled.

## Documentation

- Keep `README.md` product-facing and concise. Put operational detail in
  `docs/operations.md`, vulnerability policy in `SECURITY.md`, and trust-boundary
  analysis in `docs/threat-model.md`.
- Update `.env.example` and the operations reference when configuration changes.
  Examples must use placeholders or reserved example domains, never live values.
- Update the threat model and add focused adversarial tests for any
  security-relevant boundary change listed above.
- Keep documented tool counts, versions, feature gates, endpoints, and limits
  synchronized with code and tests.

## Verification

Use the smallest focused test while iterating, then run the complete checks
before handing off a code change:

```sh
dotnet restore UnifiMcp.slnx --locked-mode
dotnet format UnifiMcp.slnx --no-restore
dotnet test UnifiMcp.slnx --configuration Release --no-restore
git diff --check
```

Also run `bash -n` or `sh -n` for modified scripts and validate relative
Markdown links for documentation changes. If a full check cannot run, report
exactly what was skipped and why.

## Publishing and live systems

- Source changes do not authorize publishing, deployment, controller writes,
  MCP registration changes, service restarts, or GitHub operations.
- Use `scripts/publish-local.sh` only when local publishing is explicitly
  requested. It must publish a fresh tested release and atomically move the
  stable `current` symlink; never overwrite the active release in place.
- `scripts/publish.sh` builds and pushes the private ARM64 image. Running it is
  an external release action and always requires explicit authorization.
- Keep rollback releases. Do not prune releases or repoint `current` to an older
  build unless requested.
- For live UniFi work, prefer read-only discovery first. Preview any mutation
  and require explicit approval of that exact preview before applying it.

## Change discipline

- Preserve unrelated user changes in a dirty worktree. Stage only files in the
  requested scope and do not rewrite history without explicit authorization.
- Keep commits focused. Separate bug fixes, features, documentation, generated
  contract updates, and deployment changes when their rollback boundaries differ.
- Report verification evidence and any unverified live behavior at handoff.
