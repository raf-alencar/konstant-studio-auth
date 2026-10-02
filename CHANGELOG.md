# Changelog

Semantic versioning. v1 exports are never removed in a minor release; they are deprecated first, with a notice and a documented removal condition.

## 0.3.0 — resource lookups (C0c2)

### CoS verdict 4 fixes (rc3)
- **No anonymous ownership oracle.** With `tenantOf`, a credential only the platform can verify (agent, guest, MCP keys, audience tokens) is verified first; an unverified caller learns the credential outcome only (the same `401` for an owned and an unowned id, and no `503`-before-`401` from the registry).
- **One caller-visible reason.** An unowned id, an id of another tenant, and a conflicting explicit tenant are all `403 no_permission` (the post-decision helpers too); the audit event keeps the distinction (`detail`), and the returned result does not carry it. (`resource_not_owned` and `tenant_mismatch` are no longer returned to callers.)
- **No stale ownership for writes.** A stale registry answer is served for reads (the decision says `stale: true`) and refused with `503` for writes and for an unknown permission category; decisions now carry their permission `category`.
- Hardening: a snapshot tenant without a string `id` makes the snapshot unsupported (never "unowned"); repeated rows are counted and listed once; ids are sorted lazily and without allocating per comparison, so a large tenant no longer blocks the event loop.
- Docs: with `tenantOf` the owner wins over the Clerk org claim (a user bound to org tenant A who is also a member of B can act on B's objects; membership still required).

### Added
- `tenantFor(kind, localId)` and `resourcesFor(tenantId, kind)` (Python: `tenant_for`, `resources_for`): ownership lookups from the cached snapshot's per-tenant `resources` (platform C0f), so adopting repos keep no brand/company-to-tenant mapping. Fail closed (unavailable when the registry cannot be read or the platform has no C0f), `null` for an unowned id, refusal of an id claimed by two tenants, a reverse index built once per snapshot and bounded by `maxResources`.
- `tenantOf: { kind, id }` scope option (Express, Next.js, FastAPI `tenant_of`): the tenant is the owner of the object about to be touched; unowned, another tenant's, or a conflicting explicit tenant is `403 no_permission` (one answer; the audit event keeps the detail), an unreadable registry `503`.
- `requireResourceInTenant` (Express), `checkResourceInTenant` (Next.js), `require_resource_in_tenant` (FastAPI): after a decision, refuse an object that belongs to another tenant.
- Shared vectors: 29 lookup cases and 8 `tenantOf` decision cases for both languages.

### Verified against the real platform
- Parity is pinned to platform commit `5a6a698` (round 2, the commit the CoS accepted for deploy; archive the exact hash). The e2e suites run against a scratch copy built in the platform's own hash-locked environment: the world's snapshot `resources` equals the real one, every lookup vector agrees with the platform's own reverse lookup and list, the 8 `tenantOf` decision cases match `/v1/authorize`, and a service registers through `POST /v1/resources` (idempotent 200/201, 409 for another tenant's id without naming the owner, one 403 for an unentitled tenant, 422 for a value the registry cannot hold, retirement frees the id) with the library following through the change feed.

### One canonical id rule
- Both languages accept exactly what the registry could hold and nothing else: lowercase-slug `kind`; `localId` a 1-200 character string without control characters compared exactly, or a non-negative safe integer (its decimal text). BigInt, booleans, negatives, non-integers and out-of-range integers are refused (previously Node accepted any BigInt and Python an integral float). Lists are ordered by code point in both. 21 new shared vectors make each rule observable.

### Test infrastructure
- The e2e files run serially (a latent race between the change-feed test and the effective-permissions parity test); the scratch harness registers the world's registry rows through the platform's own API, refuses a port clash, and terminates its children if start-up fails.

## 0.2.0 — control-plane authorization (v2)

### Final fixes (CoS verdict 2, on 13ae0c4)
- **R1 closed:** a token that carries an org claim never uses the `x-tenant` header: an unmapped org is `tenant_required` (or `503` when the snapshot cannot be read), not a fallback to the header. The header remains a hint only for tokens with no org claim and for keys. A repeated `x-tenant` header is ignored.
- List options (`authorizedParties`, `audience`, `acceptedCallerServices`) must be arrays of non-empty strings in both languages.
- The signed change webhook asks for a fresh refresh, and `invalidate()` really expires the cached snapshot (it was a no-op against the monotonic clock early in the process life).
- Globs: `*` and `**` need at least one character (`GET /internal/*` no longer authorises `/internal` or `/internal/`); `;`, backslashes, Unicode line separators and single-dot segments are refused; `@clerk/express` and `svix` pinned; a malformed resolve reply is "could not decide", never cached as an invalid key; `effectivePermissions` degrades to a 503 instead of throwing.

### Security review fixes (CoS review of 011275b)
- **R1** `x-tenant` is only a hint (last in the tenant order) so a header cannot move a token off its org's tenant; v2's `req.auth` drops `orgId`/`orgRole` (they invited scoping data by the token's org) and gains `tenantId` (the only scoping key), `clerkOrgId`, `clerkOrgRole`. Audit events carry `tenant_source`.
- **R2** Service-key resolutions: key-shape check before any platform call; LRU valid cache plus a separate small invalid cache (garbage cannot flush good entries); a cap on in-flight resolutions; a platform 429 pauses resolution instead of becoming a verdict; nonsensical numeric options are startup errors in both languages.
- **R3** Route policy matches the path as sent; `*` is one segment, `**` many; any `%`, `..`, `//` or control character is refused; policies are validated at wiring.
- **R4** Platform booleans must be exactly `true`/`false`; an allow must name a principal and the tenant asked about.
- **R5** The tenant resolver and org lookup run only for locally verified Clerk sessions.
- Hardening: JWKS single-flight with a failure backoff; a change event is never lost to an older in-flight refresh; TTLs use a monotonic clock (the wall clock still governs token and window validity); a repeated credential header/cookie is refused; a malformed cookie escape never throws; `decideOffline` has no default principal kind; the Next adapter never throws; pinned dependencies.
- Shared vectors now also pin credential extraction and route-policy paths for both languages; the service-key vectors are un-pended and parity is re-pinned to platform commit 8335387.

### Added
- `@konstant-studio/auth/v2` (`createAuth`, also exported lazily from the package root): resolves a Clerk session token, agent key, guest key, MCP key or service key to one `Principal`; `requirePermission('service:action', { tenant, brand, domain, mailbox })`, `requireApprover({ stepUp })`, `assertTenant`, `usageContext`. Deny by default; decisions come from the stighive-platform control plane (`/v1/authorize`, the cached snapshot with ETag, the change feed).
- Offline Clerk verification with a **mandatory `azp` check** (refuses to start without `CLERK_AUTHORIZED_PARTIES`).
- Inbound service keys (`stgs_`): explicit `acceptedCallerServices` (never "any"), `expect_service` always sent, uniform `key_not_found`, a bounded 60 s / 10 s resolution cache keyed by a credential hash, no tenant permissions (`service_principal_not_granted`), and `requireServiceCaller` / `withServiceCaller` / `require_service_caller` for the app's own per-caller-service route policy (the platform's `allowed_routes` are not exposed).
- Clerk organization -> tenant from the snapshot's `org_id` (v1 `org_id` and v2 `o.id` token shapes); a `tenantResolver` still takes precedence.
- `effectivePermissions()` with `permits()`: the platform's effective permissions, parity-tested against `/v1/authorize`.
- Snapshot cache: ETag revalidation, TTL, change-feed polling (optional signed webhook receiver), bounded-age stale reads, fail-closed for sensitive actions and key checks.
- Adapters: Express, Next.js route handlers (Web-standard `Request`/`Response`), and (Python) FastAPI.
- A caller-supplied tenant that is not a UUID is a clean `403 tenant_not_found`, never a platform 422 reported as an outage; `x-run-id` is bounded and filtered before it reaches an audit event.
- Auth audit events (`onEvent`) and the usage-event actor; no token or key ever appears in either.
- `test-vectors/vectors.json`: one shared fixture for the Node and Python suites, reusable as adopter acceptance tests.
- Python package: the same API under `konstant_studio_auth.v2`.
- `docs/MIGRATION.md`, `docs/ADOPTION-CHECKLIST.md`.

### Deprecated (behaviour unchanged)
- `m2mAuth` and the `X-API-Key`/`INTERNAL_API_KEY` branch of `protectOrM2M` (Python: `m2m_auth`, `protect_or_m2m`): the shared-key path. **Removal is tied to the platform's `ACCEPT_SHARED_KEY=false` cutover, which the CoS decides.**
- `requireService` / `require_service`: entitlement-only gate through the legacy `/entitlements/{org}` endpoint. Replaced by `requirePermission`.
- One `DeprecationWarning` per process; `KSA_SILENCE_DEPRECATIONS=1` silences it.

### Known gaps
- Inbound service keys follow the CoS contract note for the platform's C0b2. The committed C0b2 (`79f4fce`) already resolves them; the CoS's fixes (mandatory `expect_service`, uniform `key_not_found`, audit bounds) are still to land, so the shared service-key vectors stay `pending-platform`. The library is correct against both: it always sends `expect_service` and answers uniformly whatever specific reason the platform gives.
- Not deployed: the production platform (c872475) has no `org_id` in its snapshot and does not resolve `stgs_` keys. The library degrades safely: no org mapping (the platform decides), service keys refused.
- Step-up reads Clerk's `fva` claim; its presence in this Clerk instance's session tokens is unconfirmed.

### Fixed (docs)
- README: `getBrandId` description now matches the 5cc7b40 behaviour.
