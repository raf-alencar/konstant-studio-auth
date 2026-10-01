# Changelog

Semantic versioning. v1 exports are never removed in a minor release; they are deprecated first, with a notice and a documented removal condition.

## 0.2.0 — control-plane authorization (v2)

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
