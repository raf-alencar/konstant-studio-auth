# Changelog

Semantic versioning. v1 exports are never removed in a minor release; they are deprecated first, with a notice and a documented removal condition.

## 0.2.0 — control-plane authorization (v2)

### Added
- `@konstant-studio/auth/v2` (`createAuth`, also exported lazily from the package root): resolves a Clerk session token, agent key, guest key, MCP key or service key to one `Principal`; `requirePermission('service:action', { tenant, brand, domain, mailbox })`, `requireApprover({ stepUp })`, `assertTenant`, `usageContext`. Deny by default; decisions come from the stighive-platform control plane (`/v1/authorize`, the cached snapshot with ETag, the change feed).
- Offline Clerk verification with a **mandatory `azp` check** (refuses to start without `CLERK_AUTHORIZED_PARTIES`).
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
- Inbound service keys (`stgs_`): the platform cannot resolve them yet (C0b2). v2 ships an isolated stub (`401 unsupported_credential`, exactly what the platform answers today); the vectors are `pending-platform`.
- Clerk org -> tenant: pass a `tenantResolver` until the platform's snapshot carries `org_id`.
- Step-up reads Clerk's `fva` claim; its presence in this Clerk instance's session tokens is unconfirmed.

### Fixed (docs)
- README: `getBrandId` description now matches the 5cc7b40 behaviour.
