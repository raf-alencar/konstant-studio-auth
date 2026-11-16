# konstant-studio-auth — Codebase Map

**Last updated:** 2026-11-16
**Updated by:** claude-opus-4-7
**Repo:** github.com/raf-alencar/konstant-studio-auth
**Current tag:** v1.0.0 (f75fa5a, published 2026-11-16, publish record befe1cde)
**graph_doc_id:** (set by graph on creation)

---

## Purpose

Shared auth library for the Konstant Studio and StigHive apps: it turns an inbound request's credential (Clerk session, service key, agent/guest/MCP key, Cloudflare Access token) into a Principal, picks the tenant the request is about, and answers "may this principal do `service:action` here?" against the stighive-platform control plane. Ships in **Node** (`@konstant-studio/auth`) and **Python** (`konstant-studio-auth`) with parity enforced by shared test vectors. Express, Next.js and FastAPI adapters cover the common surfaces; a small `tenantAudit` helper gives every consumer the same shape for its `/internal/tenant-audit` endpoint.

Not a gateway, not a key store. The platform holds the authorise rules and the registry; this library reads a cached snapshot for the offline-eligible decisions (human Clerk session, this service's own non-sensitive permission, named tenant) and forwards everything else to `POST /v1/authorize`.

---

## v1.0.0 (CR 53a0f327): what changed and what's current

The 1.0.0 cut is the first major that reshaped tenant selection. The old org-claim mapping and the x-tenant hint are gone.

**Tenant selection order (`selectTenant` in `v2/auth.js` and `python/.../v2/auth.py`), decision 321168bc #12:**

1. **explicit** — an app-code tenant on `resource.tenant` (or the route scope). Always wins.
2. **tenantResolver** — the adopter's callable (`cfg.tenantResolver(req, principal)`), app code, under the same rule as explicit.
3. **default_tenant_id** — from `GET /v1/users/me/memberships` on the platform (CR-P1). The platform already drops a default that no longer points at an active membership, so an inactive default is absent here and the next step runs.
4. **single membership** — exactly one active membership in the response: use it.
5. **TenantChoiceRequired** — adapters surface HTTP **409 `tenant_choice_required`**.

The platform's `/v1/authorize` is the final gate for reachability (member of the tenant OR reaches it through an agency/parent grant, per decision 90fdd2fe). The library does not pre-check: an unreachable explicit is denied with `no_permission` by the platform.

**Removed (consumer-visible, breaking):**
- **`org_id` mapping is gone.** The Clerk session's `org_id` claim (both the v1 `org_id`/`org_role` and the v2 `o.id`/`o.rol`) is still parsed into `principal.claims` for display and audit, but it is **never read for tenant selection**. A token cannot move itself off an org by naming one.
- **`hint` is gone.** The `x-tenant` header is no longer consulted by the Express/Next/FastAPI adapters. `resource.tenantHint` / `tenant_hint` are removed. Consumers that still send the header reach the same decision; it is silently ignored.
- The library reason `tenant_required` is no longer produced by `selectTenant`; the library-side refusal is now `tenant_choice_required` with HTTP 409.

**Added:**
- **`client.memberships(clerkToken)`** / **`client.memberships(clerk_token)`** — new `GET /v1/users/me/memberships` client method; the user's Clerk session is carried in `X-Acting-Token`, the service key still authenticates the transport. Response: `{user_id, identity, default_tenant_id, memberships: [{tenant_id, tenant_slug, tenant_name, tenant_type, role_slug, scope, status:"active", expires_at, entitled_services}]}`.
- **Per-user in-process cache** (default 60 s, `membershipCacheTtlSeconds` / `membership_cache_ttl_seconds`) in front of that call, so a repeated `authorize()` for the same principal does not re-fetch.
- **`tenantAudit` helper** (`tenant_audit` in Python) — service-key guarded, uniform `{ok, status, service, tenant_id, counts, stale}` shape for every app's `/internal/tenant-audit` endpoint. Optional `callerService` pins which caller service key is accepted.
- **Reason `tenant_choice_required` → status 409** in `v2/reasons.js` and `python/.../v2/reasons.py`; `409 "Tenant choice required"` added to the shared denial body map in both adapter shims.

**Unchanged (worth saying):**
- Service keys, agent/guest/MCP keys, Cloudflare Access audience tokens: tenancy comes from the credential itself via `POST /v1/authorize` (and `POST /v1/principals/resolve` for identity-only paths). `GET /v1/users/me/memberships` is **not** called for them.
- Offline-eligible decisions still require a Clerk session, this service's own non-sensitive permission, and a named tenant; everything else is `live`.
- The snapshot shape (`tenants[].ancestors`, `memberships[].scope.descendants`) already encodes the parent/grant relation; no new snapshot field was needed in the platform CR.

---

## Architecture

```
HTTP request
  └─ adapter (express.js / next.js / fastapi.py)
       └─ extract(headers) → { type, raw, keyKind }         v2/credentials.js
       └─ resolveScope(req) → { tenant, brand, domain, mailbox, tenantOf }
       └─ core.authorize({ headers, permission, resource, req }):
            ├─ principalFrom(cred)
            │    ├─ clerk → ClerkVerifier.verify()           v2/clerk.js
            │    ├─ service key (stgs_) → ServiceKeyResolver v2/service-keys.js
            │    └─ agent/guest/MCP → deferToPlatform
            ├─ resource.tenantOf? → tenantFor(kind, localId) v2/resources.js
            ├─ selectTenant(explicit, principal, cred, req)  v2/auth.js
            │    ├─ explicit  → source: 'explicit'
            │    ├─ resolver  → source: 'resolver'
            │    ├─ default_tenant_id  → source: 'default'       (memberships cache)
            │    ├─ single membership → source: 'single_membership'
            │    └─ TenantChoiceRequired → reason: 'tenant_choice_required', status 409
            ├─ offline-eligible? → decideOffline(snapshot)    v2/decision.js
            │                      (clerk + this service + non-sensitive + named tenant)
            └─ else → client.authorize(POST /v1/authorize)    v2/platform-client.js
       └─ audited(result, permission, requestId)             → cfg.onEvent
       └─ denialBody(status, reason, cfg) → 401/403/409/503
```

Parity: every shared vector in `test-vectors/vectors.json` runs through both `test/vectors.test.js` (Node) and `python/tests/test_vectors.py` (Python); `test/e2e/parity.test.js` cross-checks the library against a scratch platform when `REQUIRE_SCRATCH=1`.

---

## File tree (v1.0.0)

### Root
- `index.js` — the v1 Node entry (`clerkProtect`, `protectOrM2m`, `requireService`, `getBrandId`); still exported for pre-v2 consumers, slated for removal after the cutover. v2 lives under `v2/`.
- `webhooks.js` — v1 Clerk/Svix webhook verifier helper.
- `package.json` — `"version": "1.0.0"`, `scripts.test` runs the Node suite, `scripts.test:python` runs `pytest` under `python/`.
- `CHANGELOG.md`, `README.md`.
- `docs/ADOPTION-CHECKLIST.md`, `docs/MIGRATION.md` — the two living adopter docs; the v1.0.0 changes fold in here.

### `v2/` (Node, the library proper)
- `v2/auth.js` — `createAuth(opts)` builds the `core` object: `authorize`, `authorizeApprover`, `resolvePrincipal`, `effectivePermissions`, `authorizeServiceCaller`, `authorizeResourceInTenant`, `tenantFor`, `resourcesFor`, **`tenantAudit`**, `assertTenant`, `usageContext`, plus the Express/Next adapter namespaces. Owns the new `selectTenant` and the per-user memberships cache.
- `v2/config.js` — `resolveConfig()` + `ConfigError`. Reads `env` + `opts`; validates `acceptedCallerServices`, Clerk `authorizedParties`/`audience`, snapshot TTLs, service-key cache knobs, deadline/shadow timeouts.
- `v2/clerk.js` — `ClerkVerifier` (RS256, pinned issuer/JWKS, bounded JWKS refresh with single-flight; CR-L2 is on a separate branch not yet in main).
- `v2/credentials.js` — `extract(headers)`: Authorization bearer / `__session` cookie / `x-api-key`. Rejects ambiguous (repeated/joined) credentials as `invalid`.
- `v2/platform-client.js` — `PlatformClient`: `snapshot`, `events`, `authorize`, `resolve`, **`memberships(clerkToken)`**. Fail-closed on 401/403/5xx; throttled on 429 via `PlatformThrottled`.
- `v2/snapshot-cache.js` — `SnapshotCache` (fresh / stale / none), change-feed polling, `invalidate()`, `resourceIndex()`.
- `v2/decision.js` — `decideOffline()` (line-for-line mirror of the platform's `decide()` for the offline-eligible subset); `scopeAllows`, `kindRestricted`, `inWindow`.
- `v2/service-keys.js` — `ServiceKeyResolver` (bounded positive + negative caches, LRU, `max_inflight`), `validatePolicy`, `routeAllowed`.
- `v2/reasons.js` — `statusFor(reason, allow)`: 401/403/503 + **409 `tenant_choice_required`**; `COARSE_OFFLINE` pairs.
- `v2/resources.js` — `buildIndex`, `ownerOf`, `idsOf` for `tenantFor`/`resourcesFor`.
- `v2/events-webhook.js` — signed-change-feed verifier.
- `v2/index.js` — public entry: `createAuth`, `Principal`, `parsePermission`, `ConfigError`, `extract`, `COARSE_OFFLINE`.
- `v2/adapters/shared.js` — `resolveScope`, `denialBody` (now includes the 409 body), `legacyAuth` (no `orgId`/`orgRole`), `cleanRunId`.
- `v2/adapters/express.js` — `requirePermission`, `requireApprover`, `requireServiceCaller`, `requireResourceInTenant`. **No longer reads `x-tenant`.**
- `v2/adapters/next.js` — Web-standard `Request`/`Response`. `withPermission`, `withApprover`, `withServiceCaller`, `authorizeRequest`, `checkResourceInTenant`. **No longer reads `x-tenant`.**

### `python/` (Python package)
- `python/konstant_studio_auth/v2/auth.py` — the Python twin of `v2/auth.js`: `Auth`, `Result`, `Principal`, `_select_tenant`, `_user_memberships` (per-user cache), `tenant_audit`.
- `python/konstant_studio_auth/v2/{config,clerk,credentials,platform_client,snapshot_cache,decision,service_keys,reasons,resources,events_webhook}.py` — mirror of the Node v2 modules.
- `python/konstant_studio_auth/v2/adapters/{shared,fastapi}.py` — FastAPI `require_permission`, `require_approver`, `require_service_caller`, `require_resource_in_tenant`, `events_webhook`. **No longer reads `x-tenant`.**
- `python/konstant_studio_auth/auth.py`, `python/konstant_studio_auth/webhooks.py` — v1 FastAPI deps (`clerk_protect`, `protect_or_m2m`, `require_service`), still shipped, scheduled for removal after the cutover.
- `python/pyproject.toml` — `version = "1.0.0"`.

### `test-vectors/`
- `vectors.json` — the shared parity surface. Config, fake world (tenants, principals including the new `brandy` member of `acme_brand`, memberships, keys), authorization cases, extraction cases, route-policy cases, resource-lookup cases. 1.0.0 adds the `org_id-invariance-*` cases and the new per-vector `memberships_override` field (pins `default_tenant_id` and the memberships list for the `default` and `tenant_choice_required` branches).

### `test/` (Node tests)
- `test/vectors.test.js` — runs the shared vectors.
- `test/select-tenant-order.test.js` — new in 1.0.0: one case per branch (explicit / default / single / 409), grant allowed (root member with `descendants:true` → brand child), sibling denied (cl-A → cl-B **and** brand → root), inactive default fall-through, `org_id` invariance, hint refused, adapter 409, `tenantAudit` guard + `callerService` pin.
- `test/hardening.test.js` — CoS review findings (R1…R5, V2-*). R1 `the v1-shaped req.auth carries no orgId` is kept, adapted to the new order.
- `test/effective.test.js`, `test/resources.test.js`, `test/service-keys.test.js`, `test/unit.test.js`, `test/legacy.test.js`.
- `test/e2e/` — scratch-platform parity, adapter round-trips, registry round-trips.
- `test/helpers/world.js` — fake platform; 1.0.0 adds `membershipsFor` and the `GET /v1/users/me/memberships` handler (auto-derives memberships from the world when a vector doesn't pin them).

### `python/tests/` — mirrors of the Node tests
- `test_vectors.py`, `test_select_tenant_order.py`, `test_hardening.py`, `test_effective.py`, `test_fastapi.py`, `test_resources.py`, `test_service_keys.py`, `test_units.py`, `test_legacy.py`.
- `tests/world.py` — Python `FakePlatform`; also owns the memberships handler.

### `scripts/`
- `scratch_platform.py` — spins up a scratch control plane for the e2e parity run; `REQUIRE_SCRATCH=1` makes parity fail instead of skip.

---

## Public API (v1.0.0, breaking)

**Node**
- `createAuth(opts).authorize({ headers, credential?, permission, resource?, req?, requestId? })` → `{ allow, reason, status, principal, tenantId, viaTenant, roles, sensitive, source, stale, tenantSource, category }`.
  - `resource` accepts: `tenant`, `brand`, `domain`, `mailbox`, `tenantOf: { kind, localId }`. **`tenantHint` is no longer accepted** (silently dropped).
  - New `tenantSource` values from the picker: `explicit`, `resolver`, `default`, `single_membership`, `resource` (when `tenantOf` resolved it). No more `org` or `hint`.
- `createAuth(opts).authorizeApprover({ ..., stepUp })` — unchanged surface.
- `createAuth(opts).effectivePermissions({ headers, credential?, tenant?, service?, req? })` — follows the same selection order; answers `tenant_choice_required` when the user has several memberships and nothing names one.
- `createAuth(opts).tenantAudit({ headers, credential?, tenantId?, counts?, callerService?, stale? })` → `{ ok, status, service, tenant_id, counts, stale }` or `{ ok:false, status, reason }`.
- `createAuth(opts).authorizeServiceCaller`, `authorizeResourceInTenant`, `tenantFor`, `resourcesFor`, `assertTenant`, `usageContext`, `resolvePrincipal` — unchanged.
- Adapter namespaces: `core.express.{requirePermission, requireApprover, requireServiceCaller, requireResourceInTenant}`, `core.next.{withPermission, withApprover, withServiceCaller, authorizeRequest, checkResourceInTenant, deny}`.
- Config option added: `membershipCacheTtlSeconds` (default `60`).

**Python**
- `create_auth(**opts)` returns an `Auth` instance with the same surface in snake_case: `authorize(...)`, `authorize_approver(...)`, `effective_permissions(...)`, `tenant_audit(...)`, `authorize_service_caller(...)`, `authorize_resource_in_tenant(...)`, `tenant_for(...)`, `resources_for(...)`, `assert_tenant(...)`, `usage_context(...)`, `resolve_principal(...)`.
- `auth.fastapi.{require_permission, require_approver, require_service_caller, require_resource_in_tenant, events_webhook}`.
- Config option added: `membership_cache_ttl_seconds` (default `60`).

**Reasons / statuses (shared)**
- Added: `tenant_choice_required` → **409**.
- Removed from the selection path: `tenant_required` (the library no longer produces it from `selectTenant`; the platform may still return it over the wire).

---

## Consumers (today)

Each app moves to v1.0.0 in its own CR. This table is the CoS's reference for who is on what.

| Consumer | Today | Form of pin | Moves to v1.0.0 in its own CR |
|---|---|---|---|
| media-konstant-studio | `a97e6f7` | explicit commit in `requirements.txt` | yes |
| video-konstant-studio | vendored | `vendor/konstant-studio-auth/` copy | yes |
| docs-konstant-studio | vendored | `vendor/konstant-studio-auth/` copy | yes |
| social-konstant-studio | vendored | `vendor/konstant-studio-auth/` copy | yes |
| stighive-crm | vendored | `vendor/konstant-studio-auth/` copy | yes |
| stighive-character-console | `b5512766` (console pin) f3ad2da (app pin) | git+ssh branch pin | yes |

No consumer is on `v1.0.0` yet; media still holds the `a97e6f7` pin until it adopts. The vendored copies are frozen snapshots and will be refreshed per-CR, not auto-updated.

---

## Downstream dependencies of this library

The platform API at `stighive-platform` (project `stighive`): `POST /v1/authorize`, `POST /v1/principals/resolve`, `GET /v1/authorize/snapshot`, `GET /v1/events`, and — new in the v1.0.0 flow — **`GET /v1/users/me/memberships`** (CR-P1 on `cr-p1-on-ledger`, migration 019, router `app/routers/me.py`). The library reads the user's `default_tenant_id` and active memberships from this endpoint; service keys still authenticate the transport.

Clerk (`https://clerk.<deployment>`) for human sessions. RS256 JWTs with configured `issuer`, `jwks_url`, `authorized_parties`, optional `audience`. The `org_id` / `o.id` claims are parsed but **not used for tenant selection**.

Cloudflare Access (optional) for audience tokens — resolved live via the platform's resolve endpoint.
