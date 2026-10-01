# Adoption checklist (v2)

One list, reused by every adopting CR. Copy it into the CR's hand-off and tick each line with evidence (a command and its output, never a secret).

## 0. Before you start

- [ ] The service has a **catalog slug** in the platform (`docs`, `video`, `crm`, `jobs`, `mail`, ...) and its permissions are defined there. The platform owns the vocabulary; ask for missing actions, do not invent them.
- [ ] A **per-service key** (`stgs_...`) exists for this service: bound to its catalog slug, with an allow-list of only `GET /v1/authorize/snapshot`, `GET /v1/events`, `POST /v1/authorize`, `POST /v1/principals/resolve`. Never `* /*`. It lives in the service's secret store as `PLATFORM_SERVICE_KEY`, never in code, a doc, a graph note or a log.
- [ ] `PLATFORM_API_URL` is reachable from the service (the platform is tailnet-only).
- [ ] Clerk values are set: `CLERK_ISSUER`, `CLERK_JWKS_URL`, **`CLERK_AUTHORIZED_PARTIES`** (the frontend origins; the library refuses to start without it).
- [ ] Pin a **tag** of `@konstant-studio/auth` / `konstant-studio-auth`, not `main`.

## 1. Map routes to permissions

- [ ] A table of every route group -> `service:action`, with the **scope** each needs (`tenant`, `brand`, `domain`, `mailbox`) and where the tenant comes from (route param, `x-tenant`, `tenantResolver`).
- [ ] Approve / publish / send / delete / manage routes use `requireApprover` / a sensitive permission, and the UI asks for fresh MFA (step-up). Agents and guests never reach an approver action.
- [ ] No route is left ungated by accident: public-by-design routes are listed explicitly with the reason (OAuth reviewers' legal pages, health, etc.).

## 2. Wire it

- [ ] `createAuth({ service }).start()` (Python: `create_auth(...)`, then `auth.start()` inside the app's lifespan handler so change-event polling has a running loop, and `await auth.close()` on shutdown).
- [ ] Express: `auth.express.requirePermission(...)`; Next.js: `auth.next.withPermission(...)`; FastAPI: `Depends(auth.require_permission(...))`.
- [ ] No local role, user, key or entitlement table is consulted for authorization. Existing ones are listed for removal in a follow-up (design rule: no service keeps its own).
- [ ] `onEvent` is wired to the audit/usage emitter. `usageContext(req)` supplies the actor to usage events. Confirm in a log sample that no token, key or `Authorization` header appears.

## 3. Prove it (against a local copy of the platform, never the real one)

Use the scratch harness in this repo (`scripts/scratch_platform.py`), which refuses any database that is not local and named `cptest*`, and the sample-app tests (`test/e2e/adapters.test.js`, `python/tests/e2e/`) as the template. For **your** routes, show:

- [ ] no credential -> `401` (reason `no_credential`), with `WWW-Authenticate: Bearer`.
- [ ] a bearer that is not a session or a key -> `401` (reason `token_invalid`), not a `500`, not a redirect.
- [ ] a member of the tenant -> `200`; a member of **another** tenant -> `403`; no membership -> `403`.
- [ ] a tenant that is not entitled to the service -> `403` `not_entitled`.
- [ ] scope: a request outside the membership's brand/domain/mailbox -> `403` `out_of_scope`; one that omits a restricted dimension -> `scope_required`.
- [ ] a **sensitive** action is decided live (the platform's audit log shows the check).
- [ ] an **agent key** works for what its role allows and is refused an approver action (`principal_kind_restricted`); a **revoked key** is refused on the next request.
- [ ] the platform **unreachable**: sensitive routes and key checks answer `503` (never an allow); read routes keep working only from a cache no older than `SNAPSHOT_STALE_READ_TTL_SECONDS`.
- [ ] revoking a membership in the platform takes effect within the poll interval (`AUTH_EVENT_POLL_SECONDS`, default 5s).
- [ ] the shared vectors (`test-vectors/vectors.json`) are unchanged in your checkout: do not edit them to make a repo pass; a needed change goes back to this repo as a CR.

## 4. Existing behaviour

- [ ] The repo's own tests / smoke checks pass before and after.
- [ ] v1 gates that were not replaced are listed, with the reason (usually: worker-to-app calls waiting for platform C0b2).
- [ ] If the shared key is still used, the `DeprecationWarning` is understood and the removal condition (`ACCEPT_SHARED_KEY=false`, decided by the CoS) is noted in the repo's roadmap.

## 5. Hand-off and release

- [ ] A graph `handoff` note: what changed, how to run the checks above, known gaps. No secrets, fake values in examples.
- [ ] A branch and commit reference to Raf. **No production deploy before the CoS has accepted**; the interim Cloudflare Access ring stays in front until then.
- [ ] After deploy, re-probe from outside (GET-only) and update the Adoption and Exposure Register row.
