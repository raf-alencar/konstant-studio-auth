# Migrating to v2

v2 (`@konstant-studio/auth/v2`, `konstant_studio_auth.v2`) is additive. Every v1 export keeps working with the same behaviour; the only visible change in 0.2.0 is one `DeprecationWarning` per process for the shared-key path. You adopt v2 route group by route group, and v1 gates stay in place until a route group is covered.

Use this together with [ADOPTION-CHECKLIST.md](./ADOPTION-CHECKLIST.md) (the steps every adopter repeats). Nothing here edits another repo; each adopting repo gets its own change request.

## What does not change

- `setupClerk`, `protect`, `superadminOnly`, `getBrandId`, `requireLogin`, `@konstant-studio/auth/webhooks`, and the Python `clerk_protect`, `superadmin_only`, `get_brand_id`, `webhooks_router`: unchanged. Browser login still goes through Clerk; `requireLogin` still redirects HTML pages to the hosted sign-in.
- `req.auth` keeps its shape. v2 middleware sets a v1-shaped `req.auth` too (`isSuperadmin` is always `false` there: in v2 only the permission matrix grants anything).

## What is deprecated (and when it goes)

| v1 | Replacement | Removal |
|---|---|---|
| `m2mAuth`, the `X-API-Key` branch of `protectOrM2M`; `m2m_auth`, `protect_or_m2m` | a per-service `stgs_` key | tied to the platform's `ACCEPT_SHARED_KEY=false` cutover; **the CoS decides when** |
| `requireService`, `require_service` | `requirePermission('service:action')` | with the same cutover |

**A sequencing constraint to know about.** Replacing an *inbound* shared key (a worker or n8n calling your app with `INTERNAL_API_KEY`) with a service key needs the platform to resolve `stgs_` keys (the platform's C0b2). Until then v2 answers `401 unsupported_credential` for a service key, exactly like the platform. So: migrate human and agent traffic first, **leave worker-to-app calls on `protectOrM2M`**, and move them once C0b2 is accepted and `AUTH_SERVICE_KEYS=platform` is set.

## The two things every migration needs a decision on

1. **Route -> permission map.** Each route group gets a `service:action` from the platform's catalog (`docs:read`, `social:approve`, ...). The platform owns the vocabulary; an unknown permission is denied with `unknown_permission`. Approve/publish/send/delete/manage actions are `sensitive`: the library asks the platform live for them, and they need step-up in the UI.
2. **Where the tenant comes from.** v2 decides *within a tenant*. Name it from the route (`tenant: (req) => req.params.tenant`), the `x-tenant` header, or a `tenantResolver(req, principal)`. Until the platform's snapshot carries `org_id` (platform C0b2), a Clerk org id cannot be mapped to a tenant inside the library, so an app that today scopes by `orgId` supplies the mapping itself (a lookup against the platform's tenant for that org, cached; or a static map from configuration). When `org_id` is in the snapshot the library will resolve it and the resolver goes away. With no tenant named and several memberships, the platform answers `tenant_required`.

## Per adopting repo

### social-konstant-studio (admin) — current adopter

Read from `admin/server.js` (wiring at the top of the file): it imports `setupClerk, protect, protectOrM2M, superadminOnly, requireLogin, requireService, getBrandId` and mounts `@konstant-studio/auth/webhooks` at `/webhooks/clerk`.

1. Keep `setupClerk()`, the webhook mount, `requireLogin` on the HTML pages, and `getBrandId` as they are.
2. Create the library once, next to `setupClerk()`: `const auth = createAuth({ service: 'social', tenantResolver }).start();`.
3. Replace `requireService('social')` on `/api/*` route groups with permissions, group by group: reads -> `social:read`; calendar/queue edits -> `social:write` / `social:schedule`; **approvals -> `auth.express.requireApprover('social:approve', { stepUp: true, tenant })`**; publishing -> `social:publish` (also approver-class).
4. Leave `app.use('/api', protectOrM2M)` for the worker's loopback until C0b2 (see above). Once service keys resolve, give the worker its own `stgs_` key and route `/api` through `requirePermission`.
5. The Clerk webhook handlers that write the local `users` table stay for now; the control plane's own Clerk mirror is the future source of membership, and the local table goes away in a later CR (design rule: no service keeps its own user/role/key table).

### stighive-character-console — current adopter

Imports `setupClerk, requireLogin, protect, superadminOnly`.

1. Keep login and `requireLogin`.
2. `superadminOnly` reads `publicMetadata.superadmin`. In v2 a "superadmin" has no special authority: it is an `owner` membership on the root tenant with `descendants` (platform's documented gap #3). Replace `superadminOnly` on admin routes with `requirePermission('characters:write')` (or `characters:run`), after the platform grants that membership.
3. Next.js-style routes, if any, use `auth.next.withPermission`.

### image-konstant-studio (Python/FastAPI) — current adopter, **not on this machine**

Taken from the graph note of 2026-05-06, not from the code, so verify before acting. It has three auth paths feeding one `get_current_key` dependency (Clerk JWT, `INTERNAL_API_KEY` m2m, legacy per-user `X-API-Key`) with a `Principal` shim so 175 endpoints work unchanged.

1. Add the Clerk path to v2 first: `Depends(auth.require_permission('image:generate', ...))` on new or migrated routes; the legacy `X-API-Key` path keeps working until its own CR (it is a per-user key table, which the design retires).
2. Keep m2m on `m2m_auth` until C0b2.
3. `image` brand ids are local integers and Clerk org ids (usage-ledger design note): pass the tenant through a resolver, not the brand id.

### Wave-order adopters (each gets its own CR)

| Repo | Adapter | Notes |
|---|---|---|
| video-konstant-studio | FastAPI or Express (check) | most exposed; permissions `video:read`, `video:render` (spend), `video:delete` (sensitive). |
| docs-konstant-studio | Express | `docs:read` / `docs:write` / `docs:render` / `docs:delete`; the vectors in this repo are written for the `docs` service. |
| stighive-crm | Next.js | `auth.next.withPermission`. **iOS bearer**: a bearer that is not a known key goes to Clerk validation and gets a clean `401`; no change to the iOS client. |
| job-finder | FastAPI | its own login and users table migrate to Clerk + the control plane (L8). |
| stighive-character-console / runtime | Express | see above. |
| mailserver-sidecar | FastAPI | greenfield on the control plane; `mail:read`/`mail:send` scoped by domain or mailbox (`domain`/`mailbox` scope fields). |

## Rolling out safely, route group by route group

1. Add v2 beside v1; do not remove a v1 gate until its replacement passes the checklist.
2. Wire `onEvent` together with the first route group you enforce, and read the decisions (ids and reasons only) while it settles. There is deliberately no report-only mode: a mode that evaluates but lets the request through is one misconfiguration away from an accidental allow.
3. Enforce one route group, run the checklist's probes, then the next.
4. Do not deploy before the CoS has accepted the adopting CR; the interim Cloudflare Access ring stays until then.

## Publishing and versions

`0.2.0` is a minor release: additive, with deprecations. Pin a tag in adopters (`github:raf-alencar/konstant-studio-auth#v0.2.0`), not `#main`, so a library change is a deliberate bump. See the hand-off for the publish-path proposal (git dependency, private registry, or vendoring).
