# Migrating to v2

v2 (`@konstant-studio/auth/v2`, `konstant_studio_auth.v2`) is additive. Every v1 export keeps working with the same behaviour; the only visible change in 0.2.0 is one `DeprecationWarning` per process for the shared-key path. You adopt v2 route group by route group, and v1 gates stay in place until a route group is covered.

Use this together with [ADOPTION-CHECKLIST.md](./ADOPTION-CHECKLIST.md) (the steps every adopter repeats). Nothing here edits another repo; each adopting repo gets its own change request.

## What does not change

- `setupClerk`, `protect`, `superadminOnly`, `getBrandId`, `requireLogin`, `@konstant-studio/auth/webhooks`, and the Python `clerk_protect`, `superadmin_only`, `get_brand_id`, `webhooks_router`: unchanged. Browser login still goes through Clerk; `requireLogin` still redirects HTML pages to the hosted sign-in.
- `req.auth` under v2 middleware is **not** identical to v1's, on purpose. v2 sets `{ userId, tenantId, clerkOrgId, clerkOrgRole, isSuperadmin: false }`: `isSuperadmin` is always `false` (only the permission matrix grants anything) and **`orgId` / `orgRole` are gone**. In v1 the Clerk org was the scoping key; in v2 a request can be about a different tenant than the token's org (a route's tenant, an agency view), and a handler that authorises on the decision but scopes its data by the token's org would mix tenants. **Scope data by `tenantId` (= `decision.tenantId`) only.** `clerkOrgId` is for display and logs. Code that still reads `req.auth.orgId` behind v2 middleware must move to `tenantId`; v1 middleware (`protect`) is unchanged.

## What is deprecated (and when it goes)

| v1 | Replacement | Removal |
|---|---|---|
| `m2mAuth`, the `X-API-Key` branch of `protectOrM2M`; `m2m_auth`, `protect_or_m2m` | a per-service `stgs_` key | tied to the platform's `ACCEPT_SHARED_KEY=false` cutover; **the CoS decides when** |
| `requireService`, `require_service` | `requirePermission('service:action')` | with the same cutover |

**Replacing an inbound shared key (a worker or n8n calling your app with `INTERNAL_API_KEY`) with a service key** depends on the platform's C0b2 being **deployed** (it resolves `stgs_` keys; the committed C0b2 does, and the CoS's fixes before deploy make `expect_service` mandatory and failures uniform). The library is written to the final contract and is correct against both, but nothing can use it until the platform is deployed. Until then: migrate human and agent traffic first, **leave worker-to-app calls on `protectOrM2M`**, and move them when the platform is deployed. The steps for each such route group:

1. Mint the calling service a `stgs_` key bound to *its* catalog service (never `* /*`), and give your own app a key bound to *yours*.
2. Declare who you accept: `acceptedCallerServices: ['image', 'video']` (or `AUTH_ACCEPTED_CALLER_SERVICES`). Not "any".
3. Write your own route policy per accepted caller (deny by default; `*` is one path segment, `**` many; matched on the path as sent, and any path with `%`, `..` or `//` is refused) and gate the routes with `requireServiceCaller(policy)` / `withServiceCaller` / `require_service_caller`. The `allowed_routes` the platform shows for the key are *platform* routes and are not your policy.
4. Expect `401 key_not_found` for every kind of bad key (the platform's finer reason is audit detail only), and that a revoked key can keep working here for up to 60 s (the resolution cache).

## The two things every migration needs a decision on

1. **Route -> permission map.** Each route group gets a `service:action` from the platform's catalog (`docs:read`, `social:approve`, ...). The platform owns the vocabulary; an unknown permission is denied with `unknown_permission`. Approve/publish/send/delete/manage actions are `sensitive`: the library asks the platform live for them, and they need step-up in the UI.
2. **Where the tenant comes from.** v2 decides *within a tenant*. In order: the route (`tenant: (req) => req.params.tenant`), your `tenantResolver(req, principal)`, the **Clerk organization in the session token** (which the library maps to a tenant itself through the snapshot's `org_id`, platform C0b2), and last the `x-tenant` header as a weak hint, used only for tokens with **no org claim** (a token whose org does not map gets `tenant_required`, never the header). An app that scopes by `orgId` today therefore needs no resolver once C0b2 is deployed: the org in the session names the tenant, and an org the user does not belong to is denied rather than swapped for one they do. Before C0b2 is deployed the snapshot has no `org_id`, the mapping finds nothing, and the platform answers (`tenant_required` for a user with several memberships); a `tenantResolver` bridges that gap if you need it sooner.

## Resource ownership: keep no mapping of your own (C0c2)

If your repo today decides "which tenant owns this brand / channel / account / mailbox" from a column, a config file or a hard-coded map, that second copy is what the platform's registry (C0f) replaces. Go through **one seam** in your code (`tenant_for_x(id)` / `x_for_tenant(tenant)`), and back it with `auth.tenantFor(kind, id)` / `auth.resourcesFor(tenant, kind)` once the platform's registry is deployed and your service's resources are registered (provisioning registers them automatically; the one-time brand bootstrap is loaded by the platform). Until then a clearly-marked interim backing behind the same seam is fine; the platform owns the data. Rules for the seam: an object with no owner is **denied**, an unreadable registry is a **503**, never a guess; list endpoints filter with `resourcesFor`; object-id routes use `tenantOf` (or `requireResourceInTenant`) so a user of tenant A can never reach tenant B's object by guessing its id. Know what `tenantOf` implies: the **object's owner becomes the tenant and wins over the Clerk org claim**, so a user bound to org tenant A who is also a member of B can act on B's objects (membership still required); if a route must stay inside the token's org, name the tenant from the org and use `requireResourceInTenant` instead. Never read the CoS seed files at runtime.

## Per adopting repo

### social-konstant-studio (admin) — current adopter

Read from `admin/server.js` (wiring at the top of the file): it imports `setupClerk, protect, protectOrM2M, superadminOnly, requireLogin, requireService, getBrandId` and mounts `@konstant-studio/auth/webhooks` at `/webhooks/clerk`.

1. Keep `setupClerk()`, the webhook mount, `requireLogin` on the HTML pages, and `getBrandId` as they are.
2. Create the library once, next to `setupClerk()`: `const auth = createAuth({ service: 'social' }).start();` (add a `tenantResolver` only if you need to name the tenant before the platform's C0b2 is deployed).
3. Replace `requireService('social')` on `/api/*` route groups with permissions, group by group: reads -> `social:read`; calendar/queue edits -> `social:write` / `social:schedule`; **approvals -> `auth.express.requireApprover('social:approve', { stepUp: true, tenant })`**; publishing -> `social:publish` (also approver-class).
4. Leave `app.use('/api', protectOrM2M)` for the worker's loopback until the platform's C0b2 is deployed (see above). Then give the worker a `stgs_` key bound to its service, set `acceptedCallerServices`, and gate the loopback routes with `requireServiceCaller({ <worker service>: [...] })`; browser traffic goes through `requirePermission`.
5. The Clerk webhook handlers that write the local `users` table stay for now; the control plane's own Clerk mirror is the future source of membership, and the local table goes away in a later CR (design rule: no service keeps its own user/role/key table).

### stighive-character-console — current adopter

Imports `setupClerk, requireLogin, protect, superadminOnly`.

1. Keep login and `requireLogin`.
2. `superadminOnly` reads `publicMetadata.superadmin`. In v2 a "superadmin" has no special authority: it is an `owner` membership on the root tenant with `descendants` (platform's documented gap #3). Replace `superadminOnly` on admin routes with `requirePermission('characters:write')` (or `characters:run`), after the platform grants that membership.
3. Next.js-style routes, if any, use `auth.next.withPermission`.

### image-konstant-studio (Python/FastAPI) — current adopter, **not on this machine**

Taken from the graph note of 2026-05-06, not from the code, so verify before acting. It has three auth paths feeding one `get_current_key` dependency (Clerk JWT, `INTERNAL_API_KEY` m2m, legacy per-user `X-API-Key`) with a `Principal` shim so 175 endpoints work unchanged.

1. Add the Clerk path to v2 first: `Depends(auth.require_permission('image:generate', ...))` on new or migrated routes; the legacy `X-API-Key` path keeps working until its own CR (it is a per-user key table, which the design retires).
2. Keep m2m on `m2m_auth` until the platform's C0b2 is deployed, then move it to `require_service_caller`.
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
