# @konstant-studio/auth

Shared Clerk + Cloudflare Access auth middleware for every StigHive and Konstant Studio service.

One login → Cloudflare Access → Clerk JWT → service trusts the JWT and scopes data by `orgId` (the brand).

This package is **middleware only** — it does not start a server, mount routes, or talk to a database. Services install it, wire the middleware into their own Express app, and own their own route layout.

## Install

In each service's `package.json`:

```json
{
  "dependencies": {
    "@konstant-studio/auth": "github:raf-alencar/konstant-studio-auth#main"
  }
}
```

Then:

```bash
npm install
```

Copy the env vars from [.env.example](./.env.example) into each service's `.env`.

## What you get

| Export            | Purpose                                                                 |
| ----------------- | ----------------------------------------------------------------------- |
| `setupClerk`      | Mount once on the app — installs `@clerk/express` middleware.           |
| `protect`         | Require a valid Clerk session. Sets `req.auth`.                         |
| `superadminOnly`  | Restrict route to users with `publicMetadata.superadmin === true`.      |
| `getBrandId`      | Return the brand id (`orgId`) to scope DB queries by.                   |
| `m2mAuth`         | **Deprecated.** API-key auth for workers and n8n. Checks `X-API-Key` against `INTERNAL_API_KEY`. |
| `protectOrM2M`    | Accept either a Clerk session or an API key.                            |
| `requireLogin`    | For HTML pages — redirect to Clerk hosted login if no session.          |
| `requireService`  | **Deprecated.** Factory — gate routes on the caller's org being entitled to a service. |

After `protect` (or `m2mAuth`), `req.auth` is:

```js
{
  userId:       string,
  orgId:        string | null,   // the brand id, e.g. "afterthefirst"
  orgRole:      'admin' | 'member' | null,
  isSuperadmin: boolean,
}
```

## Usage

```js
const express = require('express');
const {
  setupClerk,
  protect,
  superadminOnly,
  getBrandId,
  m2mAuth,
  protectOrM2M,
  requireLogin,
} = require('@konstant-studio/auth');

const app = express();

// 1) Mount Clerk once, near the top of your middleware chain.
app.use(setupClerk());
```

### `protect` — guard an API route

```js
app.get('/api/content-items', protect, async (req, res) => {
  const brandId = getBrandId(req);
  const sql = brandId
    ? 'SELECT * FROM content_items WHERE brand_id = $1 ORDER BY publish_date'
    : 'SELECT * FROM content_items ORDER BY publish_date';
  const params = brandId ? [brandId] : [];
  const { rows } = await db.query(sql, params);
  res.json(rows);
});
```

### `superadminOnly` — restrict to Raf

```js
app.get('/api/admin/brands', protect, superadminOnly, async (req, res) => {
  const { rows } = await db.query('SELECT DISTINCT brand_id FROM platform_tokens');
  res.json(rows);
});
```

### `getBrandId` — brand scoping

- Superadmin: returns `req.query.brand_id ?? req.auth.orgId ?? null` — an explicit `?brand_id=` wins, a superadmin who is a real org member defaults to their own org, and `null` (a headless m2m caller or an org-less superadmin session) means "no default brand".
- Client: returns their `orgId`, never overrideable.

```js
const brandId = getBrandId(req);
```

### `m2mAuth` — workers and n8n *(deprecated)*

> Deprecated: shared-key auth. Still supported; removal is tied to the platform's `ACCEPT_SHARED_KEY=false` cutover (decided by the CoS). Use per-service keys and [v2](#v2--control-plane-authorization). Prints one `DeprecationWarning` per process (`KSA_SILENCE_DEPRECATIONS=1` silences it).

Caller sends `X-API-Key: <INTERNAL_API_KEY>`. No Clerk session involved.

```js
app.post('/jobs', m2mAuth, async (req, res) => {
  const { brand_id, ...job } = req.body;
  if (!brand_id) return res.status(400).json({ error: 'brand_id required' });
  // insert job...
});
```

### `protectOrM2M` — accept either

```js
app.get('/jobs/:id', protectOrM2M, async (req, res) => {
  const brandId = req.auth.isSuperadmin ? req.query.brand_id : req.auth.orgId;
  // query...
});
```

### `requireLogin` — HTML pages

For server-rendered admin pages, redirect missing sessions to Clerk hosted login:

```js
app.use('/accounts',  requireLogin);
app.use('/calendar',  requireLogin);
app.use('/approvals', requireLogin);
app.use('/queue',     requireLogin);
```

Set `CLERK_SIGN_IN_URL` to override the default redirect target.

### `requireService` — service-entitlement gate *(deprecated)*

> Deprecated: checks entitlement only, through the legacy `/entitlements/{org}` endpoint with the shared key. `requirePermission` in v2 checks entitlement **and** permission.

`requireService('slug')` returns a middleware that asks the platform API whether the caller's org is entitled to the named service. Wire `protect` (or `protectOrM2M`) before it so `req.auth` is populated.

```js
app.get('/posts', protect, requireService('social-konstant-studio'), async (req, res) => {
  // only reaches here if the caller's org is entitled to "social-konstant-studio"
});
```

Behaviour:

- Superadmin (and m2m callers, who get `isSuperadmin: true`) bypass the check.
- Org not entitled → `403` with `{ error: "No access to this service", upgrade_url: "https://www.konstant-studio.com/dashboard" }`.
- `PLATFORM_API_URL` unset or the call fails: in dev (`NODE_ENV !== 'production'`) → warn and allow; in production → `503 { error: "Entitlement service unavailable" }`.
- Per-org result cached in-process for 60s.

The platform endpoint called is `GET ${PLATFORM_API_URL}/entitlements/${orgId}` with `X-API-Key: ${INTERNAL_API_KEY}`. Expected response is `{ "services": ["slug-a", "slug-b"] }` (also accepts a bare array or an `entitlements` field).

### `/me` endpoint

Every service should expose this for the frontend:

```js
app.get('/me', protect, (req, res) => res.json(req.auth));
```

## Webhooks

Mount the Clerk webhook router from `@konstant-studio/auth/webhooks`. It verifies the Svix signature using `CLERK_WEBHOOK_SECRET`, acks with `200`, and emits the event on its `events` `EventEmitter` for the service to handle.

```js
const webhooks = require('@konstant-studio/auth/webhooks');

// Mount the router. It expects the raw body itself — do not put a JSON
// body parser ahead of it on the same path.
app.use('/webhooks/clerk', webhooks);

// Handle the events you care about.
webhooks.events.on('user.created', async (data) => {
  await db.query(
    `INSERT INTO users (id, email, full_name, is_superadmin, updated_at)
     VALUES ($1, $2, $3, $4, now())
     ON CONFLICT (id) DO UPDATE SET
       email = EXCLUDED.email,
       full_name = EXCLUDED.full_name,
       is_superadmin = EXCLUDED.is_superadmin,
       updated_at = now()`,
    [
      data.id,
      data.email_addresses?.[0]?.email_address,
      `${data.first_name ?? ''} ${data.last_name ?? ''}`.trim(),
      data.public_metadata?.superadmin === true,
    ]
  );
});

webhooks.events.on('user.updated', async (data) => { /* same shape as user.created */ });

webhooks.events.on('organizationMembership.created', async (data) => {
  await db.query(
    `UPDATE users SET org_id = $1, org_role = $2, updated_at = now() WHERE id = $3`,
    [data.organization.id, data.role, data.public_user_data.user_id]
  );
});

webhooks.events.on('organizationMembership.deleted', async (data) => {
  await db.query(
    `UPDATE users SET org_id = NULL, org_role = NULL, updated_at = now() WHERE id = $1`,
    [data.public_user_data.user_id]
  );
});

// Optional firehose — every event:
webhooks.events.on('*', (event) => console.log('clerk webhook:', event.type));
```

Register the endpoint in Clerk Dashboard → Webhooks → Add endpoint:

- URL: `https://<service-subdomain>/webhooks/clerk`
- Events: `user.created`, `user.updated`, `organizationMembership.created`, `organizationMembership.deleted`

Copy the signing secret into `CLERK_WEBHOOK_SECRET`.

## v2 — control-plane authorization

> **Login is identity, not authority.** Clerk proves who someone is. What they may do is decided per service, per action, per tenant by the [control plane](https://github.com/raf-alencar/stighive-platform) (stighive-platform): entitlements, a permission matrix, scoped memberships, keys. v2 is how an app asks it. v1 (everything above) keeps working unchanged; adopt v2 per app, per the [adoption checklist](./docs/ADOPTION-CHECKLIST.md) and the [migration guide](./docs/MIGRATION.md).

```js
const { createAuth } = require('@konstant-studio/auth/v2');   // also: require('@konstant-studio/auth').createAuth

const auth = createAuth({ service: 'docs' }).start();          // reads the environment below

// Express: deny by default; the permission is `service:action`, the scope says what it is about.
app.post('/render',
  auth.express.requirePermission('docs:render', {
    tenant: (req) => req.params.tenant,      // or leave out and send x-tenant / use a tenantResolver
    brand:  (req) => req.body?.brand,
  }),
  (req, res) => {
    req.principal;                            // { kind, id, userId, tenant, ancestry, roles, permissions, keyId, ... }
    auth.express.usageContext(req);           // { tenant_id, actor, run_id } for usage events
    res.json({ ok: true });
  });

// Approvals: a human, holding the permission, with a recent second factor.
app.post('/approve', auth.express.requireApprover('social:approve', { stepUp: true, tenant: (req) => req.params.tenant }), handler);
```

```js
// Next.js route handler (App Router) — plain Request/Response, no dependency on Next.
export const GET = auth.next.withPermission('crm:read',
  { tenant: (req) => new URL(req.url).searchParams.get('tenant') },
  async (req, ctx, { principal, decision }) => Response.json({ tenant: decision.tenantId }));
```

FastAPI and the Python API: see [python/README.md](./python/README.md).

### What it does

1. **One Principal for every credential.** A Clerk session token (from `Authorization: Bearer`, or the `__session` cookie), an agent key (`stga_`), a guest key (`stgg_`), an MCP key (`stig_`) or a service key (`stgs_`) all resolve to the same object. A bearer that is not a known key goes to Clerk validation and, if it is not a valid session, gets a clean `401` (this is what unblocks the CRM iOS path).
2. **Clerk tokens are verified offline**: RS256 only, issuer pinned, `exp`/`iat`/`sub` required, **`azp` mandatory** and must be one of `CLERK_AUTHORIZED_PARTIES`; the library refuses to start without that list.
3. **Decisions come from the platform, never from local role tables.**

   | Request | Decided |
   |---|---|
   | Human Clerk session, this service's own **non-sensitive** permission, tenant named | **offline**, from a cached snapshot (ETag + TTL, refreshed on change events) |
   | Any **sensitive** action, any agent / guest / MCP key, another service's permission, or **no tenant named** | **live**, `POST /v1/authorize` — one call |

   Offline decisions are proven equal to the platform's by the [parity test](#tests). A key is never cached, so revocation is immediate.
4. **Fail closed.** Platform unreachable: sensitive actions and key checks → `503`; read checks are served from the cache for at most `SNAPSHOT_STALE_READ_TTL_SECONDS` (default 300), then `503`; other routine checks → `503`. A `503` means "could not decide" and carries `Retry-After`; it is never an allow.
5. **Tenant.** Named by the `tenant` scope, else the `x-tenant` header, else your `tenantResolver(req, principal)` (use it to map a Clerk org to a tenant until the platform's snapshot carries `org_id`). With none named and several memberships the platform answers `tenant_required`. A tenant that is not a UUID can never name a tenant: it is denied (`tenant_not_found`) without calling the platform.
6. **Events.** `onEvent(e)` receives one `auth.decision` event per check (ids and the decision only — never a token, header or key). `usageContext(req)` gives the actor for usage events (event contract: "Usage ledger design").

Responses: `401 {error, reason}` for a credential problem, `403 {error, reason}` for a decision (`not_entitled` adds `upgrade_url`), `503` when it could not decide.

### Service keys (`stgs_`) — status

The end state is that the platform resolves a service key into a `service` principal (`{kind:'service', service, routes, tenant:null}`: denied by default for every tenant-scoped permission, never an approver, only the routes on its allow-list). The platform's C0b2 change that does this has not landed; until it does, `service-keys.js` is a **stub that answers `401 unsupported_credential`**, exactly like the platform. Switch with `serviceKeys: 'platform'` / `AUTH_SERVICE_KEYS=platform` after C0b2 is accepted. The matching vectors are marked `pending-platform`.

### Environment

| Var | Purpose |
|---|---|
| `PLATFORM_API_URL` | Base URL of the control plane (tailnet). |
| `PLATFORM_SERVICE_KEY` | This service's own `stgs_` key, bound to its catalog service. Falls back to `INTERNAL_API_KEY` (deprecated). |
| `CLERK_ISSUER`, `CLERK_JWKS_URL` | Public values of the Clerk instance (JWKS defaults to `<issuer>/.well-known/jwks.json`). |
| `CLERK_AUTHORIZED_PARTIES` | **Required** with Clerk: comma-separated frontend origins allowed as `azp`. |
| `CLERK_AUDIENCE` | Only if your session tokens carry an `aud`. |
| `AUTH_SERVICE` | The catalog service this app is (or `createAuth({ service })`). |
| `SNAPSHOT_TTL_SECONDS` / `SNAPSHOT_STALE_READ_TTL_SECONDS` | Cache lifetime / how long reads survive a platform outage (defaults 30 / 300; the snapshot's own values win). |
| `AUTH_EVENT_POLL_SECONDS` | Change-feed poll interval (default 5; `0` disables). |
| `AUTH_STEP_UP_MAX_AGE_MINUTES` | Max age of the second factor for `stepUp` (default 10). |
| `AUTH_SERVICE_KEYS` | `stub` (default) or `platform`. |

Step-up reads Clerk's `fva` session claim (`[minutes since first factor, minutes since second]`, `-1` = none). **Not yet confirmed against this Clerk instance's token shape**: if `fva` is absent, step-up is denied, never assumed.

### Optional: change-event webhook

Polling is on by default. To also receive the platform's signed webhook (a *hint* to refresh; the refresh itself is the normal conditional GET):

```js
app.post('/_platform/events', express.raw({ type: 'application/json' }), auth.eventsWebhook({ secret: process.env.PLATFORM_EVENTS_SECRET }));
```

### Tests

```bash
npm test            # shared vectors + unit + v1 compatibility (no network)
npm run test:smoke  # pack the tarball, install it into a scratch project, load it like the adopters do
# parity + sample apps against a scratch copy of the platform branch:
python scripts/scratch_platform.py start --platform-dir <copy of the C0b branch> --database-url postgresql://postgres@127.0.0.1:55433/cptest_x
npm run test:e2e
python scripts/scratch_platform.py stop
```

`test-vectors/vectors.json` is the shared fixture (one file for Node and Python; adopting repos reuse it as acceptance tests). The scratch harness refuses any database that is not local and named `cptest*`, binds 127.0.0.1 only, and uses fake secrets generated per run.

## Environment variables (v1)

See [.env.example](./.env.example).

| Var                       | Purpose                                                      |
| ------------------------- | ------------------------------------------------------------ |
| `CLERK_PUBLISHABLE_KEY`   | Public key for Clerk frontend SDK / OIDC client id.          |
| `CLERK_SECRET_KEY`        | Secret key — used by `@clerk/express` to validate JWTs.      |
| `CLERK_WEBHOOK_SECRET`    | Svix signing secret for the webhook endpoint.                |
| `INTERNAL_API_KEY`        | Shared secret for `m2mAuth` (workers, n8n) — also sent as `X-API-Key` to the platform API by `requireService`. |
| `CLERK_SIGN_IN_URL`       | (Optional) override target for `requireLogin` redirect.      |
| `PLATFORM_API_URL`        | Base URL of the platform entitlements API used by `requireService`. Unset in dev = warn + allow; unset in prod = 503. |
| `NODE_ENV`                | `production` makes `requireService` fail closed when the platform API is unavailable. |

## Architecture context

```
User → app.<brand>.com
  → Cloudflare Access (OIDC → Clerk)
    → Clerk hosted login
      → JWT (userId + orgId + orgRole + publicMetadata)
    → Cloudflare passes request through with the JWT
      → Service: setupClerk() reads the JWT
        → protect / requireLogin / m2mAuth gates
          → getBrandId(req) → DB query scoped to brand
```

`orgId` is the brand id. No `orgId` and `publicMetadata.superadmin === true` means Raf, who can see every brand.

## Peer dependency

This package expects an Express app (`^4.18 || ^5`) in the host service. It does not bundle Express itself.
