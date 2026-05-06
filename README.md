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
| `m2mAuth`         | API-key auth for workers and n8n. Checks `X-API-Key` against `INTERNAL_API_KEY`. |
| `protectOrM2M`    | Accept either a Clerk session or an API key.                            |
| `requireLogin`    | For HTML pages — redirect to Clerk hosted login if no session.          |
| `requireService`  | Factory — gate routes on the caller's org being entitled to a service.  |

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

- Superadmin: returns `req.query.brand_id ?? null` (null = all brands).
- Client: returns their `orgId`, never overrideable.

```js
const brandId = getBrandId(req);
```

### `m2mAuth` — workers and n8n

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

### `requireService` — service-entitlement gate

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

## Environment variables

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
