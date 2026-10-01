# konstant-studio-auth (Python)

FastAPI dependencies that mirror the Node middleware in this repo's root [index.js](../index.js) and [webhooks.js](../webhooks.js). Same contract, same env vars, same auth model — just rewritten as `Depends()` for Python services.

This package is **dependencies only** — no FastAPI app, no server. Services install it, wire the dependencies into their own routes, and own their own DB writes.

## Install

In each FastAPI service's `pyproject.toml` (or `requirements.txt`):

```toml
[project]
dependencies = [
  "konstant-studio-auth @ git+https://github.com/raf-alencar/konstant-studio-auth.git@main#subdirectory=python",
]
```

Or with `pip`:

```bash
pip install "git+https://github.com/raf-alencar/konstant-studio-auth.git@main#subdirectory=python"
```

Copy the env vars from the root [.env.example](../.env.example) into each service's `.env`.

## What you get

| Export              | Purpose |
|---------------------|---------|
| `clerk_protect`     | `Depends()` — validates the Clerk JWT, returns `AuthState`. 401 on failure. |
| `superadmin_only`   | `Depends()` — runs `clerk_protect`, then 403 unless `is_superadmin`. |
| `get_brand_id(auth)`| Returns the brand id (`org_id`) to scope DB queries by. |
| `m2m_auth`          | `Depends()` — validates `X-API-Key` against `INTERNAL_API_KEY`. |
| `protect_or_m2m`    | `Depends()` — accepts a Clerk JWT or an API key. |
| `require_service`   | Factory — `Depends()` that gates a route on the caller's org being entitled to a service. |
| `AuthState`         | `@dataclass` with `user_id`, `org_id`, `org_role`, `is_superadmin`. |
| `webhooks_router`   | `APIRouter` exposing `POST /webhooks/clerk`. |
| `on_webhook_event`  | Subscribe a handler to a Clerk event type. |

After `clerk_protect` (or `m2m_auth`), `auth` is:

```python
AuthState(
    user_id="user_xxx",
    org_id="afterthefirst",      # or None for the superadmin
    org_role="admin",            # or None
    is_superadmin=False,
)
```

## v2 — control-plane authorization

> **Login is identity, not authority.** v2 asks the stighive-platform control plane what a principal may do, per service, per action, per tenant. v1 (everything above) is unchanged and is never imported by v2: an app that does not use v2 needs no new dependency. The model, the offline/live split and the failure behaviour are the same as the Node package's, see the root [README](../README.md#v2--control-plane-authorization); this section is the Python surface.

```python
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI
from konstant_studio_auth.v2 import create_auth

auth = create_auth(service="docs")   # reads the environment (see the root README / .env.example)

@asynccontextmanager
async def lifespan(app):
    auth.start()                      # change-feed polling needs the running loop
    yield
    await auth.close()

app = FastAPI(lifespan=lifespan)

@app.post("/render")
async def render(d=Depends(auth.require_permission(
        "docs:render",
        tenant=lambda request: request.path_params.get("tenant"),   # str, or a (sync or async) callable(request)
        brand=lambda request: request.headers.get("x-brand"),
))):
    d.principal        # Principal(kind, id, user_id, tenant, ancestry, roles, permissions, key_id, ...)
    return {"tenant": d.tenant_id, "roles": d.roles}

@app.post("/approve")
async def approve(d=Depends(auth.require_approver("social:approve", step_up=True,
                                                  tenant=lambda r: r.path_params.get("tenant")))):
    ...
```

- Exposed as `auth.fastapi.*` and as top-level aliases: `require_permission`, `require_approver`, `require_service_caller`, `events_webhook(secret)`, `assert_tenant(request, tenant_id)`, `usage_context(request)`.
- On success: `request.state.principal`, `request.state.auth_decision`, and a v1-shaped `request.state.auth` (`is_superadmin` is always `False`).
- On failure: `HTTPException` 401 (credential; `WWW-Authenticate: Bearer`), 403 (decision), 503 (could not decide; `Retry-After: 5`). `detail` is `{"error": ..., "reason": ...}` (plus `upgrade_url` for `not_entitled`).
- Core API (no FastAPI needed): `await auth.authorize(headers=..., permission="docs:read", resource={"tenant": ...})` returns a result with `allow`, `reason`, `status`, `principal`, `tenant_id`, `via_tenant`, `roles`, `sensitive`, `source` (`offline` / `live` / `none`), `stale`; it never raises for an auth failure.
- Options are the Node options in snake_case: `platform_url`, `platform_key`, `clerk={issuer, jwks_url, authorized_parties, audience}`, `snapshot={ttl_seconds, stale_read_ttl_seconds}`, `poll_interval_seconds`, `tenant_resolver`, `on_event`, `accepted_caller_services` (env `AUTH_ACCEPTED_CALLER_SERVICES`), `service_key_cache={valid_ttl_seconds, invalid_ttl_seconds, max_entries}`, `step_up_max_age_minutes`. Tests inject `transport=` / `http_client=` and `now=`.
- Clerk verification uses `python-jose` (already a dependency): RS256 only, issuer pinned, mandatory `azp`, no new package.
- Service keys (`stgs_`) are accepted only from the services listed in `accepted_caller_services`: each is passed to the platform as `expect_service`, every failure (unknown, revoked, expired, wrong or unaccepted service) is the same `401 key_not_found`, and with none listed no service key is accepted and the platform is not asked. A matched key proves which service is calling, not what it may do: a service principal holds no tenant permissions (`service_principal_not_granted`). Gate your own internal routes with `auth.require_service_caller({"image": ["POST /internal/render", "GET /internal/status/*"]})`: deny by default, validated at wiring (a caller not in `accepted_caller_services`, `* /*`, or a malformed entry raises `ConfigError`). Resolutions are cached for at most 60 s (10 s for refusals), keyed by a hash of the key. `await auth.effective_permissions(headers=..., tenant=..., service=...)` returns what the platform says a principal may do (`.permits(permission, resource)`). Unknown option names raise `ConfigError` (the former `service_keys="stub"|"platform"` switch no longer exists).

Tests: `pytest python/tests` (shared vectors + units + the FastAPI adapter, no network); `REQUIRE_SCRATCH=1 pytest python/tests/e2e` runs the parity test and a sample app against a scratch copy of the platform branch (`scripts/scratch_platform.py`).

## Usage

```python
from fastapi import Depends, FastAPI
from konstant_studio_auth import (
    AuthState,
    clerk_protect,
    get_brand_id,
    m2m_auth,
    protect_or_m2m,
    superadmin_only,
    webhooks_router,
    on_webhook_event,
)

app = FastAPI()

# Mount the Clerk webhook router. The route /webhooks/clerk is built in.
app.include_router(webhooks_router)
```

### `clerk_protect` — guard an API route

```python
@app.get("/api/content-items")
async def list_content_items(auth: AuthState = Depends(clerk_protect)):
    brand_id = get_brand_id(auth)
    if brand_id:
        rows = await db.fetch_all(
            "SELECT * FROM content_items WHERE brand_id = :brand ORDER BY publish_date",
            {"brand": brand_id},
        )
    else:
        rows = await db.fetch_all("SELECT * FROM content_items ORDER BY publish_date")
    return rows
```

### `superadmin_only` — restrict to Raf

`superadmin_only` already runs `clerk_protect` internally — don't double-stack.

```python
@app.get("/api/admin/brands")
async def list_brands(auth: AuthState = Depends(superadmin_only)):
    rows = await db.fetch_all("SELECT DISTINCT brand_id FROM platform_tokens")
    return rows
```

### `get_brand_id` — brand scoping

- Superadmin: returns `None` — "all brands". If a service needs the Node package's `?brand_id=` override for superadmin, read it from the request manually:
  ```python
  brand_id = get_brand_id(auth) or request.query_params.get("brand_id")
  ```
- Client: returns their `org_id`, never overrideable.

### `m2m_auth` — workers and n8n

Caller sends `X-API-Key: <INTERNAL_API_KEY>`. No Clerk JWT involved.

```python
from pydantic import BaseModel

class JobInput(BaseModel):
    brand_id: str
    payload: dict

@app.post("/jobs")
async def create_job(job: JobInput, auth: AuthState = Depends(m2m_auth)):
    # insert job scoped to job.brand_id...
    return {"id": "..."}
```

### `protect_or_m2m` — accept either

```python
@app.get("/jobs/{job_id}")
async def get_job(job_id: str, auth: AuthState = Depends(protect_or_m2m)):
    brand_id = get_brand_id(auth)
    # query by job_id + brand_id...
    return {"id": job_id}
```

### `require_service` — service-entitlement gate

`require_service("slug")` returns a `Depends()` that asks the platform API whether the caller's org is entitled to the named service. It bundles `protect_or_m2m` internally — a Clerk session OR a valid `X-API-Key` is sufficient.

```python
from konstant_studio_auth import require_service

@app.get("/posts")
async def list_posts(
    auth: AuthState = Depends(require_service("social-konstant-studio")),
):
    # only reaches here if the caller's org is entitled to "social-konstant-studio"
    return {"posts": [...]}
```

Behaviour:

- Superadmin (and m2m callers — they get `is_superadmin=True`) bypass the check.
- Org not entitled → `403` with `{"error": "No access to this service", "upgrade_url": "https://www.konstant-studio.com/dashboard"}`.
- `PLATFORM_API_URL` unset or the call fails: in dev → warn and allow; in production → `503 {"detail": "Entitlement service unavailable"}`.
  - Production is detected when any of `NODE_ENV`, `PYTHON_ENV`, `ENVIRONMENT`, or `ENV` equals `"production"`.
- Per-org result is cached in-process for 60s.

The platform endpoint called is `GET ${PLATFORM_API_URL}/entitlements/${org_id}` with `X-API-Key: ${INTERNAL_API_KEY}`. Expected response is `{"services": ["slug-a", "slug-b"]}` (also accepts a bare list or an `entitlements` field).

### `/me` endpoint

```python
@app.get("/me")
async def me(auth: AuthState = Depends(clerk_protect)):
    return auth
```

## Webhooks

Mount the router and subscribe handlers via `on_webhook_event`:

```python
from konstant_studio_auth import webhooks_router, on_webhook_event

app.include_router(webhooks_router)

@on_webhook_event("user.created")
async def handle_user_created(data: dict):
    await db.execute(
        """
        INSERT INTO users (id, email, full_name, is_superadmin, updated_at)
        VALUES (:id, :email, :full_name, :is_superadmin, now())
        ON CONFLICT (id) DO UPDATE SET
            email = EXCLUDED.email,
            full_name = EXCLUDED.full_name,
            is_superadmin = EXCLUDED.is_superadmin,
            updated_at = now()
        """,
        {
            "id": data["id"],
            "email": (data.get("email_addresses") or [{}])[0].get("email_address"),
            "full_name": f"{data.get('first_name') or ''} {data.get('last_name') or ''}".strip(),
            "is_superadmin": (data.get("public_metadata") or {}).get("superadmin") is True,
        },
    )

@on_webhook_event("user.updated")
async def handle_user_updated(data: dict):
    # same shape as user.created
    pass

@on_webhook_event("organizationMembership.created")
async def handle_membership_created(data: dict):
    await db.execute(
        "UPDATE users SET org_id = :org_id, org_role = :role, updated_at = now() WHERE id = :uid",
        {
            "org_id": data["organization"]["id"],
            "role": data["role"],
            "uid": data["public_user_data"]["user_id"],
        },
    )

@on_webhook_event("organizationMembership.deleted")
async def handle_membership_deleted(data: dict):
    await db.execute(
        "UPDATE users SET org_id = NULL, org_role = NULL, updated_at = now() WHERE id = :uid",
        {"uid": data["public_user_data"]["user_id"]},
    )

# Optional firehose — every event:
@on_webhook_event("*")
async def log_every_event(event: dict):
    print("clerk webhook:", event.get("type"))
```

The router:

1. Reads the body raw.
2. Verifies the Svix signature using `CLERK_WEBHOOK_SECRET`.
3. Acks `200 {"received": true}`.
4. Dispatches to subscribed handlers. Handler exceptions are logged but never break the response.

Register the endpoint in Clerk Dashboard → Webhooks → Add endpoint:

- URL: `https://<service-subdomain>/webhooks/clerk`
- Events: `user.created`, `user.updated`, `organizationMembership.created`, `organizationMembership.deleted`

## Environment variables

Same as the Node package — see the root [.env.example](../.env.example).

| Var                       | Purpose |
|---------------------------|---------|
| `CLERK_PUBLISHABLE_KEY`   | Public Clerk key (used by frontend SDK / OIDC client id). |
| `CLERK_SECRET_KEY`        | Clerk secret key. Available for host services using `clerk-backend-api`. |
| `CLERK_WEBHOOK_SECRET`    | Svix signing secret for the webhook endpoint. |
| `INTERNAL_API_KEY`        | Shared secret for `m2m_auth` (workers, n8n) — also sent as `X-API-Key` to the platform API by `require_service`. |
| `PLATFORM_API_URL`        | Base URL of the platform entitlements API used by `require_service`. Unset in dev = warn + allow; unset in prod = 503. |
| `NODE_ENV` / `PYTHON_ENV` / `ENVIRONMENT` / `ENV` | If any equals `"production"`, `require_service` fails closed when the platform API is unavailable. |

JWT verification fetches the JWKS directly from each token's `iss` claim (cached in-process), so you don't need to set the JWKS URL explicitly.

## Token transport

`clerk_protect` reads the JWT from either:

1. `Authorization: Bearer <jwt>` — the canonical form for API clients.
2. `__session` cookie — what Clerk's frontend SDK sets after login.

Cloudflare Access in front of the service should pass through whichever form the upstream client sent.

## Differences from the Node package

These are intentional adaptations to FastAPI's dependency-injection model. The auth contract (claims read, env vars, status codes, behaviour) is identical.

- **No `setupClerk()`.** FastAPI doesn't need an app-wide middleware install — every protected route declares `Depends(clerk_protect)` directly. The JWKS cache lives at module level.
- **No `requireLogin()`.** FastAPI services in this stack are JSON APIs, not server-rendered HTML, so the "redirect to Clerk hosted login" path doesn't apply. Frontends handle the login redirect themselves using Clerk's SDK and call the API with a Bearer token.
- **`get_brand_id(auth)` takes the `AuthState`, not the request.** The Node version reads `?brand_id=` for superadmins; the Python version returns `None` for superadmins and lets the caller layer in any per-request override they want — this keeps the helper pure and testable.
- **Webhooks use an in-process subscription registry instead of a Node `EventEmitter`.** Same model: register handlers by event type, plus a `"*"` wildcard. Handlers may be sync or `async def`; the router awaits coroutines automatically.
