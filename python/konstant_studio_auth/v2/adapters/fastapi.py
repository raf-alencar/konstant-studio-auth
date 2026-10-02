"""FastAPI adapter.

    auth = create_auth(service="docs").start()   # in a lifespan handler
    @app.post("/render")
    async def render(d = Depends(auth.require_permission(
            "docs:render", tenant=lambda r: r.path_params.get("tenant"),
            brand=lambda r: r.headers.get("x-brand")))):
        ...

On success: request.state.principal (Principal), request.state.auth_decision, and the
v1-shaped request.state.auth. On failure: 401 (credential), 403 (decision), 503 (could not decide).
"""

from fastapi import HTTPException, Request

from ..service_keys import validate_policy
from .shared import clean_run_id, denial_body, legacy_auth, resolve_scope


def _header_list(request, name):
    h = request.headers
    getlist = getattr(h, "getlist", None)
    return list(getlist(name)) if getlist else ([h[name]] if name in h else [])


def _raw_path(request):
    """ASGI's `raw_path` is the request target as sent (percent-escapes intact); `url.path` is decoded.
    Policy matching must see the former. Falls back to the decoded path (which the policy then refuses
    if it contains anything ambiguous)."""
    raw = request.scope.get("raw_path")
    if raw is not None:
        raw = raw.decode("latin-1") if isinstance(raw, (bytes, bytearray)) else str(raw)
        return raw.split("?", 1)[0].split("#", 1)[0]
    return request.url.path


def fastapi_adapter(core):
    cfg = core.config

    def fail(status, reason):
        headers = {}
        if status == 401:
            headers["WWW-Authenticate"] = "Bearer"
        if status == 503:
            headers["Retry-After"] = "5"
        return HTTPException(status_code=status, detail=denial_body(status, reason, cfg), headers=headers or None)

    async def run(request, permission, scope, approver=False, step_up=False):
        try:
            resource = await resolve_scope(scope, request)
            # The x-tenant header is only a HINT, the weakest source of the tenant (see Auth._select_tenant).
            # (a repeated header, or one joined with a comma, is ambiguous: no hint at all)
            hints = _header_list(request, "x-tenant")
            if len(hints) == 1 and hints[0] and "," not in hints[0]:
                resource["tenant_hint"] = hints[0]
            request_id = clean_run_id(request.headers.get("x-run-id"))
            args = dict(headers=request.headers, permission=permission, resource=resource, request=request, request_id=request_id)
            d = await core.authorize_approver(step_up=step_up, **args) if approver else await core.authorize(**args)
        except HTTPException:
            raise
        except Exception as err:  # noqa: BLE001 - a scope callable that raises must never surface as anything but a 503
            cfg.logger.error(f"auth dependency: unexpected {type(err).__name__}")
            raise fail(503, "platform_unavailable") from None
        if not d.allow:
            raise fail(d.status, d.reason)
        request.state.principal = d.principal
        request.state.auth_decision = d
        request.state.auth = legacy_auth(d.principal, d)
        return d

    def require_permission(permission, tenant=None, brand=None, domain=None, mailbox=None):
        scope = {"tenant": tenant, "brand": brand, "domain": domain, "mailbox": mailbox}

        async def dependency(request: Request):
            return await run(request, permission, scope)

        return dependency

    def require_approver(permission, step_up=False, tenant=None, brand=None, domain=None, mailbox=None):
        scope = {"tenant": tenant, "brand": brand, "domain": domain, "mailbox": mailbox}

        async def dependency(request: Request):
            return await run(request, permission, scope, approver=True, step_up=step_up)

        return dependency

    def require_service_caller(policy):
        """Inbound calls from other internal services (stgs_ keys). `policy` is THIS app's own rule for
        each accepted caller service: {"image": ["POST /internal/render", "GET /internal/status/*"]}.
        Deny by default; the platform's allowed_routes for the key are not consulted."""
        validate_policy(policy, cfg.accepted_caller_services)

        async def dependency(request: Request):
            try:
                # The path as SENT (undecoded, unnormalised, including any mount prefix), without the query string.
                d = await core.authorize_service_caller(headers=request.headers, method=request.method, path=_raw_path(request), policy=policy)
            except Exception as err:  # noqa: BLE001
                cfg.logger.error(f"auth dependency: unexpected {type(err).__name__}")
                raise fail(503, "platform_unavailable") from None
            if not d.allow:
                raise fail(d.status, d.reason)
            request.state.principal = d.principal
            request.state.auth_decision = d
            request.state.auth = legacy_auth(d.principal, d)
            return d

        return dependency

    def events_webhook(secret):
        """Endpoint for the platform's signed change events: `app.post('/hooks/platform')(auth.fastapi.events_webhook(secret))`."""
        import asyncio

        from ..events_webhook import verify_signature

        async def endpoint(request: Request):
            ok = verify_signature(
                secret=secret,
                timestamp=request.headers.get("x-platform-timestamp"),
                signature=request.headers.get("x-platform-signature"),
                raw_body=await request.body(),
                now_ms=cfg.now(),
            )
            if not ok:
                raise HTTPException(status_code=401, detail={"error": "Invalid signature"})
            if core.cache:
                core.cache.invalidate()
                # best effort: the next check revalidates anyway
                # fresh: a request already in flight started BEFORE this change, so wait for it and ask again.
                task = asyncio.ensure_future(core.cache.refresh(fresh=True))
                task.add_done_callback(lambda t: t.cancelled() or t.exception())
            return {"received": True}

        return endpoint

    class _Adapter:
        pass

    a = _Adapter()
    a.require_permission = require_permission
    a.require_approver = require_approver
    a.require_service_caller = require_service_caller
    a.events_webhook = events_webhook
    a.assert_tenant = lambda request, tenant_id: core.assert_tenant(getattr(request.state, "auth_decision", None), tenant_id)
    a.usage_context = lambda request: core.usage_context(getattr(request.state, "auth_decision", None), clean_run_id(request.headers.get("x-run-id")))
    return a
