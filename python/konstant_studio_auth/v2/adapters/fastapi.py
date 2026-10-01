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

from ..service_keys import route_allowed
from .shared import clean_run_id, denial_body, legacy_auth, resolve_scope


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
            # An explicit tenant scope always wins; the header is only a hint when none was given.
            if not resource.get("tenant") and request.headers.get("x-tenant"):
                resource["tenant"] = request.headers["x-tenant"]
            request_id = clean_run_id(request.headers.get("x-run-id"))
            args = dict(headers=request.headers, permission=permission, resource=resource, request=request, request_id=request_id)
            d = await core.authorize_approver(step_up=step_up, **args) if approver else await core.authorize(**args)
        except HTTPException:
            raise
        except Exception as err:  # noqa: BLE001
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

    def require_service_route():
        """A SERVICE principal may call only the routes in its allow-list; every other
        principal kind passes through (their gate is require_permission)."""

        async def dependency(request: Request):
            r = await core.resolve_principal(headers=request.headers)
            if not r["ok"]:
                raise fail(r["status"], r["reason"])
            p = r["principal"]
            if p.kind == "service" and not route_allowed(p.routes, request.method, request.url.path):
                raise fail(403, "route_not_allowed")
            return p

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
                task = asyncio.ensure_future(core.cache.refresh())
                task.add_done_callback(lambda t: t.cancelled() or t.exception())
            return {"received": True}

        return endpoint

    class _Adapter:
        pass

    a = _Adapter()
    a.require_permission = require_permission
    a.require_approver = require_approver
    a.require_service_route = require_service_route
    a.events_webhook = events_webhook
    a.assert_tenant = lambda request, tenant_id: core.assert_tenant(getattr(request.state, "auth_decision", None), tenant_id)
    a.usage_context = lambda request: core.usage_context(getattr(request.state, "auth_decision", None), clean_run_id(request.headers.get("x-run-id")))
    return a
