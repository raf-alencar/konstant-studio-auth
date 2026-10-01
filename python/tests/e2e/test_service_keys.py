"""Against the real C0b2 platform (scratch copy): what it ALREADY does for inbound service keys and
effective permissions, and what the library makes of it. The shared vectors for service keys stay
`pending-platform` until the CoS's C0b2 fixes (mandatory expect_service, uniform key_not_found)
land; nothing here depends on those: the library always sends expect_service and answers uniformly
whatever specific reason the platform gives, so these pass both before and after.
"""

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from world import VECTORS

from .helpers import bearer, library_for, platform_authorize

ACCEPTED = VECTORS["config"]["accepted_caller_services"]
UNIFORM = {"ok": False, "reason": "key_not_found", "status": 401}


def build(ctx, **extra):
    return library_for(ctx, accepted_caller_services=ACCEPTED, **extra)


def hdr(ctx, ref):
    return {"x-api-key": ctx.state["keys"][ref]}


async def test_an_accepted_caller_service_resolves_to_a_service_principal_and_only_that(ctx):
    auth = build(ctx)
    try:
        r = await auth.resolve_principal(headers=hdr(ctx, "svc_image_active"))
        assert r["ok"] is True
        p = r["principal"]
        assert (p.kind, p.service, p.tenant) == ("service", "image", None)
        assert p.key_id and not hasattr(p, "routes")
        second = await auth.resolve_principal(headers=hdr(ctx, "svc_video_active"))
        assert (second["ok"], second["principal"].service) == (True, "video"), "the second accepted service is tried after the first does not match"
    finally:
        await auth.close()


async def test_unknown_revoked_expired_and_unaccepted_keys_give_the_same_answer(ctx):
    auth = build(ctx)
    try:
        for ref in ("svc_image_revoked", "svc_image_expired", "svc_image_unknown", "svc_docs_active"):
            assert await auth.resolve_principal(headers=hdr(ctx, ref)) == UNIFORM, ref
    finally:
        await auth.close()


async def test_a_service_principal_is_denied_every_tenant_permission_exactly_as_the_platform_says(ctx):
    auth = build(ctx)
    acme = ctx.world.id("tenant", "acme")
    try:
        for permission in ("docs:read", "docs:write", "docs:delete", "social:approve"):
            service, action = permission.split(":")
            _, truth = platform_authorize(ctx, {"credential": ctx.state["keys"]["svc_image_active"], "service": service, "action": action, "resource": {"tenant_id": acme}})
            assert truth["allow"] is False and truth["reason"] == "service_principal_not_granted", "platform"
            d = await auth.authorize(headers=hdr(ctx, "svc_image_active"), permission=permission, resource={"tenant": acme})
            assert (d.allow, d.reason, d.status, d.source) == (False, "service_principal_not_granted", 403, "none"), permission
    finally:
        await auth.close()


def test_the_apps_own_route_policy_governs_a_matched_caller(ctx):
    auth = build(ctx)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None,
                  dependencies=[Depends(auth.require_service_caller({"image": ["POST /internal/render"]}))])

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def anything(request: Request):
        return {"caller": request.state.principal.service}

    with TestClient(app) as c:
        call = lambda ref, method, path: c.request(method, path, headers=hdr(ctx, ref))  # noqa: E731
        assert call("svc_image_active", "POST", "/internal/render").status_code == 200
        other = call("svc_image_active", "POST", "/v1/authorize")  # a PLATFORM route the key holds
        assert (other.status_code, other.json()["detail"]["reason"]) == (403, "route_not_allowed")
        assert call("svc_video_active", "POST", "/internal/render").status_code == 403, "video is accepted but has no policy here"
        revoked = call("svc_image_revoked", "POST", "/internal/render")
        assert (revoked.status_code, revoked.json()["detail"]["reason"]) == (401, "key_not_found")


async def test_effective_permits_agrees_with_authorize_on_every_runnable_vector(ctx):
    auth = build(ctx)
    compared = 0
    try:
        for c in VECTORS["cases"]:
            if c.get("pending") or c.get("platform") == "down" or c.get("parity") is False or c["who"].get("token"):
                continue
            if not (c["who"].get("clerk") or c["who"].get("key")):
                continue
            headers = bearer(ctx, c["who"]["clerk"]) if c["who"].get("clerk") else {"x-api-key": ctx.state["keys"][c["who"]["key"]]}
            service, action = c["ask"]["permission"].split(":")
            named = c["ask"].get("tenant") or c["ask"].get("resolver_tenant") or c.get("parity_tenant")
            resource = {f: c["ask"][f] for f in ("brand", "domain", "mailbox") if c["ask"].get(f)}
            tenant = ctx.world.id("tenant", named) if named else None
            wire = {"brand": "brand_id", "domain": "domain", "mailbox": "mailbox"}
            body = {"service": service, "action": action,
                    "resource": {**({"tenant_id": tenant} if tenant else {}), **{wire[k]: v for k, v in resource.items()}}}
            if c["who"].get("clerk"):
                body["clerk_token"] = headers["authorization"][7:]
            else:
                body["credential"] = headers["x-api-key"]
            _, truth = platform_authorize(ctx, body)
            e = await auth.effective_permissions(headers=headers, tenant=tenant, service=service)
            if not e.ok:
                assert truth["allow"] is False, f"{c['id']}: no effective answer but the platform allows"
                continue  # a revoked/unknown key, etc.
            got = e.permits(c["ask"]["permission"], resource)
            assert got == truth["allow"], f"{c['id']}: effective says {got}, authorize says {truth['allow']} ({truth['reason']})"
            compared += 1
    finally:
        await auth.close()
    assert compared >= 30, f"only {compared} cases compared"


async def test_an_agents_effective_permissions_never_include_an_approver_permission(ctx):
    auth = build(ctx)
    try:
        e = await auth.effective_permissions(headers=hdr(ctx, "agent_acme_active"), service="social")
        assert e.ok is True
        assert "social:approve" not in e.principal.permissions
        assert "social:write" in e.principal.permissions
    finally:
        await auth.close()
