"""A sample FastAPI app gated end to end by the library against the SCRATCH platform: real
tokens, real keys, real decisions, real HTTP. This is also what the adoption checklist tells
each adopting repo to reproduce for its own routes.
"""

import json
import re

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from .helpers import bearer, library_for

EVENTS = []


@pytest.fixture(scope="module")
def rig(ctx):
    auth = library_for(ctx, on_event=EVENTS.append)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # "/docs" is a sample route here
    tenant_of = lambda req: req.query_params.get("tenant")  # noqa: E731

    @app.get("/docs")
    async def docs(request: Request, d=Depends(auth.require_permission("docs:read", tenant=tenant_of))):
        return {"kind": d.principal.kind, "tenant": d.tenant_id, "roles": d.principal.roles,
                "legacy_user": request.state.auth["user_id"], "usage": auth.fastapi.usage_context(request)}

    async def brand_from_body(request):
        return (await request.json()).get("brand")

    @app.post("/docs/render-gated")
    async def render_gated(d=Depends(auth.require_permission("docs:render", tenant=tenant_of, brand=brand_from_body))):
        return {"ok": True}

    @app.delete("/docs/{doc_id}")
    async def delete(doc_id: str, d=Depends(auth.require_permission("docs:delete", tenant=tenant_of))):
        return {"deleted": doc_id}

    @app.post("/approve")
    async def approve(d=Depends(auth.require_approver("social:approve", step_up=True, tenant=tenant_of))):
        return {"approved": True}

    @app.get("/by-tenant-assert")
    async def assert_tenant(request: Request, claimed: str, d=Depends(auth.require_permission("docs:read", tenant=tenant_of))):
        return {"same": auth.fastapi.assert_tenant(request, claimed)}

    with TestClient(app) as client:
        yield client
    # the app's own loop is gone by now; nothing else to close (no polling started)


def reason_of(r):
    return r.json()["detail"]["reason"]


def test_no_credential_is_a_clean_401_with_a_challenge(rig, ctx):
    acme = ctx.world.id("tenant", "acme")
    r = rig.get(f"/docs?tenant={acme}")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    assert r.json() == {"detail": {"error": "Unauthorized", "reason": "no_credential"}}


def test_garbage_bearer_is_a_clean_401(rig, ctx):
    r = rig.get(f"/docs?tenant={ctx.world.id('tenant', 'acme')}", headers={"authorization": "Bearer definitely-not-a-session"})
    assert r.status_code == 401
    assert r.json() == {"detail": {"error": "Unauthorized", "reason": "token_invalid"}}


def test_allowed_with_principal_legacy_shape_and_usage_actor(rig, ctx):
    acme = ctx.world.id("tenant", "acme")
    r = rig.get(f"/docs?tenant={acme}", headers=bearer(ctx, "alice"))
    assert r.status_code == 200
    b = r.json()
    assert [b["kind"], b["tenant"], b["roles"], b["legacy_user"]] == ["human", acme, ["operator"], "user_alice"]
    assert b["usage"]["actor"] == {"kind": "human", "id": "user_alice"} and b["usage"]["tenant_id"] == acme


def test_wrong_tenant_and_x_tenant_header(rig, ctx):
    acme, globex = ctx.world.id("tenant", "acme"), ctx.world.id("tenant", "globex")
    h = bearer(ctx, "alice")
    assert rig.get(f"/docs?tenant={globex}", headers=h).status_code == 403
    assert rig.get("/docs", headers={**h, "x-tenant": acme}).status_code == 200
    assert rig.get("/docs", headers={**h, "x-tenant": globex}).status_code == 403
    assert rig.get("/docs", headers={**h, "x-tenant": "not-a-uuid"}).status_code == 403
    # an explicit tenant scope wins over a hostile header
    assert rig.get(f"/docs?tenant={acme}", headers={**h, "x-tenant": globex}).status_code == 200


def test_brand_scope_from_the_request_body(rig, ctx):
    acme = ctx.world.id("tenant", "acme")
    h = bearer(ctx, "carol")
    send = lambda body: rig.post(f"/docs/render-gated?tenant={acme}", headers=h, json=body)  # noqa: E731
    assert send({"brand": "brand-a"}).status_code == 200
    out = send({"brand": "brand-b"})
    assert (out.status_code, reason_of(out)) == (403, "out_of_scope")
    assert reason_of(send({})) == "scope_required"


def test_sensitive_actions_are_decided_live(rig, ctx):
    acme = ctx.world.id("tenant", "acme")
    assert rig.delete(f"/docs/42?tenant={acme}", headers=bearer(ctx, "amy")).status_code == 200
    denied = rig.delete(f"/docs/42?tenant={acme}", headers=bearer(ctx, "alice"))
    assert (denied.status_code, reason_of(denied)) == (403, "no_permission")


def test_require_approver_needs_human_permission_and_recent_second_factor(rig, ctx):
    acme = ctx.world.id("tenant", "acme")
    approve = lambda headers: rig.post(f"/approve?tenant={acme}", headers=headers)  # noqa: E731
    no_mfa = approve(bearer(ctx, "dan"))
    assert (no_mfa.status_code, reason_of(no_mfa)) == (403, "step_up_required")
    assert reason_of(approve(bearer(ctx, "dan", {"extra": {"fva": [5, 45]}}))) == "step_up_required"
    assert approve(bearer(ctx, "dan", {"extra": {"fva": [5, 2]}})).status_code == 200
    agent = approve({"x-api-key": ctx.state["keys"]["agent_acme_active"]})
    assert (agent.status_code, reason_of(agent)) == (403, "principal_kind_restricted")


def test_agent_keys_work_and_a_revoked_key_stops_at_once(rig, ctx):
    assert rig.get("/docs", headers={"x-api-key": ctx.state["keys"]["agent_acme_active"]}).status_code == 200
    r = rig.get("/docs", headers={"x-api-key": ctx.state["keys"]["agent_acme_revoked"]})
    assert (r.status_code, reason_of(r)) == (401, "key_revoked")


def test_this_app_accepts_no_caller_service_so_a_service_key_is_refused_uniformly(rig, ctx):
    r = rig.get("/docs", headers={"x-api-key": ctx.state["keys"]["svc_image_active"]})
    assert (r.status_code, reason_of(r)) == (401, "key_not_found")


def test_assert_tenant_only_for_the_decision_tenant(rig, ctx):
    acme, globex = ctx.world.id("tenant", "acme"), ctx.world.id("tenant", "globex")
    h = bearer(ctx, "alice")
    assert rig.get(f"/by-tenant-assert?tenant={acme}&claimed={acme}", headers=h).json()["same"] is True
    assert rig.get(f"/by-tenant-assert?tenant={acme}&claimed={globex}", headers=h).json()["same"] is False


def test_platform_unreachable_fails_closed_with_503_and_retry_after(ctx):
    dead = library_for(ctx, platform_url="http://127.0.0.1:9", request_timeout_ms=500)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)  # "/docs" is a sample route here
    tenant_of = lambda req: req.query_params.get("tenant")  # noqa: E731

    @app.get("/docs")
    async def read(d=Depends(dead.require_permission("docs:read", tenant=tenant_of))):
        return {"ok": True}

    @app.delete("/docs")
    async def delete(d=Depends(dead.require_permission("docs:delete", tenant=tenant_of))):
        return {"ok": True}

    h = bearer(ctx, "amy")
    with TestClient(app) as c:
        for method in ("get", "delete"):  # sensitive, and a read with a cold cache
            r = getattr(c, method)(f"/docs?tenant={ctx.world.id('tenant', 'acme')}", headers=h)
            assert r.status_code == 503, method
            assert r.headers["retry-after"] == "5"
            assert reason_of(r) == "platform_unavailable"


def test_audit_events_carry_ids_and_decisions_never_a_token_or_a_key(rig, ctx):
    assert len(EVENTS) >= 10
    blob = json.dumps(EVENTS)
    secrets = [*ctx.state["keys"].values(), ctx.state["service_key"], ctx.state["shared_key"], bearer(ctx, "alice")["authorization"].split(" ")[1]]
    for s in secrets:
        assert s not in blob, "secret material in an audit event"
    assert not re.search(r"eyJ[A-Za-z0-9_-]{10,}", blob), "a JWT in an audit event"
    allowed = next(e for e in EVENTS if e["allow"] and (e["actor"] or {}).get("id") == "user_alice")
    assert allowed["type"] == "auth.decision" and allowed["source"] == "offline"
