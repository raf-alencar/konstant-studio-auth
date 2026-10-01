import hashlib
import hmac
import time

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from jose import jwt

from world import VECTORS, mint_clerk_token

CFG = VECTORS["config"]
ISS = CFG["clerk"]["issuer"]
AZP = CFG["clerk"]["authorized_parties"][0]


@pytest.fixture
def rig(make_harness, world, clerk_keys):
    h = make_harness()
    auth = h.auth
    app = FastAPI()
    acme = world.id("tenant", "acme")

    @app.get("/docs-read")
    async def read(d=Depends(auth.require_permission("docs:read", tenant=acme))):
        return {"tenant": d.tenant_id, "roles": d.roles}

    @app.get("/by-header")
    async def by_header(d=Depends(auth.require_permission("docs:read"))):
        return {"tenant": d.tenant_id}

    async def async_tenant(request):
        return request.query_params.get("t")

    @app.get("/callable/{brand}")
    async def callable_scope(d=Depends(auth.fastapi.require_permission("docs:render", tenant=async_tenant, brand=lambda r: r.path_params["brand"]))):
        return {"ok": True}

    @app.post("/write")
    async def write(d=Depends(auth.require_permission("docs:write", tenant=acme))):
        return {"ok": True}

    @app.delete("/doc")
    async def delete(d=Depends(auth.require_permission("docs:delete", tenant=acme))):
        return {"ok": True}

    @app.post("/approve")
    async def approve(d=Depends(auth.require_approver("social:approve", step_up=True, tenant=acme))):
        return {"ok": True}

    @app.get("/who")
    async def who(request: Request, d=Depends(auth.require_permission("docs:read", tenant=acme))):
        return {"principal": request.state.principal.id, "decision": request.state.auth_decision.reason, "legacy": request.state.auth}

    @app.post("/hooks/platform")
    async def hook(request: Request):
        return await auth.events_webhook("whsec")(request)

    def bearer(who="alice", spec=None, **extra):
        t = mint_clerk_token(clerk_keys, world.principal(who)["user_id"], h.now(), ISS, AZP, spec)
        return {"Authorization": f"Bearer {t}"}

    class Rig:
        pass

    r = Rig()
    r.h, r.world, r.client, r.bearer, r.acme = h, world, TestClient(app), bearer, acme
    return r


def test_allow(rig):
    r = rig.client.get("/docs-read", headers=rig.bearer("alice"))
    assert r.status_code == 200 and r.json() == {"tenant": rig.acme, "roles": ["operator"]}


def test_state_is_set_and_legacy_shape_is_never_superadmin(rig):
    r = rig.client.get("/who", headers=rig.bearer("alice"))
    assert r.status_code == 200
    j = r.json()
    assert j["principal"] == "user_alice" and j["decision"] == "allowed"
    assert j["legacy"] == {"user_id": "user_alice", "clerk_org_id": None, "clerk_org_role": None, "is_superadmin": False, "tenant_id": rig.acme}


@pytest.mark.parametrize("headers", [{"Authorization": "Bearer not-a-key-and-not-a-jwt"}, {"Authorization": "Bearer a.b.c"}, {}])
def test_clean_401_on_garbage_or_missing_credential(rig, headers):
    r = rig.client.get("/docs-read", headers=headers)
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    reason = "no_credential" if not headers else "token_invalid"
    assert r.json() == {"detail": {"error": "Unauthorized", "reason": reason}}
    assert "retry-after" not in r.headers


def test_403_has_reason_and_no_internals(rig):
    r = rig.client.post("/write", headers=rig.bearer("bob"))
    assert r.status_code == 403 and r.json() == {"detail": {"error": "Forbidden", "reason": "no_permission"}}
    assert "www-authenticate" not in r.headers


def test_not_entitled_carries_upgrade_url(rig):
    r = rig.client.get("/by-header", headers={**rig.bearer("alice"), "x-tenant": rig.world.id("tenant", "dormant")})
    assert r.status_code == 403
    assert r.json() == {"detail": {"error": "No access to this service", "reason": "not_entitled", "upgrade_url": "https://www.konstant-studio.com/dashboard"}}


def test_503_when_platform_down_for_sensitive(rig):
    rig.client.get("/docs-read", headers=rig.bearer("amy"))  # prime the cache
    rig.h.fake.down = True
    r = rig.client.delete("/doc", headers=rig.bearer("amy"))
    assert r.status_code == 503 and r.headers["retry-after"] == "5"
    assert r.json() == {"detail": {"error": "Authorization service unavailable", "reason": "platform_unavailable"}}


def test_sensitive_goes_live_and_allows(rig):
    rig.h.fake.live = {"allow": True, "reason": "allowed", "tenant": "acme", "roles": ["admin"], "sensitive": True, "principal": {"id": "p", "kind": "human", "user_id": "user_amy"}}
    r = rig.client.delete("/doc", headers=rig.bearer("amy"))
    assert r.status_code == 200 and rig.h.fake.count("POST", "/v1/authorize") == 1


def test_x_tenant_header_only_when_no_tenant_scope(rig):
    # no scope tenant: the header names the tenant, decided offline
    r = rig.client.get("/by-header", headers={**rig.bearer("alice"), "x-tenant": rig.acme})
    assert r.status_code == 200 and r.json() == {"tenant": rig.acme}
    # scope tenant given: a hostile header must not redirect the decision
    r = rig.client.get("/docs-read", headers={**rig.bearer("alice"), "x-tenant": rig.world.id("tenant", "globex")})
    assert r.status_code == 200 and r.json()["tenant"] == rig.acme
    # neither: the platform answers tenant_required
    rig.h.fake.live = {"allow": False, "reason": "tenant_required", "tenant": None}
    r = rig.client.get("/by-header", headers=rig.bearer("alice"))
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "tenant_required"


def test_callable_scopes_sync_and_async(rig):
    h = rig.bearer("carol")
    ok = rig.client.get(f"/callable/BRAND-A?t={rig.acme}", headers=h)
    assert ok.status_code == 200
    bad = rig.client.get(f"/callable/brand-b?t={rig.acme}", headers=h)
    assert bad.status_code == 403 and bad.json()["detail"]["reason"] == "out_of_scope"


def test_x_run_id_reaches_the_audit_event(rig):
    events = []
    rig.h.auth.config.on_event = events.append
    rig.client.get("/docs-read", headers={**rig.bearer("alice"), "x-run-id": "run-42"})
    assert events[0]["run_id"] == "run-42"


def test_approver_step_up(rig, clerk_keys):
    rig.h.fake.live = {"allow": True, "reason": "allowed", "tenant": "acme", "roles": ["approver"], "sensitive": True, "principal": {"id": "p", "kind": "human", "user_id": "user_dan"}}

    def tok(**extra):
        now = rig.h.now() // 1000
        c = {"sub": "user_dan", "iat": now, "exp": now + 600, "iss": ISS, "azp": AZP, **extra}
        return {"Authorization": "Bearer " + jwt.encode(c, clerk_keys.trusted.pem, algorithm="RS256", headers={"kid": "kid-trusted"})}

    assert rig.client.post("/approve", headers=tok(fva=[1, 2])).status_code == 200
    r = rig.client.post("/approve", headers=tok())
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "step_up_required"


def test_events_webhook_endpoint(rig):
    rig.client.get("/docs-read", headers=rig.bearer("alice"))
    body = b'{"x":1}'
    ts = str(rig.h.now() // 1000)
    sig = "v1=" + hmac.new(b"whsec", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    assert rig.client.post("/hooks/platform", content=body, headers={"x-platform-timestamp": ts, "x-platform-signature": "v1=00"}).status_code == 401
    r = rig.client.post("/hooks/platform", content=body, headers={"x-platform-timestamp": ts, "x-platform-signature": sig})
    assert r.status_code == 200 and r.json() == {"received": True}
