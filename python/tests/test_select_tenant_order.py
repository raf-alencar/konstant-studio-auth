"""CR 53a0f327 (select-tenant order). The order is explicit → resolver → default_tenant_id →
single membership → tenant_choice_required (adapter 409). The Clerk org_id claim is never read
for selection. The x-tenant header is ignored. Grant-based reachability is enforced by the
platform (not by the library)."""

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from world import VECTORS, mint_clerk_token

CFG = VECTORS["config"]
ISS = CFG["clerk"]["issuer"]
AZP = CFG["clerk"]["authorized_parties"][0]


@pytest.fixture
def build(make_harness, world, clerk_keys):
    def _build(**over):
        h = make_harness(separate_monotonic=True, **over)
        h.acme = world.id("tenant", "acme")
        h.globex = world.id("tenant", "globex")
        h.acme_brand = world.id("tenant", "acme_brand")
        h.root = world.id("tenant", "root")
        h.token = lambda ref, spec=None: mint_clerk_token(clerk_keys, world.principal(ref)["user_id"], h.now(), ISS, AZP, spec)
        h.bearer = lambda ref, spec=None: {"authorization": f"Bearer {h.token(ref, spec)}"}
        return h

    return _build


# ---- per-branch: explicit -----------------------------------------------------------------

async def test_branch_explicit(build):
    h = build()
    d = await h.auth.authorize(headers=h.bearer("alice"), permission="docs:read", resource={"tenant": h.acme})
    assert (d.allow, d.tenant_id, d.tenant_source) == (True, h.acme, "explicit")


# ---- per-branch: default_tenant_id --------------------------------------------------------

async def test_branch_default(build, world):
    h = build()
    h.fake.memberships_for = {world.principal("bob")["user_id"]: {"default_tenant_id": h.globex, "memberships": [{"tenant_id": h.acme}, {"tenant_id": h.globex}]}}
    d = await h.auth.authorize(headers=h.bearer("bob"), permission="docs:read")
    assert (d.tenant_id, d.tenant_source) == (h.globex, "default")


# ---- per-branch: single_membership --------------------------------------------------------

async def test_branch_single_membership(build):
    h = build()
    # alice has exactly one world membership (acme)
    d = await h.auth.authorize(headers=h.bearer("alice"), permission="docs:read")
    assert (d.tenant_id, d.tenant_source) == (h.acme, "single_membership")


# ---- per-branch: tenant_choice_required (409) ---------------------------------------------

async def test_branch_tenant_choice_required(build):
    h = build()
    # bob has two memberships, no default
    d = await h.auth.authorize(headers=h.bearer("bob"), permission="docs:read")
    assert (d.allow, d.reason, d.status) == (False, "tenant_choice_required", 409)


def test_adapter_fastapi_returns_409(build):
    h = build()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/x")
    async def x(request: Request, d=Depends(h.auth.require_permission("docs:read"))):
        return {}

    with TestClient(app) as c:
        r = c.get("/x", headers=h.bearer("bob"))
    assert r.status_code == 409
    assert r.json()["detail"]["reason"] == "tenant_choice_required"


# ---- grant allowed / sibling denied -------------------------------------------------------

async def test_grant_allowed(build):
    h = build()
    h.fake.live = {"allow": True, "reason": "allowed", "tenant": "acme_brand", "via_tenant": "root", "roles": ["owner"]}
    # rafa is a root member with scope.descendants=true; the platform allows the brand child.
    d = await h.auth.authorize(headers=h.bearer("rafa"), permission="docs:read", resource={"tenant": h.acme_brand})
    assert d.allow is True
    assert d.tenant_source == "explicit"
    assert d.via_tenant == h.root


async def test_sibling_denied_cl_a_to_cl_b(build):
    h = build()
    # alice is only a member of acme; asking about globex is denied by the platform.
    h.fake.live = {"allow": False, "reason": "no_permission"}
    d = await h.auth.authorize(headers=h.bearer("alice"), permission="docs:read", resource={"tenant": h.globex})
    assert (d.allow, d.reason) == (False, "no_permission")


async def test_sibling_denied_brand_to_root(build):
    # brandy is a member of only acme_brand; asking about root goes live and is denied.
    h = build()
    h.fake.live = {"allow": False, "reason": "no_permission"}
    d = await h.auth.authorize(headers=h.bearer("brandy"), permission="docs:read", resource={"tenant": h.root})
    assert (d.allow, d.reason) == (False, "no_permission")


# ---- inactive default falls through -------------------------------------------------------

async def test_inactive_default_falls_through(build, world):
    h = build()
    # A default pointing at an inactive tenant is dropped by the platform; the library then applies
    # the next step (single-membership or 409).
    h.fake.memberships_for = {world.principal("bob")["user_id"]: {"default_tenant_id": None, "memberships": [{"tenant_id": h.acme}, {"tenant_id": h.globex}]}}
    d = await h.auth.authorize(headers=h.bearer("bob"), permission="docs:read")
    assert (d.allow, d.reason) == (False, "tenant_choice_required")
    h.fake.memberships_for = {world.principal("alice")["user_id"]: {"default_tenant_id": None, "memberships": [{"tenant_id": h.acme}]}}
    d2 = await h.auth.authorize(headers=h.bearer("alice"), permission="docs:read")
    assert (d2.tenant_id, d2.tenant_source) == (h.acme, "single_membership")


# ---- org_id invariance --------------------------------------------------------------------

async def test_org_id_invariance(build):
    h = build()
    with_org = await h.auth.authorize(headers=h.bearer("alice", {"extra": {"org_id": "org_acme"}}), permission="docs:read")
    without_org = await h.auth.authorize(headers=h.bearer("alice"), permission="docs:read")
    assert (with_org.tenant_id, with_org.tenant_source, with_org.allow) == (h.acme, "single_membership", True)
    assert (without_org.tenant_id, without_org.tenant_source, without_org.allow) == (h.acme, "single_membership", True)
    other_org = await h.auth.authorize(headers=h.bearer("alice", {"extra": {"org_id": "org_globex"}}), permission="docs:read")
    assert (other_org.tenant_id, other_org.tenant_source) == (h.acme, "single_membership")


async def test_org_id_invariance_effective_permissions(build):
    """effectivePermissions follows the same rule: the same token with and without an org_id
    (v1 or v2 shape) returns an identical result."""
    h = build()
    reply = {"valid": True, "principal": {"id": "p", "kind": "human", "user_id": "user_alice", "tenant_id": h.acme},
             "effective": {"tenant_id": h.acme, "reason": None, "permissions": [
                 {"permission": "docs:read", "service": "docs", "action": "read", "category": "read", "sensitive": False,
                  "scopes": [{"scope": {}, "role": "operator", "via_tenant": None}]}]}}
    h.fake.override = lambda path, body: reply if path == "/v1/principals/resolve" and body.get("include_effective") else None
    without_org = await h.auth.effective_permissions(headers=h.bearer("alice"), tenant=h.acme)
    with_v1 = await h.auth.effective_permissions(headers=h.bearer("alice", {"extra": {"org_id": "org_globex"}}), tenant=h.acme)
    with_v2 = await h.auth.effective_permissions(headers=h.bearer("alice", {"extra": {"o": {"id": "org_globex", "rol": "admin"}}}), tenant=h.acme)
    for r in (without_org, with_v1, with_v2):
        assert (r.ok, r.tenant_id, len(r.permissions)) == (True, h.acme, 1)


# ---- hint refused -------------------------------------------------------------------------

def test_hint_refused_x_tenant_header_does_not_move_the_decision(build):
    h = build()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/x")
    async def x(request: Request, d=Depends(h.auth.require_permission("docs:read"))):
        return {"tenant_id": d.tenant_id, "tenant_source": d.tenant_source}

    with TestClient(app) as c:
        r = c.get("/x", headers={**h.bearer("alice"), "x-tenant": h.globex})
    assert r.status_code == 200
    assert (r.json()["tenant_id"], r.json()["tenant_source"]) == (h.acme, "single_membership")


# ---- tenant_audit helper ------------------------------------------------------------------

async def test_tenant_audit_service_key_guard(build, world):
    h = build()
    svc_key = world.raw_key(next(k for k in world.spec["keys"] if k["ref"] == "svc_image_active"))
    good = await h.auth.tenant_audit(headers={"x-api-key": svc_key}, tenant_id=h.acme, counts={"documents": 42}, stale=False)
    assert (good["ok"], good["status"], good["service"], good["tenant_id"], good["counts"], good["stale"]) == (True, 200, "docs", h.acme, {"documents": 42}, False)

    nokey = await h.auth.tenant_audit(headers={}, tenant_id=h.acme)
    assert (nokey["ok"], nokey["status"], nokey["reason"]) == (False, 401, "no_credential")

    human = await h.auth.tenant_audit(headers=h.bearer("alice"), tenant_id=h.acme)
    assert (human["ok"], human["status"], human["reason"]) == (False, 401, "service_caller_required")


async def test_tenant_audit_caller_service_pin(build, world):
    h = build()
    svc_key = world.raw_key(next(k for k in world.spec["keys"] if k["ref"] == "svc_image_active"))
    wrong = await h.auth.tenant_audit(headers={"x-api-key": svc_key}, caller_service="video", tenant_id=h.acme)
    assert (wrong["ok"], wrong["status"], wrong["reason"]) == (False, 403, "route_not_allowed")
