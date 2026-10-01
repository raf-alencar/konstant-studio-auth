"""Effective permissions (platform C0b2: POST /v1/principals/resolve with include_effective) and
Clerk organization -> tenant mapping from the snapshot's org_id.
"""

import json

import httpx

from world import VECTORS, mint_clerk_token

ISS = VECTORS["config"]["clerk"]["issuer"]
AZP = VECTORS["config"]["clerk"]["authorized_parties"][0]


class Rig:
    def __init__(self, h, world, keys):
        self.h, self.world, self.keys = h, world, keys
        self.calls = []
        self.effective_reply = None
        inner = h.fake.handle

        async def wrapped(request):
            if request.url.path == "/v1/principals/resolve" and request.content:
                body = json.loads(request.content)
                if body.get("include_effective"):
                    self.calls.append(body)
                    if h.fake.down:
                        raise httpx.ConnectError("down")
                    if self.effective_reply:
                        return httpx.Response(200, json=self.effective_reply(body))
            return await inner(request)

        h.auth.http._transport = httpx.MockTransport(wrapped)

    def token(self, ref, spec=None):
        return mint_clerk_token(self.keys, self.world.principal(ref)["user_id"], self.h.now(), ISS, AZP, spec)

    def bearer(self, ref, spec=None):
        return {"authorization": f"Bearer {self.token(ref, spec)}"}


def make(make_harness, world, clerk_keys, **over):
    return Rig(make_harness(**over), world, clerk_keys)


def eff(acme, permissions, **over):
    return {"valid": True, "key_id": None, "principal": {"id": "p1", "kind": "human", "user_id": "user_alice", "tenant_id": None},
            "effective": {"tenant_id": acme, "reason": None, "permissions": permissions, **over}}


def perm(permission, scopes):
    service, action = permission.split(":")
    return {"permission": permission, "service": service, "action": action, "category": "write", "sensitive": False, "scopes": scopes}


async def test_request_names_tenant_and_service_and_token_is_verified_first(make_harness, world, clerk_keys):
    r = make(make_harness, world, clerk_keys)
    acme = world.id("tenant", "acme")
    r.effective_reply = lambda b: eff(acme, [perm("docs:read", [{"scope": {}, "role": "operator", "via_tenant": None}])])
    e = await r.h.auth.effective_permissions(headers=r.bearer("alice"), tenant=acme, service="docs")
    assert e.ok and e.principal.permissions == ["docs:read"] and e.tenant_id == acme
    c = r.calls[0]
    assert (c["tenant_id"], c["service"], c["include_effective"], isinstance(c["clerk_token"], str)) == (acme, "docs", True, True)
    bad = await r.h.auth.effective_permissions(headers={"authorization": "Bearer not-a-session"}, tenant=acme)
    assert (bad.ok, bad.reason, bad.status) == (False, "token_invalid", 401)
    assert len(r.calls) == 1, "a token that fails local verification never reaches the platform"


async def test_permits_is_some_scope_entry_admits(make_harness, world, clerk_keys):
    r = make(make_harness, world, clerk_keys)
    r.effective_reply = lambda b: eff(world.id("tenant", "acme"), [
        perm("mail:send", [{"scope": {"domains": ["Client.Example"]}, "role": "operator", "via_tenant": None},
                           {"scope": {"mailboxes": ["ops@other.example"], "domains": ["other.example"]}, "role": "operator", "via_tenant": None}]),
        perm("docs:read", [{"scope": {}, "role": "viewer", "via_tenant": None}]),
        perm("docs:write", [{"scope": {"colour": ["red"]}, "role": "x", "via_tenant": None}])])
    e = await r.h.auth.effective_permissions(headers=r.bearer("alice"), tenant=world.id("tenant", "acme"))
    assert e.permits("mail:send", {"domain": "client.example"}) is True  # case-insensitive
    assert e.permits("mail:send", {"domain": "other.example"}) is False  # that scope also needs the mailbox
    assert e.permits("mail:send", {"domain": "other.example", "mailbox": "OPS@other.example"}) is True
    assert e.permits("mail:send", {}) is False
    assert e.permits("docs:read", {}) is True
    assert e.permits("docs:write", {}) is False  # an unknown scope key admits nothing
    assert e.permits("docs:delete", {}) is False
    assert e.principal.permissions == ["docs:read", "docs:write", "mail:send"]


async def test_uncomputable_effective_permissions_come_back_empty_with_the_reason(make_harness, world, clerk_keys):
    r = make(make_harness, world, clerk_keys)
    r.effective_reply = lambda b: eff(None, [], reason="tenant_required")
    e = await r.h.auth.effective_permissions(headers=r.bearer("bob"))
    assert (e.ok, e.reason, e.permissions, e.permits("docs:read", {})) == (True, "tenant_required", [], False)


async def test_service_principal_holds_none_and_platform_trouble_is_503(make_harness, world, clerk_keys):
    r = make(make_harness, world, clerk_keys)
    acme = world.id("tenant", "acme")
    key = world.raw_key(next(k for k in world.spec["keys"] if k["ref"] == "svc_image_active"))
    svc = await r.h.auth.effective_permissions(headers={"x-api-key": key})
    assert (svc.ok, svc.reason, svc.permits("docs:read", {})) == (True, "service_principal_not_granted", False)

    r.effective_reply = lambda b: {"valid": True, "principal": {"id": "p", "kind": "human"}}  # no `effective`
    m = await r.h.auth.effective_permissions(headers=r.bearer("alice"), tenant=acme)
    assert (m.ok, m.reason, m.status) == (False, "platform_unavailable", 503)
    r.effective_reply = lambda b: {"valid": True, "effective": {"permissions": []}}  # no `principal`
    m = await r.h.auth.effective_permissions(headers=r.bearer("alice"), tenant=acme)
    assert (m.ok, m.status) == (False, 503)
    r.h.fake.down = True
    d = await r.h.auth.effective_permissions(headers=r.bearer("alice"), tenant=acme)
    assert (d.ok, d.status) == (False, 503)
    g = await r.h.auth.effective_permissions(headers=r.bearer("alice"), tenant="not-a-uuid")
    assert g.reason == "tenant_not_found"


async def test_resolver_wins_over_the_org_claim(make_harness, world, clerk_keys):
    globex = world.id("tenant", "globex")
    r = make(make_harness, world, clerk_keys, tenant_resolver=lambda req, p: globex)
    d = await r.h.auth.authorize(headers=r.bearer("bob", {"extra": {"org_id": "org_acme"}}), permission="docs:read")
    assert d.tenant_id == globex and d.source == "offline"


async def test_org_mapping_is_for_humans_only(make_harness, world, clerk_keys):
    r = make(make_harness, world, clerk_keys)
    r.h.fake.live = {"allow": True, "reason": "allowed", "tenant": "acme", "roles": ["operator"]}
    key = world.raw_key(next(k for k in world.spec["keys"] if k["ref"] == "agent_acme_active"))
    d = await r.h.auth.authorize(headers={"x-api-key": key, "authorization": "Bearer x.y.z"}, permission="docs:read")
    assert (d.allow, d.source) == (True, "live")
    assert r.h.fake.count("GET", "/v1/authorize/snapshot") == 0, "no snapshot lookup for a key principal"


async def test_org_mapping_uses_a_stale_snapshot_but_never_none(make_harness, world, clerk_keys):
    r = make(make_harness, world, clerk_keys)
    await r.h.auth.cache.get()
    r.h.advance(120)  # past the TTL, inside the stale-read window
    r.h.fake.down = True
    stale = await r.h.auth.authorize(headers=r.bearer("bob", {"extra": {"org_id": "org_acme"}}), permission="docs:read")
    assert (stale.allow, stale.tenant_id, stale.stale) == (True, world.id("tenant", "acme"), True)

    cold = make(make_harness, world, clerk_keys)
    cold.h.fake.down = True
    none = await cold.h.auth.authorize(headers=cold.bearer("bob", {"extra": {"org_id": "org_acme"}}), permission="docs:read")
    assert (none.allow, none.reason) == (False, "platform_unavailable")


async def test_clerk_v1_and_v2_token_shapes(make_harness, world, clerk_keys):
    r = make(make_harness, world, clerk_keys)
    v1 = await r.h.auth.resolve_principal(headers=r.bearer("alice", {"extra": {"org_id": "org_acme", "org_role": "org:admin"}}))
    v2 = await r.h.auth.resolve_principal(headers=r.bearer("alice", {"extra": {"o": {"id": "org_acme", "rol": "admin"}}}))
    assert (v1["principal"].claims["org_id"], v1["principal"].claims["org_role"]) == ("org_acme", "org:admin")
    assert (v2["principal"].claims["org_id"], v2["principal"].claims["org_role"]) == ("org_acme", "admin")
