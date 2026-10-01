"""Parity: the library's decision must equal the platform's /v1/authorize decision, for every
shared vector, against a SCRATCH copy of the C0b branch on a scratch database
(scripts/scratch_platform.py). A divergence is a library bug (or a documented platform gap),
never silently accepted.

Skips when no scratch platform is running, unless REQUIRE_SCRATCH=1 (CI / acceptance).
"""

import json
from datetime import datetime

import httpx
import pytest

from konstant_studio_auth.v2.reasons import COARSE_OFFLINE
from world import VECTORS, World

from .helpers import bearer, library_for, platform_authorize, psql


def _cases():
    for c in VECTORS["cases"]:
        reason = c.get("pending") or (c.get("parity_note") if c.get("parity") is False else None) or (
            "needs a down platform: covered by the unit vectors" if c.get("platform") == "down" else None
        )
        yield pytest.param(c, id=c["id"], marks=[pytest.mark.skip(reason=reason)] if reason else [])


def _ms(s):
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000) if s else None


def test_fixture_world_builds_the_snapshot_the_platform_serves(ctx):
    resp = httpx.get(f"{ctx.state['platform_url']}/v1/authorize/snapshot?service=docs", headers={"X-API-Key": ctx.state["service_key"]})
    assert resp.status_code == 200
    real = resp.json()
    # The world's windows and expiries are offsets from the moment the scratch DB was seeded.
    at_seed = World(include_transient=False)
    at_seed.now_ms = ctx.state["seeded_at_ms"]
    built = at_seed.snapshot("docs")

    role_slug = {r["id"]: r["slug"] for r in [*real["roles"], *built["roles"]]}

    def norm(s):
        return {
            "permissions": sorted(s["permissions"], key=lambda p: p["action"]),
            "tenants": sorted(
                [{"id": x["id"], "type": x["type"], "org_id": x["org_id"], "parent_id": x["parent_id"], "ancestors": x["ancestors"], "plan": x["plan"],
                  "starts": _ms(x["starts_at"]), "ends": _ms(x["ends_at"])} for x in s["tenants"]], key=lambda x: x["id"]),
            "roles": sorted([{"slug": r["slug"], "tenant_id": r["tenant_id"], "permissions": r["permissions"]} for r in s["roles"]],
                            key=lambda r: r["slug"] + (r["tenant_id"] or "null")),
            "memberships": sorted(
                [{"who": m["user_id"] if m["kind"] == "human" else m["principal_id"], "kind": m["kind"], "tenant_id": m["tenant_id"],
                  "role": role_slug.get(m["role_id"]), "scope": m["scope"], "expires": _ms(m["expires_at"])} for m in s["memberships"]],
                key=lambda m: json.dumps(m, sort_keys=True)),
            "rules": s["rules"],
        }

    # Timestamps are offsets from "now" on two different clocks (this test's and the database's):
    # equal to within a couple of minutes is equal. Everything else must match exactly.
    r, b = norm(real), norm(built)

    def near(x, y):
        return (x is None and y is None) or (x is not None and y is not None and abs(x - y) < 120000)

    assert len(r["tenants"]) == len(b["tenants"]) and len(r["memberships"]) == len(b["memberships"])
    for x, y in zip(r["tenants"], b["tenants"]):
        assert near(x["starts"], y["starts"]) and near(x["ends"], y["ends"]), f"window of {x['id']}"
        x["starts"] = x["ends"] = y["starts"] = y["ends"] = 0
    for x, y in zip(r["memberships"], b["memberships"]):
        assert near(x["expires"], y["expires"]), f"expiry of {x['who']}"
        x["expires"] = y["expires"] = 0
    assert r == b


def _credential(ctx, c):
    who = c["who"]
    if who.get("clerk"):
        return bearer(ctx, who["clerk"], who.get("token"))
    if who.get("key"):
        return {"x-api-key": ctx.state["keys"][who["key"]]}
    if who.get("bearer"):
        return {"authorization": f"Bearer {who['bearer']}"}
    return {}


def _resource(ctx, c):
    r = {}
    if c["ask"].get("tenant"):
        r["tenant"] = ctx.world.id("tenant", c["ask"]["tenant"])
    for f in ("brand", "domain", "mailbox"):
        if c["ask"].get(f):
            r[f] = c["ask"][f]
    return r


def _truth_body(c, resource, headers):
    if "authorization" in headers:
        kind, raw = "clerk_token", headers["authorization"].removeprefix("Bearer ")
    else:
        kind, raw = "credential", headers.get("x-api-key")
    service, action = c["ask"]["permission"].split(":")
    wire = {"tenant": "tenant_id", "brand": "brand_id", "domain": "domain", "mailbox": "mailbox"}
    return {kind: raw, "service": service, "action": action, "resource": {wire[k]: v for k, v in resource.items() if v}}


@pytest.mark.parametrize("c", _cases())
async def test_library_equals_platform(c, ctx):
    exp = c["expect"]
    headers = _credential(ctx, c)
    resource = _resource(ctx, c)
    # The platform has no tenant resolver: the tenant an adopter's resolver would supply is stated explicitly.
    # ...and the tenant an org claim maps to is stated explicitly too (vector field parity_tenant).
    rt = c["ask"].get("resolver_tenant")
    named = rt or c.get("parity_tenant")
    asked = {**resource, "tenant": ctx.world.id("tenant", named)} if named else resource
    _, truth = platform_authorize(ctx, _truth_body(c, asked, headers))
    assert truth["reason"] == exp["reason"], "the vector must state what the platform really answers"
    assert truth["allow"] == exp["allow"]

    tid = ctx.world.id("tenant", rt) if rt else None
    auth = library_for(ctx, tenant_resolver=(lambda req, p: tid) if rt else None)
    try:
        lib = await auth.authorize(headers=headers, permission=c["ask"]["permission"], resource=resource)
    finally:
        await auth.close()

    assert lib.allow == truth["allow"], f"library said {lib.reason}, platform said {truth['reason']}"
    expected_reason = COARSE_OFFLINE.get(truth["reason"], truth["reason"]) if lib.source == "offline" else truth["reason"]
    assert lib.reason == expected_reason
    assert lib.source == exp["source"]
    if truth["allow"]:
        assert lib.tenant_id == truth["tenant_id"]
        assert lib.via_tenant == truth["via_tenant"]
        assert sorted(lib.roles) == sorted(truth["roles"])
    if truth["reason"] not in COARSE_OFFLINE and truth["tenant_id"] is not None:
        assert lib.tenant_id == truth["tenant_id"]


async def test_revoked_membership_reaches_the_library_through_the_change_feed(ctx):
    auth = library_for(ctx)
    acme = ctx.world.id("tenant", "acme")

    async def read():
        return await auth.authorize(headers=bearer(ctx, "alice"), permission="docs:read", resource={"tenant": acme})

    who = "(SELECT id FROM stighive_platform.principals WHERE user_id = 'user_alice')"
    try:
        assert (await read()).allow is True
        assert await auth.cache.poll_once() is False, "no change yet: nothing to refresh"
        psql(ctx, f"UPDATE stighive_platform.memberships SET status = 'revoked' WHERE principal_id = {who}")
        assert (await read()).allow is True, "still cached inside the TTL: that is the window the feed closes"
        assert await auth.cache.poll_once() is True, "the feed reported the change"
        after = await read()
        assert (after.allow, after.reason) == (False, "no_permission")
    finally:
        psql(ctx, f"UPDATE stighive_platform.memberships SET status = 'active' WHERE principal_id = {who}")
        await auth.close()


async def test_etag_revalidation_answers_304(ctx):
    statuses = []

    async def hook(response):
        if "/snapshot" in str(response.request.url):
            statuses.append(response.status_code)

    http = httpx.AsyncClient(event_hooks={"response": [hook]})
    auth = library_for(ctx, http_client=http)
    try:
        await auth.cache.refresh()
        await auth.cache.refresh()
        assert statuses == [200, 304]
    finally:
        await auth.close()
        await http.aclose()


async def test_revoked_agent_key_is_refused_immediately(ctx):
    auth = library_for(ctx)
    headers = {"x-api-key": ctx.state["keys"]["agent_acme_active"]}
    try:
        assert (await auth.authorize(headers=headers, permission="docs:read")).allow is True
        psql(ctx, "UPDATE stighive_platform.principal_keys SET revoked_at = now() WHERE name = 'agent_acme_active'")
        d = await auth.authorize(headers=headers, permission="docs:read")
        assert (d.allow, d.reason, d.status) == (False, "key_revoked", 401)
    finally:
        psql(ctx, "UPDATE stighive_platform.principal_keys SET revoked_at = NULL WHERE name = 'agent_acme_active'")
        await auth.close()
