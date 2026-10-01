"""Runs the shared vectors (test-vectors/vectors.json) against the library with a fake
platform. Node runs the very same file. `pending-platform` cases are skipped with their
reason: they describe the end state once the platform resolves service keys, and are
deliberately not asserted against the stub.
"""

import pytest

from konstant_studio_auth.v2.reasons import COARSE_OFFLINE
from world import VECTORS, mint_clerk_token

CFG = VECTORS["config"]


def _params():
    for c in VECTORS["cases"]:
        marks = [pytest.mark.skip(reason=c["pending"])] if c.get("pending") else []
        yield pytest.param(c, id=c["id"], marks=marks)


def headers_for(c, world, keys, now):
    who = c["who"]
    if who.get("clerk"):
        token = mint_clerk_token(
            keys, world.principal(who["clerk"])["user_id"], now, CFG["clerk"]["issuer"], CFG["clerk"]["authorized_parties"][0], who.get("token")
        )
        return {"authorization": f"Bearer {token}"}
    if who.get("key"):
        return {"x-api-key": world.raw_key(next(k for k in world.spec["keys"] if k["ref"] == who["key"]))}
    if who.get("bearer"):
        return {"authorization": f"Bearer {who['bearer']}"}
    return {}


def resource_for(c, world):
    r = {}
    ask = c["ask"]
    if ask.get("tenant"):
        r["tenant"] = world.id("tenant", ask["tenant"])
    if ask.get("tenant_raw"):
        r["tenant"] = ask["tenant_raw"]
    for f in ("brand", "domain", "mailbox"):
        if ask.get(f):
            r[f] = ask[f]
    return r


@pytest.mark.parametrize("c", _params())
async def test_shared_vector(c, make_harness, world, clerk_keys):
    resolver = None
    if c["ask"].get("resolver_tenant"):
        tid = world.id("tenant", c["ask"]["resolver_tenant"])
        resolver = lambda req, principal: tid  # noqa: E731
    h = make_harness(tenant_resolver=resolver)
    exp = c["expect"]
    h.fake.live = exp
    down_cached = c.get("cache_age_s") is not None

    if down_cached:
        await h.auth.cache.get()  # prime while the platform is up, then let the consumer's clock run
        h.advance(c["cache_age_s"])
    if c.get("platform") == "down":
        h.fake.down = True
    h.fake.calls.clear()

    token_now = h.now() - c["cache_age_s"] * 1000 if down_cached else h.now()
    d = await h.auth.authorize(headers=headers_for(c, world, clerk_keys, token_now), permission=c["ask"]["permission"], resource=resource_for(c, world))

    coarse = exp.get("offline_reason")
    assert d.allow == exp["allow"], f"allow (reason {d.reason})"
    assert d.reason == (coarse or exp["reason"])
    assert d.status == exp["status"]
    assert d.source == exp["source"]
    assert d.stale == bool(exp.get("stale"))
    if not coarse:
        assert d.tenant_id == world.id("tenant", exp.get("tenant"))
    assert d.via_tenant == world.id("tenant", exp.get("via_tenant"))
    if exp["allow"]:
        assert sorted(d.roles) == exp["roles"]
    if "sensitive" in exp and not coarse:
        assert d.sensitive == bool(exp["sensitive"])

    # Who decided: offline/none means the platform's authorize endpoint was never asked; a live
    # decision is exactly one call (and no separate resolve). Skipped when the platform is down,
    # where the library correctly TRIES the call and it fails.
    if c.get("platform") != "down":
        assert h.fake.count("POST", "/v1/authorize") == (1 if exp["source"] == "live" else 0), "authorize calls"
        assert h.fake.count("POST", "/v1/principals/resolve") == 0, "decisions never need a separate resolve"


def test_offline_denials_use_only_documented_coarse_reasons():
    for c in (x for x in VECTORS["cases"] if x["expect"].get("offline_reason")):
        assert COARSE_OFFLINE[c["expect"]["reason"]] == c["expect"]["offline_reason"], c["id"]
