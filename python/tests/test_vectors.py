"""Runs the shared vectors (test-vectors/vectors.json) against the library with a fake platform. Node
runs the very same file: decision cases, credential extraction, and the route policy. No vector is
skipped: the inbound-service-key cases run against a fake that implements the platform's final
contract (mandatory expect_service, uniform key_not_found).
"""

import pytest
from starlette.datastructures import Headers

from konstant_studio_auth.v2.credentials import extract
from konstant_studio_auth.v2.reasons import COARSE_OFFLINE
from konstant_studio_auth.v2.service_keys import route_allowed
from world import VECTORS, mint_clerk_token

CFG = VECTORS["config"]


def test_no_vector_is_pending():
    assert not [c["id"] for c in VECTORS["cases"] if c.get("pending")]


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
    if ask.get("tenant_hint"):
        r["tenant_hint"] = world.id("tenant", ask["tenant_hint"])  # the x-tenant header: the weakest source
    if ask.get("tenant_of"):
        r["tenant_of"] = {"kind": ask["tenant_of"]["kind"], "local_id": ask["tenant_of"]["local_id"]}
    if ask.get("tenant_raw"):
        r["tenant"] = ask["tenant_raw"]
    for f in ("brand", "domain", "mailbox"):
        if ask.get(f):
            r[f] = ask[f]
    return r


@pytest.mark.parametrize("c", VECTORS["cases"], ids=lambda c: c["id"])
async def test_shared_vector(c, make_harness, world, clerk_keys):
    resolver = None
    if c["ask"].get("resolver_tenant"):
        tid = world.id("tenant", c["ask"]["resolver_tenant"])
        resolver = lambda req, principal: tid  # noqa: E731
    h = make_harness(tenant_resolver=resolver)
    exp = c["expect"]
    key = next((k for k in world.spec["keys"] if k["ref"] == c["who"].get("key")), None)
    is_service_key = bool(key and key["kind"] == "service")

    if c.get("resolve_only"):
        # identity only: the library asked each accepted caller service, and every failure is the same uniform answer
        r = await h.auth.resolve_principal(headers=headers_for(c, world, clerk_keys, h.now()))
        if exp["allow"]:
            assert r["ok"] is True
            p = r["principal"]
            assert (p.kind, p.service, p.tenant) == (exp["principal"]["kind"], exp["principal"]["service"], exp["principal"]["tenant"])
            assert not hasattr(p, "routes"), "the platform's allowed_routes are not exposed as this app's policy"
        else:
            assert (r["ok"], r["reason"], r["status"]) == (False, exp["reason"], exp["status"])
        return

    # a real platform names who an allow is for
    h.fake.live = {**exp, "principal": h.fake._principal_summary(world.principal(c["who"]["clerk"]))} if c["who"].get("clerk") else exp
    if c.get("cache_age_s") is not None:
        await h.auth.cache.get()  # prime while the platform is up, then let the consumer's clock run
        h.advance(c["cache_age_s"])
    if c.get("platform") == "down":
        h.fake.down = True
    h.fake.calls.clear()

    token_now = h.now() - c["cache_age_s"] * 1000 if c.get("cache_age_s") is not None else h.now()
    d = await h.auth.authorize(headers=headers_for(c, world, clerk_keys, token_now), permission=c["ask"]["permission"], resource=resource_for(c, world))

    coarse = exp.get("offline_reason")
    assert d.allow == exp["allow"], f"allow (reason {d.reason})"
    assert d.reason == (coarse or exp["reason"])
    assert d.status == exp["status"]
    assert d.source == exp.get("source", "none")
    assert d.stale == bool(exp.get("stale"))
    if not coarse:
        assert d.tenant_id == world.id("tenant", exp.get("tenant"))
    assert d.via_tenant == world.id("tenant", exp.get("via_tenant"))
    if exp["allow"]:
        assert sorted(d.roles) == exp["roles"]
    if exp.get("tenant_source") is not None:
        assert d.tenant_source == exp["tenant_source"]
    if "sensitive" in exp and not coarse:
        assert d.sensitive == bool(exp["sensitive"])

    # Who decided: offline/none means the platform's authorize endpoint was never asked; a live
    # decision is exactly one call (and no separate resolve). Skipped when the platform is down,
    # where the library correctly TRIES the call and it fails.
    if c.get("platform") != "down":
        assert h.fake.count("POST", "/v1/authorize") == (1 if exp.get("source") == "live" else 0), "authorize calls"
        if not is_service_key:
            assert h.fake.count("POST", "/v1/principals/resolve") == 0, "decisions never need a separate resolve"


def test_offline_denials_use_only_documented_coarse_reasons():
    for c in (x for x in VECTORS["cases"] if x["expect"].get("offline_reason")):
        assert COARSE_OFFLINE[c["expect"]["reason"]] == c["expect"]["offline_reason"], c["id"]


# ---- credential extraction: both languages must read a request the same way ---------------------


def _asdict(spec):
    # A list value is a header sent more than once; a plain dict carries it joined with ", " (as Express does).
    return {k: ", ".join(v) if isinstance(v, list) else v for k, v in spec.items()}


def _starlette(spec):
    # Starlette keeps a repeated header as separate entries.
    raw = [(k.lower().encode(), one.encode()) for k, v in spec.items() for one in ([v] if isinstance(v, str) else v)]
    return Headers(raw=raw)


@pytest.mark.parametrize("c", VECTORS["extraction"]["cases"], ids=lambda c: c["id"])
@pytest.mark.parametrize("build", [_asdict, _starlette], ids=["dict", "starlette"])
def test_shared_extraction_vector(c, build):
    got = extract(build(c["headers"]))
    assert got.type == c["expect"]["type"]
    if "key_kind" in c["expect"]:
        assert got.key_kind == c["expect"]["key_kind"]


def test_extraction_never_raises_whatever_the_headers_hold():
    nasty = ["%", "%%", "%E0%A4%A", "\u0000", "a" * 100000, "=", ";;;", "__session=", "__session=%"]
    for v in nasty:
        extract({"cookie": v})
        extract({"cookie": f"__session={v}"})
        extract({"authorization": v, "x-api-key": v})
        extract(_starlette({"cookie": v}))


# ---- the app's route policy: both languages pin the same path semantics -------------------------


@pytest.mark.parametrize("c", VECTORS["route_policy"]["cases"], ids=lambda c: c["id"])
def test_shared_route_policy_vector(c):
    assert route_allowed(c["routes"], c["method"], c["path"]) is c["allow"], f"{c['method']} {c['path']!r}"


# ---- resource lookups (platform C0f): who owns a service-local id? --------------------------------------


@pytest.mark.parametrize("c", VECTORS["lookups"]["cases"], ids=lambda c: c["id"])
async def test_shared_lookup_vector(c, make_harness, world):
    h = make_harness()
    mode = c.get("snapshot", "fresh")
    if mode == "no-resources-field":
        h.fake.omit_resources = True
    if mode in ("stale", "beyond-stale"):
        await h.auth.cache.get()  # primed while the platform is up
        h.advance(120 if mode == "stale" else 400)
    if mode not in ("fresh", "no-resources-field"):
        h.fake.down = True

    a = c["args"]
    tenant = a.get("tenant_raw") or (world.id("tenant", a["tenant"]) if a.get("tenant") else None)
    got = await h.auth.tenant_for(a.get("kind"), a.get("local_id")) if c["call"] == "tenantFor" else await h.auth.resources_for(tenant, a.get("kind"))

    e = c["expect"]
    assert got["ok"] is e["ok"]
    if not e["ok"]:
        assert (got["reason"], got["status"]) == (e["reason"], e["status"])
        return
    if c["call"] == "tenantFor":
        assert got["tenant_id"] == (None if e["tenant"] is None else world.id("tenant", e["tenant"]))
    else:
        assert got["ids"] == e["ids"]
    assert got["stale"] is e["stale"]
