"""Inbound service keys (stgs_), as the CoS contract note specifies the final platform behaviour
(mandatory expect_service, uniform key_not_found, bounded resolution cache, no tenant
permissions, the app's OWN route policy for each accepted caller service).

The shared vectors for these cases stay `pending-platform` in test_vectors.py. Here the very same
cases run against a fake that implements the contract note, so the expectations are executable
today; e2e/test_service_keys.py proves against the real C0b2 platform what it already does.
"""

import asyncio
import json
import re

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from konstant_studio_auth.v2 import ConfigError, create_auth
from konstant_studio_auth.v2.service_keys import route_allowed, validate_policy
from world import VECTORS, SilentLogger, mint_clerk_token

ACCEPTED = VECTORS["config"]["accepted_caller_services"]


def key_of(world, ref):
    return next(k for k in world.spec["keys"] if k["ref"] == ref)


def hdr(world, ref):
    return {"x-api-key": world.raw_key(key_of(world, ref))}


def _service_key_cases():
    # Every service-key vector, once more through the contract-note fake (they also run in the shared runner).
    for c in VECTORS["cases"]:
        if c["who"].get("key", "").startswith("svc_"):
            yield pytest.param(c, id=c["id"])


@pytest.mark.parametrize("c", _service_key_cases())
async def test_service_key_vectors_against_the_contract_note_fake(c, make_harness, world):
    h = make_harness()
    exp = c["expect"]
    headers = hdr(world, c["who"]["key"])
    if c.get("resolve_only"):
        r = await h.auth.resolve_principal(headers=headers)
        if exp["allow"]:
            assert r["ok"] is True
            p = r["principal"]
            assert (p.kind, p.service, p.tenant) == (exp["principal"]["kind"], exp["principal"]["service"], exp["principal"]["tenant"])
            assert not hasattr(p, "routes"), "the platform's allowed_routes must not be exposed as this app's policy"
        else:
            assert (r["ok"], r["reason"], r["status"]) == (False, exp["reason"], exp["status"])
    else:
        d = await h.auth.authorize(headers=headers, permission=c["ask"]["permission"], resource={"tenant": world.id("tenant", c["ask"]["tenant"])})
        assert (d.allow, d.reason, d.status) == (exp["allow"], exp["reason"], exp["status"])
        assert d.source == "none"
        assert h.fake.count("POST", "/v1/authorize") == 0, "decided locally: a service principal has no tenant permissions"


async def test_every_resolution_names_the_caller_service_it_expects(make_harness, world):
    h = make_harness()
    await h.auth.resolve_principal(headers=hdr(world, "svc_video_active"))
    assert h.fake.service_resolves == ["image", "video"]  # tried in the configured order; stops at the match
    assert all(e in ACCEPTED for e in h.fake.service_resolves)


async def test_uniform_failure(make_harness, world):
    h = make_harness()
    answers = [await h.auth.resolve_principal(headers=hdr(world, r)) for r in ("svc_image_revoked", "svc_image_expired", "svc_image_unknown", "svc_docs_active")]
    assert all(a == answers[0] for a in answers)
    assert answers[0] == {"ok": False, "reason": "key_not_found", "status": 401}
    # ...and through authorize(), too
    d = await h.auth.authorize(headers=hdr(world, "svc_image_revoked"), permission="docs:read", resource={"tenant": world.id("tenant", "acme")})
    assert (d.allow, d.reason, d.status) == (False, "key_not_found", 401)


async def test_the_platforms_specific_reason_is_never_branched_on(make_harness, world):
    for reason in ("key_revoked", "key_expired", "unsupported_credential", "anything", None):
        h = make_harness(transport=httpx.MockTransport(lambda r, reason=reason: httpx.Response(200, json={"valid": False, "reason": reason})))
        r = await h.auth.resolve_principal(headers=hdr(world, "svc_image_active"))
        assert r == {"ok": False, "reason": "key_not_found", "status": 401}


async def test_no_accepted_services_means_no_platform_call(make_harness, world):
    warnings = []

    class L(SilentLogger):
        def warning(self, msg, *a, **k):
            warnings.append(msg)

    h = make_harness(accepted_caller_services=[], logger=L())
    for _ in range(3):
        r = await h.auth.resolve_principal(headers=hdr(world, "svc_image_active"))
        assert (r["ok"], r["reason"]) == (False, "key_not_found")
    assert h.fake.calls == []
    assert len(warnings) == 1  # warned once, lazily, never at startup


def test_bad_accepted_slug_is_a_startup_error():
    with pytest.raises(ConfigError, match="not a catalog service slug"):
        create_auth(service="docs", accepted_caller_services=["Image Studio"], env={})
    with pytest.raises(ConfigError):
        create_auth(service="docs", accepted_caller_services=["1abc"], env={})
    create_auth(service="docs", accepted_caller_services=["image-studio"], env={})


async def test_resolution_cache_valid_invalid_hash_only(make_harness, world):
    h = make_harness()
    asked = lambda: len(h.fake.service_resolves)  # noqa: E731
    img = hdr(world, "svc_image_active")
    await h.auth.resolve_principal(headers=img)
    first = asked()
    await h.auth.resolve_principal(headers=img)
    assert asked() == first, "valid resolution served from the cache"
    h.advance(59)
    await h.auth.resolve_principal(headers=img)
    assert asked() == first
    h.advance(2)
    await h.auth.resolve_principal(headers=img)
    assert asked() > first, "refreshed after 60 s"

    bad = hdr(world, "svc_image_revoked")
    before = asked()
    await h.auth.resolve_principal(headers=bad)
    after_first = asked()
    await h.auth.resolve_principal(headers=bad)
    assert asked() == after_first, "invalid resolution cached"
    h.advance(11)
    await h.auth.resolve_principal(headers=bad)
    assert asked() > after_first, "invalid resolution re-asked after 10 s"
    assert after_first > before

    cache = h.auth.service_keys.cache
    dump = json.dumps([[k, e.until, e.value] for k, e in cache.items()])
    for ref in ("svc_image_active", "svc_image_revoked"):
        assert world.raw_key(key_of(world, ref)) not in dump, "raw credential in the cache"
    assert all(re.fullmatch(r"[0-9a-f]{64}", k) for k in cache)


async def test_resolution_cache_never_outlives_the_key(make_harness, world):
    h = make_harness()
    h.fake.service_key_expires_at = _iso(h.now() + 20_000)
    img = hdr(world, "svc_image_active")
    await h.auth.resolve_principal(headers=img)
    n = len(h.fake.service_resolves)
    h.advance(25)
    await h.auth.resolve_principal(headers=img)
    assert len(h.fake.service_resolves) > n, "asked again once the key expired, not after 60 s"


def _iso(ms):
    from world import iso_ms

    return iso_ms(ms)


async def test_resolution_cache_is_bounded(make_harness):
    h = make_harness(service_key_cache={"negative_max_entries": 5})
    for i in range(50):
        await h.auth.resolve_principal(headers={"x-api-key": "stgs_" + str(i).zfill(40)})
    assert len(h.auth.service_keys.negative) <= 5
    # expired entries go first, then the least recently used
    h.advance(11)
    await h.auth.resolve_principal(headers={"x-api-key": "stgs_" + "9" * 40})
    assert len(h.auth.service_keys.negative) <= 5


async def test_platform_outage_is_not_cached_as_a_verdict(make_harness, world):
    h = make_harness()
    h.fake.down = True
    r = await h.auth.resolve_principal(headers=hdr(world, "svc_image_active"))
    assert (r["ok"], r["reason"], r["status"]) == (False, "platform_unavailable", 503)
    h.fake.down = False
    assert (await h.auth.resolve_principal(headers=hdr(world, "svc_image_active")))["ok"] is True  # recovers at once


async def test_concurrent_presentations_share_one_resolution(make_harness, world):
    h = make_harness()
    rs = await asyncio.gather(*[h.auth.resolve_principal(headers=hdr(world, "svc_image_active")) for _ in range(10)])
    assert all(r["ok"] for r in rs)
    assert len(h.fake.service_resolves) == 1


async def test_an_answer_for_a_different_service_than_asked_is_not_trusted(make_harness, world):
    h = make_harness()
    inner = h.fake.handle

    async def lying(request):
        resp = await inner(request)
        if request.url.path == "/v1/principals/resolve":
            body = json.loads(resp.content)
            if body.get("principal"):
                body["principal"]["service"] = "video"  # a platform that ignores expect_service
            return httpx.Response(200, json=body)
        return resp

    h.auth.http._transport = httpx.MockTransport(lying)
    r = await h.auth.resolve_principal(headers=hdr(world, "svc_image_active"))
    # asked for image -> answered video (rejected); asked for video -> answered video for an image key: a match
    # only because the answer names the service we asked about. The lie must never yield service 'image'.
    assert not r["ok"] or r["principal"].service == "video"
    h2 = make_harness(accepted_caller_services=["image"])
    h2.auth.http._transport = httpx.MockTransport(lying)
    r2 = await h2.auth.resolve_principal(headers=hdr(world, "svc_image_active"))
    assert r2["ok"] is False, "the answer must match the service we asked about"


async def test_a_well_formed_reply_that_does_not_match_is_a_refusal(make_harness, world):
    for payload in ({"valid": True}, {"valid": True, "principal": {"kind": "agent", "service": "image"}},
                    {"valid": True, "principal": {"kind": "service", "service": "video"}}):
        h = make_harness(accepted_caller_services=["image"], transport=httpx.MockTransport(lambda r, p=payload: httpx.Response(200, json=p)))
        r = await h.auth.resolve_principal(headers=hdr(world, "svc_image_active"))
        assert (r["ok"], r["reason"]) == (False, "key_not_found")


async def test_a_malformed_reply_is_could_not_decide_and_never_cached(make_harness, world):
    asked = []

    def handler(request):
        asked.append(1)
        return httpx.Response(200, json=payload)

    for payload in ([], "x", {}, {"valid": "yes"}, {"valid": "true", "principal": {"kind": "service", "service": "image"}}, {"valid": 1}, {"valid": None}):
        asked.clear()
        h = make_harness(transport=httpx.MockTransport(handler))
        for _ in range(3):
            r = await h.auth.resolve_principal(headers=hdr(world, "svc_image_active"))
            assert (r["ok"], r["reason"], r["status"]) == (False, "platform_unavailable", 503), payload
        assert len(asked) >= 3, "asked again each time: nothing was cached"


# ---- caller policy ---------------------------------------------------------------


def policy_app(auth, policy):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, dependencies=[Depends(auth.require_service_caller(policy))])

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def anything(request: Request):
        return {"caller": request.state.principal.service, "as": request.state.auth["user_id"]}

    return app


def test_service_caller_policy_per_accepted_caller_deny_by_default(make_harness, world):
    h = make_harness()
    app = policy_app(h.auth, {"image": ["POST /internal/render", "GET /internal/status/*"], "video": ["GET /internal/status/*"]})
    with TestClient(app) as c:
        call = lambda ref, method, path: c.request(method, path, headers=hdr(world, ref) if ref else {})  # noqa: E731
        assert call("svc_image_active", "POST", "/internal/render").json() == {"caller": "image", "as": "service:image"}
        assert call("svc_image_active", "GET", "/internal/status/42").status_code == 200
        r = call("svc_image_active", "GET", "/internal/render")
        assert (r.status_code, r.json()["detail"]["reason"]) == (403, "route_not_allowed")
        r = call("svc_video_active", "POST", "/internal/render")
        assert (r.status_code, r.json()["detail"]["reason"]) == (403, "route_not_allowed"), "video does not inherit image's routes"
        r = call("svc_docs_active", "GET", "/internal/status/1")
        assert (r.status_code, r.json()["detail"]["reason"]) == (401, "key_not_found")
        assert r.headers["www-authenticate"] == "Bearer"
        r = call(None, "GET", "/internal/status/1")
        assert (r.status_code, r.json()["detail"]["reason"]) == (401, "no_credential")


async def test_policy_ignores_platform_allowed_routes_and_refuses_non_service_callers(make_harness, world, clerk_keys):
    h = make_harness()
    # svc_image_active holds "POST /v1/authorize" on the PLATFORM; that must not open this app's route of the same name.
    d = await h.auth.authorize_service_caller(headers=hdr(world, "svc_image_active"), method="POST", path="/v1/authorize", policy={"image": []})
    assert (d.allow, d.reason) == (False, "route_not_allowed")
    tok = mint_clerk_token(clerk_keys, "user_alice", h.now(), VECTORS["config"]["clerk"]["issuer"], VECTORS["config"]["clerk"]["authorized_parties"][0])
    human = await h.auth.authorize_service_caller(headers={"authorization": f"Bearer {tok}"}, method="GET", path="/internal/x", policy={"image": ["GET /internal/*"]})
    assert (human.allow, human.reason, human.status) == (False, "service_caller_required", 403)


def test_wiring_errors(make_harness):
    auth = create_auth(service="docs", accepted_caller_services=["image"], logger=SilentLogger(), env={})
    for policy, msg in (({"video": ["GET /x"]}, "not in accepted_caller_services"), ({"image": ["* /*"]}, "allow everything"),
                        ({"image": "GET /x"}, "list of"), ({"image": ["nonsense"]}, "bad route entry"), (["GET /x"], "dict keyed")):
        with pytest.raises(ConfigError, match=msg):
            auth.require_service_caller(policy)
    validate_policy({"image": ["GET /x/*", "* /health", "POST /a:b/c_d-e.f"]}, ["image"])


def test_route_allowed_globs():
    assert route_allowed(["GET /internal/status/**"], "get", "/internal/status/1/2")
    assert not route_allowed(["GET /internal/status/*"], "get", "/internal/status/1/2")
    assert not route_allowed(["GET /internal/status/*"], "GET", "/internal/other")
    assert not route_allowed(["POST /a.b"], "POST", "/aXb")


async def test_audit_events_name_the_caller_service_and_never_carry_the_key(make_harness, world):
    events = []
    h = make_harness(on_event=events.append)
    await h.auth.authorize(headers=hdr(world, "svc_image_active"), permission="docs:read", resource={"tenant": world.id("tenant", "acme")})
    await h.auth.authorize_service_caller(headers=hdr(world, "svc_image_active"), method="GET", path="/x", policy={"image": ["GET /x"]})
    assert len(events) == 2
    assert all(e["caller_service"] == "image" and e["actor"]["kind"] == "system" and e["actor"]["key_prefix"] == "stgs_" for e in events)
    assert world.raw_key(key_of(world, "svc_image_active")) not in json.dumps(events)
    assert not any("allowed_routes" in json.dumps(e) for e in events)
