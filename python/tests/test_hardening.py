"""The CoS review of 011275b (verdict and CR): R1 to R5 and the hardening list. One test per finding,
each written to FAIL on the code as it was before the fix. Mirrors test/hardening.test.js.
"""

import asyncio
import base64
import json
from types import SimpleNamespace
from urllib.parse import unquote

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from konstant_studio_auth.v2 import ConfigError, create_auth
from konstant_studio_auth.v2.adapters.shared import denial_body
from konstant_studio_auth.v2.clerk import ClerkVerifier, Denied
from konstant_studio_auth.v2.decision import decide_offline
from konstant_studio_auth.v2.snapshot_cache import SnapshotCache
from world import VECTORS, ClerkKeys, SilentLogger, mint_clerk_token

CFG = VECTORS["config"]
ISS = CFG["clerk"]["issuer"]
AZP = CFG["clerk"]["authorized_parties"][0]


def key_of(world, ref):
    return next(k for k in world.spec["keys"] if k["ref"] == ref)


def raw(world, ref):
    return world.raw_key(key_of(world, ref))


def fake_key(i):
    return "stgs_" + str(i).zfill(43)


@pytest.fixture
def build(make_harness, world, clerk_keys):
    def _build(**over):
        h = make_harness(separate_monotonic=True, **over)
        h.acme, h.globex = world.id("tenant", "acme"), world.id("tenant", "globex")
        h.token = lambda ref, spec=None: mint_clerk_token(clerk_keys, world.principal(ref)["user_id"], h.now(), ISS, AZP, spec)
        h.bearer = lambda ref, spec=None: {"authorization": f"Bearer {h.token(ref, spec)}"}
        return h

    return _build


# ---- R1: the x-tenant header cannot move a token off its org's tenant ------------------------------


async def test_r1_org_mapped_tenant_is_not_moved_by_a_hint(build):
    h = build()
    d = await h.auth.authorize(headers=h.bearer("bob", {"extra": {"org_id": "org_acme"}}), permission="docs:read", resource={"tenant_hint": h.globex})
    assert (d.allow, d.tenant_id, d.tenant_source) == (True, h.acme, "org"), "bob is a member of BOTH, but the token says acme"

    no_org = await h.auth.authorize(headers=h.bearer("bob"), permission="docs:read", resource={"tenant_hint": h.globex})
    assert (no_org.allow, no_org.tenant_id, no_org.tenant_source) == (True, h.globex, "hint"), "with nothing else naming a tenant the hint is used (and still needs a membership)"

    explicit = await h.auth.authorize(headers=h.bearer("bob", {"extra": {"org_id": "org_acme"}}), permission="docs:read", resource={"tenant": h.globex, "tenant_hint": h.acme})
    assert (explicit.tenant_id, explicit.tenant_source) == (h.globex, "explicit")


async def test_r1_resolver_beats_the_hint_and_the_audit_event_says_where_the_tenant_came_from(build):
    events = []
    gl = None
    h = build(tenant_resolver=lambda req, p: gl, on_event=events.append)
    gl = h.globex
    d = await h.auth.authorize(headers=h.bearer("bob"), permission="docs:read", resource={"tenant_hint": h.acme})
    assert (d.tenant_id, d.tenant_source) == (h.globex, "resolver")
    assert events[-1]["tenant_source"] == "resolver"


def test_r1_legacy_auth_carries_no_org_id_the_only_scoping_key_is_tenant_id(build):
    h = build()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/x")
    async def x(request: Request, d=Depends(h.auth.require_permission("docs:read"))):
        return {"auth": request.state.auth, "decision_tenant": d.tenant_id}

    with TestClient(app) as c:
        r = c.get("/x", headers={**h.bearer("bob", {"extra": {"org_id": "org_acme", "org_role": "org:admin"}}), "x-tenant": h.globex}).json()
    assert "org_id" not in r["auth"] and "org_role" not in r["auth"]
    assert (r["auth"]["tenant_id"], r["auth"]["clerk_org_id"], r["auth"]["is_superadmin"]) == (h.acme, "org_acme", False)
    assert r["auth"]["tenant_id"] == r["decision_tenant"]


# ---- R2: a flood of garbage keys cannot flush good entries or hammer the platform --------------------


async def test_r2_garbage_keys_cannot_evict_a_valid_cached_key(build, world):
    h = build()
    good = {"x-api-key": raw(world, "svc_image_active")}
    assert (await h.auth.resolve_principal(headers=good))["ok"] is True
    asked = len(h.fake.service_resolves)
    for i in range(2000):
        await h.auth.resolve_principal(headers={"x-api-key": fake_key(i)})
    assert len(h.auth.service_keys.negative) <= 256, "invalid answers live in their own bounded cache"
    before = len(h.fake.service_resolves)
    assert (await h.auth.resolve_principal(headers=good))["ok"] is True
    assert len(h.fake.service_resolves) == before, "the valid entry survived: served from cache, no platform call"
    assert before > asked, "the garbage did reach the platform (that is what the other limits are for)"


async def test_r2_valid_cache_is_lru(build, world):
    h = build(service_key_cache={"max_entries": 2})
    hd = lambda ref: {"x-api-key": raw(world, ref)}  # noqa: E731
    await h.auth.resolve_principal(headers=hd("svc_image_active"))
    await h.auth.resolve_principal(headers=hd("svc_video_active"))
    await h.auth.resolve_principal(headers=hd("svc_image_active"))  # image is now the most recently used
    # a third distinct valid key must evict the LRU entry (video), not image
    spare = {**key_of(world, "svc_image_active"), "ref": "svc_image_second"}
    spare_raw = world.raw_key(spare)
    world.keys_by_raw[spare_raw] = spare
    try:
        await h.auth.resolve_principal(headers={"x-api-key": spare_raw})
        n = len(h.fake.service_resolves)
        await h.auth.resolve_principal(headers=hd("svc_image_active"))
        assert len(h.fake.service_resolves) == n, "image (recently used) is still cached"
        await h.auth.resolve_principal(headers=hd("svc_video_active"))
        assert len(h.fake.service_resolves) > n, "video (least recently used) was evicted"
    finally:
        del world.keys_by_raw[spare_raw]


async def test_r2_a_string_that_cannot_be_a_platform_key_never_reaches_the_platform(build):
    h = build()
    for bad in ["stgs_short", "stgs_" + "a" * 300, "stgs_" + "a" * 30 + "!!", "stgs_" + "a" * 30 + " x", "stgs_" + "é" * 30, "stgs_" + "a" * 30 + "\n"]:
        r = await h.auth.resolve_principal(headers={"x-api-key": bad})
        assert (r["ok"], r["reason"]) == (False, "key_not_found"), bad[:20]
    assert h.fake.calls == []


def test_r2_nonsensical_limits_are_startup_errors():
    bad = [
        {"service_key_cache": {"max_entries": 0}}, {"service_key_cache": {"max_entries": -1}}, {"service_key_cache": {"max_entries": 1.5}},
        {"service_key_cache": {"valid_ttl_seconds": 0}}, {"service_key_cache": {"invalid_ttl_seconds": -5}}, {"service_key_cache": {"negative_max_entries": 0}},
        {"service_key_cache": {"max_inflight": 0}}, {"snapshot": {"ttl_seconds": 0}}, {"poll_interval_seconds": -1}, {"request_timeout_ms": 0},
        {"step_up_max_age_minutes": 0}, {"snapshot": {"ttl_seconds": "soon"}}, {"service_key_cache": {"max_entries": True}},
        {"snapshot": {"stale_read_ttl_seconds": -1}}, {"snapshot": {"ttl_seconds": float("nan")}},
    ]
    for o in bad:
        with pytest.raises(ConfigError):
            create_auth(service="docs", logger=SilentLogger(), env={}, **o)
    create_auth(service="docs", logger=SilentLogger(), env={}, poll_interval_seconds=0, snapshot={"stale_read_ttl_seconds": 0})


async def test_r2_at_most_max_inflight_resolutions_beyond_is_could_not_decide(build):
    h = build(service_key_cache={"max_inflight": 3})
    gate = asyncio.Event()
    h.fake.gate = gate
    pending = [asyncio.ensure_future(h.auth.resolve_principal(headers={"x-api-key": fake_key(i)})) for i in range(10)]
    await asyncio.sleep(0.05)
    gate.set()
    out = await asyncio.gather(*pending)
    shed = [r for r in out if r["reason"] == "platform_unavailable"]
    assert len(shed) == 7, "three ran, seven were shed"
    assert all(r["status"] == 503 for r in shed)
    again = await h.auth.resolve_principal(headers={"x-api-key": fake_key(9)})
    assert again["reason"] == "key_not_found", "a shed key was not cached as invalid: asked again, it gets a real answer"


async def test_r2_a_platform_429_pauses_resolution_and_is_never_a_verdict(build, world):
    h = build()
    h.fake.throttle_resolve = 7
    first = await h.auth.resolve_principal(headers={"x-api-key": raw(world, "svc_image_active")})
    assert (first["reason"], first["status"]) == ("platform_unavailable", 503)
    calls = len(h.fake.calls)
    for i in range(20):
        await h.auth.resolve_principal(headers={"x-api-key": fake_key(i)})
    assert len(h.fake.calls) == calls, "no calls while the platform said slow down"
    h.fake.throttle_resolve = 0
    h.tick(8)
    after = await h.auth.resolve_principal(headers={"x-api-key": raw(world, "svc_image_active")})
    assert after["ok"] is True, "after the pause the real key resolves: the 429 left nothing negative in the cache"


# ---- R3: route policy on the path as sent -------------------------------------------------------------


async def asgi_get(app, raw_path, headers, method="GET", with_raw_path=True):
    """A request exactly as an ASGI server would hand it over: raw_path undecoded, path decoded. (An HTTP
    client such as httpx would normalise `..` away before the request is sent.)"""
    path, _, query = raw_path.partition("?")
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "scheme": "http",
        "path": unquote(path), "query_string": query.encode(), "root_path": "", "server": ("test", 80), "client": ("1.2.3.4", 5),
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    if with_raw_path:
        scope["raw_path"] = path.encode("latin-1")
    sent = {}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            sent["status"] = message["status"]

    await app(scope, receive, send)
    return sent["status"]


def policy_app(h, policy, mount=None):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    sub = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, dependencies=[Depends(h.auth.require_service_caller(policy))])

    @sub.api_route("/{path:path}", methods=["GET"])
    async def anything(path: str):
        return {"ok": True}

    if mount:
        app.mount(mount, sub)
        return app
    return sub


async def test_r3_matches_the_full_original_path_mount_prefix_included_and_refuses_ambiguous_ones(build, world):
    h = build()
    # mounted: the sub-app sees "/status/1" and would have matched a policy written for "/status/*"
    app = policy_app(h, {"image": ["GET /internal/status/*"]}, mount="/internal")
    hd = {"x-api-key": raw(world, "svc_image_active")}
    assert await asgi_get(app, "/internal/status/1", hd) == 200
    assert await asgi_get(app, "/internal/status/1?x=/../", hd) == 200, "query string is not the path"
    for bad in ["/internal/status/..%2fadmin", "/internal/status/../x", "/internal//status/1", "/internal/status/a%2fb", "/internal/status/1/extra", "/internal/status/%31"]:  # %31 decodes to a path the policy would allow

        assert await asgi_get(app, bad, hd) == 403, bad


async def test_r3_the_decoded_path_is_never_what_gets_matched(build, world):
    h = build()
    app = policy_app(h, {"image": ["GET /internal/status/*"]})
    hd = {"x-api-key": raw(world, "svc_image_active")}
    # no raw_path from the server: the decoded path "/internal/status/a/b" does not match one segment either
    assert await asgi_get(app, "/internal/status/1", hd, with_raw_path=False) == 200
    assert await asgi_get(app, "/internal/status/a%2fb", hd, with_raw_path=False) == 403
    assert await asgi_get(app, "/internal/status/..%2fadmin", hd, with_raw_path=False) == 403


# ---- R4: booleans mean exactly true / false -----------------------------------------------------------


@pytest.mark.parametrize("allow", ["true", "false", 1, 0, "yes", {}, [], None])
async def test_r4_a_non_boolean_allow_is_a_malformed_answer_never_a_yes(allow, build):
    h = build()
    h.fake.override = lambda path, body: (
        {"allow": allow, "reason": "allowed", "tenant_id": h.acme, "principal": {"id": "p", "kind": "human", "user_id": "user_amy"}, "roles": ["admin"]}
        if path == "/v1/authorize" else None
    )
    d = await h.auth.authorize(headers=h.bearer("amy"), permission="docs:delete", resource={"tenant": h.acme})
    assert (d.allow, d.reason) == (False, "platform_unavailable"), repr(allow)


async def test_r4_valid_must_be_exactly_true(build, world):
    h = build()
    h.fake.override = lambda path, body: (
        {"valid": "false", "reason": "key_revoked", "principal": {"id": "p", "kind": "agent", "tenant_id": h.acme}} if path == "/v1/principals/resolve" else None
    )
    r = await h.auth.resolve_principal(headers={"x-api-key": raw(world, "agent_acme_active")})
    assert r["ok"] is False
    s = await h.auth.resolve_principal(headers={"x-api-key": raw(world, "svc_image_active")})
    assert s["ok"] is False, "and for service keys"


async def test_r4_an_allow_about_a_different_tenant_than_asked_is_refused(build):
    h = build()
    h.fake.override = lambda path, body: (
        {"allow": True, "reason": "allowed", "tenant_id": h.globex, "principal": {"id": "p", "kind": "human", "user_id": "user_amy"}, "roles": ["admin"]}
        if path == "/v1/authorize" else None
    )
    d = await h.auth.authorize(headers=h.bearer("amy"), permission="docs:delete", resource={"tenant": h.acme})
    assert (d.allow, d.reason) == (False, "platform_unavailable")


async def test_r4_an_allow_without_a_principal_is_refused(build):
    h = build()
    h.fake.override = lambda path, body: (
        {"allow": True, "reason": "allowed", "tenant_id": h.acme, "roles": ["admin"]} if path == "/v1/authorize" else None
    )
    d = await h.auth.authorize(headers=h.bearer("amy"), permission="docs:delete", resource={"tenant": h.acme})
    assert (d.allow, d.reason) == (False, "platform_unavailable")


async def test_r4_sensitive_only_if_exactly_true(build):
    h = build()
    h.fake.override = lambda path, body: (
        {"allow": True, "reason": "allowed", "tenant_id": h.acme, "sensitive": "yes", "principal": {"id": "p", "kind": "human", "user_id": "user_amy"}, "roles": []}
        if path == "/v1/authorize" else None
    )
    d = await h.auth.authorize(headers=h.bearer("amy"), permission="docs:delete", resource={"tenant": h.acme})
    assert (d.allow, d.sensitive) == (True, False)


# ---- R5: no work on behalf of an unverified credential ------------------------------------------------


def b64(o):
    return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()


async def test_r5_audience_token_runs_neither_resolver_nor_org_lookup_and_an_allow_must_name_a_principal(build):
    calls = []
    h = build(tenant_resolver=lambda req, p: calls.append(1) or h.acme)
    aud = f"{b64({'alg': 'EdDSA'})}.{b64({'iss': 'stighive-platform'})}.c2ln"
    h.fake.override = lambda path, body: (
        {"allow": True, "reason": "allowed", "tenant_id": h.acme, "roles": ["viewer"]} if path == "/v1/authorize" else None
    )  # an allow with NO principal
    d = await h.auth.authorize(headers={"authorization": f"Bearer {aud}"}, permission="docs:read")
    assert calls == [], "the app's resolver is not run for a credential nobody has verified"
    assert h.fake.count("GET", "/v1/authorize/snapshot") == 0, "no org lookup either"
    assert (d.allow, d.reason) == (False, "platform_unavailable"), "an allow that identifies no one is not accepted"


async def test_r5_resolver_is_not_run_for_key_credentials_either(build, world):
    calls = []
    h = build(tenant_resolver=lambda req, p: calls.append(1) or h.acme)
    h.fake.live = {"allow": True, "reason": "allowed", "tenant": "acme", "roles": ["operator"]}
    await h.auth.authorize(headers={"x-api-key": raw(world, "agent_acme_active")}, permission="docs:read")
    assert calls == []


# ---- hardening ----------------------------------------------------------------------------------------


def _verifier(handler, mono):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cfg = SimpleNamespace(issuer="https://c.test", jwks_url="http://j.test/jwks", authorized_parties=["x"], audience=[])
    import time

    return ClerkVerifier(cfg, http, lambda: int(time.time() * 1000), SilentLogger(), monotonic=lambda: mono[0])


async def test_jwks_outage_one_fetch_at_a_time_and_a_backoff():
    keys = ClerkKeys()
    fetches = []

    async def failing(request):
        fetches.append(1)
        await asyncio.sleep(0.005)
        raise httpx.ConnectError("down")

    mono = [0]
    v = _verifier(failing, mono)
    import time

    tok = mint_clerk_token(keys, "u", int(time.time() * 1000), "https://c.test", "x")
    await asyncio.gather(*[v.verify(tok) for _ in range(25)], return_exceptions=True)
    assert len(fetches) == 1, "concurrent callers share one fetch"
    for _ in range(50):
        with pytest.raises(Denied):
            await v.verify(tok)
    assert len(fetches) == 1, "and during the backoff nobody fetches"
    with pytest.raises(Denied) as e:
        await v.verify(tok)
    assert e.value.reason == "clerk_jwks_unavailable"
    mono[0] += 11_000
    with pytest.raises(Denied):
        await v.verify(tok)
    assert len(fetches) == 2, "retried once the backoff passed"


async def test_jwks_outage_with_keys_already_cached_keeps_verifying():
    keys = ClerkKeys()
    state = {"ok": True}

    def handler(request):
        if not state["ok"]:
            raise httpx.ConnectError("down")
        return httpx.Response(200, json={"keys": [keys.trusted.jwk]})

    mono = [0]
    v = _verifier(handler, mono)
    import time

    tok = mint_clerk_token(keys, "u", int(time.time() * 1000), "https://c.test", "x")
    assert (await v.verify(tok))["sub"] == "u"
    state["ok"] = False
    mono[0] += 6 * 60_000  # past the 5 minute cache
    assert (await v.verify(tok))["sub"] == "u", "stale keys used rather than turning a Clerk blip into an outage"


async def test_a_change_event_during_an_in_flight_refresh_is_not_lost_to_that_older_request():
    gate = asyncio.Event()
    snapshots = []

    class Client:
        async def snapshot(self, service, etag=None):
            mine = len(snapshots) + 1
            snapshots.append(mine)
            if mine == 2:
                await gate.wait()  # the older request is slow
            return {"body": {"service": "docs", "version": mine, "ttl_seconds": 30, "stale_read_ttl_seconds": 300, "tenants": [{"id": f"t{mine}"}]}, "etag": f'"e{mine}"'}

        async def events(self, after, limit=200):
            return {"events": [{"id": after + 1}], "next_cursor": after + 1, "head": after + 1}

    cache = SnapshotCache(Client(), "docs", 30, 300, lambda: 0, 0, SilentLogger())
    await cache.refresh()  # snapshot #1
    slow = asyncio.ensure_future(cache.refresh())  # #2 starts (in flight, built BEFORE the change below)
    await asyncio.sleep(0.01)
    polled = asyncio.ensure_future(cache.poll_once())  # a change event arrives now
    await asyncio.sleep(0.01)
    gate.set()
    await slow
    await polled
    assert len(snapshots) == 3, "a third refresh ran AFTER the event"
    assert cache.entry.body["tenants"][0]["id"] == "t3"


async def test_ttls_use_the_monotonic_clock(build):
    h = build()
    await h.auth.cache.get()
    n = h.fake.count("GET", "/v1/authorize/snapshot")
    h.jump(3600)  # the wall clock leaps an hour; no monotonic time passed
    await h.auth.cache.get()
    assert h.fake.count("GET", "/v1/authorize/snapshot") == n, "still fresh"
    h.tick(31)  # real time passes
    await h.auth.cache.get()
    assert h.fake.count("GET", "/v1/authorize/snapshot") > n, "refreshed after 30 monotonic seconds"


async def test_the_wall_clock_still_governs_token_validity(build):
    h = build()
    headers = h.bearer("alice")
    assert (await h.auth.authorize(headers=headers, permission="docs:read", resource={"tenant": h.acme})).allow is True
    h.jump(2 * 3600)  # the token (1 h) has expired on the wall clock
    d = await h.auth.authorize(headers=headers, permission="docs:read", resource={"tenant": h.acme})
    assert (d.allow, d.reason) == (False, "token_expired")


async def test_the_service_key_expiry_is_wall_clock_converted_to_a_monotonic_deadline(build, world):
    from world import iso_ms

    h = build()
    h.fake.service_key_expires_at = iso_ms(h.now() + 20_000)
    hd = {"x-api-key": raw(world, "svc_image_active")}
    await h.auth.resolve_principal(headers=hd)
    n = len(h.fake.service_resolves)
    h.tick(25)
    await h.auth.resolve_principal(headers=hd)
    assert len(h.fake.service_resolves) > n


def test_decide_offline_refuses_a_principal_kind_it_cannot_read():
    snap = {"service": "docs", "permissions": [{"action": "read", "category": "read", "sensitive": False}],
            "tenants": [{"id": "t", "ancestors": [], "starts_at": None, "ends_at": None}], "roles": [], "memberships": []}
    for kind in (None, "agent", "guest", "service", "robot"):
        d = decide_offline(snap, SimpleNamespace(user_id="u", kind=kind), "docs", "read", {"tenant": "t"}, 1790856000000)
        assert (d["allow"], d["reason"]) == (False, "principal_kind_restricted"), str(kind)


def test_fastapi_dependencies_never_raise_anything_but_http_exception(build):
    h = build()

    def boom(request):
        raise RuntimeError("bug in the app")

    async def aboom(request):
        raise ValueError("bug in the app")

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/a")
    async def a(d=Depends(h.auth.require_permission("docs:read", tenant=boom))):
        return {"should": "not run"}

    @app.post("/b")
    async def b(d=Depends(h.auth.require_approver("social:approve", step_up=True, brand=aboom))):
        return {"should": "not run"}

    with TestClient(app, raise_server_exceptions=True) as c:
        for r in (c.get("/a", headers=h.bearer("alice")), c.post("/b", headers=h.bearer("alice")), c.get("/a")):
            assert r.status_code == 503 and r.headers["retry-after"] == "5"
            assert r.json() == {"detail": {"error": "Authorization service unavailable", "reason": "platform_unavailable"}}


def test_step_up_denial_explains_itself():
    body = denial_body(403, "step_up_required", SimpleNamespace(upgrade_url="x"))
    assert "second-factor" in body["message"] and "fva" in body["message"]
    assert "message" not in denial_body(403, "no_permission", SimpleNamespace(upgrade_url="x"))


# ---- extraction through the adapter: an ambiguous credential is a clean 401 -----------------------------


def test_a_repeated_credential_header_is_a_clean_401(build, world):
    h = build()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/x")
    async def x(d=Depends(h.auth.require_permission("docs:read", tenant=h.acme))):
        return {"ok": True}

    good = raw(world, "agent_acme_active")
    with TestClient(app) as c:
        h.fake.live = {"allow": True, "reason": "allowed", "tenant": "acme", "roles": ["operator"]}
        r = c.get("/x", headers=[("x-api-key", good), ("x-api-key", good)])
        assert (r.status_code, r.json()["detail"]["reason"]) == (401, "token_invalid")
        r = c.get("/x", headers={"cookie": "__session=a.b.c; __session=d.e.f"})
        assert (r.status_code, r.json()["detail"]["reason"]) == (401, "token_invalid")
        r = c.get("/x", headers={"cookie": "__session=aaaa%E0%A4%A.bbbb.cccc"})
        assert (r.status_code, r.json()["detail"]["reason"]) == (401, "token_invalid")
