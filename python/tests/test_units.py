import asyncio
import hashlib
import hmac
import json

import httpx
import pytest

from konstant_studio_auth.v2 import ConfigError, create_auth, parse_permission, route_allowed, verify_signature
from konstant_studio_auth.v2.decision import in_window, parse_ms, scope_allows
from konstant_studio_auth.v2.reasons import status_for
from world import VECTORS, SilentLogger, mint_clerk_token

CFG = VECTORS["config"]
ISS = CFG["clerk"]["issuer"]
AZP = CFG["clerk"]["authorized_parties"][0]


def clerk_headers(world, keys, who, now, spec=None):
    token = mint_clerk_token(keys, world.principal(who)["user_id"], now, ISS, AZP, spec)
    return {"authorization": f"Bearer {token}"}


# ---- scope ---------------------------------------------------------------------


def test_scope_matching():
    assert scope_allows({}, {}) is None
    assert scope_allows({"brand_ids": ["Brand-A"]}, {"brand": "brand-a"}) is None  # case-insensitive
    assert scope_allows({"brand_ids": ["a"]}, {"brand": "b"}) == "out_of_scope"
    assert scope_allows({"brand_ids": ["a"]}, {}) == "scope_required"
    assert scope_allows({"brand_ids": ["a"]}, {"brand": ""}) == "scope_required"
    assert scope_allows({"domains": ["x.example"]}, {"domain": "X.EXAMPLE"}) is None
    assert scope_allows({"mailboxes": ["a@x"]}, {"mailbox": "b@x"}) == "out_of_scope"
    # a typo'd key or a malformed dimension must never read as "no restriction"
    assert scope_allows({"brand_id": ["a"]}, {"brand": "a"}) == "out_of_scope"
    assert scope_allows({"brand_ids": "a"}, {"brand": "a"}) == "out_of_scope"
    assert scope_allows(["brand_ids"], {}) == "out_of_scope"
    assert scope_allows(None, {}) == "out_of_scope"
    # `descendants` is a known key and restricts nothing by itself
    assert scope_allows({"descendants": True}, {}) is None


def test_parse_permission():
    assert parse_permission("docs:render") == {"service": "docs", "action": "render"}
    assert parse_permission("docs:") is None and parse_permission(":x") is None
    assert parse_permission("nocolon") is None and parse_permission(None) is None


def test_entitlement_window_uses_given_clock():
    now = parse_ms("2026-10-01T12:00:00Z")
    assert now == 1790856000000
    assert in_window({"starts_at": None, "ends_at": None}, now)
    assert not in_window({"starts_at": "2026-10-01T12:00:00.001Z"}, now)
    assert not in_window({"ends_at": "2026-10-01T12:00:00.000Z"}, now)  # end is exclusive
    assert in_window({"ends_at": "2026-10-01T12:00:00.001Z"}, now)
    assert parse_ms("2026-10-01T14:00:00+02:00") == now
    assert parse_ms("garbage") is None


def test_status_mapping():
    assert status_for("allowed", True) == 200
    assert status_for("token_expired", False) == 401
    assert status_for("platform_unavailable", False) == 503
    assert status_for("no_permission", False) == 403
    assert status_for("something_new", False) == 403


# ---- route_allowed -------------------------------------------------------------


def test_route_allowed():
    routes = ["GET /v1/docs/*", "* /health", "POST /render"]
    assert route_allowed(routes, "get", "/v1/docs/123/pages")
    assert not route_allowed(routes, "POST", "/v1/docs/123")
    assert route_allowed(routes, "DELETE", "/health")
    assert route_allowed(routes, "POST", "/render")
    assert not route_allowed(routes, "POST", "/render/extra")
    assert not route_allowed(routes, "POST", "/xrender")
    assert not route_allowed([], "GET", "/")
    assert not route_allowed(None, "GET", "/")
    assert not route_allowed(["GET /a.b"], "GET", "/aXb")  # `.` is literal, `*` is the only glob


# ---- service keys --------------------------------------------------------------


async def test_service_key_stub_is_unsupported_and_never_calls_the_platform(make_harness):
    h = make_harness()
    key = "stgs_" + hashlib.sha256(b"fake").hexdigest()
    d = await h.auth.authorize(headers={"x-api-key": key}, permission="docs:read", resource={"tenant": "t"})
    assert (d.allow, d.reason, d.status, d.source) == (False, "unsupported_credential", 401, "none")
    assert h.fake.calls == []
    r = await h.auth.resolve_principal(headers={"authorization": f"Bearer {key}"})
    assert r == {"ok": False, "reason": "unsupported_credential", "status": 401}
    assert h.fake.calls == []


async def test_service_key_platform_mode_maps_the_amendment_shape(make_harness):
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        if request.url.path == "/v1/principals/resolve":
            return httpx.Response(200, json={"valid": True, "key_id": "k1", "principal": {"kind": "service", "id": "p1", "service": "crm", "routes": ["GET /ok"]}})
        return httpx.Response(200, json={"allow": False, "reason": "no_permission", "tenant_id": None})

    h = make_harness(service_keys="platform", transport=httpx.MockTransport(handler))
    key = "stgs_" + "a" * 40
    r = await h.auth.resolve_principal(headers={"x-api-key": key})
    assert r["ok"] and r["principal"].kind == "service" and r["principal"].routes == ["GET /ok"]
    d = await h.auth.authorize(headers={"x-api-key": key}, permission="docs:read", resource={"tenant": "t"})
    assert (d.allow, d.reason, d.status, d.source) == (False, "no_permission", 403, "live")


# ---- snapshot cache ------------------------------------------------------------


def snapshot_calls(h):
    return [c for c in h.fake.calls if c["path"] == "/v1/authorize/snapshot"]


async def test_cache_etag_304_path(make_harness):
    h = make_harness()
    first = await h.auth.cache.get()
    assert first.state == "fresh" and len(snapshot_calls(h)) == 1
    assert "if-none-match" not in snapshot_calls(h)[0]["headers"]
    await h.auth.cache.get()
    assert len(snapshot_calls(h)) == 1  # inside the TTL: no call
    h.advance(31)
    again = await h.auth.cache.get()
    calls = snapshot_calls(h)
    assert len(calls) == 2 and calls[1]["headers"]["if-none-match"].startswith('"')
    assert again.state == "fresh" and again.age_seconds == 0 and again.snapshot is first.snapshot  # 304 kept the body


async def test_cache_single_flight(make_harness):
    h = make_harness()
    views = await asyncio.gather(*[h.auth.cache.get() for _ in range(8)])
    assert len(snapshot_calls(h)) == 1
    assert all(v.state == "fresh" for v in views)


async def test_cache_retry_backoff_after_failed_refresh(make_harness):
    h = make_harness()
    h.fake.down = True
    assert (await h.auth.cache.get()).state == "none"
    assert (await h.auth.cache.get()).state == "none"
    assert len(snapshot_calls(h)) == 1  # second call inside the 1s backoff did not try
    h.advance(1.1)
    await h.auth.cache.get()
    assert len(snapshot_calls(h)) == 2
    h.fake.down = False
    h.advance(1.1)
    assert (await h.auth.cache.get()).state == "fresh"


async def test_cache_stale_window(make_harness):
    h = make_harness()
    await h.auth.cache.get()
    h.fake.down = True
    h.advance(31)
    assert (await h.auth.cache.get()).state == "stale"
    h.advance(269)  # 300s old: still inside (<=)
    assert (await h.auth.cache.get()).state == "stale"
    h.advance(2)
    assert (await h.auth.cache.get()).state == "none"


async def test_cache_change_feed_refresh(make_harness):
    h = make_harness()
    await h.auth.cache.get()
    assert h.auth.cache.cursor == 100  # starts at the snapshot's own version
    assert await h.auth.cache.poll_once() is False
    assert len(snapshot_calls(h)) == 1
    h.fake.events = [{"id": 101}, {"id": 102}]
    assert await h.auth.cache.poll_once() is True
    assert h.auth.cache.cursor == 102 and len(snapshot_calls(h)) == 2  # refetched before the TTL ran out


async def test_start_polls_and_close_stops(make_harness):
    h = make_harness(poll_interval_seconds=0.01)
    await h.auth.cache.get()
    h.fake.events = [{"id": 101}]
    h.auth.start()
    await asyncio.sleep(0.1)
    assert len(snapshot_calls(h)) >= 2
    await h.auth.close()
    assert h.auth.cache._task is None


# ---- clerk / decisions beyond the vectors --------------------------------------


async def test_jwks_forced_refresh_is_throttled(make_harness, world, clerk_keys):
    h = make_harness()
    jwks_calls = []
    inner = h.fake.transport.handler

    async def counting(request):
        if str(request.url) == h.fake.jwks_url:
            jwks_calls.append(1)
        return await inner(request)

    h.auth.http._transport = httpx.MockTransport(counting)
    bad = clerk_headers(world, clerk_keys, "alice", h.now(), {"kid": "nope"})
    for _ in range(3):
        d = await h.auth.authorize(headers=bad, permission="docs:read", resource={"tenant": world.id("tenant", "acme")})
        assert d.reason == "token_invalid"
    assert len(jwks_calls) == 2  # one initial load + ONE forced refresh, not one per bad token


async def test_jwks_stale_reuse_when_refresh_fails(make_harness, world, clerk_keys):
    h = make_harness()
    good = clerk_headers(world, clerk_keys, "alice", h.now())
    acme = {"tenant": world.id("tenant", "acme")}
    assert (await h.auth.authorize(headers=good, permission="docs:read", resource=acme)).allow
    h.auth.http._transport = httpx.MockTransport(lambda r: httpx.Response(500))
    h.advance(6 * 60)
    good = clerk_headers(world, clerk_keys, "alice", h.now())
    h.auth.cache.entry.fetched_at = h.now()  # keep the permission snapshot fresh; this test is about the JWKS
    assert (await h.auth.authorize(headers=good, permission="docs:read", resource=acme)).allow


async def test_jwks_unavailable_on_cold_start_is_503(make_harness, world, clerk_keys):
    h = make_harness(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    d = await h.auth.authorize(headers=clerk_headers(world, clerk_keys, "alice", h.now()), permission="docs:read", resource={"tenant": "x"})
    assert (d.reason, d.status) == ("clerk_jwks_unavailable", 503)


async def test_clock_tolerance(make_harness, world, clerk_keys):
    h = make_harness()
    acme = {"tenant": world.id("tenant", "acme")}
    # exp 4s ago is inside the 5s leeway; 6s ago is not
    ok = clerk_headers(world, clerk_keys, "alice", h.now(), {"exp_in_s": -4})
    late = clerk_headers(world, clerk_keys, "alice", h.now(), {"exp_in_s": -6})
    assert (await h.auth.authorize(headers=ok, permission="docs:read", resource=acme)).allow
    assert (await h.auth.authorize(headers=late, permission="docs:read", resource=acme)).reason == "token_expired"


async def test_audience_rules(make_harness, world, clerk_keys):
    acme = {"tenant": world.id("tenant", "acme")}
    h = make_harness(clerk={"issuer": ISS, "jwks_url": "http://jwks.vectors.test/jwks.json", "authorized_parties": [AZP], "audience": ["https://api.vectors.test"]})
    ok = clerk_headers(world, clerk_keys, "alice", h.now(), {"aud": ["x", "https://api.vectors.test"]})
    assert (await h.auth.authorize(headers=ok, permission="docs:read", resource=acme)).allow
    bad = clerk_headers(world, clerk_keys, "alice", h.now(), {"aud": "other"})
    assert (await h.auth.authorize(headers=bad, permission="docs:read", resource=acme)).reason == "token_invalid"


async def test_authorize_never_raises_on_garbage(make_harness):
    h = make_harness()
    for headers in ({}, {"authorization": "Bearer"}, {"authorization": "Bearer a.b.c"}, {"x-api-key": "x"}, {"cookie": "__session=%E0%A4%A"}):
        d = await h.auth.authorize(headers=headers, permission="docs:read", resource={"tenant": "t"})
        assert not d.allow and d.status in (401, 503)
    d = await h.auth.authorize(headers={}, permission="bad", resource={})
    assert d.reason == "unknown_permission" and d.status == 403


async def test_session_cookie_is_a_credential(make_harness, world, clerk_keys):
    h = make_harness()
    token = clerk_headers(world, clerk_keys, "alice", h.now())["authorization"].split(" ")[1]
    d = await h.auth.authorize(headers={"cookie": f"a=b; __session={token}"}, permission="docs:read", resource={"tenant": world.id("tenant", "acme")})
    assert d.allow


async def test_audience_token_is_never_trusted_offline(make_harness, world):
    import base64

    seg = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()  # noqa: E731
    token = f"{seg({'alg': 'RS256'})}.{seg({'iss': 'stighive-platform'})}.sig"
    h = make_harness()
    h.fake.live = {"allow": True, "reason": "allowed", "tenant": "acme", "roles": ["operator"], "principal": {"id": "p", "kind": "human", "user_id": "u"}}
    d = await h.auth.authorize(headers={"authorization": f"Bearer {token}"}, permission="docs:read", resource={"tenant": world.id("tenant", "acme")})
    assert d.source == "live" and d.allow and h.fake.count("POST", "/v1/authorize") == 1


async def test_approver_and_step_up(make_harness, world, clerk_keys):
    from jose import jwt

    h = make_harness()
    h.fake.live = {"allow": True, "reason": "allowed", "tenant": "acme", "roles": ["approver"], "sensitive": True}
    acme = {"tenant": world.id("tenant", "acme")}

    def tok(**extra):
        c = {"sub": "user_dan", "iat": h.now() // 1000, "exp": h.now() // 1000 + 600, "iss": ISS, "azp": AZP, **extra}
        return {"authorization": "Bearer " + jwt.encode(c, clerk_keys.trusted.pem, algorithm="RS256", headers={"kid": "kid-trusted"})}

    async def ask(headers, step_up):
        return await h.auth.authorize_approver(step_up=step_up, headers=headers, permission="social:approve", resource=acme)

    assert (await ask(tok(), False)).allow
    assert (await ask(tok(fva=[5, 3]), True)).allow
    for fva in ({}, {"fva": [5, -1]}, {"fva": [5, 11]}, {"fva": "x"}):
        d = await ask(tok(**fva), True)
        assert (d.allow, d.reason, d.status) == (False, "step_up_required", 403)
    # a non-human principal (agent key) is never an approver, even if the platform allowed it
    key = world.raw_key(next(k for k in world.spec["keys"] if k["ref"] == "agent_acme_active"))
    d = await h.auth.authorize_approver(headers={"x-api-key": key}, permission="social:approve", resource=acme)
    assert (d.allow, d.reason) == (False, "principal_kind_restricted")


async def test_assert_tenant_and_usage_context(make_harness, world, clerk_keys):
    h = make_harness()
    t = world.id("tenant", "acme")
    d = await h.auth.authorize(headers=clerk_headers(world, clerk_keys, "alice", h.now()), permission="docs:read", resource={"tenant": t}, request_id="run-1")
    assert h.auth.assert_tenant(d, t) and not h.auth.assert_tenant(d, world.id("tenant", "globex")) and not h.auth.assert_tenant(None, t)
    ctx = h.auth.usage_context(d, "run-1")
    assert ctx == {"tenant_id": t, "actor": {"kind": "human", "id": "user_alice"}, "run_id": "run-1"}


# ---- audit event ----------------------------------------------------------------


async def test_audit_event_has_no_credential_material(make_harness, world, clerk_keys):
    events = []
    h = make_harness(on_event=events.append)
    t = world.id("tenant", "acme")
    h.fake.live = {"allow": True, "reason": "allowed", "tenant": "acme", "roles": ["operator"]}
    clerk = clerk_headers(world, clerk_keys, "alice", h.now())
    secrets = [clerk["authorization"].split(" ")[1]]
    key = world.raw_key(next(k for k in world.spec["keys"] if k["ref"] == "agent_acme_active"))
    secrets.append(key)
    junk = "Bearer junk.token.value-that-must-not-leak"
    await h.auth.authorize(headers=clerk, permission="docs:read", resource={"tenant": t}, request_id="r1")
    await h.auth.authorize(headers={"x-api-key": key}, permission="docs:read", resource={"tenant": t})
    await h.auth.authorize(headers={"authorization": junk}, permission="docs:read", resource={"tenant": t})
    await h.auth.authorize(headers={"x-api-key": "stgs_" + "z" * 40}, permission="docs:read", resource={"tenant": t})
    assert len(events) == 4
    blob = json.dumps(events)
    for s in [*secrets, "junk.token", "z" * 40, "Bearer ", "stgs_fake-service-key-for-tests"]:
        assert s not in blob
    assert events[0]["type"] == "auth.decision" and events[0]["run_id"] == "r1" and events[0]["ts"].endswith("Z")
    assert events[1]["actor"]["key_prefix"] == "stga_"
    assert set(events[0]) == {"type", "ts", "service", "permission", "allow", "reason", "source", "stale", "tenant_id", "via_tenant", "actor", "key_id", "run_id"}


async def test_a_failing_event_sink_never_breaks_a_request(make_harness, world, clerk_keys):
    def boom(_):
        raise RuntimeError("sink down")

    h = make_harness(on_event=boom)
    d = await h.auth.authorize(headers=clerk_headers(world, clerk_keys, "alice", h.now()), permission="docs:read", resource={"tenant": world.id("tenant", "acme")})
    assert d.allow


async def test_unexpected_error_is_a_denial_not_an_allow(make_harness, world, clerk_keys):
    def bad_resolver(request, principal):
        raise ValueError("boom")

    h = make_harness(tenant_resolver=bad_resolver)
    d = await h.auth.authorize(headers=clerk_headers(world, clerk_keys, "alice", h.now()), permission="docs:read")
    assert (d.allow, d.reason, d.status) == (False, "platform_unavailable", 503)


# ---- config ---------------------------------------------------------------------


def test_config_requires_authorized_parties():
    with pytest.raises(ConfigError):
        create_auth(clerk={"issuer": "https://c.test"}, env={})
    with pytest.raises(ConfigError):
        create_auth(env={"CLERK_JWKS_URL": "https://c.test/jwks"})
    create_auth(env={})  # Clerk not configured at all is fine (everything goes live / 503 clerk_not_configured)


def test_config_env_fallbacks():
    env = {
        "CLERK_ISSUER": "https://c.test/", "CLERK_AUTHORIZED_PARTIES": " https://a.test , https://b.test ", "CLERK_AUDIENCE": "aud1",
        "PLATFORM_API_URL": "https://p.test///", "INTERNAL_API_KEY": "old", "SNAPSHOT_TTL_SECONDS": "12", "SNAPSHOT_STALE_READ_TTL_SECONDS": "x",
        "AUTH_EVENT_POLL_SECONDS": "7", "AUTH_STEP_UP_MAX_AGE_MINUTES": "3", "AUTH_SERVICE_KEYS": "platform", "AUTH_UPGRADE_URL": "https://u.test", "AUTH_SERVICE": "docs",
    }
    cfg = create_auth(env=env).config
    assert cfg.clerk.issuer == "https://c.test/" and cfg.clerk.jwks_url == "https://c.test/.well-known/jwks.json"
    assert cfg.clerk.authorized_parties == ["https://a.test", "https://b.test"] and cfg.clerk.audience == ["aud1"]
    assert cfg.platform_url == "https://p.test" and cfg.platform_key == "old"
    assert (cfg.snapshot.ttl_seconds, cfg.snapshot.stale_read_ttl_seconds) == (12, 300)
    assert (cfg.poll_interval_seconds, cfg.step_up_max_age_minutes) == (7, 3)
    assert (cfg.service_keys, cfg.upgrade_url, cfg.service) == ("platform", "https://u.test", "docs")
    env["PLATFORM_SERVICE_KEY"] = "new"
    assert create_auth(env=env).config.platform_key == "new"  # per-service key beats the deprecated shared one
    assert create_auth(env={}, clerk=None).config.service_keys == "stub"


# ---- webhook signature ----------------------------------------------------------


def sign(secret, ts, body):
    return "v1=" + hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()


def test_webhook_signature():
    body = b'{"event":"x"}'
    now = 1_790_856_000_000
    ts = str(now // 1000)
    good = sign("s3cret", ts, body)
    assert verify_signature(secret="s3cret", timestamp=ts, signature=good, raw_body=body, now_ms=now)
    assert verify_signature(secret="s3cret", timestamp=ts, signature=good[3:], raw_body=body, now_ms=now)  # bare hex also accepted
    assert not verify_signature(secret="other", timestamp=ts, signature=good, raw_body=body, now_ms=now)
    assert not verify_signature(secret="s3cret", timestamp=ts, signature=good, raw_body=body + b" ", now_ms=now)
    assert not verify_signature(secret="s3cret", timestamp=str(int(ts) + 1), signature=good, raw_body=body, now_ms=now)
    old = str(int(ts) - 301)
    assert not verify_signature(secret="s3cret", timestamp=old, signature=sign("s3cret", old, body), raw_body=body, now_ms=now)
    edge = str(int(ts) - 300)
    assert verify_signature(secret="s3cret", timestamp=edge, signature=sign("s3cret", edge, body), raw_body=body, now_ms=now)
    for bad in (dict(secret="", timestamp=ts, signature=good), dict(secret="s3cret", timestamp="", signature=good),
                dict(secret="s3cret", timestamp=ts, signature=""), dict(secret="s3cret", timestamp="abc", signature=good),
                dict(secret="s3cret", timestamp=ts, signature="v1=zz"), dict(secret="s3cret", timestamp=ts, signature="v1=" + "0" * 64)):
        assert not verify_signature(raw_body=body, now_ms=now, **bad)


# ---- fail-closed behaviours -------------------------------------------------------


class _FakeClient:
    def __init__(self):
        self.etag = '"v1"'
        self.body = {"version": 1, "tenants": [{"id": "old"}], "permissions": []}
        self.feed = []
        self.fail = False

    async def snapshot(self, service, etag=None):
        from konstant_studio_auth.v2.platform_client import PlatformUnavailable

        if self.fail:
            raise PlatformUnavailable("blip")
        return {"body": self.body, "etag": self.etag}

    async def events(self, after, limit=200):
        return {"events": self.feed, "next_cursor": after + len(self.feed) + 1}


async def test_change_event_is_not_lost_when_the_refresh_fails():
    from konstant_studio_auth.v2.platform_client import PlatformUnavailable
    from konstant_studio_auth.v2.snapshot_cache import SnapshotCache

    client = _FakeClient()
    cache = SnapshotCache(client, "docs", 30, 300, lambda: 1_000_000, 0, SilentLogger())
    await cache.get()
    client.body = {**client.body, "version": 2, "tenants": [{"id": "new"}]}
    client.etag = '"v2"'
    client.feed = [{"id": 2}]
    client.fail = True
    cursor = cache.cursor
    with pytest.raises(PlatformUnavailable):
        await cache.poll_once()
    assert cache.cursor == cursor  # did not move past the event
    client.fail = False
    assert await cache.poll_once() is True
    assert cache.entry.body["tenants"][0]["id"] == "new"
    assert cache.cursor == cursor + 2


def test_unparseable_timestamps_deny():
    from konstant_studio_auth.v2.decision import decide_offline
    from konstant_studio_auth.v2.auth import Principal

    def snap(tenant=None, membership=None):
        return {
            "service": "docs", "permissions": [{"action": "read", "category": "read", "sensitive": False}],
            "tenants": [{"id": "t1", "ancestors": [], "starts_at": None, "ends_at": None, **(tenant or {})}],
            "roles": [{"id": "r1", "slug": "viewer", "tenant_id": None, "permissions": ["docs:read"]}],
            "memberships": [{"principal_id": "p", "user_id": "u1", "kind": "human", "tenant_id": "t1", "role_id": "r1", "scope": {}, "expires_at": None, **(membership or {})}],
        }

    def ask(s):
        return decide_offline(s, Principal(kind="human", user_id="u1"), "docs", "read", {"tenant": "t1"}, 1790856000000)

    assert ask(snap())["allow"] is True
    assert ask(snap(tenant={"ends_at": "garbage"}))["allow"] is False
    assert ask(snap(tenant={"starts_at": "garbage"}))["allow"] is False
    assert ask(snap(membership={"expires_at": "garbage"}))["allow"] is False
    assert ask(snap(membership={"expires_at": "2026-10-01T12:00:00Z"}))["allow"] is False  # exactly now: expired


async def test_malformed_resolve_reply_identifies_no_one(make_harness):
    h = make_harness(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"valid": True})))
    r = await h.auth.resolve_principal(headers={"x-api-key": "stga_" + "a" * 30})
    assert (r["ok"], r["reason"], r["status"]) == (False, "platform_unavailable", 503)


async def test_empty_tenant_string_asks_the_platform(make_harness):
    h = make_harness()
    h.fake.live = {"allow": False, "reason": "tenant_required", "tenant": None}
    h.fake.down = True
    d = await h.auth.authorize(headers={"x-api-key": "stga_" + "a" * 30}, permission="docs:read", resource={"tenant": ""})
    assert not d.allow
    assert h.fake.count("POST", "/v1/authorize") == 1 and h.fake.count("GET", "/v1/authorize/snapshot") == 0


async def test_future_iat_and_nbf(make_harness, world, clerk_keys):
    h = make_harness()
    acme = {"tenant": world.id("tenant", "acme")}
    for spec, reason in (({"iat_in_s": 60}, "token_invalid"), ({"nbf_in_s": 60}, "token_invalid")):
        d = await h.auth.authorize(headers=clerk_headers(world, clerk_keys, "alice", h.now(), spec), permission="docs:read", resource=acme)
        assert (d.allow, d.reason) == (False, reason)
    ok = clerk_headers(world, clerk_keys, "alice", h.now(), {"iat_in_s": 4, "nbf_in_s": 4})  # inside the 5s leeway
    assert (await h.auth.authorize(headers=ok, permission="docs:read", resource=acme)).allow


def test_run_id_from_the_caller_is_bounded_and_printable():
    from konstant_studio_auth.v2.adapters.shared import clean_run_id

    assert clean_run_id(None) is None
    assert clean_run_id("run-123") == "run-123"
    assert clean_run_id("a\r\nb\x00cé") == "abc"  # no log/header injection
    assert len(clean_run_id("x" * 500)) == 128
    assert clean_run_id("\n\n") is None
