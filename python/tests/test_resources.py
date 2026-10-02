"""Resource lookups (C0c2): the mechanics the shared vectors cannot express: index lifetime, bounds,
hostile snapshots, and the adapter helpers that turn a lookup into a 403/503. Mirrors test/resources.test.js.
"""

import copy

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from conftest import Harness
from konstant_studio_auth.v2 import ConfigError, create_auth
from world import VECTORS, SilentLogger, World, mint_clerk_token

ISS = VECTORS["config"]["clerk"]["issuer"]
AZP = VECTORS["config"]["clerk"]["authorized_parties"][0]


class RecLogger(SilentLogger):
    def __init__(self):
        self.logs = []

    def error(self, msg, *a, **k):
        self.logs.append(("error", msg))

    def warning(self, msg, *a, **k):
        self.logs.append(("warn", msg))


@pytest.fixture
def local_world():
    return World(copy.deepcopy(VECTORS["world"]))  # private copy: tests mutate resources


@pytest.fixture
def build(local_world, clerk_keys):
    def _build(**over):
        logger = RecLogger()
        h = Harness(local_world, clerk_keys, separate_monotonic=True, logger=logger, **over)
        h.logs = logger.logs
        h.acme, h.globex = local_world.id("tenant", "acme"), local_world.id("tenant", "globex")
        h.token = lambda ref: mint_clerk_token(clerk_keys, local_world.principal(ref)["user_id"], h.now(), ISS, AZP)
        h.bearer = lambda ref: {"authorization": f"Bearer {h.token(ref)}"}
        return h

    return _build


def snapshot_with(tenants):
    return {"service": "docs", "version": 1, "ttl_seconds": 30, "stale_read_ttl_seconds": 300, "permissions": [], "roles": [], "memberships": [], "tenants": tenants}


def tenant(tid, resources=None, with_field=True):
    t = {"id": tid, "slug": tid, "type": "client", "parent_id": None, "ancestors": [], "org_id": None, "plan": None, "limits": {}, "starts_at": None, "ends_at": None}
    if with_field:
        t["resources"] = resources if resources is not None else []
    return t


def snapshots_calls(h):
    return h.fake.count("GET", "/v1/authorize/snapshot")


async def test_the_reverse_index_is_built_once_per_snapshot_survives_a_304_and_a_new_snapshot_replaces_it(build, local_world):
    h = build()
    await h.auth.tenant_for("brand", "brand-a")
    first = h.auth.cache.entry.index
    assert first is not None, "built on first use"
    for _ in range(50):
        await h.auth.tenant_for("brand", "brand-a")
    await h.auth.resources_for(h.acme, "brand")
    assert h.auth.cache.entry.index is first, "no rebuild per request"

    h.tick(31)  # past the TTL: revalidated with the ETag, nothing changed => 304 => the same entry
    await h.auth.tenant_for("brand", "brand-a")
    assert snapshots_calls(h) == 2
    assert h.auth.cache.entry.index is first, "a 304 keeps the index"

    local_world.spec["resources"].append({"tenant": "acme", "service": "docs", "kind": "brand", "local_id": "brand-new", "status": "active"})
    h.tick(31)
    assert (await h.auth.tenant_for("brand", "brand-new"))["tenant_id"] == h.acme, "a changed snapshot is picked up"
    assert h.auth.cache.entry.index is not first, "and its index is a new one"


async def test_lookups_are_refused_when_the_index_would_exceed_max_resources(build):
    h = build(max_resources=3)
    r = await h.auth.tenant_for("brand", "brand-a")
    assert (r["ok"], r["status"]) == (False, 503)
    assert any("larger than 3" in m for _, m in h.logs)
    with pytest.raises(ConfigError):
        create_auth(service="docs", max_resources=0, logger=SilentLogger(), env={})
    with pytest.raises(ConfigError):
        create_auth(service="docs", max_resources=True, logger=SilentLogger(), env={})


async def test_a_local_id_given_to_two_tenants_is_refused_once_logged_other_ids_still_work(build):
    h = build()
    h.fake.override = lambda path, body: snapshot_with([
        tenant(h.acme, [{"kind": "brand", "local_id": "dup"}, {"kind": "brand", "local_id": "fine"}]),
        tenant(h.globex, [{"kind": "brand", "local_id": "dup"}]),
    ]) if path == "/v1/authorize/snapshot" else None
    assert (await h.auth.tenant_for("brand", "dup"))["tenant_id"] is None, "ambiguous ownership is denial"
    assert (await h.auth.tenant_for("brand", "fine"))["tenant_id"] == h.acme
    assert len([1 for _, m in h.logs if "two tenants" in m]) == 1
    assert (await h.auth.resources_for(h.globex, "brand"))["ids"] == ["dup"], "the tenant still lists its own rows"


async def test_malformed_entries_never_grant_ownership_and_a_partly_missing_field_is_unavailable(build):
    h = build()
    h.fake.override = lambda path, body: snapshot_with([
        tenant(h.acme, [None, 7, {"kind": 5, "local_id": "x"}, {"kind": "brand"}, {"kind": "brand", "local_id": ["a"]},
                        {"kind": "", "local_id": "y"}, {"kind": "brand", "local_id": True}, {"kind": "brand", "local_id": "ok"}]),
    ]) if path == "/v1/authorize/snapshot" else None
    assert (await h.auth.tenant_for("brand", "ok"))["tenant_id"] == h.acme
    for ident in ("x", "y", "a", True):
        assert (await h.auth.tenant_for("brand", ident))["tenant_id"] is None, repr(ident)

    mixed = build()
    mixed.fake.override = lambda path, body: snapshot_with([tenant(mixed.acme, [{"kind": "brand", "local_id": "a"}]), tenant(mixed.globex, with_field=False)]) if path == "/v1/authorize/snapshot" else None
    assert [(await mixed.auth.tenant_for("brand", "a"))["ok"], (await mixed.auth.resources_for(mixed.acme, "brand"))["ok"]] == [False, False], \
        "one tenant without the field means this platform cannot be trusted to list everyone: unavailable, not 'unowned'"


async def test_a_snapshot_with_no_tenants_owns_nothing_and_is_not_unsupported(build):
    h = build()
    h.fake.override = lambda path, body: snapshot_with([]) if path == "/v1/authorize/snapshot" else None
    assert await h.auth.tenant_for("brand", "a") == {"ok": True, "tenant_id": None, "stale": False}
    assert (await h.auth.resources_for(h.acme, "brand"))["ids"] == []


async def test_lookups_never_raise_whatever_they_are_asked(build):
    h = build()
    for bad in (None, float("nan"), {}, [], object(), lambda: 1, 10**30, "x" * 100000, 2**53 + 1, b"bytes", {"a": [1]}):
        a = await h.auth.tenant_for(bad, bad)
        b = await h.auth.resources_for(bad, bad)
        assert (a["ok"] is True and a["tenant_id"] is None) or a["ok"] is False
        assert b["ok"] is False or isinstance(b["ids"], list)


async def test_integer_ids_are_their_decimal_text_but_a_bool_is_not_an_id(build):
    h = build()
    assert (await h.auth.tenant_for("account", 42))["tenant_id"] == h.acme
    assert (await h.auth.tenant_for("account", 42.0))["tenant_id"] == h.acme
    assert (await h.auth.tenant_for("account", True))["tenant_id"] is None


# ---- adapter helpers -----------------------------------------------------------------------------------------


def sample_app(h):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    owned_by = lambda req: req.path_params["id"]  # noqa: E731

    # tenant derived from the object, in the permission check itself
    @app.get("/brands/{id}")
    async def brand(d=Depends(h.auth.require_permission("docs:read", tenant_of=("brand", owned_by)))):
        return {"tenant": d.tenant_id, "source": d.tenant_source}

    # the tenant is decided elsewhere (explicit route tenant), then the object is checked against it
    @app.get("/t/{tenant}/brands/{id}", dependencies=[
        Depends(h.auth.require_permission("docs:read", tenant=lambda r: r.path_params["tenant"])),
        Depends(h.auth.require_resource_in_tenant("brand", owned_by)),
    ])
    async def in_tenant():
        return {"ok": True}

    @app.get("/no-decision/{id}", dependencies=[Depends(h.auth.require_resource_in_tenant("brand", owned_by))])
    async def no_decision():
        return {"ok": True}

    return app


def test_fastapi_tenant_of_the_object_names_the_tenant_unowned_and_unreadable_are_denied(build):
    h = build()
    with TestClient(sample_app(h)) as c:
        alice = h.bearer("alice")
        ok = c.get("/brands/brand-a", headers=alice)
        assert (ok.status_code, ok.json()) == (200, {"tenant": h.acme, "source": "resource"})
        other = c.get("/brands/brand-g", headers=alice)  # globex's: alice has nothing there
        assert (other.status_code, other.json()["detail"]["reason"]) == (403, "no_permission")
        unowned = c.get("/brands/nope", headers=alice)
        assert (unowned.status_code, unowned.json()["detail"]["reason"]) == (403, "resource_not_owned")
        assert sorted(unowned.json()["detail"]) == ["error", "reason"], "nothing about who owns what leaks in a denial"
        h.fake.omit_resources = True
        h.auth.cache.invalidate()
        down = c.get("/brands/brand-a", headers=alice)
        assert (down.status_code, down.json()["detail"]["reason"], down.headers["retry-after"]) == (503, "platform_unavailable", "5")


def test_fastapi_require_resource_in_tenant_same_tenant_passes_others_are_refused(build):
    h = build()
    with TestClient(sample_app(h)) as c:
        bob = h.bearer("bob")  # a member of acme AND globex
        assert c.get(f"/t/{h.acme}/brands/brand-a", headers=bob).status_code == 200
        mismatch = c.get(f"/t/{h.acme}/brands/brand-g", headers=bob)  # allowed in acme, but the object is globex's
        assert (mismatch.status_code, mismatch.json()["detail"]["reason"]) == (403, "tenant_mismatch")
        unowned = c.get(f"/t/{h.acme}/brands/nope", headers=bob)
        assert (unowned.status_code, unowned.json()["detail"]["reason"]) == (403, "resource_not_owned")
        no_decision = c.get("/no-decision/brand-a", headers=bob)  # misuse: nothing was decided first
        assert (no_decision.status_code, no_decision.json()["detail"]["reason"]) == (403, "tenant_mismatch"), "refused, never assumed"
        h.fake.omit_resources = True
        h.auth.cache.invalidate()
        assert c.get(f"/t/{h.acme}/brands/brand-a", headers=bob).status_code == 503


def test_fastapi_an_id_callback_that_raises_is_a_503_not_an_unhandled_error_or_an_allow(build):
    h = build()

    def bug(request):
        raise RuntimeError("app bug")

    async def abug(request):
        raise ValueError("app bug")

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.get("/x", dependencies=[Depends(h.auth.require_permission("docs:read", tenant=h.acme)), Depends(h.auth.require_resource_in_tenant("brand", bug))])(lambda: {"ok": True})
    app.get("/y", dependencies=[Depends(h.auth.require_permission("docs:read", tenant_of=("brand", bug)))])(lambda: {"ok": True})
    app.get("/z", dependencies=[Depends(h.auth.require_permission("docs:read", tenant_of=("brand", abug)))])(lambda: {"ok": True})
    with TestClient(app, raise_server_exceptions=True) as c:
        for path in ("/x", "/y", "/z"):
            assert c.get(path, headers=h.bearer("alice")).status_code == 503, path


async def test_the_audit_event_for_a_resource_derived_tenant_says_so_and_carries_no_resource_id(build):
    events = []
    h = build(on_event=events.append)
    await h.auth.authorize(headers=h.bearer("alice"), permission="docs:read", resource={"tenant_of": {"kind": "brand", "local_id": "brand-a"}})
    assert events[-1]["tenant_source"] == "resource"
    d = await h.auth.authorize(headers=h.bearer("alice"), permission="docs:read", resource={"tenant": h.acme})
    res = await h.auth.authorize_resource_in_tenant(decision=d, kind="brand", local_id="brand-a")
    assert (res.allow, res.reason, res.tenant_source) == (True, "allowed", "resource")
    assert events[-1]["permission"] == "resource_in_tenant"
    assert "brand-a" not in str(events), "local ids stay out of audit events"


async def test_authorize_resource_in_tenant_needs_an_allowing_decision(build):
    h = build()
    for decision in (None, "nonsense", object()):
        r = await h.auth.authorize_resource_in_tenant(decision=decision, kind="brand", local_id="brand-a")
        assert (r.allow, r.reason) == (False, "tenant_mismatch")
    denied = await h.auth.authorize(headers={}, permission="docs:read", resource={"tenant": h.acme})
    r = await h.auth.authorize_resource_in_tenant(decision=denied, kind="brand", local_id="brand-a")
    assert (r.allow, r.reason) == (False, "tenant_mismatch")


async def test_tenant_of_is_only_reached_after_the_credential_is_verified(build):
    h = build()
    d = await h.auth.authorize(headers={}, permission="docs:read", resource={"tenant_of": {"kind": "brand", "local_id": "brand-a"}})
    assert (d.allow, d.reason) == (False, "no_credential")
    assert snapshots_calls(h) == 0
