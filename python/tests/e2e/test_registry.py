"""The real tenant-resource registry (platform C0f, the pinned commit): every lookup vector is answered by the
library AND checked against the platform's own reverse lookup, and a service registers, conflicts and retires
rows through the platform's API exactly as a real service would. Mirrors test/e2e/registry.test.js.
"""

import re
import time
from urllib.parse import quote

import httpx

from world import VECTORS

from .helpers import library_for, psql


def decode(v):
    if isinstance(v, dict) and "$type" in v:
        return float(v["value"]) if v["$type"] == "float" else int(v["value"])
    return v


def build(ctx):
    return library_for(ctx, accepted_caller_services=VECTORS["config"]["accepted_caller_services"])


def api(ctx, method, path, body=None, key=None):
    r = httpx.request(method, f"{ctx.state['platform_url']}{path}", headers={"X-API-Key": key or ctx.state["service_key"]}, json=body, timeout=10)
    try:
        data = r.json()
    except Exception:  # noqa: BLE001
        data = None
    return r.status_code, data


def platform_owner(ctx, kind, local_id):
    """The platform's own answer to "who owns this local id for my service?" (reverse lookup)."""
    status, body = api(ctx, "GET", f"/v1/resources?kind={quote(kind, safe='')}&local_id={quote(local_id, safe='')}")
    return body[0]["tenant_id"] if status == 200 and len(body) == 1 else None  # 422 (cannot be held) is "nobody"


def platform_ids(ctx, tenant, kind):
    status, body = api(ctx, "GET", f"/v1/resources?tenant_id={tenant}&kind={quote(kind, safe='')}&limit=1000")
    return [x["local_id"] for x in body] if status == 200 else []


async def test_every_lookup_vector_agrees_with_the_platforms_own_registry_answers(ctx):
    tid = lambda ref: ctx.world.id("tenant", ref)  # noqa: E731
    compared = 0
    for c in VECTORS["lookups"]["cases"]:
        if c.get("snapshot"):
            continue  # stale / down / no-field modes need a platform that is not answering
        auth = build(ctx)
        try:
            a = c["args"]
            kind, local_id = decode(a.get("kind")), decode(a.get("local_id"))
            if c["call"] == "tenantFor":
                got = await auth.tenant_for(kind, local_id)
                assert got["ok"] is True, c["id"]
                assert got["tenant_id"] == (None if c["expect"]["tenant"] is None else tid(c["expect"]["tenant"])), f"{c['id']}: library vs vector"
                # The platform's truth, only where the value is a plain registry string (a number or odd type is the library's rule).
                plain_int = isinstance(local_id, int) and not isinstance(local_id, bool) and 0 <= local_id <= 2**53 - 1
                if isinstance(kind, str) and (isinstance(local_id, str) or plain_int):
                    truth = platform_owner(ctx, kind, str(local_id))
                    assert got["tenant_id"] == truth, f"{c['id']}: library vs the platform's reverse lookup"
                    compared += 1
            else:
                tenant = a.get("tenant_raw") or (tid(a["tenant"]) if a.get("tenant") else None)
                got = await auth.resources_for(tenant, kind)
                assert got["ids"] == c["expect"]["ids"], f"{c['id']}: library vs vector"
                if isinstance(tenant, str) and re.fullmatch(r"[0-9a-f-]{36}", tenant) and isinstance(kind, str) and kind:
                    assert sorted(got["ids"]) == sorted(platform_ids(ctx, tenant, kind)), f"{c['id']}: library vs the platform's list"
                    compared += 1
        finally:
            await auth.close()
    assert compared >= 25, f"only {compared} cases were compared with the platform itself"


async def test_the_observable_id_rules_the_registry_really_holds_what_the_refused_values_would_have_matched(ctx):
    acme = ctx.world.id("tenant", "acme")
    for s in ("9007199254740993", "-1", "1.5", "true", "café"):
        kind = "brand" if s == "café" else "account"
        assert platform_owner(ctx, kind, s) == acme, f"{kind}:{s} is registered for acme in the real registry"
    auth = build(ctx)
    try:
        for v in (2**53 + 1, -1, 1.5, True, 10**16):
            assert (await auth.tenant_for("account", v))["tenant_id"] is None, repr(v)
    finally:
        await auth.close()


async def test_a_service_registers_conflicts_is_refused_for_an_unentitled_tenant_retires_and_the_library_follows(ctx):
    tid = lambda ref: ctx.world.id("tenant", ref)  # noqa: E731
    auth = build(ctx)
    ident = f"e2e-{int(time.time() * 1000)}"
    reg = "/v1/resources"
    try:
        await auth.cache.get()  # snapshot loaded: the change feed starts from here
        assert (await auth.tenant_for("brand", ident))["tenant_id"] is None

        status, _ = api(ctx, "POST", reg, {"tenant_id": tid("acme"), "kind": "brand", "local_id": ident})
        assert status == 201
        assert api(ctx, "POST", reg, {"tenant_id": tid("acme"), "kind": "brand", "local_id": ident})[0] == 200, "idempotent"
        assert await auth.cache.poll_once() is True, "the registration is a change event: the library refreshes"
        assert (await auth.tenant_for("brand", ident))["tenant_id"] == tid("acme")

        status, body = api(ctx, "POST", reg, {"tenant_id": tid("globex"), "kind": "brand", "local_id": ident})
        assert status == 409, "another tenant cannot claim an active id"
        assert tid("acme") not in str(body), "the response never names the current owner"
        auth.cache.invalidate()
        assert (await auth.tenant_for("brand", ident))["tenant_id"] == tid("acme"), "ownership did not move"

        assert api(ctx, "POST", reg, {"tenant_id": tid("dormant"), "kind": "brand", "local_id": f"{ident}-d"})[0] == 403, "one answer for a tenant that is not entitled"
        assert api(ctx, "POST", reg, {"tenant_id": tid("acme"), "kind": "Bad Kind", "local_id": ident})[0] == 422, "a value the registry cannot hold is a 422, never a 500"

        # retire (an operator action): the id is freed and the library stops reporting it
        psql(ctx, f"UPDATE stighive_platform.tenant_resources SET status='retired', retired_at=now() WHERE service='docs' AND kind='brand' AND local_id='{ident}'")
        auth.cache.invalidate()
        assert (await auth.tenant_for("brand", ident))["tenant_id"] is None, "a retired resource is absent from the snapshot"
        assert api(ctx, "POST", reg, {"tenant_id": tid("globex"), "kind": "brand", "local_id": ident})[0] == 201, "and the freed id can be claimed by another tenant"
        auth.cache.invalidate()
        assert (await auth.tenant_for("brand", ident))["tenant_id"] == tid("globex")
    finally:
        psql(ctx, "DELETE FROM stighive_platform.tenant_resources WHERE service='docs' AND local_id LIKE 'e2e-%'")
        await auth.close()


def test_other_services_rows_and_unentitled_tenants_rows_are_invisible_in_the_real_snapshot(ctx):
    snap = httpx.get(f"{ctx.state['platform_url']}/v1/authorize/snapshot?service=docs", headers={"X-API-Key": ctx.state["service_key"]}, timeout=10).json()
    everything = [r["local_id"] for t in snap["tenants"] for r in t["resources"]]
    assert "ops@client.example" not in everything, "the mail service's row is not in the docs snapshot"
    assert "brand-dormant" not in everything, "a tenant not entitled to docs is not in the snapshot, nor are its rows"
    assert "brand-old" not in everything, "a retired row is absent"
    assert all(isinstance(t.get("resources"), list) for t in snap["tenants"]), "every entitled tenant carries the list (empty when none)"
