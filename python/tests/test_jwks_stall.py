"""CR-L2: a stuck Clerk key fetch must never hang a request (Python v2). REAL local servers that stall in each way
the CR lists, a REAL httpx client, small deadlines. 127.0.0.1 only; keys and tokens are generated per run."""

import asyncio
import json
import time

import httpx
import pytest
from fastapi import Depends, FastAPI

from konstant_studio_auth.v2 import create_auth
from konstant_studio_auth.v2.clerk import ClerkVerifier, Denied
from konstant_studio_auth.v2.config import resolve_clerk
from world import ClerkKeys, SilentLogger, mint_clerk_token

ISSUER = "https://clerk.example.test"
AZP = "https://app.example.test"
DEADLINE, BUDGET = 400, 250  # ms
MARGIN = 0.35  # s of scheduling slack
MODES = ["accept-silent", "headers-then-stall", "body-trickle", "tls-stall", "keepalive-half-dead", "client-ignores-cancel"]


class Servers:
    def __init__(self):
        self.servers, self.writers = [], set()

    async def stall(self, mode):
        state = {"n": 0}

        async def handle(r, w):
            self.writers.add(w)
            try:
                if mode in ("accept-silent", "tls-stall"):
                    await asyncio.sleep(3600)
                while True:
                    await r.readuntil(b"\r\n\r\n")
                    state["n"] += 1
                    if mode == "keepalive-half-dead" and state["n"] > 1:
                        await asyncio.sleep(3600)  # the reused socket never answers again
                    if mode == "keepalive-half-dead":
                        body = b'{"keys":[]}'
                        w.write(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: %d\r\n\r\n" % len(body) + body)
                        await w.drain()
                        continue
                    w.write(b'HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100000\r\n\r\n{"keys":[')
                    await w.drain()
                    while True:  # headers-then-stall: nothing more; body-trickle: a byte every 50 ms
                        await asyncio.sleep(0.05 if mode == "body-trickle" else 3600)
                        if mode == "body-trickle":
                            w.write(b" ")
                            await w.drain()
            except (asyncio.CancelledError, ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                w.close()

        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.servers.append(srv)
        return f"{'https' if mode == 'tls-stall' else 'http'}://127.0.0.1:{srv.sockets[0].getsockname()[1]}/jwks.json"

    async def healthy(self, body):
        async def handle(r, w):
            try:
                await r.readuntil(b"\r\n\r\n")
                w.write(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: %d\r\n\r\n" % len(body) + body)
                await w.drain()
            finally:
                w.close()

        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.servers.append(srv)
        return f"http://127.0.0.1:{srv.sockets[0].getsockname()[1]}/jwks.json"

    async def close(self):
        for w in list(self.writers):
            w.close()
        for s in self.servers:
            s.close()


class Rig:
    def __init__(self, mode, keys, urls, http, logger=None, timeouts=None):
        self.mode, self.keys, self.urls, self.http = mode, keys, urls, http
        self.skew = 0
        self.release = False
        cfg = resolve_clerk({"issuer": ISSUER, "jwks_url": urls["stall"], "authorized_parties": [AZP]}, {})
        self.cfg = cfg
        self.mono = lambda: time.monotonic() * 1000 + self.skew
        http_for_verifier = http
        if mode == "client-ignores-cancel":
            outer = self

            class Deaf:  # a client that swallows cancellation: the deadline must still settle the caller
                async def get(self, *a, **k):
                    while not outer.release:
                        try:
                            await asyncio.sleep(0.05)
                        except asyncio.CancelledError:
                            continue
            self.release = False
            http_for_verifier = Deaf()
        self.v = ClerkVerifier(cfg, http_for_verifier, lambda: int(time.time() * 1000), logger or SilentLogger(), monotonic=self.mono,
                               timeouts=timeouts or {"refresh_deadline_ms": DEADLINE, "wait_budget_ms": BUDGET})

    def token(self):
        return mint_clerk_token(self.keys, "user_x", int(time.time() * 1000), ISSUER, AZP)

    def fix(self):
        self.release = True
        self.v.http = self.http
        self.v.cfg.jwks_url = self.urls["healthy"]


@pytest.fixture
async def env():
    pass


def run(coro):
    return asyncio.run(coro)


async def make(mode, **kw):
    keys = ClerkKeys()
    servers = Servers()
    stall = await servers.stall(mode if mode != "client-ignores-cancel" else "accept-silent")
    healthy = await servers.healthy(json.dumps({"keys": [keys.trusted.jwk]}).encode())
    http = httpx.AsyncClient(follow_redirects=False)
    if mode == "keepalive-half-dead":
        await http.get(stall, timeout=5)  # the pooled socket is now 'half dead'
    return Rig(mode, keys, {"stall": stall, "healthy": healthy}, http, **kw), servers, http


async def timed(coro):
    t0 = time.monotonic()
    try:
        return await coro, None, time.monotonic() - t0
    except Exception as err:  # noqa: BLE001
        return None, err, time.monotonic() - t0


@pytest.mark.parametrize("mode", MODES)
def test_stall_mode_recovers(mode):
    async def go():
        r, servers, http = await make(mode)
        try:
            _, err, took = await timed(r.v.verify(r.token()))
            assert isinstance(err, Denied) and err.reason == "clerk_jwks_unavailable", f"{mode}: {err!r}"
            assert took < BUDGET / 1000 + MARGIN, f"{mode}: waited {took:.2f}s"
            await asyncio.sleep(DEADLINE / 1000 + MARGIN)
            assert r.v.inflight is None, f"{mode}: slot still occupied"
            assert r.v.status()["failures"] >= 1 and r.v.status()["last_failure"]
            before = r.v.stats["refreshes"]
            _, err, took = await timed(r.v.verify(r.token()))
            assert err and err.reason == "clerk_jwks_unavailable" and took < 0.1 and r.v.stats["refreshes"] == before, f"{mode}: back-off not applied"
            r.fix()
            r.skew += 11_000
            claims, err, _ = await timed(r.v.verify(r.token()))
            assert claims and claims["sub"] == "user_x", f"{mode}: did not recover ({err!r})"
        finally:
            r.release = True
            await http.aclose()
            await servers.close()

    run(go())


def test_many_concurrent_requests_during_a_stall_answer_within_the_budget_with_one_refresh():
    async def go():
        r, servers, http = await make("accept-silent")
        try:
            tok = r.token()
            results = await asyncio.gather(*[timed(r.v.verify(tok)) for _ in range(80)])
            for _, err, took in results:
                assert err and err.reason == "clerk_jwks_unavailable"
                assert took < BUDGET / 1000 + MARGIN, f"waited {took:.2f}s"
            assert r.v.stats["refreshes"] == 1
        finally:
            r.release = True
            await http.aclose()
            await servers.close()

    run(go())


def test_a_stall_while_cached_keys_are_valid_does_not_interrupt_service_and_fails_closed_past_hard_expiry():
    async def go():
        r, servers, http = await make("accept-silent", timeouts={"refresh_deadline_ms": DEADLINE, "wait_budget_ms": BUDGET, "hard_expiry_ms": 30 * 60 * 1000})
        try:
            r.fix()
            assert (await r.v.verify(r.token()))["sub"]
            r.v.cfg.jwks_url = r.urls["stall"]
            r.skew += 6 * 60 * 1000
            claims, err, took = await timed(r.v.verify(r.token()))
            assert claims and took < 0.1, f"cached keys must serve at once ({took:.2f}s, {err!r})"
            await asyncio.sleep(DEADLINE / 1000 + MARGIN)
            assert r.v.inflight is None
            r.skew += 11_000
            assert (await r.v.verify(r.token()))["sub"]
            r.skew += 31 * 60 * 1000
            _, err, _ = await timed(r.v.verify(r.token()))
            assert err and err.reason == "clerk_jwks_unavailable", "fails closed past the hard expiry"
        finally:
            r.release = True
            await http.aclose()
            await servers.close()

    run(go())


def test_status_reports_degraded_for_a_stuck_refresh_or_old_keys():
    async def go():
        r, servers, http = await make("accept-silent")
        try:
            assert r.v.status()["degraded"] is False
            r.fix()
            await r.v.verify(r.token())
            assert r.v.status()["degraded"] is False
            r.skew += 11 * 60 * 1000
            s = r.v.status()
            assert s["degraded"] and s["reason"] == "last_success_too_old"
            assert "BEGIN" not in json.dumps(s)
            r2, servers2, http2 = await make("client-ignores-cancel")
            try:
                r2.v._refresh()
                r2.v._inflight_started -= 1000  # this refresh has been running longer than its 400 ms deadline
                await asyncio.sleep(0.01)
                assert r2.v.status()["reason"] == "refresh_older_than_deadline"
            finally:
                r2.release = True
                await asyncio.sleep(0.1)
                await http2.aclose()
                await servers2.close()
        finally:
            r.release = True
            await http.aclose()
            await servers.close()

    run(go())


def test_a_slot_older_than_its_deadline_is_replaced_and_counted():
    async def go():
        r, servers, http = await make("accept-silent")
        try:
            r.v.inflight = asyncio.ensure_future(asyncio.sleep(3600))
            r.v._inflight_started = r.v.monotonic() - 60_000
            r.fix()
            claims, err, _ = await timed(r.v.verify(r.token()))
            assert claims, repr(err)
            assert r.v.stats["wedge_recoveries"] == 1
        finally:
            r.release = True
            await http.aclose()
            await servers.close()

    run(go())


def test_failures_are_logged_once_a_minute_with_a_counter_and_no_secret():
    lines = []

    class L(SilentLogger):
        def warning(self, m, *a, **k):
            lines.append(m)

    async def go():
        r, servers, http = await make("accept-silent", logger=L())
        try:
            for _ in range(4):
                await timed(r.v.verify(r.token()))
                await asyncio.sleep(DEADLINE / 1000 + 0.05)
                r.skew += 11_000
            mine = [l for l in lines if "refresh failed" in l]
            assert len(mine) == 1 and "failures=" in mine[0], mine
            assert not any("eyJ" in l or "BEGIN" in l for l in lines)
        finally:
            r.release = True
            await http.aclose()
            await servers.close()

    run(go())


def test_httpx_per_read_timeout_alone_does_not_end_a_trickling_body():
    """The Python root cause, with evidence: httpx's timeout is per phase and per read, so a server that sends one
    byte at a time is never 'late' and `await client.get(url, timeout=1)` never returns."""
    async def go():
        servers = Servers()
        url = await servers.stall("body-trickle")
        async with httpx.AsyncClient() as c:
            try:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(c.get(url, timeout=0.5, follow_redirects=False), 2.5)
            finally:
                await servers.close()

    run(go())


def test_log_mode_never_holds_a_request_and_enforce_is_a_bounded_503():
    async def hang_transport_handler(request):
        await asyncio.sleep(3600)

    class Hang(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            await asyncio.sleep(3600)

    async def go():
        keys = ClerkKeys()
        auth = create_auth(
            service="docs", platform_url="http://platform.test", platform_key="stgs_fake", poll_interval_seconds=0,
            clerk={"issuer": ISSUER, "jwks_url": "http://jwks.test/j", "authorized_parties": [AZP]},
            transport=Hang(), logger=SilentLogger(), shadow_wait_ms=200, decision_deadline_ms=600,
            jwks_timeouts={"refresh_deadline_ms": DEADLINE, "wait_budget_ms": BUDGET},
        )
        app = FastAPI()

        @app.get("/x")
        async def x(d=Depends(auth.fastapi.shadow_permission("docs:read", tenant=lambda r: "t"))):
            return {"reached": True, "decided": bool(d is not None and d.allow)}

        token = mint_clerk_token(keys, "user_x", int(time.time() * 1000), ISSUER, AZP)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://app") as c:
            t0 = time.monotonic()
            resp = await c.get("/x", headers={"authorization": f"Bearer {token}"})
            took = time.monotonic() - t0
        assert resp.status_code == 200 and resp.json() == {"reached": True, "decided": False}
        assert took < 0.2 + MARGIN, f"log mode held the request {took:.2f}s"
        t0 = time.monotonic()
        d = await auth.authorize(headers={"authorization": f"Bearer {token}"}, permission="docs:read", resource={"tenant_hint": "t"})
        assert d.allow is False and d.status == 503
        assert time.monotonic() - t0 < 0.6 + MARGIN
        assert isinstance(auth.clerk_status()["degraded"], bool)
        await auth.close()

    run(go())
