"""Offline verification of a Clerk session token. Mirrors the platform's
app/clerk_jwt.py so a token means the same thing everywhere: RS256 only,
issuer pinned, exp/iat/sub required, `azp` MANDATORY and must be one of the
authorized frontend origins, and an `aud` (normally absent on Clerk session
tokens) must match a configured audience. The JWKS is cached for 5 minutes;
if a refresh fails the cached copy is used instead of turning a Clerk blip
into an outage, and a forced refresh for an unknown `kid` is throttled so a
caller cycling kids cannot turn this into an outbound-request cannon.
"""

import asyncio
import math

from jose import jwt
from jose.exceptions import JWTError

CACHE_TTL_MS = 5 * 60 * 1000
FORCE_MIN_INTERVAL_MS = 60 * 1000
RETRY_AFTER_FAILURE_MS = 10 * 1000  # a JWKS outage must not become a fetch per request
CLOCK_TOLERANCE_S = 5
# CR-L2: nothing about the key fetch may be able to hold a request forever. httpx's `timeout=` is PER PHASE and
# per read (a server trickling one byte at a time never trips it), so the deadline below is an asyncio one around
# the WHOLE refresh (connect, headers, body, JSON parse).
REFRESH_DEADLINE_MS = 5 * 1000
WAIT_BUDGET_MS = 3 * 1000  # how long ONE request waits for a refresh before it answers 503
HARD_EXPIRY_MS = 60 * 60 * 1000  # last good keys are never served past this age
LOG_EVERY_MS = 60 * 1000


async def within(awaitable, seconds):
    """Result of `awaitable`, or asyncio.TimeoutError after `seconds`. Unlike asyncio.wait_for it never waits for the
    cancelled work to finish unwinding: a client that swallows cancellation (or is stuck in a thread) cannot hold the
    caller. The work is cancelled and abandoned (its late outcome is consumed so nothing is logged as unhandled)."""
    task = asyncio.ensure_future(awaitable)
    try:
        done, _ = await asyncio.wait({task}, timeout=seconds)
    except asyncio.CancelledError:
        task.cancel()
        task.add_done_callback(lambda t: t.cancelled() or t.exception())
        raise
    if task in done:
        return task.result()
    task.cancel()
    task.add_done_callback(lambda t: t.cancelled() or t.exception())
    raise asyncio.TimeoutError()


class Denied(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


class ClerkVerifier:
    def __init__(self, cfg, http, now, logger, monotonic=None, timeouts=None):
        self.cfg = cfg  # SimpleNamespace(issuer, jwks_url, authorized_parties, audience)
        self.http = http
        self.now = now  # wall clock: token validity
        self.monotonic = monotonic or now  # cache ages
        self.logger = logger
        timeouts = timeouts or {}
        self.refresh_deadline_ms = timeouts.get("refresh_deadline_ms", REFRESH_DEADLINE_MS)
        self.wait_budget_ms = timeouts.get("wait_budget_ms", WAIT_BUDGET_MS)
        self.hard_expiry_ms = timeouts.get("hard_expiry_ms", HARD_EXPIRY_MS)
        self.keys = None
        self.inflight = None  # asyncio.Task
        self._inflight_started = 0
        self.next_attempt_at = -math.inf
        self.fetched_at = 0
        self.forced_at = -math.inf
        self.stats = {"last_success_at": None, "last_failure_at": None, "last_failure": None, "failures": 0,
                      "deadline_hits": 0, "wedge_recoveries": 0, "refreshes": 0}
        self._logged = {}

    @property
    def configured(self):
        return bool(self.cfg.issuer and self.cfg.jwks_url)

    def status(self):
        """Health for an app's /health: times and counters only, never a key or a token. `degraded` when a refresh
        has been running longer than its deadline, the last success is older than twice the refresh interval, or
        the keys never loaded and refreshes are failing."""
        t = self.monotonic()
        inflight_age = max(0, t - self._inflight_started) if self.inflight is not None else None
        success_age = None if self.stats["last_success_at"] is None else max(0, t - self.fetched_at)
        reason = None
        if not self.configured:
            reason = None
        elif inflight_age is not None and inflight_age > self.refresh_deadline_ms:
            reason = "refresh_older_than_deadline"
        elif success_age is not None and success_age > 2 * CACHE_TTL_MS:
            reason = "last_success_too_old"
        elif success_age is None and self.stats["failures"] > 0:
            reason = "keys_never_loaded"
        return {
            "configured": self.configured, "degraded": reason is not None, "reason": reason,
            "last_success_at": self.stats["last_success_at"], "last_failure_at": self.stats["last_failure_at"],
            "last_failure": self.stats["last_failure"], "last_success_age_ms": success_age, "inflight_age_ms": inflight_age,
            "keys_cached": self.keys is not None, "failures": self.stats["failures"],
            "deadline_hits": self.stats["deadline_hits"], "wedge_recoveries": self.stats["wedge_recoveries"],
            "refreshes": self.stats["refreshes"],
        }

    def _log(self, kind, message):
        """One line per kind per minute, with the running counters, so an outage is loud but cannot flood a log."""
        t = self.monotonic()
        prev = self._logged.get(kind)
        if prev and t - prev["at"] < LOG_EVERY_MS:
            prev["suppressed"] += 1
            return
        self._logged[kind] = {"at": t, "suppressed": 0}
        extra = f" (+{prev['suppressed']} more in the last minute)" if prev and prev["suppressed"] else ""
        self.logger.warning(f"clerk JWKS {message}{extra} [failures={self.stats['failures']} deadline_hits={self.stats['deadline_hits']}]")

    def _usable(self, t):
        return self.keys if self.keys is not None and t - self.fetched_at < self.hard_expiry_ms else None

    def _refresh(self):
        """Start (or share) the single refresh. The task ALWAYS ends within the deadline (asyncio cancels the request,
        closing its socket), so the slot cannot stay occupied; a slot found older than its deadline anyway is replaced."""
        t = self.monotonic()
        if self.inflight is not None and t - self._inflight_started > self.refresh_deadline_ms + 1000:
            self.stats["wedge_recoveries"] += 1
            self._log("wedge", "refresh slot was older than its deadline; replaced it")
            self.inflight.cancel()
            self.inflight = None
        if self.inflight is None:
            task = asyncio.ensure_future(self._fetch_keys())
            self.inflight = task
            self._inflight_started = t
            self.stats["refreshes"] += 1

            def _clear(tk):
                if self.inflight is tk:
                    self.inflight = None
                if not tk.cancelled():
                    tk.exception()  # consume: a refresh nobody waits for is not an unhandled error

            task.add_done_callback(_clear)
        return self.inflight

    async def _jwks(self, force=False):
        t = self.monotonic()
        usable = self._usable(t)
        if usable is not None and not force and t - self.fetched_at < CACHE_TTL_MS:
            return usable
        if force and usable is not None and t - self.forced_at < FORCE_MIN_INTERVAL_MS:
            return usable
        # After a failure, keep serving the last good keys (or fail fast with none) instead of retrying on every request.
        if t < self.next_attempt_at and self.inflight is None:
            if usable is not None:
                return usable
            raise Denied("clerk_jwks_unavailable")
        if force:
            self.forced_at = t
        task = self._refresh()
        # Good keys that are merely past their refresh time keep serving while the refresh runs in the background.
        if usable is not None and not force:
            return usable
        # Otherwise this request waits, but only for its own short budget (shield: one waiter giving up must not
        # cancel the shared refresh).
        try:
            return await asyncio.wait_for(asyncio.shield(task), self.wait_budget_ms / 1000)
        except asyncio.TimeoutError:
            raise Denied("clerk_jwks_unavailable") from None

    async def _fetch_once(self):
        resp = await self.http.get(self.cfg.jwks_url, timeout=5, follow_redirects=False)
        if not resp.is_success:
            raise RuntimeError(f"HTTP {resp.status_code}")
        body = resp.json()  # inside the deadline
        keys = body.get("keys") if isinstance(body, dict) else None
        return keys if isinstance(keys, list) else []

    async def _fetch_keys(self):
        try:
            try:
                keys = await within(self._fetch_once(), self.refresh_deadline_ms / 1000)
            except asyncio.TimeoutError:
                self.stats["deadline_hits"] += 1
                raise RuntimeError("refresh deadline exceeded") from None
            self.keys = keys
            self.fetched_at = self.monotonic()
            self.stats["last_success_at"] = self.now()
            self.next_attempt_at = -math.inf
            return keys
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            self.stats["failures"] += 1
            self.stats["last_failure_at"] = self.now()
            self.stats["last_failure"] = (str(err) or type(err).__name__)[:80]
            self._log("deadline" if "deadline" in str(err) else "refresh", f"refresh failed: {self.stats['last_failure']}")
            self.next_attempt_at = self.monotonic() + RETRY_AFTER_FAILURE_MS
            usable = self._usable(self.monotonic())
            if usable is None:
                raise Denied("clerk_jwks_unavailable") from None
            return usable

    async def verify(self, token):
        if not self.configured:
            raise Denied("clerk_not_configured")
        try:
            header = jwt.get_unverified_header(token)
        except Exception:  # noqa: BLE001 - malformed anything is token_invalid
            raise Denied("token_invalid") from None
        if header.get("alg") != "RS256":
            raise Denied("token_invalid")
        # The issuer is PINNED by configuration and compared EXACTLY (no normalisation: a trailing slash, another
        # scheme, case, a port, a sub- or parent-domain, userinfo or surrounding whitespace is a different
        # issuer). The token's own `iss` is only ever compared with it, never used to decide where to
        # fetch keys, and a mismatch is refused here, BEFORE any network call: a forged token costs no request,
        # not even to the legitimate key server. (Signature and issuer are verified again below.)
        try:
            claimed = jwt.get_unverified_claims(token).get("iss")
        except Exception:  # noqa: BLE001
            raise Denied("token_invalid") from None
        if not isinstance(claimed, str) or claimed != self.cfg.issuer:
            raise Denied("token_invalid")
        kid = header.get("kid")

        def find(keys):
            return next((k for k in keys if k.get("kid") == kid), None)

        jwk = find(await self._jwks())
        if jwk is None:
            jwk = find(await self._jwks(True))  # key rotation: one throttled refresh
        if jwk is None:
            raise Denied("token_invalid")

        # jose has no clock injection, so it only checks signature, algorithm and
        # issuer here; exp/iat/nbf are checked below against the library's clock,
        # so a test clock and production agree.
        try:
            claims = jwt.decode(
                token,
                jwk,
                algorithms=["RS256"],
                issuer=self.cfg.issuer,
                options={
                    "verify_exp": False, "verify_iat": False, "verify_nbf": False,
                    "verify_aud": False, "verify_sub": False, "verify_at_hash": False,
                    "verify_iss": True,
                },
            )
        except (JWTError, Exception):  # noqa: BLE001 - bad signature, bad key, bad issuer
            raise Denied("token_invalid") from None

        # Required claims, as requiredClaims in clerk.js; a non-numeric exp is invalid, not "never expires".
        if "exp" not in claims or "iat" not in claims or "sub" not in claims:
            raise Denied("token_invalid")
        if not _is_num(claims["exp"]) or not _is_num(claims["iat"]):
            raise Denied("token_invalid")
        now_s = self.now() / 1000
        # Matches the platform (PyJWT raises ImmatureSignatureError): a token issued in the
        # future, beyond the leeway, is not valid yet.
        if claims["iat"] > int(now_s) + CLOCK_TOLERANCE_S:
            raise Denied("token_invalid")
        if "nbf" in claims and (not _is_num(claims["nbf"]) or claims["nbf"] > now_s + CLOCK_TOLERANCE_S):
            raise Denied("token_invalid")
        if claims["exp"] <= now_s - CLOCK_TOLERANCE_S:
            raise Denied("token_expired")

        # azp is mandatory: a token without one, or from an unlisted origin, is not ours.
        azp = claims.get("azp")
        if not isinstance(azp, str) or azp not in self.cfg.authorized_parties:
            raise Denied("token_invalid")
        if "aud" in claims:
            aud = claims["aud"]
            if isinstance(aud, str):
                lst = [aud]
            elif isinstance(aud, list) and all(isinstance(a, str) for a in aud):
                lst = aud
            else:
                lst = None
            if not lst or not self.cfg.audience or not any(a in self.cfg.audience for a in lst):
                raise Denied("token_invalid")
        return claims
