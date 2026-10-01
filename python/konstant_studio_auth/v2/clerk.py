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


class Denied(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


class ClerkVerifier:
    def __init__(self, cfg, http, now, logger, monotonic=None):
        self.cfg = cfg  # SimpleNamespace(issuer, jwks_url, authorized_parties, audience)
        self.http = http
        self.now = now  # wall clock: token validity
        self.monotonic = monotonic or now  # cache ages
        self.logger = logger
        self.keys = None
        self.inflight = None
        self.next_attempt_at = -math.inf
        self.fetched_at = 0
        self.forced_at = -math.inf

    @property
    def configured(self):
        return bool(self.cfg.issuer and self.cfg.jwks_url)

    async def _jwks(self, force=False):
        t = self.monotonic()
        if self.keys is not None and not force and t - self.fetched_at < CACHE_TTL_MS:
            return self.keys
        if force and self.keys is not None and t - self.forced_at < FORCE_MIN_INTERVAL_MS:
            return self.keys
        # After a failure, keep serving the last good keys (or fail fast with none) instead of
        # retrying on every request.
        if t < self.next_attempt_at:
            if self.keys is not None:
                return self.keys
            raise Denied("clerk_jwks_unavailable")
        if force:
            self.forced_at = t
        # One fetch at a time: concurrent requests share it.
        if self.inflight is None:
            task = asyncio.ensure_future(self._fetch_keys())
            self.inflight = task

            def _clear(tk):
                if self.inflight is tk:
                    self.inflight = None
                if not tk.cancelled():
                    tk.exception()

            task.add_done_callback(_clear)
        return await asyncio.shield(self.inflight)

    async def _fetch_keys(self):
        try:
            resp = await self.http.get(self.cfg.jwks_url, timeout=5, follow_redirects=False)
            if not resp.is_success:
                raise RuntimeError(f"HTTP {resp.status_code}")
            self.keys = resp.json().get("keys") or []
            self.fetched_at = self.monotonic()
            self.next_attempt_at = -math.inf
        except Exception as err:  # noqa: BLE001
            self.logger.warning(f"clerk JWKS refresh failed: {err}")
            self.next_attempt_at = self.monotonic() + RETRY_AFTER_FAILURE_MS
            if self.keys is None:
                raise Denied("clerk_jwks_unavailable") from None
        return self.keys

    async def verify(self, token):
        if not self.configured:
            raise Denied("clerk_not_configured")
        try:
            header = jwt.get_unverified_header(token)
        except Exception:  # noqa: BLE001 - malformed anything is token_invalid
            raise Denied("token_invalid") from None
        if header.get("alg") != "RS256":
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
