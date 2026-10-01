"""Inbound SERVICE keys (stgs_...): another internal service calling this app.

What the platform's C0b2 gives us (CoS contract note, final behaviour):
  POST /v1/principals/resolve {credential: 'stgs_...', expect_service: '<slug>'}
  -> valid:true with a principal {kind: 'service', service, tenant_id: None}, or valid:false.

Rules this module enforces:
  1. Configuration, not discovery. The app declares `accepted_caller_services`; each is
     passed as `expect_service` (mandatory for a bound caller; never "any"). With none
     declared, every service key is refused here, without asking the platform.
  2. Uniform failure. Unknown, revoked, expired, disabled, wrong-service and unaccepted
     keys all produce the same result (`key_not_found`); the finer reason is the
     platform's audit detail and is never branched on, returned or logged here.
  3. A match proves WHO is calling, not what they may do. The platform's
     `allowed_routes` are routes on the PLATFORM API and are deliberately not exposed
     on the Principal. What a caller service may do on THIS app's routes is the app's
     own policy (require_service_caller + route_allowed below).
  4. A service principal holds no tenant permissions (see auth.py).
  5. Unfloodable. A key that cannot be a platform key (wrong prefix, charset or length) is
     refused here without a platform call. Valid resolutions live in an LRU cache; invalid ones
     in a SEPARATE small cache, so garbage can never evict a good entry. At most `max_inflight`
     resolutions run at once (beyond that: could not decide, 503, never a verdict), and a
     platform 429 pauses resolution for its Retry-After instead of being turned into a verdict.
  6. Bounded cache: a valid resolution is kept for at most 60 s, an invalid one for at
     most 10 s, keyed by a hash of the credential (never the credential), with a cap on
     entries so garbage keys cannot grow memory. The platform audits every UNCACHED
     resolution; the cache is what keeps that volume sane. Cost: a revoked service key
     keeps working here for up to a minute (agent/guest/MCP keys are never cached).
"""

import asyncio
import hashlib
import re

from .clerk import Denied
from .config import ConfigError
from .config import ConfigError
from .decision import parse_ms
from .platform_client import PlatformThrottled, PlatformUnavailable

# Same shape the platform enforces on every service name that crosses its API.
SLUG = re.compile(r"[a-z][a-z0-9_-]{0,63}")  # used with fullmatch: `$` would accept a trailing newline
# What a platform service key looks like: the stgs_ prefix and url-safe characters, 20..200 long (the
# platform's own floor is 20). Anything else cannot be a key and is not worth a platform call.
# (fullmatch with an ASCII class: `$` would accept a trailing newline.)
KEY_SHAPE = re.compile(r"stgs_[A-Za-z0-9_-]+")
KEY_MIN = 20
KEY_MAX = 200
_ROUTE_ENTRY = re.compile(r"(GET|POST|PUT|PATCH|DELETE|\*) /[A-Za-z0-9_\-./*:]*")


class _Entry:
    __slots__ = ("until", "value")

    def __init__(self, until, value):
        self.until = until
        self.value = value


class ServiceKeyResolver:
    def __init__(self, client, accepted, now, logger, monotonic=None, valid_ttl_seconds=60, invalid_ttl_seconds=10,
                 max_entries=1000, negative_max_entries=256, max_inflight=8):
        """`now` is the wall clock (a key's expires_at); `monotonic` measures cache ages."""
        self.client = client
        self.accepted = list(accepted)
        self.now = now
        self.monotonic = monotonic or now
        self.logger = logger
        self.valid_ttl_ms = valid_ttl_seconds * 1000
        self.invalid_ttl_ms = invalid_ttl_seconds * 1000
        self.max_entries = max_entries
        self.negative_max_entries = negative_max_entries
        self.max_inflight = max_inflight
        self.cache = {}  # sha256(credential) -> _Entry(until, value)   (valid answers; LRU: insertion order = recency)
        self.negative = {}  # sha256(credential) -> _Entry(until, None)  (invalid answers; own small cache)
        self.inflight = {}
        self.throttled_until = 0
        self.warned_empty = False

    @staticmethod
    def validate_accepted(accepted):
        for s in accepted:
            if not isinstance(s, str) or not SLUG.fullmatch(s):
                raise ConfigError(f'accepted_caller_services: "{s}" is not a catalog service slug')

    async def resolve(self, raw):
        """-> {id, service, key_id} | raises Denied('key_not_found' | 'platform_unavailable')"""
        if not self.accepted:
            if not self.warned_empty:
                self.warned_empty = True  # once: an app that never expects service keys is not spammed at startup
                self.logger.warning("an inbound service key was presented but no accepted_caller_services is configured: refused")
            raise Denied("key_not_found")
        # It cannot be a platform key: the same uniform answer, without costing the platform anything.
        if len(raw) < KEY_MIN or len(raw) > KEY_MAX or not KEY_SHAPE.fullmatch(raw):
            raise Denied("key_not_found")

        h = hashlib.sha256(raw.encode()).hexdigest()
        t = self.monotonic()
        hit = self.cache.get(h)
        if hit and hit.until > t:
            del self.cache[h]  # refresh recency: least recently USED is what gets evicted
            self.cache[h] = hit
            return hit.value
        miss = self.negative.get(h)
        if miss and miss.until > t:
            raise Denied("key_not_found")

        if t < self.throttled_until:
            raise Denied("platform_unavailable")  # the platform asked us to slow down
        task = self.inflight.get(h)
        if task is None:
            if len(self.inflight) >= self.max_inflight:
                raise Denied("platform_unavailable")  # shed load, no verdict
            task = asyncio.ensure_future(self._ask(raw, h))
            self.inflight[h] = task

            def _done(tk, h=h):
                if self.inflight.get(h) is tk:
                    del self.inflight[h]
                if not tk.cancelled():
                    tk.exception()

            task.add_done_callback(_done)
        value = await asyncio.shield(task)
        if value is None:
            raise Denied("key_not_found")
        return value

    async def _ask(self, raw, h):
        found = None
        expires_at_ms = None
        for slug in self.accepted:
            try:
                res = await self.client.resolve({"credential": raw, "expect_service": slug})
            except PlatformUnavailable as err:
                if isinstance(err, PlatformThrottled):
                    self.throttled_until = self.monotonic() + err.retry_after_ms
                raise Denied("platform_unavailable") from None  # not cached: not a verdict
            p = res.get("principal") if isinstance(res, dict) else None
            # Check the answer ourselves too: it must be a service principal bound to exactly the service we asked about.
            # (valid is True, not truthy: a string like "false" must never read as a yes.)
            if isinstance(p, dict) and res.get("valid") is True and p.get("kind") == "service" and p.get("service") == slug:
                found = {"id": p.get("id"), "service": p["service"], "key_id": res.get("key_id")}
                sk = res.get("service_key")
                expires_at_ms = parse_ms(sk.get("expires_at")) if isinstance(sk, dict) and sk.get("expires_at") else None
                break
        t = self.monotonic()
        if found:
            # Never outlive the key: cap at its expiry (wall clock) converted to a monotonic deadline.
            room = self.valid_ttl_ms if expires_at_ms is None else min(self.valid_ttl_ms, max(0, expires_at_ms - self.now()))
            self._remember(self.cache, self.max_entries, h, _Entry(t + room, found))
        else:
            self._remember(self.negative, self.negative_max_entries, h, _Entry(t + self.invalid_ttl_ms, None))
        return found

    def _remember(self, store, maximum, h, entry):
        """Insert, evicting expired entries first and then the least recently used. `maximum` is validated
        >= 1 at startup, and the loop is bounded by the map's own size anyway."""
        if len(store) >= maximum:
            t = self.monotonic()
            for k in [k for k, e in store.items() if e.until <= t]:
                del store[k]
            for k in list(store):
                if len(store) < maximum:
                    break
                del store[k]
        store.pop(h, None)
        store[h] = entry


# "METHOD /path/glob" entries; METHOD may be `*`.
# THIS app's own policy for the routes of this app (never the platform's `allowed_routes`), and
# deliberately stricter than the platform's glob:
#   *   matches within ONE path segment (never a "/");   **  matches across segments.
# It is matched against the path exactly as it was SENT (undecoded, without the query string), and a
# path that could be read two ways is refused outright: any `%`, `..`, `//`, control character, or
# one that does not start with `/`. Decoded or normalised matching is how `/internal/..%2fadmin`
# gets past a policy written for `/internal/*`.
_GLOBS = {}
_UNSAFE = re.compile(r"[\x00-\x1f\x7f%]")


def _compile_glob(glob):
    pat = _GLOBS.get(glob)
    if pat is None:
        body = ".*".join("[^/]*".join(re.escape(lit) for lit in part.split("*")) for part in glob.split("**"))
        pat = _GLOBS[glob] = re.compile(body, re.DOTALL)
    return pat


def safe_path(path):
    if not isinstance(path, str):
        return None
    p = re.split(r"[?#]", path, maxsplit=1)[0]
    if p[:1] != "/" or _UNSAFE.search(p) or ".." in p or "//" in p:
        return None
    return p


def route_allowed(routes, method, path):
    p = safe_path(path)
    if p is None:
        return False
    m = str(method).upper()
    for entry in routes or []:
        parts = str(entry).split(" ")
        em = parts[0]
        if em != "*" and em != m:
            continue
        if _compile_glob(" ".join(parts[1:])).fullmatch(p):
            return True
    return False


def validate_policy(policy, accepted):
    """policy: {'<caller service slug>': ['METHOD /path/glob', ...]}. Deny by default: a caller
    service with no entry, or no matching route, gets nothing. Checked at wiring time so a policy
    for a service that is not accepted (which could never match) is a startup error, not a silent hole."""
    if not isinstance(policy, dict):
        raise ConfigError("service caller policy must be a dict keyed by caller service")
    for service, routes in policy.items():
        if service not in accepted:
            raise ConfigError(f'service caller policy names "{service}", which is not in accepted_caller_services')
        if not isinstance(routes, list):
            raise ConfigError(f'service caller policy for "{service}" must be a list of "METHOD /path" entries')
        for r in routes:
            if not isinstance(r, str) or not _ROUTE_ENTRY.fullmatch(r):
                raise ConfigError(f'bad route entry "{r}" for "{service}"')
            if ".." in r or "//" in r:
                raise ConfigError(f'route entry "{r}" for "{service}" contains ".." or "//"')
            if r in ("* /*", "* /**"):
                raise ConfigError(f'"* /*" for "{service}" would allow everything: list the routes this caller needs')
