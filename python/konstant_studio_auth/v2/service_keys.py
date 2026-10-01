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
  5. Bounded cache: a valid resolution is kept for at most 60 s, an invalid one for at
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
from .platform_client import PlatformUnavailable

SLUG = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_ROUTE_ENTRY = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|\*) /[A-Za-z0-9_\-./*:]*$")


class _Entry:
    __slots__ = ("until", "value")

    def __init__(self, until, value):
        self.until = until
        self.value = value


class ServiceKeyResolver:
    def __init__(self, client, accepted, now, logger, valid_ttl_seconds=60, invalid_ttl_seconds=10, max_entries=1000):
        self.client = client
        self.accepted = list(accepted)
        self.now = now
        self.logger = logger
        self.valid_ttl_ms = valid_ttl_seconds * 1000
        self.invalid_ttl_ms = invalid_ttl_seconds * 1000
        self.max_entries = max_entries
        self.cache = {}  # sha256(credential) -> _Entry; insertion order = age
        self.inflight = {}
        self.warned_empty = False

    @staticmethod
    def validate_accepted(accepted):
        for s in accepted:
            if not isinstance(s, str) or not SLUG.match(s):
                raise ConfigError(f'accepted_caller_services: "{s}" is not a catalog service slug')

    async def resolve(self, raw):
        """-> {id, service, key_id} | raises Denied('key_not_found' | 'platform_unavailable')"""
        if not self.accepted:
            if not self.warned_empty:
                self.warned_empty = True  # once: an app that never expects service keys is not spammed at startup
                self.logger.warning("an inbound service key was presented but no accepted_caller_services is configured: refused")
            raise Denied("key_not_found")
        h = hashlib.sha256(raw.encode()).hexdigest()
        hit = self.cache.get(h)
        if hit and hit.until > self.now():
            if hit.value is None:
                raise Denied("key_not_found")
            return hit.value
        task = self.inflight.get(h)
        if task is None:
            task = asyncio.ensure_future(self._ask(raw, h))
            self.inflight[h] = task

            def _done(t, h=h):
                if self.inflight.get(h) is t:
                    del self.inflight[h]
                if not t.cancelled():
                    t.exception()

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
            except PlatformUnavailable:
                raise Denied("platform_unavailable") from None  # not cached: not a verdict
            p = res.get("principal") if isinstance(res, dict) else None
            # Check the answer ourselves too: it must be a service principal bound to exactly the service we asked about.
            if isinstance(p, dict) and res.get("valid") is True and p.get("kind") == "service" and p.get("service") == slug:
                found = {"id": p.get("id"), "service": p["service"], "key_id": res.get("key_id")}
                sk = res.get("service_key")
                exp = parse_ms(sk.get("expires_at")) if isinstance(sk, dict) and sk.get("expires_at") else None
                expires_at_ms = exp
                break
        ttl = self.valid_ttl_ms if found else self.invalid_ttl_ms
        until = self.now() + ttl
        if found and expires_at_ms is not None:
            until = min(until, expires_at_ms)
        self._remember(h, _Entry(until, found))
        return found

    def _remember(self, h, entry):
        if len(self.cache) >= self.max_entries:
            for k in [k for k, e in self.cache.items() if e.until <= self.now()]:
                del self.cache[k]
            while len(self.cache) >= self.max_entries:
                del self.cache[next(iter(self.cache))]  # oldest first
        self.cache.pop(h, None)
        self.cache[h] = entry


def route_allowed(routes, method, path):
    """"METHOD /path/glob" entries; METHOD may be `*`, glob characters are `*` only.
    Same matching as the platform's allow-list, but THIS is the app's own policy for
    the routes of this app, never the platform's `allowed_routes`."""
    m = str(method).upper()
    for entry in routes or []:
        parts = str(entry).split(" ")
        em, glob = parts[0], " ".join(parts[1:])
        if em != "*" and em != m:
            continue
        pattern = ".*".join(re.escape(piece) for piece in glob.split("*"))
        if re.fullmatch(pattern, path):
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
            if not isinstance(r, str) or not _ROUTE_ENTRY.match(r):
                raise ConfigError(f'bad route entry "{r}" for "{service}"')
            if r == "* /*":
                raise ConfigError(f'"* /*" for "{service}" would allow everything: list the routes this caller needs')
