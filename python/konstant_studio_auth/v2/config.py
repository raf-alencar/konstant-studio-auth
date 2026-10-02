"""Everything the library needs comes from the options passed to create_auth()
or from environment variables; nothing is hard-coded, and no secret has a
default. The Clerk issuer and JWKS URL are public values but still come
from the environment so each deployment states which Clerk instance it trusts.
"""

import os
import re
import time
from types import SimpleNamespace


class ConfigError(Exception):
    pass


def _csv(value):
    return [s.strip() for s in (value or "").split(",") if s.strip()]


def _int(value, fallback):
    # parseInt semantics (as in config.js): leading integer, else the fallback.
    m = re.match(r"\s*([+-]?\d+)", value or "")
    return int(m.group(1)) if m else fallback


def _first(*values):
    # `??` in the Node code: only None falls through, an empty string does not.
    for v in values:
        if v is not None:
            return v
    return None


_KNOWN_OPTIONS = {
    "service", "platform_url", "platform_key", "clerk", "snapshot", "poll_interval_seconds", "request_timeout_ms",
    "step_up_max_age_minutes", "accepted_caller_services", "service_key_cache", "upgrade_url", "tenant_resolver",
    "on_event", "now", "monotonic", "logger",
}


def _positive(name, value, integer=False, allow_zero=False):
    """Numeric options are validated at startup: a zero or negative limit is a loop or an always-expired
    cache waiting to happen. A bool is not a number (True would read as 1)."""
    ok = (
        isinstance(value, (int, float)) and not isinstance(value, bool) and value == value and abs(value) != float("inf")
        and (value >= 0 if allow_zero else value > 0) and (not integer or float(value).is_integer())
    )
    if not ok:
        raise ConfigError(f"{name} must be a {'whole ' if integer else ''}number {'>= 0' if allow_zero else '> 0'} (got {value!r})")
    return value


def _string_list(name, value):
    """A string where a list belongs is a silent hole (`"abc" in "abcdef"` is a substring test, and
    list("abc") splits it into characters): refuse anything but a list of non-empty strings."""
    if not isinstance(value, (list, tuple)) or any(not isinstance(v, str) or not v.strip() for v in value):
        raise ConfigError(f"{name} must be a list of non-empty strings (got {value!r})")
    return list(value)


def resolve_config(opts=None, env=None):
    opts = opts or {}
    # Unlike JS, a misspelled or removed option (e.g. the old `service_keys`) is an error, not silently ignored.
    unknown = sorted(set(opts) - _KNOWN_OPTIONS)
    if unknown:
        raise ConfigError(f"unknown option(s): {', '.join(unknown)}")
    env = os.environ if env is None else env
    clerk_opts = opts.get("clerk") or {}
    snap_opts = opts.get("snapshot") or {}
    sk = opts.get("service_key_cache") or {}

    issuer = _first(clerk_opts.get("issuer"), env.get("CLERK_ISSUER"), "")
    jwks_url = _first(
        clerk_opts.get("jwks_url"),
        env.get("CLERK_JWKS_URL"),
        f"{issuer.rstrip('/')}/.well-known/jwks.json" if issuer else "",
    )
    authorized_parties = _string_list("clerk.authorized_parties", _first(clerk_opts.get("authorized_parties"), _csv(env.get("CLERK_AUTHORIZED_PARTIES"))))
    audience = _string_list("clerk.audience", _first(clerk_opts.get("audience"), _csv(env.get("CLERK_AUDIENCE"))))

    # Same rule as the platform: without a list of allowed `azp` origins, any
    # token this Clerk instance ever issued (for any of its apps) would be
    # accepted. Refuse to start rather than run that way.
    if (issuer or jwks_url) and len(authorized_parties) == 0:
        raise ConfigError(
            "CLERK_AUTHORIZED_PARTIES is required when Clerk verification is configured (the azp check is mandatory)"
        )

    platform_url = _first(opts.get("platform_url"), env.get("PLATFORM_API_URL"), "").rstrip("/")
    # Per-service key (stgs_...). INTERNAL_API_KEY is the deprecated shared key;
    # it is only a fallback until the platform's ACCEPT_SHARED_KEY=false cutover.
    platform_key = _first(opts.get("platform_key"), env.get("PLATFORM_SERVICE_KEY"), env.get("INTERNAL_API_KEY"), "")

    now = opts.get("now") or (lambda: int(time.time() * 1000))

    return SimpleNamespace(
        service=_first(opts.get("service"), env.get("AUTH_SERVICE"), ""),
        platform_url=platform_url,
        platform_key=platform_key,
        clerk=SimpleNamespace(
            issuer=issuer, jwks_url=jwks_url, authorized_parties=list(authorized_parties), audience=list(audience)
        ),
        snapshot=SimpleNamespace(
            ttl_seconds=_positive("snapshot.ttl_seconds", _first(snap_opts.get("ttl_seconds"), _int(env.get("SNAPSHOT_TTL_SECONDS"), 30))),
            stale_read_ttl_seconds=_positive(
                "snapshot.stale_read_ttl_seconds",
                _first(snap_opts.get("stale_read_ttl_seconds"), _int(env.get("SNAPSHOT_STALE_READ_TTL_SECONDS"), 300)),
                allow_zero=True,
            ),
        ),
        poll_interval_seconds=_positive(
            "poll_interval_seconds", _first(opts.get("poll_interval_seconds"), _int(env.get("AUTH_EVENT_POLL_SECONDS"), 5)), allow_zero=True
        ),
        request_timeout_ms=_positive("request_timeout_ms", _first(opts.get("request_timeout_ms"), 5000)),
        step_up_max_age_minutes=_positive(
            "step_up_max_age_minutes", _first(opts.get("step_up_max_age_minutes"), _int(env.get("AUTH_STEP_UP_MAX_AGE_MINUTES"), 10))
        ),
        # Catalog services whose inbound service keys (stgs_) this app accepts. Explicit configuration,
        # never "any": with none, every service key is refused (see service_keys.py).
        accepted_caller_services=_string_list(
            "accepted_caller_services", _first(opts.get("accepted_caller_services"), _csv(env.get("AUTH_ACCEPTED_CALLER_SERVICES")))
        ),
        service_key_cache=SimpleNamespace(
            valid_ttl_seconds=_positive("service_key_cache.valid_ttl_seconds", _first(sk.get("valid_ttl_seconds"), 60)),
            invalid_ttl_seconds=_positive("service_key_cache.invalid_ttl_seconds", _first(sk.get("invalid_ttl_seconds"), 10)),
            max_entries=_positive("service_key_cache.max_entries", _first(sk.get("max_entries"), 1000), integer=True),
            # Invalid answers live in their own small cache so garbage keys can never evict a valid one.
            negative_max_entries=_positive("service_key_cache.negative_max_entries", _first(sk.get("negative_max_entries"), 256), integer=True),
            # At most this many resolutions in flight at once; beyond it the answer is "could not decide" (503).
            max_inflight=_positive("service_key_cache.max_inflight", _first(sk.get("max_inflight"), 8), integer=True),
        ),
        upgrade_url=_first(
            opts.get("upgrade_url"), env.get("AUTH_UPGRADE_URL"), "https://www.konstant-studio.com/dashboard"
        ),
        tenant_resolver=opts.get("tenant_resolver"),
        on_event=opts.get("on_event"),
        # Wall clock: token expiry, entitlement windows, membership expiry. Monotonic clock: how old a
        # cache entry is (immune to the clock being stepped). A test that injects only `now` drives both.
        now=now,
        monotonic=opts.get("monotonic") or opts.get("now") or (lambda: time.monotonic() * 1000),
        logger=opts.get("logger"),
    )
