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


def resolve_config(opts=None, env=None):
    opts = opts or {}
    env = os.environ if env is None else env
    clerk_opts = opts.get("clerk") or {}
    snap_opts = opts.get("snapshot") or {}

    issuer = _first(clerk_opts.get("issuer"), env.get("CLERK_ISSUER"), "")
    jwks_url = _first(
        clerk_opts.get("jwks_url"),
        env.get("CLERK_JWKS_URL"),
        f"{issuer.rstrip('/')}/.well-known/jwks.json" if issuer else "",
    )
    authorized_parties = _first(clerk_opts.get("authorized_parties"), _csv(env.get("CLERK_AUTHORIZED_PARTIES")))
    audience = _first(clerk_opts.get("audience"), _csv(env.get("CLERK_AUDIENCE")))

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

    return SimpleNamespace(
        service=_first(opts.get("service"), env.get("AUTH_SERVICE"), ""),
        platform_url=platform_url,
        platform_key=platform_key,
        clerk=SimpleNamespace(
            issuer=issuer, jwks_url=jwks_url, authorized_parties=list(authorized_parties), audience=list(audience)
        ),
        snapshot=SimpleNamespace(
            ttl_seconds=_first(snap_opts.get("ttl_seconds"), _int(env.get("SNAPSHOT_TTL_SECONDS"), 30)),
            stale_read_ttl_seconds=_first(
                snap_opts.get("stale_read_ttl_seconds"), _int(env.get("SNAPSHOT_STALE_READ_TTL_SECONDS"), 300)
            ),
        ),
        poll_interval_seconds=_first(opts.get("poll_interval_seconds"), _int(env.get("AUTH_EVENT_POLL_SECONDS"), 5)),
        request_timeout_ms=_first(opts.get("request_timeout_ms"), 5000),
        step_up_max_age_minutes=_first(
            opts.get("step_up_max_age_minutes"), _int(env.get("AUTH_STEP_UP_MAX_AGE_MINUTES"), 10)
        ),
        # 'stub' until the platform's C0b2 resolves stgs_ keys; then 'platform'.
        service_keys=_first(opts.get("service_keys"), env.get("AUTH_SERVICE_KEYS"), "stub"),
        upgrade_url=_first(
            opts.get("upgrade_url"), env.get("AUTH_UPGRADE_URL"), "https://www.konstant-studio.com/dashboard"
        ),
        tenant_resolver=opts.get("tenant_resolver"),
        on_event=opts.get("on_event"),
        now=opts.get("now") or (lambda: int(time.time() * 1000)),
        logger=opts.get("logger"),
    )
