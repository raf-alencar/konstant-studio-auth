"""create_auth(): one object per service that turns a request's credential into a
Principal and answers "may this principal do service:action here?".

Never raises for an auth failure: every outcome is a Result
  (allow, reason, status, principal, tenant_id, via_tenant, roles, sensitive, source, stale)
so adapters map it to a response without try/except, and a bug cannot turn
into an accidental allow. `source` says who decided: 'offline' (from the
cached snapshot), 'live' (POST /v1/authorize) or 'none' (stopped earlier).

What is decided where (CoS amendment, section 3):
  offline  human Clerk session, this service's own non-sensitive permission,
           tenant named by the caller;
  live     everything else: sensitive actions, agent/guest/MCP keys, other
           services' permissions, and any check with no tenant named (so the
           platform, not a guess here, answers tenant_required).
Platform unreachable: sensitive and key checks fail closed; read checks may
be served from a bounded-age cache; other routine checks fail closed.
"""

import asyncio
import copy
import inspect
import logging
import re
from datetime import datetime, timezone

import httpx

from .clerk import ClerkVerifier, Denied
from .config import resolve_config
from .credentials import extract
from .decision import decide_offline
from .platform_client import PlatformClient, PlatformUnavailable
from .reasons import status_for
from .service_keys import resolve_service_key
from .snapshot_cache import SnapshotCache

# The platform's tenant ids are UUIDs (see the tenant check in `authorize`).
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

ACTOR_KIND = {"human": "human", "agent": "agent", "guest": "guest", "service": "system"}

_PRINCIPAL_DEFAULTS = dict(
    kind=None, id=None, user_id=None, tenant=None, ancestry=[], roles=[], permissions=[],
    key_id=None, key_prefix=None, source=None, service=None, routes=None, claims=None,
)


class Principal:
    def __init__(self, **fields):
        for k, v in _PRINCIPAL_DEFAULTS.items():
            setattr(self, k, copy.copy(v))
        for k, v in fields.items():
            if k not in _PRINCIPAL_DEFAULTS:
                raise TypeError(f"unknown Principal field {k!r}")
            setattr(self, k, v)

    def evolve(self, **fields):
        return Principal(**{**self.__dict__, **fields})

    def actor(self):
        """Actor for usage events (event contract: "Usage ledger design"): ids only, never a key or token."""
        a = {"kind": ACTOR_KIND.get(self.kind, "system"), "id": self.id}
        if self.key_prefix:
            a["key_prefix"] = self.key_prefix
        return a

    def __repr__(self):
        return f"Principal(kind={self.kind!r}, id={self.id!r}, tenant={self.tenant!r})"


class Result:
    __slots__ = ("allow", "reason", "status", "principal", "tenant_id", "via_tenant", "roles", "sensitive", "source", "stale")

    def __init__(self, allow, reason, principal=None, tenant_id=None, via_tenant=None, roles=None,
                 sensitive=False, source="none", stale=False):
        self.allow = bool(allow)
        self.reason = reason
        self.status = status_for(reason, self.allow)
        self.principal = principal
        self.tenant_id = tenant_id
        self.via_tenant = via_tenant
        self.roles = roles if roles is not None else []
        self.sensitive = bool(sensitive)
        self.source = source or "none"
        self.stale = bool(stale)

    def evolve(self, **fields):
        base = {s: getattr(self, s) for s in self.__slots__ if s != "status"}
        base.update(fields)
        return Result(**base)

    def __repr__(self):
        return f"Result(allow={self.allow}, reason={self.reason!r}, status={self.status}, source={self.source!r})"


def parse_permission(permission):
    i = permission.find(":") if isinstance(permission, str) else -1
    if i <= 0 or i == len(permission) - 1:
        return None
    return {"service": permission[:i], "action": permission[i + 1:]}


def _iso(ms):
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(ms) % 1000:03d}Z"


async def _maybe_await(v):
    return await v if inspect.isawaitable(v) else v


class Auth:
    def __init__(self, **opts):
        http_client = opts.pop("http_client", None)
        transport = opts.pop("transport", None)
        env = opts.pop("env", None)
        cfg = resolve_config(opts, env)
        if cfg.logger is None:
            cfg.logger = logging.getLogger("konstant_studio_auth.v2")
        self.config = cfg
        self._owns_http = http_client is None
        # Redirects are never followed: a redirect could carry the service key to another host.
        self.http = http_client or httpx.AsyncClient(transport=transport, follow_redirects=False)
        self.client = PlatformClient(cfg.platform_url, cfg.platform_key, self.http, cfg.request_timeout_ms, cfg.logger)
        self.clerk = ClerkVerifier(cfg.clerk, self.http, cfg.now, cfg.logger)
        self.cache = (
            SnapshotCache(
                self.client, cfg.service, cfg.snapshot.ttl_seconds, cfg.snapshot.stale_read_ttl_seconds,
                cfg.now, cfg.poll_interval_seconds, cfg.logger,
            )
            if cfg.service
            else None
        )

    # ---- lifecycle ----------------------------------------------------------

    def start(self):
        """Begin change-feed polling. Needs a running event loop (call it from a lifespan handler)."""
        if self.cache:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                self.config.logger.warning("auth.start() called without a running event loop; polling not started")
                return self
            self.cache.start_polling()
        return self

    async def close(self):
        if self.cache:
            self.cache.stop()
        if self._owns_http:
            await self.http.aclose()

    # ---- events -------------------------------------------------------------

    def _emit(self, event):
        if not self.config.on_event:
            return
        try:
            r = self.config.on_event(event)
            if inspect.isawaitable(r):
                asyncio.ensure_future(r)
        except Exception as err:  # noqa: BLE001
            self.config.logger.warning(f"auth event sink failed: {type(err).__name__}")  # an audit sink must never break a request

    def _audited(self, res, permission, request_id):
        """The audit event carries ids and the decision only: never a credential,
        header, token or request body."""
        self._emit({
            "type": "auth.decision", "ts": _iso(self.config.now()), "service": self.config.service or None,
            "permission": permission, "allow": res.allow, "reason": res.reason, "source": res.source,
            "stale": res.stale, "tenant_id": res.tenant_id, "via_tenant": res.via_tenant,
            "actor": res.principal.actor() if res.principal else None,
            "key_id": res.principal.key_id if res.principal else None, "run_id": request_id,
        })
        return res

    # ---- principal resolution -----------------------------------------------

    async def _principal_from(self, cred):
        """-> (principal, defer_to_platform, denied_reason)"""
        if cred.type == "none":
            return None, False, "no_credential"

        if cred.type == "clerk":
            try:
                claims = await self.clerk.verify(cred.raw)
            except Denied as d:
                return None, False, d.reason
            return Principal(
                kind="human", id=claims["sub"], user_id=claims["sub"], source="clerk",
                claims={"azp": claims.get("azp"), "org_id": claims.get("org_id"),
                        "org_role": claims.get("org_role"), "fva": claims.get("fva")},
            ), False, None

        if cred.type == "audience":
            # Never trusted offline: authority and revocation are re-checked by the platform on every use.
            return Principal(kind="human", source="audience_token"), True, None

        # keys
        if not cred.key_kind:
            return None, False, "key_not_found"
        if cred.key_kind == "service":
            try:
                sp = await resolve_service_key(cred.raw, self.config.service_keys, self.client)
            except Denied as d:
                return None, False, d.reason
            return Principal(
                kind="service", id=sp["id"], service=sp["service"], routes=sp["routes"], key_id=sp["key_id"],
                key_prefix="stgs_", source="platform_key",
            ), False, None
        # agent / guest / mcp keys: only the platform knows; resolved and decided live.
        return Principal(kind=None, source="platform_key", key_prefix=cred.raw[:5]), True, None

    async def resolve_principal(self, headers=None, credential=None):
        """POST /v1/principals/resolve for keys, so identity is available without a decision.
        -> dict {ok, principal} or {ok: False, reason, status}"""
        cred = credential if credential is not None else extract(headers)
        principal, defer, denied = await self._principal_from(cred)
        if denied:
            return {"ok": False, "reason": denied, "status": status_for(denied, False)}
        if not defer:
            return {"ok": True, "principal": principal}
        try:
            body = {"audience_token": cred.raw} if cred.type == "audience" else {"credential": cred.raw}
            res = await self.client.resolve(body)
            if not res.get("valid"):
                return {"ok": False, "reason": res.get("reason"), "status": status_for(res.get("reason"), False)}
            if not isinstance(res.get("principal"), dict):
                return {"ok": False, "reason": "platform_unavailable", "status": 503}  # a reply that identifies no one
            return {"ok": True, "principal": self._from_summary(res["principal"], res.get("key_id"), principal)}
        except PlatformUnavailable:
            return {"ok": False, "reason": "platform_unavailable", "status": 503}

    @staticmethod
    def _from_summary(p, key_id, base):
        uid = p.get("user_id")
        return base.evolve(
            kind=p.get("kind"), id=uid if uid is not None else p.get("id"), user_id=uid,
            tenant=p.get("tenant_id"), key_id=key_id,
        )

    # ---- decisions ----------------------------------------------------------

    async def _live(self, cred, principal, parsed, resource):
        resource_body = {}
        for field, wire in (("tenant", "tenant_id"), ("brand", "brand_id"), ("domain", "domain"), ("mailbox", "mailbox")):
            if resource.get(field):
                resource_body[wire] = resource[field]
        body = {"service": parsed["service"], "action": parsed["action"], "resource": resource_body}
        if cred.type == "clerk":
            body["clerk_token"] = cred.raw
        elif cred.type == "audience":
            body["audience_token"] = cred.raw
        else:
            body["credential"] = cred.raw
        try:
            res = await self.client.authorize(body)
        except PlatformUnavailable:
            return Result(False, "platform_unavailable", principal=principal)
        p = principal
        if res.get("principal"):
            p = self._from_summary(res["principal"], None, principal)
        if res.get("allow"):
            p.tenant = res.get("tenant_id")
            p.roles = res.get("roles") or []
        return Result(
            res.get("allow"), res.get("reason"), principal=p, tenant_id=res.get("tenant_id"),
            via_tenant=res.get("via_tenant"), roles=res.get("roles"), sensitive=res.get("sensitive"), source="live",
        )

    async def _decide(self, headers=None, credential=None, permission=None, resource=None, request=None):
        """Decision without the audit event (so wrappers that add checks emit exactly one). `headers` is
        anything with .get() or a plain dict; `credential` (from extract()) may be passed instead."""
        cfg = self.config
        try:
            resource = resource or {}
            parsed = parse_permission(permission)
            cred = credential if credential is not None else extract(headers)
            if not parsed:
                return Result(False, "unknown_permission")

            principal, defer, denied = await self._principal_from(cred)
            if denied:
                return Result(False, denied)

            # Service principals are denied by default for tenant-scoped permissions; the
            # platform (C0b2) is the only thing that can say otherwise, so ask it.
            if principal.kind == "service":
                return await self._live(cred, principal, parsed, resource)

            # Tenant: explicit argument, else the adopter's resolver (Clerk org -> tenant until
            # the snapshot carries org_id). With none, the platform answers tenant_required.
            tenant = resource.get("tenant") or None
            if not tenant and cfg.tenant_resolver and principal.kind == "human":
                tenant = (await _maybe_await(cfg.tenant_resolver(request, principal))) or None
            # The platform's tenant ids are UUIDs. A caller-supplied value that is not one can never name
            # a tenant: answer it here as a denial instead of sending it on and reporting the platform's
            # 422 as an outage (a client mistake must not look like platform_unavailable).
            if tenant and not _UUID_RE.match(str(tenant)):
                return Result(False, "tenant_not_found", principal=principal)
            scoped = {**resource, "tenant": tenant}

            offline_eligible = (
                cred.type == "clerk" and self.cache is not None and parsed["service"] == cfg.service and tenant is not None
            )
            if not offline_eligible:
                return await self._live(cred, principal, parsed, scoped)

            snap = await self.cache.get()
            if snap.state == "none":
                return Result(False, "platform_unavailable", principal=principal)
            perm = next((p for p in snap.snapshot["permissions"] if p["action"] == parsed["action"]), None)
            if perm and perm.get("sensitive"):
                return await self._live(cred, principal, parsed, scoped)
            if snap.state == "stale" and perm and perm.get("category") != "read":
                return Result(False, "platform_unavailable", principal=principal)

            d = decide_offline(snap.snapshot, principal, parsed["service"], parsed["action"], scoped, cfg.now())
            p = principal.evolve(tenant=d["tenant_id"], ancestry=d["ancestry"], roles=d["roles"], permissions=d["permissions"])
            return Result(
                d["allow"], d["reason"], principal=p, tenant_id=d["tenant_id"], via_tenant=d["via_tenant"],
                roles=d["roles"], sensitive=d["sensitive"], source="offline", stale=snap.state == "stale",
            )
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            # A bug must never read as an allow. Log the class only (messages can echo input).
            cfg.logger.error(f"auth: unexpected {type(err).__name__} while deciding")
            return Result(False, "platform_unavailable")

    async def authorize(self, headers=None, credential=None, permission=None, resource=None, request=None, request_id=None):
        res = await self._decide(headers=headers, credential=credential, permission=permission, resource=resource, request=request)
        return self._audited(res, permission, request_id)

    def _check_step_up(self, res):
        """Clerk session tokens carry `fva` (minutes since [first, second] factor, -1 when none);
        this is the claim the step-up rule reads. It has NOT been confirmed against this Clerk
        instance's token shape (the CR leaves JWT-template limits unverified):
        if `fva` is absent, step-up is denied, never assumed."""
        claims = res.principal.claims if res.principal else None
        fva = claims.get("fva") if claims else None
        second = fva[1] if isinstance(fva, list) and len(fva) > 1 else None
        return (
            isinstance(second, (int, float)) and not isinstance(second, bool)
            and 0 <= second <= self.config.step_up_max_age_minutes
        )

    async def authorize_approver(self, step_up=False, headers=None, credential=None, permission=None,
                                 resource=None, request=None, request_id=None):
        """requireApprover: a human who holds the permission AND, when step_up is set, has a recent
        second-factor verification."""
        res = await self._decide(headers=headers, credential=credential, permission=permission, resource=resource, request=request)
        if res.allow and (not res.principal or res.principal.kind != "human"):
            res = res.evolve(allow=False, reason="principal_kind_restricted")
        elif res.allow and step_up and not self._check_step_up(res):
            res = res.evolve(allow=False, reason="step_up_required")
        return self._audited(res, permission, request_id)

    @staticmethod
    def assert_tenant(res, tenant_id):
        """A request-supplied tenant id must be the tenant the decision was made in."""
        return bool(res and res.allow and res.tenant_id and res.tenant_id == tenant_id)

    @staticmethod
    def usage_context(res, request_id=None):
        """Context for usage events: who acted, for which tenant, and the run id to propagate."""
        return {
            "tenant_id": res.tenant_id if res else None,
            "actor": res.principal.actor() if res and res.principal else {"kind": "system", "id": None},
            "run_id": request_id,
        }
