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
from .decision import decide_offline, scope_allows
from .platform_client import PlatformClient, PlatformUnavailable
from .reasons import status_for
from .service_keys import ServiceKeyResolver, route_allowed
from .snapshot_cache import SnapshotCache

# The platform's tenant ids are UUIDs (see the tenant check in `authorize`).
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)  # fullmatch

ACTOR_KIND = {"human": "human", "agent": "agent", "guest": "guest", "service": "system"}

_PRINCIPAL_DEFAULTS = dict(
    kind=None, id=None, user_id=None, tenant=None, ancestry=[], roles=[], permissions=[],
    key_id=None, key_prefix=None, source=None, service=None, claims=None,
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
    __slots__ = ("allow", "reason", "status", "principal", "tenant_id", "via_tenant", "roles", "sensitive", "source", "stale", "tenant_source")

    def __init__(self, allow, reason, principal=None, tenant_id=None, via_tenant=None, roles=None,
                 sensitive=False, source="none", stale=False, tenant_source=None):
        self.allow = allow is True  # exactly True: a truthy string must never read as a yes
        self.tenant_source = tenant_source
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


def _first_set(*vals):
    for v in vals:
        if v is not None:
            return v
    return None


async def _maybe_await(v):
    return await v if inspect.isawaitable(v) else v


class EffectiveResult:
    """Result of Auth.effective_permissions. `permissions` is the platform's list of
    {permission, service, action, category, sensitive, scopes: [{scope, role, via_tenant}]}."""

    def __init__(self, ok, principal=None, tenant_id=None, reason=None, permissions=None, status=None):
        self.ok = ok
        self.principal = principal
        self.tenant_id = tenant_id
        self.reason = reason
        self.permissions = permissions or []
        self.status = status

    def permits(self, permission, resource=None):
        resource = resource or {}
        entry = next((e for e in self.permissions if e.get("permission") == permission), None)
        return bool(entry) and any(scope_allows(sc.get("scope"), resource) is None for sc in entry.get("scopes") or [])


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
        ServiceKeyResolver.validate_accepted(cfg.accepted_caller_services)  # a bad slug is a startup error
        self.service_keys = ServiceKeyResolver(
            self.client, cfg.accepted_caller_services, cfg.now, cfg.logger, monotonic=cfg.monotonic,
            valid_ttl_seconds=cfg.service_key_cache.valid_ttl_seconds,
            invalid_ttl_seconds=cfg.service_key_cache.invalid_ttl_seconds,
            max_entries=cfg.service_key_cache.max_entries,
            negative_max_entries=cfg.service_key_cache.negative_max_entries,
            max_inflight=cfg.service_key_cache.max_inflight,
        )
        self.clerk = ClerkVerifier(cfg.clerk, self.http, cfg.now, cfg.logger, monotonic=cfg.monotonic)
        self.cache = (
            SnapshotCache(
                self.client, cfg.service, cfg.snapshot.ttl_seconds, cfg.snapshot.stale_read_ttl_seconds,
                cfg.monotonic, cfg.poll_interval_seconds, cfg.logger,
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
            "stale": res.stale, "tenant_id": res.tenant_id, "via_tenant": res.via_tenant, "tenant_source": res.tenant_source,
            "caller_service": res.principal.service if res.principal and res.principal.kind == "service" else None,
            "actor": res.principal.actor() if res.principal else None,
            "key_id": res.principal.key_id if res.principal else None, "run_id": request_id,
        })
        return res

    # ---- principal resolution -----------------------------------------------

    async def _principal_from(self, cred):
        """-> (principal, defer_to_platform, denied_reason)"""
        if cred.type == "none":
            return None, False, "no_credential"
        if cred.type == "invalid":
            return None, False, "token_invalid"  # an ambiguous credential (a repeated header or cookie) is refused

        if cred.type == "clerk":
            try:
                claims = await self.clerk.verify(cred.raw)
            except Denied as d:
                return None, False, d.reason
            o = claims.get("o") if isinstance(claims.get("o"), dict) else {}
            return Principal(
                kind="human", id=claims["sub"], user_id=claims["sub"], source="clerk",
                # Clerk's v1 session token carries org_id/org_role, the v2 token carries them as o.{id,rol}.
                claims={"azp": claims.get("azp"), "org_id": _first_set(claims.get("org_id"), o.get("id")),
                        "org_role": _first_set(claims.get("org_role"), o.get("rol")), "fva": claims.get("fva")},
            ), False, None

        if cred.type == "audience":
            # Never trusted offline: authority and revocation are re-checked by the platform on every use.
            return Principal(kind="human", source="audience_token"), True, None

        # keys
        if not cred.key_kind:
            return None, False, "key_not_found"
        if cred.key_kind == "service":
            try:
                sp = await self.service_keys.resolve(cred.raw)
            except Denied as d:
                return None, False, d.reason
            return Principal(
                kind="service", id=sp["id"], service=sp["service"], key_id=sp["key_id"],
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
            if not isinstance(res, dict):
                return {"ok": False, "reason": "platform_unavailable", "status": 503}
            if res.get("valid") is False:
                reason = res["reason"] if isinstance(res.get("reason"), str) else "key_not_found"
                return {"ok": False, "reason": reason, "status": status_for(reason, False)}
            if res.get("valid") is not True or not isinstance(res.get("principal"), dict):
                return {"ok": False, "reason": "platform_unavailable", "status": 503}  # malformed reply: cannot identify anyone
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

    async def _select_tenant(self, explicit, hint, principal, request):
        """Which tenant is this request about, and where did that come from? In order:
          1. `explicit`: the route's own tenant scope. Always wins.
          2. the adopter's tenant_resolver, then
          3. the Clerk organization in the session token, mapped through the snapshot's tenant.org_id;
          4. `hint`: the x-tenant header, the weakest source, used only when nothing above named a tenant.
        So a token whose org maps to a tenant is not moved to another by a header. The mapping is identity,
        not authority: whatever comes out, the decision still has to find the user's membership in it (an
        org the user does not belong to is denied, never silently swapped for one they do).
        Steps 2 and 3 run only for a principal this library has itself verified (a Clerk session): never
        app code or cache work on behalf of a credential the platform has not yet confirmed.
        -> (tenant, source)"""
        if explicit:
            return explicit, "explicit"  # '' is no tenant
        if principal.source == "clerk" and principal.kind == "human":
            if self.config.tenant_resolver:
                t = (await _maybe_await(self.config.tenant_resolver(request, principal))) or None
                if t:
                    return t, "resolver"
            org_id = (principal.claims or {}).get("org_id")
            if org_id and self.cache:
                snap = await self.cache.get()  # a stale snapshot is fine here: it only names a tenant
                if snap.state != "none":
                    mapped = next((t["id"] for t in snap.snapshot["tenants"] if t.get("org_id") == org_id), None)
                    if mapped:
                        return mapped, "org"
        return (hint, "hint") if hint else (None, None)

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

        # The reply must say exactly true or exactly false, and a yes must identify who it is for and be
        # about the tenant we asked about; anything else is a malformed platform, not an answer.
        def malformed():
            return Result(False, "platform_unavailable", principal=principal)

        if not isinstance(res, dict) or res.get("allow") not in (True, False) or not isinstance(res.get("allow"), bool):
            return malformed()
        if res["allow"] is True:
            if not isinstance(res.get("principal"), dict):
                return malformed()
            if resource.get("tenant") and str(res.get("tenant_id")).lower() != str(resource["tenant"]).lower():
                return malformed()
        p = principal
        if isinstance(res.get("principal"), dict):
            p = self._from_summary(res["principal"], None, principal)
        if res["allow"] is True:
            p.tenant = res.get("tenant_id")
            p.roles = res.get("roles") or []
        return Result(
            res["allow"], res["reason"] if isinstance(res.get("reason"), str) else "platform_unavailable", principal=p,
            tenant_id=res.get("tenant_id"), via_tenant=res.get("via_tenant"), roles=res.get("roles"),
            sensitive=res.get("sensitive") is True, source="live", tenant_source=resource.get("tenant_source"),
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

            # A service principal holds no tenant permissions: a tenant is not part of one, and the platform
            # grants it nothing (it answers service_principal_not_granted, so this offline answer is the same).
            # Who a service caller is allowed to be on THIS app's routes is require_service_caller's job.
            if principal.kind == "service":
                return Result(False, "service_principal_not_granted", principal=principal)

            tenant, tenant_source = await self._select_tenant(resource.get("tenant"), resource.get("tenant_hint"), principal, request)
            # The platform's tenant ids are UUIDs. A caller-supplied value that is not one can never name
            # a tenant: answer it here as a denial instead of sending it on and reporting the platform's
            # 422 as an outage (a client mistake must not look like platform_unavailable).
            if tenant and not _UUID_RE.fullmatch(str(tenant)):
                return Result(False, "tenant_not_found", principal=principal)
            scoped = {k: v for k, v in resource.items() if k != "tenant_hint"}
            scoped.update(tenant=tenant, tenant_source=tenant_source)

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
                tenant_source=tenant_source,
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

    async def effective_permissions(self, headers=None, credential=None, tenant=None, service=None, request=None):
        """What the platform says this principal may do in a tenant (POST /v1/principals/resolve with
        include_effective), computed by the same code path as /v1/authorize, so a caller (a UI deciding
        which buttons to show, a service listing what an agent can reach) need not re-implement the rules.
        `permits(permission, resource)` applies the documented matching rule: allowed iff SOME scope entry
        admits the resource (same rule as the offline decision). This is information, not a gate:
        enforcement is authorize(). -> EffectiveResult"""
        cred = credential if credential is not None else extract(headers)
        principal, _defer, denied = await self._principal_from(cred)
        if denied:
            return EffectiveResult(False, reason=denied, status=status_for(denied, False))

        def none(reason):
            return EffectiveResult(True, principal=principal, reason=reason)

        if principal.kind == "service":
            return none("service_principal_not_granted")
        chosen = (await self._select_tenant(tenant, None, principal, request))[0]
        if chosen and not _UUID_RE.fullmatch(str(chosen)):
            return none("tenant_not_found")
        body = {"include_effective": True}
        if chosen:
            body["tenant_id"] = chosen
        if service:
            body["service"] = service
        if cred.type == "clerk":
            body["clerk_token"] = cred.raw
        elif cred.type == "audience":
            body["audience_token"] = cred.raw
        else:
            body["credential"] = cred.raw
        try:
            res = await self.client.resolve(body)
        except PlatformUnavailable:
            return EffectiveResult(False, reason="platform_unavailable", status=503)
        if not isinstance(res, dict):
            return EffectiveResult(False, reason="platform_unavailable", status=503)
        if res.get("valid") is False:
            reason = res["reason"] if isinstance(res.get("reason"), str) else "key_not_found"
            return EffectiveResult(False, reason=reason, status=status_for(reason, False))
        if res.get("valid") is not True or not isinstance(res.get("principal"), dict) or not isinstance(res.get("effective"), dict):
            return EffectiveResult(False, reason="platform_unavailable", status=503)
        p = self._from_summary(res["principal"], res.get("key_id"), principal)
        eff = res["effective"]
        p.tenant = eff.get("tenant_id")
        perms = eff.get("permissions") or []
        p.permissions = sorted(e["permission"] for e in perms)
        return EffectiveResult(True, principal=p, tenant_id=p.tenant, reason=eff.get("reason"), permissions=perms)

    async def authorize_service_caller(self, headers=None, credential=None, method=None, path=None, policy=None):
        """An inbound call from another internal service. A matched service key proves WHICH service is
        calling (and only that); what it may do on this app's routes is this app's own policy:
          policy = {'<caller service>': ['METHOD /path/glob', ...]}   (deny by default)
        The platform's allowed_routes for the key are routes on the platform's API and play no part here."""
        try:
            cred = credential if credential is not None else extract(headers)
            principal, _defer, denied = await self._principal_from(cred)
            if denied:
                res = Result(False, denied)
            elif principal.kind != "service":
                res = Result(False, "service_caller_required", principal=principal)
            elif not route_allowed((policy or {}).get(principal.service), method, path):
                res = Result(False, "route_not_allowed", principal=principal)
            else:
                res = Result(True, "allowed", principal=principal, source="live")
            return self._audited(res, "service_caller", None)
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001
            self.config.logger.error(f"auth: unexpected {type(err).__name__} while deciding")
            return self._audited(Result(False, "platform_unavailable"), "service_caller", None)

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
