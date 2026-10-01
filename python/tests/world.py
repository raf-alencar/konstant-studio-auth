"""Test support: turns test-vectors/vectors.json's `world` into what the platform would
serve (snapshot, key resolution) and mints Clerk tokens, all with fake data generated per
run. A line-for-line mirror of test/helpers/world.js: same uuid5 name scheme, same
snapshot builder, same fake platform semantics.
"""

import base64
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "test-vectors" / "vectors.json").read_text())

ROLE_CATEGORIES = {
    "viewer": ["read"],
    "operator": ["read", "write"],
    "approver": ["read", "approve"],
    "admin": ["read", "write", "manage"],
}


def b64u(data):
    if not isinstance(data, bytes):
        data = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def iso_ms(ms):
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(ms) % 1000:03d}Z"


def parse_iso_ms(s):
    return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


class World:
    def __init__(self, spec=None, include_transient=True):
        spec = spec or VECTORS["world"]
        if not include_transient:
            # `transient` rows exist only to exercise the consumer's clock inside a cached snapshot.
            keep = lambda rows: [x for x in rows if not x.get("transient")]  # noqa: E731
            spec = {**spec, **{k: keep(spec[k]) for k in ("tenants", "entitlements", "principals", "memberships")}}
        self.spec = spec
        self.now_ms = parse_iso_ms(self.spec["now"])
        self._ns = uuid.UUID(self.spec["namespace"])
        self.keys_by_raw = {self.raw_key(k): k for k in self.spec["keys"]}

    def id(self, kind, ref):
        return None if ref is None else str(uuid.uuid5(self._ns, f"{kind}:{ref}"))

    def raw_key(self, key):
        # Fake raw keys: deterministic, obviously not real.
        prefix = {"agent": "stga_", "guest": "stgg_", "service": "stgs_"}[key["kind"]]
        return prefix + hashlib.sha256(f"fake:{key['ref']}".encode()).hexdigest()

    def principal(self, ref):
        return next((p for p in self.spec["principals"] if p["ref"] == ref), None)

    def all_roles(self):
        system = [{"slug": s, "tenant": None, "ref": s} for s in [*ROLE_CATEGORIES, "owner"]]
        return system + [dict(r) for r in self.spec["roles"]]

    def role_permissions(self, role):
        if role["slug"] == "owner":
            return list(dict.fromkeys(f"{p['service']}:*" for p in self.spec["catalog"]))
        if role.get("permissions"):
            return role["permissions"]
        cats = ROLE_CATEGORIES[role["slug"]]
        return [f"{p['service']}:{p['action']}" for p in self.spec["catalog"] if p["category"] in cats]

    def snapshot(self, service, version=100, ttl=30, stale=300):
        """What GET /v1/authorize/snapshot?service=<service> returns for this world at now_ms."""
        s = self.spec
        tenant_by_ref = {t["ref"]: t for t in s["tenants"]}

        def ancestors(ref):
            out = []
            p = tenant_by_ref[ref]["parent"]
            while p:
                out.append(p)
                p = tenant_by_ref[p]["parent"]
            return out

        def iso(offset_s):
            return None if offset_s is None else iso_ms(self.now_ms + offset_s * 1000)

        entitled = [
            e for e in s["entitlements"]
            if e["service"] == service and e["state"] == "on" and tenant_by_ref[e["tenant"]]["status"] == "active"
        ]
        tenants = [
            {
                "id": self.id("tenant", t["ref"]), "slug": t["ref"], "type": t["type"], "org_id": t.get("org_id"),
                "parent_id": self.id("tenant", t["parent"]), "ancestors": [self.id("tenant", a) for a in ancestors(t["ref"])],
                "plan": e.get("plan"), "limits": {}, "starts_at": iso(e.get("starts_in_s")), "ends_at": iso(e.get("ends_in_s")),
            }
            for e, t in sorted(((e, tenant_by_ref[e["tenant"]]) for e in entitled), key=lambda x: x[1]["ref"])
        ]
        tenant_ids = {e["tenant"] for e in entitled}
        relevant = set(tenant_ids)
        for ref in tenant_ids:
            relevant.update(ancestors(ref))

        roles = []
        for r in self.all_roles():
            if not (r["tenant"] is None or r["tenant"] in tenant_ids):
                continue
            perms = sorted(p for p in self.role_permissions(r) if p.split(":")[0] == service)
            if perms:
                roles.append({"id": self.id("role", r["ref"]), "slug": r["slug"], "tenant_id": self.id("tenant", r["tenant"]), "permissions": perms})
        role_ids = {r["id"] for r in roles}

        memberships = []
        for m in s["memberships"]:
            p = self.principal(m["principal"])
            if not (
                p and not p.get("no_principal") and p.get("status", "active") == "active"
                and m.get("status", "active") == "active"
                and (m.get("expires_in_s") is None or m["expires_in_s"] > 0)
                and m["tenant"] in relevant and self.id("role", m["role"]) in role_ids
            ):
                continue
            memberships.append({
                "principal_id": self.id("principal", p["ref"]), "user_id": p["user_id"] if p["kind"] == "human" else None,
                "kind": p["kind"], "tenant_id": self.id("tenant", m["tenant"]), "role_id": self.id("role", m["role"]),
                "scope": m.get("scope") or {}, "expires_at": iso(m.get("expires_in_s")),
            })

        return {
            "service": service, "version": version, "ttl_seconds": ttl, "stale_read_ttl_seconds": stale,
            "fail_closed": {"stale_serves_categories": ["read"], "always_live": ["sensitive actions", "agent and guest key checks", "revocation questions"]},
            "rules": {"guest_allowed_categories": ["read"], "agent_denied_categories": ["approve"]},
            "permissions": [{"action": p["action"], "category": p["category"], "sensitive": p["sensitive"]} for p in s["catalog"] if p["service"] == service],
            "tenants": tenants, "roles": roles, "memberships": memberships,
        }


# ---- Clerk tokens ---------------------------------------------------------------


class ClerkKey:
    def __init__(self, kid):
        self.kid = kid
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        n = key.public_key().public_numbers()
        enc = lambda i: b64u(i.to_bytes((i.bit_length() + 7) // 8, "big"))  # noqa: E731
        self.jwk = {"kty": "RSA", "n": enc(n.n), "e": enc(n.e), "kid": kid, "alg": "RS256", "use": "sig"}


class ClerkKeys:
    def __init__(self):
        self.trusted = ClerkKey("kid-trusted")
        self.foreign = ClerkKey("kid-foreign")


def mint_clerk_token(keys, sub, now_ms, issuer, azp, spec=None):
    """spec fields (all optional): exp_in_s, iat_in_s, nbf_in_s, extra (more claims, e.g. fva), azp (None = omit), iss, aud, kid, alg, sign_with"""
    spec = spec or {}
    iat = now_ms // 1000
    claims = {"sub": sub, "iat": iat + spec.get("iat_in_s", 0), "exp": iat + spec.get("exp_in_s", 3600), "iss": spec.get("iss") or issuer}
    if "nbf_in_s" in spec:
        claims["nbf"] = iat + spec["nbf_in_s"]
    claims.update(spec.get("extra") or {})
    if "azp" not in spec:
        claims["azp"] = azp
    elif spec["azp"] is not None:
        claims["azp"] = spec["azp"]
    if spec.get("aud"):
        claims["aud"] = spec["aud"]
    alg = spec.get("alg")
    if alg == "none":
        return f"{b64u({'alg': 'none', 'typ': 'JWT'})}.{b64u(claims)}."
    if alg == "HS256":
        return jwt.encode(claims, os.urandom(32), algorithm="HS256", headers={"kid": keys.trusted.kid})
    signer = keys.foreign if spec.get("sign_with") == "foreign" else keys.trusted
    return jwt.encode(claims, signer.pem, algorithm="RS256", headers={"kid": spec.get("kid") or signer.kid, "typ": "JWT"})


# ---- fake platform ---------------------------------------------------------------


def _json(body, status=200, headers=None):
    return httpx.Response(status, json=body, headers=headers)


class FakePlatform:
    """Answers over an httpx.MockTransport (no sockets). `live` is what POST /v1/authorize
    returns for a valid credential: the vector's platform-truth answer."""

    def __init__(self, world, keys, jwks_url):
        self.world = world
        self.keys = keys
        self.jwks_url = jwks_url
        self.down = False
        self.live = None
        self.calls = []
        self.snapshot_version = 100
        self.events = []
        self.service_resolves = []  # expect_service of every stgs_ resolve, in order
        self.service_key_expires_at = None
        self.transport = httpx.MockTransport(self.handle)

    def count(self, method, path):
        return sum(1 for c in self.calls if c["method"] == method and c["path"] == path)

    def _principal_summary(self, p):
        return {"id": self.world.id("principal", p["ref"]), "kind": p["kind"],
                "user_id": p["user_id"] if p["kind"] == "human" else None, "tenant_id": self.world.id("tenant", p.get("tenant")),
                **({"service": p["service"]} if p["kind"] == "service" else {})}

    def _resolve_service_key(self, key, body):
        """POST /v1/principals/resolve for a stgs_ key, as the CoS contract note specifies the FINAL platform:
        `expect_service` is mandatory for a bound caller (400 without), and an unknown, revoked, expired,
        disabled or mismatching key all answer the same valid:false / key_not_found. The key's metadata is
        returned only on a match. (The committed C0b2 differs: optional expect_service, specific reasons.
        The library must be correct against both, so it always sends expect_service and never branches on the reason.)"""
        self.service_resolves.append(body.get("expect_service"))
        if not body.get("expect_service"):
            return _json({"detail": "expect_service is required for a bound service key"}, 400)
        p = self.world.principal(key["principal"]) if key and key["state"] == "active" and key["kind"] == "service" else None
        if not p or p.get("service") != body["expect_service"]:
            return _json({"valid": False, "reason": "key_not_found"})
        return _json({
            "valid": True, "key_id": self.world.id("key", key["ref"]), "principal": self._principal_summary(p),
            "service_key": {"service": p["service"], "allowed_routes": key.get("routes") or [], "expires_at": self.service_key_expires_at, "status": "active"},
        })

    async def handle(self, request):
        url = str(request.url)
        u = urlparse(url)
        method = request.method.upper()
        if url == self.jwks_url:
            return _json({"keys": [self.keys.trusted.jwk]})
        self.calls.append({"method": method, "path": u.path, "headers": dict(request.headers)})
        if self.down:
            raise httpx.ConnectError("fetch failed")
        body = json.loads(request.content) if request.content else {}
        w = self.world

        if method == "GET" and u.path == "/v1/authorize/snapshot":
            snap = w.snapshot(parse_qs(u.query)["service"][0], version=self.snapshot_version)
            etag = '"' + hashlib.sha256(json.dumps({**snap, "version": 0}, sort_keys=True).encode()).hexdigest()[:32] + '"'
            if request.headers.get("if-none-match") == etag:
                return httpx.Response(304, headers={"etag": etag})
            return _json(snap, 200, {"etag": etag})
        if method == "GET" and u.path == "/v1/events":
            after = int(parse_qs(u.query)["after"][0])
            return _json({"events": self.events, "next_cursor": after + len(self.events), "head": self.snapshot_version})

        cred = body.get("credential")
        key = w.keys_by_raw.get(cred) if cred else None
        key_problem = None
        if cred:
            key_problem = "key_not_found" if (not key or key["state"] == "unknown") else {"revoked": "key_revoked", "expired": "key_expired"}.get(key["state"])
        if u.path == "/v1/principals/resolve":
            if cred and cred.startswith("stgs_"):
                return self._resolve_service_key(key, body)
            if cred and key_problem:
                return _json({"valid": False, "reason": key_problem})
            return _json({"valid": True, "principal": self._principal_summary(w.principal(key["principal"])),
                          "key_id": w.id("key", key["ref"]) if key else None})
        if u.path == "/v1/authorize":
            if cred and cred.startswith("stgs_"):
                return _json({"allow": False, "reason": "service_principal_not_granted"})
            if cred and key_problem:
                return _json({"allow": False, "reason": key_problem})
            e = self.live
            principal = self._principal_summary(w.principal(key["principal"])) if key else e.get("principal")
            return _json({
                "allow": e["allow"], "reason": e["reason"], "tenant_id": w.id("tenant", e.get("tenant")),
                "via_tenant": w.id("tenant", e.get("via_tenant")), "principal": principal,
                "sensitive": bool(e.get("sensitive")), "roles": e.get("roles") or [],
            })
        return _json({"detail": "not found"}, 404)


class SilentLogger:
    def error(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def info(self, *a, **k): pass
    def debug(self, *a, **k): pass
