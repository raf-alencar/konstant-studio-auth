#!/usr/bin/env python3
"""Start / stop a SCRATCH copy of the control-plane platform, seeded from the shared vectors.

Used by the e2e and parity tests (test/e2e, python/tests/e2e). Never touches a real database:
it refuses anything that is not a local database whose name starts with `cptest`, and it
binds 127.0.0.1 only. Every secret it uses (shared key, Fernet key, Ed25519 key, the fake
Clerk RSA key, all API keys) is generated fresh per start and written only to the state
file (default .scratch/state.json, git-ignored).

    python scripts/scratch_platform.py start --platform-dir <checkout of the C0b branch> \
        --database-url postgresql://postgres@127.0.0.1:55433/cptest_ksa
    python scripts/scratch_platform.py stop

`--platform-dir` is a COPY of the platform branch (e.g. from `git archive`), never the live
repo: this script does not read or write the platform repository.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
VECTORS = json.loads((REPO / "test-vectors" / "vectors.json").read_text())
WORLD = VECTORS["world"]
NS = uuid.UUID(WORLD["namespace"])
SERVICE_KEY_PREFIX = {"agent": "stga_", "guest": "stgg_", "service": "stgs_"}
FORBIDDEN_PORTS = {3229, 3227}  # the real platform and graph


def uid(kind: str, ref: str | None):
    return None if ref is None else uuid.uuid5(NS, f"{kind}:{ref}")


def guard_database(url: str) -> None:
    u = urlparse(url)
    if u.hostname not in ("127.0.0.1", "localhost") or not u.path.lstrip("/").startswith("cptest"):
        sys.exit(f"refusing: {u.hostname}{u.path} is not a local cptest* scratch database")


def keypair_pems() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ed_key = ed25519.Ed25519PrivateKey.generate()
    enc = dict(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    return rsa_key.private_bytes(**enc).decode(), ed_key.private_bytes(**enc).decode()


def rsa_public_jwk(pem: str, kid: str) -> dict:
    from cryptography.hazmat.primitives import serialization

    pub = serialization.load_pem_private_key(pem.encode(), password=None).public_key().public_numbers()

    def b64u(n: int) -> str:
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    return {"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid, "n": b64u(pub.n), "e": b64u(pub.e)}


def wait_http(url: str, seconds: float = 30) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1).read()
            return
        except Exception:
            time.sleep(0.3)
    raise SystemExit(f"timed out waiting for {url}")


async def seed(conn, raw_keys: dict) -> None:
    """Load WORLD into the platform's tables with explicit, deterministic ids."""
    async def q(sql, *a):
        return await conn.execute(sql, *a)

    catalog = {(p["service"], p["action"]): p for p in WORLD["catalog"]}
    for (svc, act), p in catalog.items():
        row = await conn.fetchrow("SELECT category, sensitive FROM stighive_platform.service_permissions WHERE service=$1 AND action=$2", svc, act)
        if row is None or row["category"] != p["category"] or row["sensitive"] != p["sensitive"]:
            raise SystemExit(f"vectors catalog drifted from the platform for {svc}:{act}: platform has {dict(row) if row else None}")

    # `transient` rows only exist for in-memory clock tests (they expire within seconds): never seeded.
    live = lambda rows: [r for r in rows if not r.get("transient")]
    for t in live(WORLD["tenants"]):  # parents are listed before children
        await q("INSERT INTO stighive_platform.tenants (id, slug, name, type, parent_id, status) VALUES ($1,$2,$3,$4,$5,$6)",
                uid("tenant", t["ref"]), t["ref"].replace("_", "-"), t["ref"], t["type"], uid("tenant", t["parent"]), t["status"])
    for e in live(WORLD["entitlements"]):
        await q("INSERT INTO stighive_platform.tenant_entitlements (tenant_id, service, state, plan, starts_at, ends_at) "
                "VALUES ($1,$2,$3,$4, CASE WHEN $5::int IS NULL THEN NULL ELSE now() + make_interval(secs => $5::int) END, "
                "CASE WHEN $6::int IS NULL THEN NULL ELSE now() + make_interval(secs => $6::int) END)",
                uid("tenant", e["tenant"]), e["service"], e["state"], e.get("plan"), e.get("starts_in_s"), e.get("ends_in_s"))

    role_ids = {r["slug"]: r["id"] for r in await conn.fetch("SELECT id, slug FROM stighive_platform.roles WHERE tenant_id IS NULL")}
    for r in WORLD["roles"]:
        rid = uid("role", r["ref"])
        await q("INSERT INTO stighive_platform.roles (id, tenant_id, slug, name) VALUES ($1,$2,$3,$3)", rid, uid("tenant", r["tenant"]), r["slug"])
        for perm in r["permissions"]:
            await q("INSERT INTO stighive_platform.role_permissions (role_id, permission) VALUES ($1,$2)", rid, perm)
        role_ids[r["ref"]] = rid

    principal_ids: dict[str, uuid.UUID] = {}
    for p in live(WORLD["principals"]):
        if p.get("no_principal"):
            continue
        if p["kind"] == "human":
            # The users trigger mirrors this into a human principal (random id).
            await q("INSERT INTO stighive_platform.users (id, email) VALUES ($1,$2)", p["user_id"], f"{p['ref']}@vectors.test")
            pid = await conn.fetchval("SELECT id FROM stighive_platform.principals WHERE user_id=$1", p["user_id"])
            if p.get("status") == "disabled":
                await q("UPDATE stighive_platform.principals SET status='disabled' WHERE id=$1", pid)
        else:
            pid = uid("principal", p["ref"])
            await q("INSERT INTO stighive_platform.principals (id, kind, tenant_id, service_slug, name) VALUES ($1,$2,$3,$4,$5)",
                    pid, p["kind"], uid("tenant", p.get("tenant")), p.get("service"), p["ref"])
        principal_ids[p["ref"]] = pid

    for m in live(WORLD["memberships"]):
        if m["principal"] not in principal_ids:
            continue
        await q("INSERT INTO stighive_platform.memberships (principal_id, tenant_id, role_id, scope, status, expires_at) "
                "VALUES ($1,$2,$3,$4::jsonb,$5, CASE WHEN $6::int IS NULL THEN NULL ELSE now() + make_interval(secs => $6::int) END)",
                principal_ids[m["principal"]], uid("tenant", m["tenant"]), role_ids[m["role"]], json.dumps(m.get("scope", {})),
                m.get("status", "active"), m.get("expires_in_s"))

    for k in WORLD["keys"]:
        raw = SERVICE_KEY_PREFIX[k["kind"]] + secrets.token_urlsafe(32)
        raw_keys[k["ref"]] = raw
        if k["state"] == "unknown":
            continue  # a well-formed key the platform has never seen
        await q("INSERT INTO stighive_platform.principal_keys (principal_id, name, key_hash, key_prefix, key_suffix, allowed_routes, expires_at, revoked_at) "
                "VALUES ($1,$2,$3,$4,$5,$6, CASE WHEN $7 THEN now() - interval '1 hour' END, CASE WHEN $8 THEN now() END)",
                principal_ids[k["principal"]], k["ref"], hashlib.sha256(raw.encode()).hexdigest(), raw[:12], raw[-4:],
                k.get("routes", []), k["state"] == "expired", k["state"] == "revoked")


def start(args) -> None:
    import asyncpg
    from cryptography.fernet import Fernet

    guard_database(args.database_url)
    if args.port in FORBIDDEN_PORTS:
        sys.exit(f"refusing to use port {args.port}")
    state_path = Path(args.state)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    if state_path.exists():
        stop(args)

    async def reset() -> None:
        conn = await asyncpg.connect(args.database_url)
        try:
            await conn.execute("DROP SCHEMA IF EXISTS stighive_platform CASCADE")
        finally:
            await conn.close()

    asyncio.run(reset())

    clerk_pem, ed_pem = keypair_pems()
    kid = "kid-scratch-clerk"
    # One JWKS directory per state file, so two scratch instances never overwrite each other's signing key.
    jwks_dir = state_path.parent / f"jwks-{state_path.stem}"
    jwks_dir.mkdir(exist_ok=True)
    (jwks_dir / "jwks.json").write_text(json.dumps({"keys": [rsa_public_jwk(clerk_pem, kid)]}))
    jwks_port = args.port + 1
    jwks = subprocess.Popen([sys.executable, "-m", "http.server", str(jwks_port), "--bind", "127.0.0.1", "--directory", str(jwks_dir)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    shared_key = "fake-shared-" + secrets.token_urlsafe(24)
    env = {
        **os.environ,
        "DATABASE_URL": args.database_url, "INTERNAL_API_KEY": shared_key, "PORT": str(args.port),
        "CLERK_WEBHOOK_SECRET": "whsec_" + base64.b64encode(secrets.token_bytes(24)).decode(),
        "GRAPH_KEY_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "AUDIENCE_TOKEN_PRIVATE_KEY": ed_pem,
        "CLERK_JWKS_URL": f"http://127.0.0.1:{jwks_port}/jwks.json",
        "CLERK_ISSUER": VECTORS["config"]["clerk"]["issuer"],
        "CLERK_AUTHORIZED_PARTIES": ",".join(VECTORS["config"]["clerk"]["authorized_parties"]),
        "SNAPSHOT_TTL_SECONDS": "30", "EVENT_DELIVERY_ENABLED": "false",
    }
    env.pop("CLERK_AUDIENCE", None)
    log = open(state_path.parent / f"platform-{state_path.stem}.log", "wb")
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(args.port)],
        cwd=args.platform_dir, env=env, stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{args.port}"
    wait_http(f"{base}/health")

    raw_keys: dict[str, str] = {}

    async def do_seed() -> None:
        conn = await asyncpg.connect(args.database_url)
        try:
            await seed(conn, raw_keys)
        finally:
            await conn.close()

    seeded_at_ms = int(time.time() * 1000)  # offsets in the world (windows, expiries) are relative to this
    asyncio.run(do_seed())

    # The key THIS library presents to the platform: bound to the docs service, with only the routes it needs.
    req = urllib.request.Request(
        f"{base}/v1/service-keys", method="POST", headers={"X-API-Key": shared_key, "Content-Type": "application/json"},
        data=json.dumps({"name": "docs-adopter", "service": "docs", "allowed_routes": [
            "GET /v1/authorize/snapshot", "GET /v1/events", "POST /v1/authorize", "POST /v1/principals/resolve"]}).encode())
    service_key = json.loads(urllib.request.urlopen(req).read())["raw_key"]

    state = {
        "platform_url": base, "jwks_url": f"http://127.0.0.1:{jwks_port}/jwks.json",
        "issuer": VECTORS["config"]["clerk"]["issuer"], "authorized_party": VECTORS["config"]["clerk"]["authorized_parties"][0],
        "clerk_private_key_pem": clerk_pem, "clerk_kid": kid, "shared_key": shared_key, "service_key": service_key,
        "keys": raw_keys, "database_url": args.database_url, "pids": {"platform": server.pid, "jwks": jwks.pid},
        "platform_commit": args.platform_commit, "seeded_at_ms": seeded_at_ms,
    }
    state_path.write_text(json.dumps(state, indent=2))
    os.chmod(state_path, 0o600)
    print(f"scratch platform up at {base} (state: {state_path})")


def stop(args) -> None:
    p = Path(args.state)
    if not p.exists():
        return
    for pid in json.loads(p.read_text()).get("pids", {}).values():
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    p.unlink()
    print("scratch platform stopped")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["start", "stop"])
    ap.add_argument("--platform-dir", default=os.environ.get("SCRATCH_PLATFORM_DIR"))
    ap.add_argument("--database-url", default=os.environ.get("SCRATCH_DATABASE_URL"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("SCRATCH_PLATFORM_PORT", "3329")))
    ap.add_argument("--state", default=str(REPO / ".scratch" / "state.json"))
    ap.add_argument("--platform-commit", default=VECTORS["contract"]["platform_commit"])
    args = ap.parse_args()
    if args.cmd == "stop":
        stop(args)
        return
    if not args.platform_dir or not args.database_url:
        sys.exit("--platform-dir and --database-url (or SCRATCH_PLATFORM_DIR / SCRATCH_DATABASE_URL) are required")
    start(args)


if __name__ == "__main__":
    main()
