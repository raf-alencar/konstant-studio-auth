"""Compatibility: the Python v1 surface (what image-konstant-studio imports) must keep
working untouched. These tests pin the behaviour of every v1 dependency, so a change that
alters one fails here before it reaches an adopter. They describe v1 exactly: they also pass
against the untouched 0.1.0 code, except the deprecation test."""

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

import konstant_studio_auth as lib
from konstant_studio_auth import auth as legacy

ISSUER = "https://clerk.legacy.test"
KID = "legacy-kid"


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setenv("KSA_SILENCE_DEPRECATIONS", "1")
    monkeypatch.delenv("INTERNAL_API_KEY", raising=False)
    monkeypatch.delenv("PLATFORM_API_URL", raising=False)
    legacy._reset_entitlement_cache()
    legacy._JWKS_CACHE.clear()
    yield
    legacy._reset_entitlement_cache()
    legacy._JWKS_CACHE.clear()


@pytest.fixture(scope="module")
def clerk_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub = key.public_key().public_numbers()
    import base64

    def b64u(n):
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    return pem, {"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": KID, "n": b64u(pub.n), "e": b64u(pub.e)}]}


def token(clerk_key, **claims):
    pem, jwks = clerk_key
    legacy._JWKS_CACHE[ISSUER] = jwks  # no network: the cache is the JWKS source
    base = {"sub": "user_legacy", "iss": ISSUER, "iat": int(time.time()), "exp": int(time.time()) + 600}
    return jose_jwt.encode({**base, **claims}, pem, algorithm="RS256", headers={"kid": KID})


def app_with(*routes):
    app = FastAPI()
    for path, dep in routes:
        app.get(path)(lambda auth=Depends(dep): {"user_id": auth.user_id, "org_id": auth.org_id, "org_role": auth.org_role, "is_superadmin": auth.is_superadmin})
    return TestClient(app)


def test_export_surface_is_unchanged():
    for name in ["AuthState", "clerk_protect", "get_brand_id", "m2m_auth", "protect_or_m2m", "require_service", "superadmin_only", "webhooks_router", "on_webhook_event"]:
        assert name in lib.__all__ and hasattr(lib, name), name


def test_importing_the_package_does_not_import_v2():
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-c", "import sys, konstant_studio_auth; print(any(m.startswith('konstant_studio_auth.v2') for m in sys.modules))"],
        capture_output=True, text=True, cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1]),
    )
    assert out.stdout.strip() == "False", out.stderr


def test_clerk_protect_session_and_cookie(clerk_key):
    c = app_with(("/me", lib.clerk_protect))
    assert c.get("/me").status_code == 401
    t = token(clerk_key, org_id="org_a", org_role="admin")
    r = c.get("/me", headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 200
    assert r.json() == {"user_id": "user_legacy", "org_id": "org_a", "org_role": "admin", "is_superadmin": False}
    assert c.get("/me", cookies={"__session": t}).status_code == 200
    assert c.get("/me", headers={"Authorization": "Bearer not.a.jwt"}).status_code == 401
    expired = token(clerk_key, exp=int(time.time()) - 600)
    assert c.get("/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_superadmin_only_and_get_brand_id(clerk_key):
    c = app_with(("/admin", lib.superadmin_only))
    plain = token(clerk_key, org_id="org_a")
    assert c.get("/admin", headers={"Authorization": f"Bearer {plain}"}).status_code == 403
    root = token(clerk_key, public_metadata={"superadmin": True})
    assert c.get("/admin", headers={"Authorization": f"Bearer {root}"}).status_code == 200
    assert lib.get_brand_id(lib.AuthState("u", "org_a", None, False)) == "org_a"
    assert lib.get_brand_id(lib.AuthState("u", "org_a", None, True)) is None  # Python v1: superadmin = all brands


def test_m2m_and_protect_or_m2m(monkeypatch, clerk_key):
    monkeypatch.setenv("INTERNAL_API_KEY", "fake-shared-key")
    c = app_with(("/m2m", lib.m2m_auth), ("/either", lib.protect_or_m2m))
    assert c.get("/m2m").status_code == 401
    assert c.get("/m2m", headers={"X-API-Key": "nope"}).json() == {"detail": "Invalid API key"}
    ok = c.get("/m2m", headers={"X-API-Key": "fake-shared-key"})
    assert ok.json() == {"user_id": "system", "org_id": None, "org_role": None, "is_superadmin": True}
    assert c.get("/either", headers={"X-API-Key": "fake-shared-key"}).json()["user_id"] == "system"
    assert c.get("/either", headers={"Authorization": f"Bearer {token(clerk_key)}"}).json()["user_id"] == "user_legacy"
    assert c.get("/either").status_code == 401
    monkeypatch.delenv("INTERNAL_API_KEY")
    assert c.get("/m2m", headers={"X-API-Key": "anything"}).status_code == 401, "an unset key never matches"


def test_require_service_semantics(monkeypatch, clerk_key):
    calls = []
    result = {"value": {"social"}}

    async def fake_fetch(org_id):
        calls.append(org_id)
        return result["value"]

    monkeypatch.setattr(legacy, "_fetch_entitlements", fake_fetch)
    c = app_with(("/social", lib.require_service("social")), ("/video", lib.require_service("video")))
    org = {"Authorization": f"Bearer {token(clerk_key, org_id='org_a')}"}

    assert c.get("/social", headers=org).status_code == 200
    c.get("/social", headers=org)
    assert calls == ["org_a"], "cached for 60s per org"

    denied = c.get("/video", headers=org)
    assert denied.status_code == 403
    assert denied.json()["detail"] == {"error": "No access to this service", "upgrade_url": "https://www.konstant-studio.com/dashboard"}

    assert c.get("/social", headers={"Authorization": f"Bearer {token(clerk_key)}"}).status_code == 403, "no org => no access"
    root = {"Authorization": f"Bearer {token(clerk_key, public_metadata={'superadmin': True})}"}
    assert c.get("/social", headers=root).status_code == 200, "superadmin bypasses"

    # platform unreachable: dev allows, production fails closed
    legacy._reset_entitlement_cache()
    result["value"] = None
    assert c.get("/social", headers={"Authorization": f"Bearer {token(clerk_key, org_id='org_b')}"}).status_code == 200
    monkeypatch.setenv("ENV", "production")
    legacy._reset_entitlement_cache()
    r = c.get("/social", headers={"Authorization": f"Bearer {token(clerk_key, org_id='org_c')}"})
    assert (r.status_code, r.json()["detail"]) == (503, "Entitlement service unavailable")


def test_webhook_router_refuses_unsigned_deliveries(monkeypatch):
    import base64

    app = FastAPI()
    app.include_router(lib.webhooks_router)
    c = TestClient(app)
    post = lambda headers: c.post("/webhooks/clerk", content=b"{}", headers={"content-type": "application/json", **headers})
    svix = {"svix-id": "msg_fake", "svix-timestamp": str(int(time.time())), "svix-signature": "v1,AAAA"}

    assert post({}).status_code == 422, "the three svix headers are required"
    monkeypatch.delenv("CLERK_WEBHOOK_SECRET", raising=False)
    assert post(svix).status_code == 500, "a missing secret is a server error, never an accept"
    monkeypatch.setenv("CLERK_WEBHOOK_SECRET", "whsec_" + base64.b64encode(b"fake-secret-for-tests").decode())
    assert post(svix).status_code == 400, "a bad signature is refused"


def test_deprecations_warn_once_and_change_nothing_else(monkeypatch, caplog):
    monkeypatch.delenv("KSA_SILENCE_DEPRECATIONS", raising=False)
    monkeypatch.setenv("INTERNAL_API_KEY", "fake-shared-key")
    legacy._warned.clear()
    c = app_with(("/m2m", lib.m2m_auth))
    with caplog.at_level("WARNING"), pytest.warns(DeprecationWarning, match="m2m_auth is deprecated"):
        assert c.get("/m2m", headers={"X-API-Key": "fake-shared-key"}).status_code == 200
    first = [r for r in caplog.records if "deprecated" in r.getMessage()]
    assert len(first) == 1
    caplog.clear()
    c.get("/m2m", headers={"X-API-Key": "fake-shared-key"})
    assert not [r for r in caplog.records if "deprecated" in r.getMessage()], "once per process"
