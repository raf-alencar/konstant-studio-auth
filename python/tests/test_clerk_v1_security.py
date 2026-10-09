"""CR-L1: the v1 Python Clerk verification (clerk_protect, protect_or_m2m, superadmin_only) is pinned to
configuration. These tests use REAL local HTTP servers that record every request they receive, so "the server
fetched nothing" is checked, not assumed. Nothing here talks to a real host; every key and token is generated
for the test and never printed."""

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

import konstant_studio_auth as lib
from konstant_studio_auth import auth as v1
from konstant_studio_auth.v2.config import ConfigError

ISSUER = "https://clerk.example.test"  # pinned by configuration; the host is never contacted
AZP = "https://app.example.test"
KID = "pinned-kid"


def _keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub = key.public_key().public_numbers()

    def b64u(n):
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    return pem, {"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": KID, "n": b64u(pub.n), "e": b64u(pub.e)}]}


class KeyServer:
    """A local key-set server that records every request it gets. `mode`: ok | error | garbage | redirect."""

    def __init__(self, jwks, mode="ok", redirect_to=None):
        self.jwks, self.mode, self.redirect_to, self.requests = jwks, mode, redirect_to, []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.requests.append(("GET", self.path))
                if outer.mode == "error":
                    self.send_response(500)
                    self.end_headers()
                elif outer.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_to)
                    self.end_headers()
                else:
                    body = b"<<not json" if outer.mode == "garbage" else json.dumps(outer.jwks).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *args):  # silence
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture(scope="module")
def keys():
    return {"trusted": _keypair(), "attacker": _keypair()}


@pytest.fixture
def world(keys, monkeypatch):
    legit = KeyServer(keys["trusted"][1])
    attacker = KeyServer(keys["attacker"][1])
    internal = KeyServer({"keys": []})  # stands in for "an internal address the token names"
    monkeypatch.setenv("CLERK_ISSUER", ISSUER)
    monkeypatch.setenv("CLERK_JWKS_URL", f"{legit.url}/jwks.json")
    monkeypatch.setenv("CLERK_AUTHORIZED_PARTIES", AZP)
    monkeypatch.delenv("CLERK_AUDIENCE", raising=False)
    monkeypatch.setenv("KSA_SILENCE_DEPRECATIONS", "1")
    monkeypatch.delenv("INTERNAL_API_KEY", raising=False)
    v1._reset_clerk_verifier()
    app = FastAPI()
    for path, dep in (("/me", lib.clerk_protect), ("/either", lib.protect_or_m2m), ("/admin", lib.superadmin_only)):
        app.get(path)(lambda auth=Depends(dep): {"user_id": auth.user_id, "is_superadmin": auth.is_superadmin})
    yield type("W", (), {"legit": legit, "attacker": attacker, "internal": internal, "client": TestClient(app), "keys": keys})
    for server in (legit, attacker, internal):
        server.stop()
    v1._reset_clerk_verifier()


def mint(key, iss=ISSUER, azp=AZP, kid=KID, headers=None, **claims):
    pem, _ = key
    body = {"sub": "user_victim", "iss": iss, "iat": int(time.time()), "exp": int(time.time()) + 600, **claims}
    if azp is not None:
        body["azp"] = azp
    return jose_jwt.encode(body, pem, algorithm="RS256", headers={"kid": kid, **(headers or {})})


def call(world, path, token):
    return world.client.get(path, headers={"Authorization": f"Bearer {token}"})


def no_requests(world):
    assert world.legit.requests == [], "the legitimate key server was contacted for a refused token"
    assert world.attacker.requests == [], "a token-supplied URL was contacted"
    assert world.internal.requests == [], "an internal address named by a token was contacted"


# ---- the attack from the CR ---------------------------------------------------------------------------------------

def test_forged_issuer_token_is_refused_and_nothing_is_fetched(world):
    # signed by the attacker, issuer = the attacker's own key server, claims to be a superadmin
    forged = mint(world.keys["attacker"], iss=world.attacker.url, public_metadata={"superadmin": True})
    for path in ("/me", "/either", "/admin"):
        r = call(world, path, forged)
        assert r.status_code == 401, (path, r.status_code)
        assert r.json() == {"detail": "Invalid token"} or r.json() == {"detail": "Unauthorized"}
    no_requests(world)


def test_forged_token_naming_an_internal_address_causes_no_request(world):
    forged = mint(world.keys["attacker"], iss=world.internal.url, public_metadata={"superadmin": True})
    assert call(world, "/me", forged).status_code == 401
    no_requests(world)


def test_a_forged_token_cannot_choose_where_keys_come_from_via_header_urls(world):
    for header in ({"jku": f"{world.attacker.url}/jwks.json"}, {"x5u": f"{world.attacker.url}/cert.pem"}, {"jwk": world.keys["attacker"][1]["keys"][0]}):
        forged = mint(world.keys["attacker"], iss=world.attacker.url, headers=header, public_metadata={"superadmin": True})
        assert call(world, "/admin", forged).status_code == 401
        # ...and the same headers on a token that IS valid are simply ignored: it verifies against the configured keys
        assert call(world, "/me", mint(world.keys["trusted"], headers=header)).status_code == 200
    assert world.attacker.requests == [] and world.internal.requests == []
    assert {path for _, path in world.legit.requests} == {"/jwks.json"}, "only the configured key-set URL is ever fetched"


def test_many_forged_issuers_cost_nothing_and_the_cache_does_not_grow(world):
    for i in range(300):
        assert call(world, "/me", mint(world.keys["attacker"], iss=f"https://tenant{i}.evil.test")).status_code == 401
    no_requests(world)
    assert v1._clerk_verifier is None or len(v1._clerk_verifier[1].keys or []) <= 1, "a single pinned key set, never one per issuer"


LOOKALIKES = [
    ISSUER + "/",                          # trailing slash
    "http://clerk.example.test",           # scheme
    ISSUER + ".evil.test",                 # suffix / parent-domain look-alike
    "https://clerk.example.test@evil.test",  # userinfo trick
    "https://evil.clerk.example.test",     # subdomain
    "https://clerk.example.testx",         # prefix of a longer name
    ISSUER + "/extra",                     # path
    "HTTPS://CLERK.EXAMPLE.TEST",          # case
    ISSUER + ":443",                       # explicit port
    " " + ISSUER,                          # leading whitespace
    ISSUER + "\n",                         # trailing newline
    ISSUER[:-1],                           # prefix of the real one
    "",                                    # empty
]


@pytest.mark.parametrize("issuer", LOOKALIKES)
def test_look_alike_issuers_are_refused_even_when_the_signature_is_valid(world, issuer):
    # signed by the TRUSTED key, so only the issuer check can refuse it
    token = mint(world.keys["trusted"], iss=issuer, public_metadata={"superadmin": True})
    for path in ("/me", "/admin"):
        assert call(world, path, token).status_code == 401, (issuer, path)
    no_requests(world)


@pytest.mark.parametrize("iss", [None, 123, ["https://clerk.example.test"], {"u": ISSUER}, True])
def test_missing_or_non_string_issuer_is_refused(world, iss):
    pem, _ = world.keys["trusted"]
    claims = {"sub": "u", "iat": int(time.time()), "exp": int(time.time()) + 600, "azp": AZP}
    if iss is not None:
        claims["iss"] = iss
    token = jose_jwt.encode(claims, pem, algorithm="RS256", headers={"kid": KID})
    assert call(world, "/me", token).status_code == 401
    no_requests(world)


# ---- azp ------------------------------------------------------------------------------------------------------------

def test_missing_or_wrong_azp_is_refused(world):
    trusted = world.keys["trusted"]
    assert call(world, "/me", mint(trusted, azp=None)).status_code == 401, "no azp"
    assert call(world, "/me", mint(trusted, azp="https://other-app.example.test")).status_code == 401, "wrong azp"
    assert call(world, "/me", mint(trusted, azp="")).status_code == 401, "empty azp"
    assert call(world, "/me", mint(trusted, azp=[AZP])).status_code == 401, "azp that is not a string"
    assert call(world, "/me", mint(trusted, azp=AZP)).status_code == 200, "the configured azp"


# ---- superadmin -----------------------------------------------------------------------------------------------------

def test_superadmin_only_ever_comes_from_the_pinned_issuer(world):
    trusted, attacker = world.keys["trusted"], world.keys["attacker"]
    forged = mint(attacker, iss=world.attacker.url, public_metadata={"superadmin": True})
    assert call(world, "/admin", forged).status_code == 401, "foreign issuer, claims superadmin"
    assert call(world, "/admin", mint(attacker, public_metadata={"superadmin": True})).status_code == 401, "right issuer string, wrong key"
    assert call(world, "/admin", mint(trusted)).status_code == 403, "pinned issuer, not a superadmin"
    assert call(world, "/admin", mint(trusted, public_metadata={"superadmin": "true"})).status_code == 403, "a string is not True"
    ok = call(world, "/admin", mint(trusted, public_metadata={"superadmin": True}))
    assert (ok.status_code, ok.json()["is_superadmin"]) == (200, True), "the pinned issuer's own claim still works"


def test_protect_or_m2m_with_a_forged_token_falls_back_to_nothing(world):
    forged = mint(world.keys["attacker"], iss=world.attacker.url, public_metadata={"superadmin": True})
    assert call(world, "/either", forged).status_code == 401
    no_requests(world)


# ---- key-fetch failures are documented errors, never a 500 ------------------------------------------------------------

@pytest.mark.parametrize("mode", ["error", "garbage"])
def test_a_key_server_failure_is_a_503_not_a_500(world, mode):
    world.legit.mode = mode
    r = call(world, "/me", mint(world.keys["trusted"]))
    assert r.status_code == 503
    assert r.json() == {"detail": "Authentication service temporarily unavailable"}
    assert r.headers.get("retry-after") == "10"


def test_an_unreachable_key_server_is_a_503_not_a_500(world, monkeypatch):
    world.legit.stop()
    r = call(world, "/me", mint(world.keys["trusted"]))
    assert r.status_code == 503 and r.json() == {"detail": "Authentication service temporarily unavailable"}


def test_a_failing_key_server_is_not_hammered(world):
    world.legit.mode = "error"
    token = mint(world.keys["trusted"])
    for _ in range(12):
        assert call(world, "/me", token).status_code == 503
    assert len(world.legit.requests) == 1, "one attempt, then a back-off: not one fetch per request"


def test_a_redirecting_key_server_is_not_followed(world):
    world.legit.mode = "redirect"
    world.legit.redirect_to = f"{world.attacker.url}/jwks.json"
    assert call(world, "/me", mint(world.keys["trusted"])).status_code == 503
    assert world.attacker.requests == [] and world.internal.requests == []


def test_after_the_outage_the_service_recovers(world, monkeypatch):
    world.legit.mode = "error"
    token = mint(world.keys["trusted"])
    assert call(world, "/me", token).status_code == 503
    world.legit.mode = "ok"
    real = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real() + 3600)  # past the back-off window
    assert call(world, "/me", token).status_code == 200


# ---- correct issuer and key still verify -------------------------------------------------------------------------------

def test_the_pinned_issuer_with_its_key_verifies_and_fetches_only_the_configured_url(world):
    r = call(world, "/me", mint(world.keys["trusted"], org_id="org_a"))
    assert (r.status_code, r.json()["user_id"]) == (200, "user_victim")
    assert world.legit.requests == [("GET", "/jwks.json")]
    call(world, "/me", mint(world.keys["trusted"]))
    assert len(world.legit.requests) == 1, "the key set is cached"
    no_requests_elsewhere = world.attacker.requests == [] and world.internal.requests == []
    assert no_requests_elsewhere


def test_a_key_the_configured_set_does_not_contain_is_refused(world):
    assert call(world, "/me", mint(world.keys["trusted"], kid="unknown-kid")).status_code == 401


def test_expired_and_unsigned_tokens_are_refused(world):
    pem, _ = world.keys["trusted"]
    assert call(world, "/me", mint(world.keys["trusted"], exp=int(time.time()) - 3600)).status_code == 401
    unsigned = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode() + "." + base64.urlsafe_b64encode(
        json.dumps({"sub": "u", "iss": ISSUER, "azp": AZP, "exp": int(time.time()) + 600, "iat": int(time.time()), "public_metadata": {"superadmin": True}}).encode()).rstrip(b"=").decode() + "."
    assert call(world, "/admin", unsigned).status_code == 401
    hs = jose_jwt.encode({"sub": "u", "iss": ISSUER, "azp": AZP, "iat": int(time.time()), "exp": int(time.time()) + 600}, "x" * 32, algorithm="HS256", headers={"kid": KID})
    assert call(world, "/me", hs).status_code == 401, "algorithm confusion"


# ---- not configured: a loud refusal, not trust ----------------------------------------------------------------------------

def test_not_configured_refuses_every_token_loudly(world, monkeypatch, caplog):
    monkeypatch.delenv("CLERK_ISSUER")
    monkeypatch.delenv("CLERK_JWKS_URL")
    v1._reset_clerk_verifier()
    forged = mint(world.keys["attacker"], iss=world.attacker.url, public_metadata={"superadmin": True})
    with caplog.at_level("ERROR"):
        for token in (forged, mint(world.keys["trusted"])):
            r = call(world, "/admin", token)
            assert (r.status_code, r.json()) == (503, {"detail": "Authentication is not configured"})
    assert any("CLERK_ISSUER is not set" in rec.getMessage() for rec in caplog.records), "the refusal is logged"
    assert len([rec for rec in caplog.records if "CLERK_ISSUER is not set" in rec.getMessage()]) == 1, "once, not per request"
    no_requests(world)
    with pytest.raises(ConfigError):
        lib.require_clerk_config()


def test_an_issuer_without_authorized_parties_is_a_misconfiguration_not_a_free_for_all(world, monkeypatch):
    monkeypatch.delenv("CLERK_AUTHORIZED_PARTIES")
    v1._reset_clerk_verifier()
    r = call(world, "/me", mint(world.keys["trusted"]))
    assert (r.status_code, r.json()) == (503, {"detail": "Authentication is not configured"})
    with pytest.raises(ConfigError):
        lib.require_clerk_config()


def test_require_clerk_config_passes_when_configured(world):
    lib.require_clerk_config()  # no raise


def test_the_old_verifier_is_gone():
    for name in ("_get_jwks", "_JWKS_CACHE"):
        assert not hasattr(v1, name), f"{name} (the token-supplied-issuer path) must not exist"
    src = open(v1.__file__).read()
    assert "get_unverified_claims" not in src and 'unverified.get("iss")' not in src


def test_requests_without_a_token_never_touch_the_verifier(world):
    assert world.client.get("/me").status_code == 401
    no_requests(world)
