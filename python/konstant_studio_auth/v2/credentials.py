"""What credential did the caller present? The platform's key prefixes say what
kind of principal a key belongs to (app/principal_keys.py), so a key can
never be presented as a different kind. Anything that is not a known key is
handed to Clerk validation, which answers with a clean 401 when it is not a
valid session token (this is what unblocks the CRM iOS bearer path).
"""

import base64
import json
import re
from urllib.parse import unquote

KEY_KINDS = {"stig_": "mcp", "stga_": "agent", "stgg_": "guest", "stgs_": "service"}
MIN_KEY_LENGTH = 20  # the platform treats shorter strings as not a key
PLATFORM_ISS = "stighive-platform"


def header(headers, name):
    """Case-insensitive lookup in a Starlette/httpx Headers or a plain dict."""
    if not headers:
        return None
    lname = name.lower()
    v = None
    try:
        v = headers.get(name)
        if v is None:
            v = headers.get(lname)
    except Exception:  # noqa: BLE001
        v = None
    if v is None and hasattr(headers, "items"):
        for k, val in headers.items():
            if str(k).lower() == lname:
                v = val
                break
    if isinstance(v, (list, tuple)):
        v = v[0] if v else None
    return v


def cookie(headers, name):
    raw = header(headers, "cookie")
    if not raw:
        return None
    for part in raw.split(";"):
        i = part.find("=")
        if i > 0 and part[:i].strip() == name:
            return unquote(part[i + 1:].strip())
    return None


def key_kind_of(raw):
    return KEY_KINDS.get(raw[:5])


def looks_like_jwt(raw):
    return len(raw.split(".")) == 3


def is_audience_token(raw):
    """Audience tokens (POST /v1/tokens/exchange) are JWTs issued by the platform
    itself; they are re-checked live against the source key, never trusted offline."""
    try:
        seg = raw.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode("utf-8"))
        return isinstance(payload, dict) and payload.get("iss") == PLATFORM_ISS
    except Exception:  # noqa: BLE001
        return False


class Credential:
    """type: 'key' | 'clerk' | 'audience' | 'none'."""

    def __init__(self, type, raw=None, key_kind=None):
        self.type = type
        self.raw = raw
        self.key_kind = key_kind

    def __repr__(self):  # never print the raw credential
        return f"Credential(type={self.type!r}, key_kind={self.key_kind!r})"


def classify(raw):
    key_kind = key_kind_of(raw)
    if key_kind:
        return Credential("key", raw, key_kind if len(raw) >= MIN_KEY_LENGTH else None)
    if looks_like_jwt(raw) and is_audience_token(raw):
        return Credential("audience", raw)
    return Credential("clerk", raw)  # includes junk: Clerk validation answers token_invalid


def extract(headers):
    api_key = header(headers, "x-api-key")
    auth = header(headers, "authorization")
    bearer = re.sub(r"^bearer\s+", "", auth, flags=re.I).strip() if auth and re.match(r"bearer\s+", auth, re.I) else None

    if api_key and key_kind_of(api_key):
        return classify(api_key)
    if bearer:
        return classify(bearer)
    if api_key:
        return Credential("key", api_key, None)  # not a platform key: key_not_found, not a guess
    session = cookie(headers, "__session")
    if session:
        return classify(session)
    return Credential("none")
