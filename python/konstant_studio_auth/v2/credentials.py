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


def header_values(headers, name):
    """Every value sent for a header, case-insensitively: Starlette/httpx Headers keep repeats
    (getlist/get_list), a plain dict may hold a list, or a ", "-joined string."""
    if not headers:
        return []
    lname = name.lower()
    vals = None
    for getter in ("getlist", "get_list"):
        fn = getattr(headers, getter, None)
        if fn is not None:
            try:
                vals = list(fn(name))
            except Exception:  # noqa: BLE001
                vals = None
            break
    if vals is None:
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
        vals = [] if v is None else list(v) if isinstance(v, (list, tuple)) else [v]
    return [x for x in vals if x is not None]


def header(headers, name):
    vals = header_values(headers, name)
    return vals[0] if vals else None


def _cookie_header(headers):
    vals = header_values(headers, "cookie")
    return "; ".join(vals) if vals else None


def cookie(headers, name):
    """-> the cookie's value, None if absent, or INVALID if it is present MORE THAN ONCE (ambiguous).
    A malformed percent-escape never raises: the raw value is used, and Clerk validation then
    answers token_invalid (a session JWT contains no % at all)."""
    raw = _cookie_header(headers)
    if not raw:
        return None
    found = []
    for part in raw.split(";"):
        i = part.find("=")
        if i > 0 and part[:i].strip() == name:
            found.append(part[i + 1:].strip())
    if not found:
        return None
    if len(found) > 1:
        return INVALID
    try:
        return unquote(found[0], errors="strict")
    except Exception:  # noqa: BLE001
        return found[0]


INVALID = object()


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
    """type: 'key' | 'clerk' | 'audience' | 'none' | 'invalid'."""

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
    """-> Credential. type 'invalid' means the request carried an AMBIGUOUS credential: the same header
    (or cookie) more than once. Repeated header values arrive as a list (Starlette) or joined with ", ",
    and no key or JWT contains a comma, so a comma means "more than one value". Which of two credentials
    the sender meant is not a question to guess at: it is refused (token_invalid), whatever each would have
    resolved to."""
    api_keys = header_values(headers, "x-api-key")
    auths = header_values(headers, "authorization")
    if len(api_keys) > 1 or len(auths) > 1:
        return Credential("invalid")
    api_key = api_keys[0] if api_keys else None
    auth = auths[0] if auths else None
    if (api_key and "," in api_key) or (auth and "," in auth):
        return Credential("invalid")
    session = cookie(headers, "__session")
    if session is INVALID:
        return Credential("invalid")

    bearer = re.sub(r"^bearer\s+", "", auth, flags=re.I).strip() if auth and re.match(r"bearer\s+", auth, re.I) else None
    if api_key and key_kind_of(api_key):
        return classify(api_key)
    if bearer:
        return classify(bearer)
    if api_key:
        return Credential("key", api_key, None)  # not a platform key: key_not_found, not a guess
    if session:
        return classify(session)
    return Credential("none")
