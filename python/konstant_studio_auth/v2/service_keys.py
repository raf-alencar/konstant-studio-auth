"""Inbound SERVICE keys (stgs_...): another internal service calling an app.

END STATE (CoS amendment to the C0c CR, 2026-10-01): the platform resolves a
stgs_ key into a `service` principal exactly like the other credential
kinds; apps never hold a key table. That platform work ("C0b2") has not
landed: on the accepted C0b branch a stgs_ key presented as a credential is
answered `unsupported_credential` (tests/test_c0b_authorize.py).

So this is the ONE isolated place that knows about it. Mode 'stub' (the
default) behaves exactly like the platform does today. Mode 'platform' is
the switch to flip once C0b2 ships; its response mapping below is the shape
the amendment specifies and has NOT been verified against a real platform.
The service-key vectors stay `pending-platform` until it has.

Principal shape (as the platform will return it):
  {kind: 'service', service: '<slug>', routes: ['METHOD /glob', ...], tenant: None}
A service principal holds no tenant permissions unless explicitly granted,
is never an approver, and may call only the routes in its allow-list.
"""

import re

from .clerk import Denied
from .platform_client import PlatformUnavailable


async def resolve_service_key(raw, mode, client):
    if mode != "platform":
        raise Denied("unsupported_credential")
    try:
        res = await client.resolve({"credential": raw})
    except PlatformUnavailable:
        raise Denied("platform_unavailable") from None
    if not res.get("valid"):
        raise Denied(res.get("reason") or "key_not_found")
    p = res.get("principal") or {}
    if p.get("kind") != "service":
        raise Denied("unsupported_credential")
    routes = p.get("routes")
    return {"id": p.get("id"), "service": p.get("service"), "routes": [] if routes is None else routes, "key_id": res.get("key_id")}


def route_allowed(routes, method, path):
    """"METHOD /path/glob" entries; METHOD may be `*`, glob characters are `*` only.
    Same semantics as the platform's route allow-list (app/principal_keys.py)."""
    m = str(method).upper()
    for entry in routes or []:
        parts = str(entry).split(" ")
        em, glob = parts[0], " ".join(parts[1:])
        if em != "*" and em != m:
            continue
        pattern = ".*".join(re.escape(piece) for piece in glob.split("*"))
        if re.fullmatch(pattern, path):
            return True
    return False
