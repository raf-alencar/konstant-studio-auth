"""Pieces the adapters use: turning a `scope` option into the resource a
decision is about, and the response bodies. Bodies carry the reason code and
nothing else a caller could not already know: no tenant ids, no principal
details, no platform error text.
"""

import inspect
import re

BODIES = {401: "Unauthorized", 403: "Forbidden", 503: "Authorization service unavailable"}
SCOPE_FIELDS = ("tenant", "brand", "domain", "mailbox")


async def resolve_scope(scope, *args):
    """scope: {tenant, brand, domain, mailbox}, each a str or callable(*args) -> str|None (sync or async)."""
    out = {}
    for field in SCOPE_FIELDS:
        v = (scope or {}).get(field)
        if callable(v):
            v = v(*args)
            if inspect.isawaitable(v):
                v = await v
        if v is not None and v != "":
            out[field] = str(v)
    return out


def denial_body(status, reason, cfg):
    error = "No access to this service" if reason == "not_entitled" else BODIES.get(status, "Forbidden")
    body = {"error": error, "reason": reason}
    if reason == "not_entitled":
        body["upgrade_url"] = cfg.upgrade_url
    return body


def legacy_auth(principal, decision):
    """The shape existing adopters read from request.state.auth (see README "What you get"),
    so v2 dependencies can sit behind code written for v1. Authority is never derived from
    it: is_superadmin is always False here, because in v2 only the permission matrix grants anything."""
    claims = principal.claims or {}
    return {
        "user_id": principal.user_id or principal.id or None,
        "org_id": claims.get("org_id"),
        "org_role": claims.get("org_role"),
        "is_superadmin": False,
        "tenant_id": decision.tenant_id,
    }


_NOT_PRINTABLE = re.compile(r"[^\x20-\x7e]")


def clean_run_id(value):
    """X-Run-Id is caller-supplied and ends up in audit events: printable ASCII only, bounded."""
    if value is None:
        return None
    return _NOT_PRINTABLE.sub("", str(value))[:128] or None
