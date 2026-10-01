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


MESSAGES = {
    "step_up_required": (
        "This action needs a fresh second-factor verification, and the session token does not carry one that is recent enough "
        "(multi-factor sign-in must be enabled for the account and the session token must include the fva claim). "
        "Sign in again with your second factor. Until the fva claim is confirmed for this deployment this action is denied."
    ),
}


def denial_body(status, reason, cfg):
    error = "No access to this service" if reason == "not_entitled" else BODIES.get(status, "Forbidden")
    body = {"error": error, "reason": reason}
    if reason in MESSAGES:
        body["message"] = MESSAGES[reason]
    if reason == "not_entitled":
        body["upgrade_url"] = cfg.upgrade_url
    return body


def legacy_auth(principal, decision):
    """The shape existing adopters read from request.state.auth, so v2 dependencies can sit behind code
    written for v1. Authority is never derived from it: is_superadmin is always False here, because in v2
    only the permission matrix grants anything.

    `org_id` / `org_role` are deliberately GONE. In v1 the Clerk org WAS the scoping key; in v2 the request
    may be about a different tenant than the token's org (a route's tenant, an agency view), and a handler
    that authorises on the decision but scopes its data by the token's org would mix tenants. The ONLY
    scoping key is `tenant_id` (= decision.tenant_id). The token's Clerk org is kept as `clerk_org_id` /
    `clerk_org_role` for display and logs; never scope data by it."""
    claims = principal.claims or {}
    return {
        "user_id": f"service:{principal.service}" if principal.kind == "service" else principal.user_id or principal.id or None,
        "clerk_org_id": claims.get("org_id"),
        "clerk_org_role": claims.get("org_role"),
        "is_superadmin": False,
        "tenant_id": decision.tenant_id,
    }


_NOT_PRINTABLE = re.compile(r"[^\x20-\x7e]")


def clean_run_id(value):
    """X-Run-Id is caller-supplied and ends up in audit events: printable ASCII only, bounded."""
    if value is None:
        return None
    return _NOT_PRINTABLE.sub("", str(value))[:128] or None
