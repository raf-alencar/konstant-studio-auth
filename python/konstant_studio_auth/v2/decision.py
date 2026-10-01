"""Offline authorization decision from a snapshot. This is a line-for-line
mirror of the platform's `decide()` (app/authz.py on the C0b branch) for the
subset a cached snapshot can answer: HUMAN principals, permissions of the
snapshot's own service, a NAMED tenant, non-sensitive. Everything else goes
to POST /v1/authorize. The parity test runs every vector against the real
platform; a divergence is a bug here, never an accepted difference.

Order (first failure is the reason), as in docs/control-plane.md:
  unknown_permission -> tenant not entitled -> kind restriction ->
  no_permission -> scope.
"""

import re
from datetime import datetime, timezone

SCOPE_DIMENSIONS = [("brand_ids", "brand"), ("domains", "domain"), ("mailboxes", "mailbox")]
SCOPE_KEYS = {"brand_ids", "domains", "mailboxes", "descendants"}


def _js_str(v):
    # String(x).toLowerCase() as in decision.js, so True compares as "true", not "True".
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    return str(v).lower()


def scope_allows(scope, resource):
    """None when the resource is inside the scope, else the deny reason. A
    restricted dimension the request does not name fails closed, and so does any
    scope key we do not know (a typo must never read as "no restriction")."""
    if not isinstance(scope, dict):
        return "out_of_scope"
    for key in scope:
        if key not in SCOPE_KEYS:
            return "out_of_scope"
    for dim, field in SCOPE_DIMENSIONS:
        if dim not in scope:
            continue
        allowed = scope[dim]
        if not isinstance(allowed, list):
            return "out_of_scope"
        value = resource.get(field)
        if value is None or value == "":
            return "scope_required"
        if not any(_js_str(a) == _js_str(value) for a in allowed):
            return "out_of_scope"
    return None


def kind_restricted(kind, category):
    """True when a principal of this kind may never hold a permission of this category."""
    return (kind == "guest" and category != "read") or (kind == "agent" and category == "approve")


_ISO = re.compile(
    r"^(\d{4})-(\d\d)-(\d\d)(?:[T ](\d\d):(\d\d)(?::(\d\d)(?:[.,](\d+))?)?)?\s*(Z|[+-]\d\d(?::?\d\d)?)?$", re.I
)


def parse_ms(value):
    """Date.parse(): epoch milliseconds, or None where JS would give NaN (callers deny on None). Done by hand
    because fromisoformat on 3.10 rejects 'Z' and fractions that are not 3 or 6 digits."""
    if not isinstance(value, str):
        return None
    m = _ISO.match(value.strip())
    if not m:
        return None
    y, mo, d, hh, mi, ss, frac, tz = m.groups()
    try:
        base = datetime(int(y), int(mo), int(d), int(hh or 0), int(mi or 0), int(ss or 0), tzinfo=timezone.utc)
    except ValueError:
        return None
    ms = int(base.timestamp()) * 1000 + (int((frac + "000")[:3]) if frac else 0)
    if tz and tz.upper() != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        off = int(digits[:2]) * 60 + int(digits[2:4] or 0)
        ms -= sign * off * 60000
    return ms


def in_window(t, now_ms):
    """Entitlement windows are data: apply them against the consumer's clock.
    Written as positive comparisons so an unparseable timestamp fails closed, never open."""
    if t.get("starts_at"):
        starts = parse_ms(t["starts_at"])
        if not (starts is not None and starts <= now_ms):
            return False
    if t.get("ends_at"):
        ends = parse_ms(t["ends_at"])
        if not (ends is not None and ends > now_ms):
            return False
    return True


def _deny(reason, tenant_id=None, sensitive=False):
    return {
        "allow": False, "reason": reason, "tenant_id": tenant_id, "via_tenant": None,
        "roles": [], "permissions": [], "sensitive": sensitive, "ancestry": [],
    }


def decide_offline(snapshot, principal, service, action, resource, now_ms):
    """`principal` is anything with .user_id and .kind (default 'human')."""
    user_id = principal.user_id
    kind = principal.kind or "human"

    perm = next((p for p in snapshot["permissions"] if p["action"] == action), None)
    if snapshot["service"] != service or not perm:
        return _deny("unknown_permission")
    sensitive = bool(perm.get("sensitive"))
    tenant_id = resource.get("tenant")

    # The snapshot lists only tenants that are active AND have the entitlement 'on',
    # so absence covers not-entitled, suspended and inactive alike (see COARSE_OFFLINE).
    tenant = next((t for t in snapshot["tenants"] if t["id"] == tenant_id), None)
    if not tenant or not in_window(tenant, now_ms):
        return _deny("not_entitled", tenant_id, sensitive)

    if kind_restricted(kind, perm.get("category")):
        return _deny("principal_kind_restricted", tenant_id, sensitive)

    roles_by_id = {r["id"]: r for r in snapshot["roles"]}
    wanted = {f"{service}:{action}", f"{service}:*"}
    reach = {tenant_id, *tenant["ancestors"]}

    candidates = []
    held = set()
    for m in snapshot["memberships"]:
        if m.get("kind") != kind or m.get("user_id") != user_id:
            continue
        if m.get("expires_at"):
            exp = parse_ms(m["expires_at"])
            if not (exp is not None and exp > now_ms):  # unparseable counts as expired
                continue
        here = m["tenant_id"] == tenant_id
        # Agency view: a HUMAN membership with scope.descendants on an ancestor applies below it. Never upward or sideways.
        # (The platform compares scope->>'descendants' to 'true', which the JSON string "true" also satisfies.)
        mscope = m.get("scope")
        d = mscope.get("descendants") if isinstance(mscope, dict) else None
        opted = d is True or d == "true"
        inherited = not here and kind == "human" and opted and m["tenant_id"] in reach
        if not here and not inherited:
            continue
        role = roles_by_id.get(m["role_id"])
        # A custom role counts only inside its own tenant.
        if not role or (role.get("tenant_id") is not None and role["tenant_id"] != m["tenant_id"]):
            continue
        for p in role["permissions"]:
            if p.startswith(f"{service}:"):
                held.add(p)
        if any(p in wanted for p in role["permissions"]):
            candidates.append((m, role))
    if not candidates:
        return _deny("no_permission", tenant_id, sensitive)

    first_failure = None
    for m, _role in candidates:
        failure = scope_allows(m.get("scope"), resource)
        if failure is None:
            permissions = []
            for p in held:
                if p.endswith(":*"):
                    permissions.extend(f"{service}:{q['action']}" for q in snapshot["permissions"])
                else:
                    permissions.append(p)
            return {
                "allow": True,
                "reason": "allowed",
                "tenant_id": tenant_id,
                "via_tenant": m["tenant_id"] if m["tenant_id"] != tenant_id else None,
                "roles": sorted({r["slug"] for _, r in candidates}),
                "permissions": sorted(set(permissions)),
                "sensitive": sensitive,
                "ancestry": tenant["ancestors"],
            }
        first_failure = first_failure or failure
    return _deny(first_failure, tenant_id, sensitive)
