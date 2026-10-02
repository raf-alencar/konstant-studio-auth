"""Resource lookups: "which tenant owns this service-local id?" and "which local ids does this tenant
have in this service?", answered from the cached snapshot (platform C0f). The platform owns the
brand/company <-> tenant crosswalk; an adopting repo keeps no mapping of its own and asks here.

Each snapshot tenant carries `resources: [{kind, local_id}]` for THIS service only (active rows
only: a retired resource is simply absent). The platform guarantees (service, kind, local_id) maps
to exactly one tenant, so the reverse lookup is a plain dict, built ONCE per snapshot and reused for
every request (a 304 revalidation keeps the same snapshot, and so the same index).

Fail closed, in this order:
  - no usable snapshot (never loaded, unreadable, older than the stale-read window) => unavailable;
  - a snapshot with no `resources` field (a platform without C0f) => unavailable, NEVER "unowned":
    "this platform cannot tell" must not read as "nobody owns it";
  - a local id with no owner => None (callers deny);
  - a local id the snapshot claims for two tenants (a platform bug) => None (deny), logged once;
  - an index larger than `max_resources` => unavailable (memory stays bounded).
"""

import re

# The canonical id rule, one for both languages (it mirrors what the platform's registry can hold, so
# anything it could never hold can never be owned and is refused up front):
#   kind     a lowercase slug, [a-z][a-z0-9_-]{0,63} (the registry's own CHECK);
#   local_id 1-200 characters, no control characters (C0, DEL and the C1 range: the registry's CHECK);
#            compared EXACTLY (case-sensitive, no Unicode normalisation);
#   numbers  an integer id (an image account) is accepted only as a NON-NEGATIVE integer within the safe range
#            (<= 2**53-1), and is then exactly its decimal text. Booleans, floats, objects, negative numbers
#            and anything out of range are refused: nothing is parsed, rounded or stringified into a form the
#            registry might hold ("1.0", "1e3", "+7", "-0"), so a value one language would accept and another
#            refuse cannot exist. (A JavaScript number cannot tell 42.0 from 42; Python refuses EVERY float.
#            That is the one inherent asymmetry and the shared vectors avoid it.)
# fullmatch with explicit classes throughout: `$` would accept a trailing newline.
KIND_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}")
MAX_LOCAL_ID = 200
SAFE_INT = 2**53 - 1
_CONTROL_RE = re.compile("[\u0000-\u001f\u007f-\u009f]")
_CONFLICT = object()


def normalize_id(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if 0 <= value <= SAFE_INT else None
    if isinstance(value, str):
        return value if value != "" and len(value) <= MAX_LOCAL_ID and not _CONTROL_RE.search(value) else None
    return None  # float, bytes, list, dict, None...


def normalize_kind(kind):
    return kind if isinstance(kind, str) and KIND_RE.fullmatch(kind) else None


class ResourceIndex:
    def __init__(self):
        self.supported = True
        self.too_large = False
        self.owners = {}  # kind -> {local_id: tenant_id | _CONFLICT}
        self.by_tenant = {}  # lower(tenant_id) -> {kind: [ids]}
        self.count = 0


def build_index(snapshot, max_resources, logger):
    index = ResourceIndex()
    tenants = snapshot.get("tenants") if isinstance(snapshot, dict) else None
    tenants = tenants if isinstance(tenants, list) else []
    # Zero tenants proves nothing about support, and cannot own anything either way. With tenants, every one
    # of them must carry the field: a platform that has C0f always sends it (an empty list when none).
    if tenants and any(not isinstance(t, dict) or not isinstance(t.get("resources"), list) for t in tenants):
        index.supported = False
        return index
    warned_conflict = False
    for t in tenants:
        for r in t.get("resources") or []:
            r = r if isinstance(r, dict) else {}
            kind = normalize_kind(r.get("kind"))
            rid = normalize_id(r.get("local_id"))
            if kind is None or rid is None:
                continue  # a malformed entry can never grant ownership
            index.count += 1
            if index.count > max_resources:
                index.too_large = True
                logger.error(f"resource index larger than {max_resources} entries: lookups are refused")
                index.owners, index.by_tenant = {}, {}
                return index
            by_id = index.owners.setdefault(kind, {})
            have = by_id.get(rid)
            if have is None:
                by_id[rid] = t.get("id")
            elif have != t.get("id"):
                by_id[rid] = _CONFLICT
                if not warned_conflict:
                    warned_conflict = True
                    logger.error("the snapshot gives one local id to two tenants: that id is refused (deny) until the platform is fixed")
            index.by_tenant.setdefault(str(t.get("id")).lower(), {}).setdefault(kind, []).append(rid)
    for kinds in index.by_tenant.values():
        for ids in kinds.values():
            ids.sort()
    return index


def owner_of(index, kind, local_id):
    k = normalize_kind(kind)
    rid = normalize_id(local_id)
    if k is None or rid is None:
        return None
    owner = index.owners.get(k, {}).get(rid)
    return None if owner is None or owner is _CONFLICT else owner


def ids_of(index, tenant_id, kind):
    k = normalize_kind(kind)
    if k is None or not isinstance(tenant_id, str):
        return []
    return list(index.by_tenant.get(tenant_id.lower(), {}).get(k, []))
