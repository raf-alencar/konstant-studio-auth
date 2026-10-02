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

MAX_ID_LENGTH = 256
SAFE_INT = 2**53 - 1
_CONFLICT = object()


def normalize_id(value):
    """A local id as the services keep them: text, but an integer id (an image account) is the same thing
    as its decimal text. Anything else cannot name a resource. (A bool is not an int id; an integer beyond
    JS's safe range is refused, as Node refuses such a number.)"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if abs(value) <= SAFE_INT else None
    if isinstance(value, float):
        return str(int(value)) if value == value and value not in (float("inf"), float("-inf")) and value.is_integer() and abs(value) <= SAFE_INT else None
    if isinstance(value, str) and value != "" and len(value) <= MAX_ID_LENGTH:
        return value
    return None


def normalize_kind(kind):
    return kind if isinstance(kind, str) and kind != "" and len(kind) <= MAX_ID_LENGTH else None


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
