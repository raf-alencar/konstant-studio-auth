// Resource lookups: "which tenant owns this service-local id?" and "which local ids does this tenant
// have in this service?", answered from the cached snapshot (platform C0f). The platform owns the
// brand/company <-> tenant crosswalk; an adopting repo keeps no mapping of its own and asks here.
//
// Each snapshot tenant carries `resources: [{ kind, local_id }]` for THIS service only (active rows
// only: a retired resource is simply absent). The platform guarantees (service, kind, local_id) maps
// to exactly one tenant, so the reverse lookup is a plain map, built ONCE per snapshot and reused for
// every request (a 304 revalidation keeps the same snapshot, and so the same index).
//
// Fail closed, in this order:
//   - no usable snapshot (never loaded, unreadable, older than the stale-read window) => unavailable;
//   - a snapshot with no `resources` field (a platform without C0f) => unavailable, NEVER "unowned":
//     "this platform cannot tell" must not read as "nobody owns it";
//   - a local id with no owner => null (callers deny);
//   - a local id the snapshot claims for two tenants (a platform bug) => null (deny), logged once;
//   - an index larger than `maxResources` => unavailable (memory stays bounded).

const MAX_ID_LENGTH = 256;
const CONFLICT = Symbol('conflict');

// A local id as the services keep them: text, but an integer id (an image account) is the same thing
// as its decimal text. Anything else cannot name a resource.
function normalizeId(value) {
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (typeof value === 'bigint') return String(value);
  if (typeof value === 'string' && value !== '' && value.length <= MAX_ID_LENGTH) return value;
  return null;
}

function normalizeKind(kind) {
  return typeof kind === 'string' && kind !== '' && kind.length <= MAX_ID_LENGTH ? kind : null;
}

function buildIndex(snapshot, { maxResources, logger }) {
  const index = { supported: true, tooLarge: false, owners: new Map(), byTenant: new Map(), count: 0 };
  const tenants = Array.isArray(snapshot?.tenants) ? snapshot.tenants : [];
  // Zero tenants proves nothing about support, and cannot own anything either way. With tenants, every one
  // of them must carry the field: a platform that has C0f always sends it (an empty list when none).
  if (tenants.length > 0 && tenants.some((t) => !Array.isArray(t.resources))) {
    index.supported = false;
    return index;
  }
  let warnedConflict = false;
  for (const t of tenants) {
    for (const r of t.resources || []) {
      const kind = normalizeKind(r?.kind);
      const id = normalizeId(r?.local_id);
      if (kind === null || id === null) continue; // a malformed entry can never grant ownership
      if (++index.count > maxResources) {
        index.tooLarge = true;
        logger.error(`resource index larger than ${maxResources} entries: lookups are refused`);
        return { ...index, owners: new Map(), byTenant: new Map() };
      }
      let byId = index.owners.get(kind);
      if (!byId) index.owners.set(kind, (byId = new Map()));
      const have = byId.get(id);
      if (have === undefined) byId.set(id, t.id);
      else if (have !== t.id) {
        byId.set(id, CONFLICT);
        if (!warnedConflict) {
          warnedConflict = true;
          logger.error('the snapshot gives one local id to two tenants: that id is refused (deny) until the platform is fixed');
        }
      }
      const tkey = String(t.id).toLowerCase();
      let kinds = index.byTenant.get(tkey);
      if (!kinds) index.byTenant.set(tkey, (kinds = new Map()));
      let ids = kinds.get(kind);
      if (!ids) kinds.set(kind, (ids = []));
      ids.push(id);
    }
  }
  for (const kinds of index.byTenant.values()) for (const ids of kinds.values()) ids.sort();
  return index;
}

function ownerOf(index, kind, localId) {
  const k = normalizeKind(kind);
  const id = normalizeId(localId);
  if (k === null || id === null) return null;
  const owner = index.owners.get(k)?.get(id);
  return owner === undefined || owner === CONFLICT ? null : owner;
}

function idsOf(index, tenantId, kind) {
  const k = normalizeKind(kind);
  if (k === null || typeof tenantId !== 'string') return [];
  return [...(index.byTenant.get(tenantId.toLowerCase())?.get(k) || [])];
}

module.exports = { buildIndex, ownerOf, idsOf, normalizeId, normalizeKind };
