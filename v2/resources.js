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

// The canonical id rule, one for both languages (it mirrors what the platform's registry can hold, so
// anything it could never hold can never be owned and is refused up front):
//   kind     a lowercase slug, ^[a-z][a-z0-9_-]{0,63}$ (the registry's own CHECK);
//   local_id 1-200 characters, no control characters (C0, DEL and the C1 range: the registry's CHECK);
//            compared EXACTLY (case-sensitive, no Unicode normalisation);
//   numbers  an integer id (an image account) is accepted only as a NON-NEGATIVE integer within the safe range
//            (<= 2^53-1), and is then exactly its decimal text. BigInt, booleans, objects, negative numbers,
//            non-integers and anything out of range are refused: nothing is parsed, rounded or stringified
//            into a form the registry might hold ("1.0", "1e3", "+7", "-0"), so a value one language would
//            accept and another refuse cannot exist. (A JavaScript number cannot tell 42.0 from 42; Python
//            refuses every float. That is the one inherent asymmetry and the shared vectors avoid it.)
const KIND_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const MAX_LOCAL_ID = 200;
const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;
const CONFLICT = Symbol('conflict');

function normalizeId(value) {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0) ? String(value) : null;
  }
  if (typeof value === 'string') {
    return value !== '' && [...value].length <= MAX_LOCAL_ID && !CONTROL_RE.test(value) ? value : null;
  }
  return null; // bigint, boolean, object, null, undefined...
}

function normalizeKind(kind) {
  return typeof kind === 'string' && KIND_RE.test(kind) ? kind : null;
}

// Order by Unicode code point (what Python's sorted() does), without allocating per comparison: JavaScript's
// default sort compares UTF-16 code units, which disagrees with code point order only for supplementary
// characters, so map the surrogate range above the high BMP (0xE000-0xFFFF) and compare unit by unit.
const unit = (c) => (c >= 0xe000 ? c - 0x800 : c >= 0xd800 ? c + 0x2000 : c);
function byCodePoint(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a.charCodeAt(i);
    const y = b.charCodeAt(i);
    if (x !== y) return unit(x) - unit(y);
  }
  return a.length - b.length;
}

function buildIndex(snapshot, { maxResources, logger }) {
  const index = { supported: true, tooLarge: false, owners: new Map(), byTenant: new Map(), count: 0 };
  const tenants = Array.isArray(snapshot?.tenants) ? snapshot.tenants : [];
  // A tenant without a usable id cannot own anything, and silently skipping it would let a LATER tenant take
  // its ids as if nobody had them: the whole snapshot is then unsupported (unavailable), never "unowned".
  if (tenants.some((t) => typeof t?.id !== 'string' || t.id === '')) {
    index.supported = false;
    return index;
  }
  // Zero tenants proves nothing about support, and cannot own anything either way. With tenants, every one
  // of them must carry the field: a platform that has C0f always sends it (an empty list when none).
  if (tenants.length > 0 && tenants.some((t) => !Array.isArray(t.resources))) {
    index.supported = false;
    return index;
  }
  let warnedConflict = false;
  for (const t of tenants) {
    const tkey = t.id.toLowerCase();
    for (const r of t.resources) {
      const kind = normalizeKind(r?.kind);
      const id = normalizeId(r?.local_id);
      if (kind === null || id === null) continue; // a malformed entry can never grant ownership
      let byId = index.owners.get(kind);
      if (!byId) index.owners.set(kind, (byId = new Map()));
      const have = byId.get(id);
      if (have === t.id) continue; // the same row repeated: one resource (and one against the cap)
      if (++index.count > maxResources) {
        index.tooLarge = true;
        logger.error(`resource index larger than ${maxResources} entries: lookups are refused`);
        return { ...index, owners: new Map(), byTenant: new Map() };
      }
      if (have === undefined) byId.set(id, t.id);
      else {
        byId.set(id, CONFLICT);
        if (!warnedConflict) {
          warnedConflict = true;
          logger.error('the snapshot gives one local id to two tenants: that id is refused (deny) until the platform is fixed');
        }
      }
      let kinds = index.byTenant.get(tkey);
      if (!kinds) index.byTenant.set(tkey, (kinds = new Map()));
      let list = kinds.get(kind);
      if (!list) kinds.set(kind, (list = { ids: [], sorted: false }));
      list.ids.push(id); // sorted lazily, on the first resourcesFor that needs it: tenantFor never pays for it
    }
  }
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
  const list = index.byTenant.get(tenantId.toLowerCase())?.get(k);
  if (!list) return [];
  if (!list.sorted) {
    list.ids.sort(byCodePoint);
    list.sorted = true;
  }
  return [...list.ids];
}

module.exports = { buildIndex, ownerOf, idsOf, normalizeId, normalizeKind };
