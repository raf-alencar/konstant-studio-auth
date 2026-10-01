// Offline authorization decision from a snapshot. This is a line-for-line
// mirror of the platform's `decide()` (app/authz.py on the C0b branch) for the
// subset a cached snapshot can answer: HUMAN principals, permissions of the
// snapshot's own service, a NAMED tenant, non-sensitive. Everything else goes
// to POST /v1/authorize. The parity test runs every vector against the real
// platform; a divergence is a bug here, never an accepted difference.
//
// Order (first failure is the reason), as in docs/control-plane.md:
//   unknown_permission -> tenant not entitled -> kind restriction ->
//   no_permission -> scope.

const SCOPE_DIMENSIONS = [
  ['brand_ids', 'brand'],
  ['domains', 'domain'],
  ['mailboxes', 'mailbox'],
];
const SCOPE_KEYS = new Set(['brand_ids', 'domains', 'mailboxes', 'descendants']);

// `null` when the resource is inside the scope, else the deny reason. A
// restricted dimension the request does not name fails closed, and so does any
// scope key we do not know (a typo must never read as "no restriction").
function scopeAllows(scope, resource) {
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) return 'out_of_scope';
  for (const key of Object.keys(scope)) if (!SCOPE_KEYS.has(key)) return 'out_of_scope';
  for (const [dim, field] of SCOPE_DIMENSIONS) {
    if (!(dim in scope)) continue;
    const allowed = scope[dim];
    if (!Array.isArray(allowed)) return 'out_of_scope';
    const value = resource[field];
    if (value === null || value === undefined || value === '') return 'scope_required';
    if (!allowed.some((a) => String(a).toLowerCase() === String(value).toLowerCase())) return 'out_of_scope';
  }
  return null;
}

// True when a principal of this kind may never hold a permission of this category.
function kindRestricted(kind, category) {
  return (kind === 'guest' && category !== 'read') || (kind === 'agent' && category === 'approve');
}

// Entitlement windows are data: apply them against the consumer's clock.
// Written as positive comparisons so an unparseable timestamp (NaN) fails closed, never open.
function inWindow(t, nowMs) {
  if (t.starts_at && !(Date.parse(t.starts_at) <= nowMs)) return false;
  if (t.ends_at && !(Date.parse(t.ends_at) > nowMs)) return false;
  return true;
}

function decideOffline(snapshot, { userId, kind = 'human' }, service, action, resource, nowMs) {
  const deny = (reason, tenantId = null, sensitive = false) => ({
    allow: false, reason, tenantId, viaTenant: null, roles: [], permissions: [], sensitive,
  });

  const perm = snapshot.permissions.find((p) => p.action === action);
  if (snapshot.service !== service || !perm) return deny('unknown_permission');
  const sensitive = !!perm.sensitive;
  const tenantId = resource.tenant;

  // The snapshot lists only tenants that are active AND have the entitlement 'on',
  // so absence covers not-entitled, suspended and inactive alike (see COARSE_OFFLINE).
  const tenant = snapshot.tenants.find((t) => t.id === tenantId);
  if (!tenant || !inWindow(tenant, nowMs)) return deny('not_entitled', tenantId, sensitive);

  if (kindRestricted(kind, perm.category)) return deny('principal_kind_restricted', tenantId, sensitive);

  const rolesById = new Map(snapshot.roles.map((r) => [r.id, r]));
  const wanted = new Set([`${service}:${action}`, `${service}:*`]);
  const reach = new Set([tenantId, ...tenant.ancestors]);

  const candidates = [];
  const held = new Set();
  for (const m of snapshot.memberships) {
    if (m.kind !== kind || m.user_id !== userId) continue;
    if (m.expires_at && !(Date.parse(m.expires_at) > nowMs)) continue;
    const here = m.tenant_id === tenantId;
    // Agency view: a HUMAN membership with scope.descendants on an ancestor applies below it. Never upward or sideways.
    // (The platform compares scope->>'descendants' to 'true', which the JSON string "true" also satisfies.)
    const opted = m.scope?.descendants === true || m.scope?.descendants === 'true';
    const inherited = !here && kind === 'human' && opted && reach.has(m.tenant_id);
    if (!here && !inherited) continue;
    const role = rolesById.get(m.role_id);
    // A custom role counts only inside its own tenant.
    if (!role || (role.tenant_id !== null && role.tenant_id !== m.tenant_id)) continue;
    for (const p of role.permissions) if (p.startsWith(`${service}:`)) held.add(p);
    if (role.permissions.some((p) => wanted.has(p))) candidates.push({ m, role });
  }
  if (candidates.length === 0) return deny('no_permission', tenantId, sensitive);

  let firstFailure = null;
  for (const { m } of candidates) {
    const failure = scopeAllows(m.scope, resource);
    if (failure === null) {
      const permissions = [...held].flatMap((p) =>
        p.endsWith(':*') ? snapshot.permissions.map((q) => `${service}:${q.action}`) : [p]
      );
      return {
        allow: true,
        reason: 'allowed',
        tenantId,
        viaTenant: m.tenant_id !== tenantId ? m.tenant_id : null,
        roles: [...new Set(candidates.map((c) => c.role.slug))].sort(),
        permissions: [...new Set(permissions)].sort(),
        sensitive,
        ancestry: tenant.ancestors,
      };
    }
    firstFailure = firstFailure || failure;
  }
  return deny(firstFailure, tenantId, sensitive);
}

module.exports = { decideOffline, scopeAllows, kindRestricted, inWindow };
