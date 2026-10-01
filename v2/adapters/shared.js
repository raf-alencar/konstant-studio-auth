// Pieces both adapters use: turning a `scope` option into the resource a
// decision is about, and the response bodies. Bodies carry the reason code and
// nothing else a caller could not already know: no tenant ids, no principal
// details, no platform error text.

const BODIES = { 401: 'Unauthorized', 403: 'Forbidden', 503: 'Authorization service unavailable' };

// scope: { tenant, brand, domain, mailbox }, each a string or (…args) => string|undefined.
async function resolveScope(scope = {}, ...args) {
  const out = {};
  for (const field of ['tenant', 'brand', 'domain', 'mailbox']) {
    const v = scope[field];
    const value = typeof v === 'function' ? await v(...args) : v;
    if (value !== undefined && value !== null && value !== '') out[field] = String(value);
  }
  return out;
}

function denialBody(d, cfg) {
  const error = d.reason === 'not_entitled' ? 'No access to this service' : BODIES[d.status] || 'Forbidden';
  return { error, reason: d.reason, ...(d.reason === 'not_entitled' ? { upgrade_url: cfg.upgradeUrl } : {}) };
}

// The shape existing adopters read from req.auth (see README "What you get"),
// so v2 middleware can sit behind code written for v1. Authority is never
// derived from it: isSuperadmin is always false here, because in v2 only the
// permission matrix grants anything.
function legacyAuth(principal, decision) {
  return {
    userId: principal.userId ?? principal.id ?? null,
    orgId: principal.claims?.org_id ?? null,
    orgRole: principal.claims?.org_role ?? null,
    isSuperadmin: false,
    tenantId: decision.tenantId,
  };
}

// X-Run-Id is caller-supplied and ends up in audit events: printable ASCII only, bounded.
function cleanRunId(value) {
  if (value === undefined || value === null) return undefined;
  const v = String(value).replace(/[^\x20-\x7e]/g, '').slice(0, 128);
  return v || undefined;
}

module.exports = { resolveScope, denialBody, legacyAuth, cleanRunId };
