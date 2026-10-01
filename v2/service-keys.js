// Inbound SERVICE keys (stgs_...): another internal service calling an app.
//
// END STATE (CoS amendment to the C0c CR, 2026-10-01): the platform resolves a
// stgs_ key into a `service` principal exactly like the other credential
// kinds; apps never hold a key table. That platform work ("C0b2") has not
// landed: on the accepted C0b branch a stgs_ key presented as a credential is
// answered `unsupported_credential` (tests/test_c0b_authorize.py).
//
// So this is the ONE isolated place that knows about it. Mode 'stub' (the
// default) behaves exactly like the platform does today. Mode 'platform' is
// the switch to flip once C0b2 ships; its response mapping below is the shape
// the amendment specifies and has NOT been verified against a real platform.
// The service-key vectors stay `pending-platform` until it has.
//
// Principal shape (as the platform will return it):
//   { kind: 'service', service: '<slug>', routes: ['METHOD /glob', ...], tenant: null }
// A service principal holds no tenant permissions unless explicitly granted,
// is never an approver, and may call only the routes in its allow-list.

const { PlatformUnavailable } = require('./platform-client');
const { Denied } = require('./clerk');

async function resolveServiceKey(raw, { mode, client }) {
  if (mode !== 'platform') throw new Denied('unsupported_credential');
  let res;
  try {
    res = await client.resolve({ credential: raw });
  } catch (err) {
    if (err instanceof PlatformUnavailable) throw new Denied('platform_unavailable');
    throw err;
  }
  if (!res.valid) throw new Denied(res.reason || 'key_not_found');
  const p = res.principal || {};
  if (p.kind !== 'service') throw new Denied('unsupported_credential');
  return { id: p.id, service: p.service ?? null, routes: p.routes ?? [], keyId: res.key_id ?? null };
}

// "METHOD /path/glob" entries; METHOD may be `*`, glob characters are `*` only.
// Same semantics as the platform's route allow-list (app/principal_keys.py).
function routeAllowed(routes, method, path) {
  const m = String(method).toUpperCase();
  return (routes || []).some((entry) => {
    const [em, ...rest] = String(entry).split(' ');
    const glob = rest.join(' ');
    if (em !== '*' && em !== m) return false;
    const re = new RegExp(`^${glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`);
    return re.test(path);
  });
}

module.exports = { resolveServiceKey, routeAllowed };
