// Inbound SERVICE keys (stgs_...): another internal service calling this app.
//
// What the platform's C0b2 gives us (CoS contract note, final behaviour):
//   POST /v1/principals/resolve { credential: 'stgs_...', expect_service: '<slug>' }
//   -> valid:true with a principal { kind: 'service', service, tenant_id: null }, or valid:false.
//
// Rules this module enforces:
//   1. Configuration, not discovery. The app declares `acceptedCallerServices`; each is
//      passed as `expect_service` (mandatory for a bound caller; never "any"). With none
//      declared, every service key is refused here, without asking the platform.
//   2. Uniform failure. Unknown, revoked, expired, disabled, wrong-service and unaccepted
//      keys all produce the same result (`key_not_found`); the finer reason is the
//      platform's audit detail and is never branched on, returned or logged here.
//   3. A match proves WHO is calling, not what they may do. The platform's
//      `allowed_routes` are routes on the PLATFORM API and are deliberately not exposed
//      on the Principal. What a caller service may do on THIS app's routes is the app's
//      own policy (requireServiceCaller + routeAllowed below).
//   4. A service principal holds no tenant permissions (see auth.js).
//   5. Bounded cache: a valid resolution is kept for at most 60 s, an invalid one for at
//      most 10 s, keyed by a hash of the credential (never the credential), with a cap on
//      entries so garbage keys cannot grow memory. The platform audits every UNCACHED
//      resolution; the cache is what keeps that volume sane. Cost: a revoked service key
//      keeps working here for up to a minute (agent/guest/MCP keys are never cached).

const crypto = require('crypto');
const { PlatformUnavailable } = require('./platform-client');
const { Denied } = require('./clerk');

const SLUG = /^[a-z][a-z0-9-]{0,63}$/;

class ServiceKeyResolver {
  constructor({ client, accepted, now, logger, validTtlSeconds = 60, invalidTtlSeconds = 10, maxEntries = 1000 }) {
    this.client = client;
    this.accepted = accepted;
    this.now = now;
    this.logger = logger;
    this.validTtlMs = validTtlSeconds * 1000;
    this.invalidTtlMs = invalidTtlSeconds * 1000;
    this.maxEntries = maxEntries;
    this.cache = new Map(); // sha256(credential) -> { until, value | null }
    this.inflight = new Map();
    this.warnedEmpty = false;
  }

  static validateAccepted(accepted) {
    for (const s of accepted) {
      if (!SLUG.test(s)) throw new Error(`acceptedCallerServices: "${s}" is not a catalog service slug`);
    }
  }

  // -> { id, service, keyId } | throws Denied('key_not_found' | 'platform_unavailable')
  async resolve(raw) {
    if (this.accepted.length === 0) {
      if (!this.warnedEmpty) {
        this.warnedEmpty = true; // once: an app that never expects service keys is not spammed at startup
        this.logger.warn('an inbound service key was presented but no acceptedCallerServices is configured: refused');
      }
      throw new Denied('key_not_found');
    }
    const hash = crypto.createHash('sha256').update(raw).digest('hex');
    const hit = this.cache.get(hash);
    if (hit && hit.until > this.now()) {
      if (hit.value === null) throw new Denied('key_not_found');
      return hit.value;
    }
    if (!this.inflight.has(hash)) {
      this.inflight.set(hash, this._ask(raw, hash).finally(() => this.inflight.delete(hash)));
    }
    const value = await this.inflight.get(hash);
    if (value === null) throw new Denied('key_not_found');
    return value;
  }

  async _ask(raw, hash) {
    let found = null;
    let expiresAtMs = null;
    for (const slug of this.accepted) {
      let res;
      try {
        res = await this.client.resolve({ credential: raw, expect_service: slug });
      } catch (err) {
        if (err instanceof PlatformUnavailable) throw new Denied('platform_unavailable'); // not cached: not a verdict
        throw err;
      }
      const p = res?.principal;
      // Check the answer ourselves too: it must be a service principal bound to exactly the service we asked about.
      if (res?.valid === true && p && p.kind === 'service' && p.service === slug) {
        found = { id: p.id, service: p.service, keyId: res.key_id ?? null };
        const exp = res.service_key?.expires_at ? Date.parse(res.service_key.expires_at) : null;
        expiresAtMs = Number.isFinite(exp) ? exp : null;
        break;
      }
    }
    const ttl = found ? this.validTtlMs : this.invalidTtlMs;
    const until = found && expiresAtMs !== null ? Math.min(this.now() + ttl, expiresAtMs) : this.now() + ttl;
    this._remember(hash, { until, value: found });
    return found;
  }

  _remember(hash, entry) {
    if (this.cache.size >= this.maxEntries) {
      for (const [k, e] of this.cache) if (e.until <= this.now()) this.cache.delete(k);
      while (this.cache.size >= this.maxEntries) this.cache.delete(this.cache.keys().next().value); // oldest first
    }
    this.cache.set(hash, entry);
  }
}

// "METHOD /path/glob" entries; METHOD may be `*`, glob characters are `*` only.
// Same matching as the platform's allow-list, but THIS is the app's own policy for
// the routes of this app, never the platform's `allowed_routes`.
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

// policy: { '<caller service slug>': ['METHOD /path/glob', ...] }. Deny by default:
// a caller service with no entry, or no matching route, gets nothing. Checked at
// wiring time so a policy for a service that is not accepted (which could never
// match) is a startup error, not a silent hole.
function validatePolicy(policy, accepted) {
  if (!policy || typeof policy !== 'object') throw new Error('service caller policy must be an object keyed by caller service');
  for (const [service, routes] of Object.entries(policy)) {
    if (!accepted.includes(service)) {
      throw new Error(`service caller policy names "${service}", which is not in acceptedCallerServices`);
    }
    if (!Array.isArray(routes)) throw new Error(`service caller policy for "${service}" must be a list of "METHOD /path" entries`);
    for (const r of routes) {
      if (!/^(GET|POST|PUT|PATCH|DELETE|\*) \/[A-Za-z0-9_\-./*:]*$/.test(r)) throw new Error(`bad route entry "${r}" for "${service}"`);
      if (r === '* /*') throw new Error(`"* /*" for "${service}" would allow everything: list the routes this caller needs`);
    }
  }
}

module.exports = { ServiceKeyResolver, routeAllowed, validatePolicy, SLUG };
