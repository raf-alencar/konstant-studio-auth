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
//   5. Unfloodable. A key that cannot be a platform key (wrong prefix, charset or length) is
//      refused here without a platform call. Valid resolutions live in an LRU cache; invalid ones
//      in a SEPARATE small cache, so garbage can never evict a good entry. At most `maxInflight`
//      resolutions run at once (beyond that: could not decide, 503, never a verdict), and a
//      platform 429 pauses resolution for its Retry-After instead of being turned into a verdict.
//   6. Bounded cache: a valid resolution is kept for at most 60 s, an invalid one for at
//      most 10 s, keyed by a hash of the credential (never the credential), with a cap on
//      entries so garbage keys cannot grow memory. The platform audits every UNCACHED
//      resolution; the cache is what keeps that volume sane. Cost: a revoked service key
//      keeps working here for up to a minute (agent/guest/MCP keys are never cached).

const crypto = require('crypto');
const { PlatformUnavailable, PlatformThrottled } = require('./platform-client');
const { Denied } = require('./clerk');

// Same shape the platform enforces on every service name that crosses its API.
const SLUG = /^[a-z][a-z0-9_-]{0,63}$/;
// What a platform service key looks like: the stgs_ prefix and url-safe characters, 20..200 long
// (the platform's own floor is 20). Anything else cannot be a key and is not worth a platform call.
const KEY_SHAPE = /^stgs_[A-Za-z0-9_-]+$/;
const KEY_MIN = 20;
const KEY_MAX = 200;

class ServiceKeyResolver {
  // `now` is the wall clock (a key's expires_at); `monotonic` measures cache ages.
  constructor({ client, accepted, now, monotonic, logger, validTtlSeconds = 60, invalidTtlSeconds = 10,
    maxEntries = 1000, negativeMaxEntries = 256, maxInflight = 8 }) {
    this.client = client;
    this.accepted = accepted;
    this.now = now;
    this.monotonic = monotonic ?? now;
    this.logger = logger;
    this.validTtlMs = validTtlSeconds * 1000;
    this.invalidTtlMs = invalidTtlSeconds * 1000;
    this.maxEntries = maxEntries;
    this.negativeMaxEntries = negativeMaxEntries;
    this.maxInflight = maxInflight;
    this.cache = new Map(); // sha256(credential) -> { until, value }   (valid answers; LRU)
    this.negative = new Map(); // sha256(credential) -> { until }        (invalid answers; own small cache)
    this.inflight = new Map();
    this.throttledUntil = 0;
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
    // It cannot be a platform key: the same uniform answer, without costing the platform anything.
    if (raw.length < KEY_MIN || raw.length > KEY_MAX || !KEY_SHAPE.test(raw)) throw new Denied('key_not_found');

    const hash = crypto.createHash('sha256').update(raw).digest('hex');
    const t = this.monotonic();
    const hit = this.cache.get(hash);
    if (hit && hit.until > t) {
      this.cache.delete(hash); // refresh recency: least recently USED is what gets evicted
      this.cache.set(hash, hit);
      return hit.value;
    }
    const miss = this.negative.get(hash);
    if (miss && miss.until > t) throw new Denied('key_not_found');

    if (t < this.throttledUntil) throw new Denied('platform_unavailable'); // the platform asked us to slow down
    if (!this.inflight.has(hash)) {
      if (this.inflight.size >= this.maxInflight) throw new Denied('platform_unavailable'); // shed load, no verdict
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
        if (err instanceof PlatformThrottled) this.throttledUntil = this.monotonic() + err.retryAfterMs;
        if (err instanceof PlatformUnavailable) throw new Denied('platform_unavailable'); // not cached: not a verdict
        throw err;
      }
      if (res?.valid !== true && res?.valid !== false) throw new Denied('platform_unavailable'); // a malformed reply is not a verdict: never cached
      const p = res?.principal;
      // Check the answer ourselves too: it must be a service principal bound to exactly the service we asked about.
      // (valid === true, not truthy: a string like "false" must never read as a yes.)
      if (res?.valid === true && p && p.kind === 'service' && p.service === slug) {
        found = { id: p.id, service: p.service, keyId: res.key_id ?? null };
        const exp = res.service_key?.expires_at ? Date.parse(res.service_key.expires_at) : null;
        expiresAtMs = Number.isFinite(exp) ? exp : null;
        break;
      }
    }
    const t = this.monotonic();
    if (found) {
      // Never outlive the key: cap at its expiry (wall clock) converted to a monotonic deadline.
      const room = expiresAtMs === null ? this.validTtlMs : Math.min(this.validTtlMs, Math.max(0, expiresAtMs - this.now()));
      this._remember(this.cache, this.maxEntries, hash, { until: t + room, value: found });
    } else {
      this._remember(this.negative, this.negativeMaxEntries, hash, { until: t + this.invalidTtlMs });
    }
    return found;
  }

  // Insert, evicting expired entries first and then the least recently used. `max` is validated >= 1
  // at startup (a zero would never terminate), and the loop is bounded by the map's own size anyway.
  _remember(map, max, hash, entry) {
    if (map.size >= max) {
      const t = this.monotonic();
      for (const [k, e] of map) if (e.until <= t) map.delete(k);
      for (const k of map.keys()) {
        if (map.size < max) break;
        map.delete(k);
      }
    }
    map.set(hash, entry);
  }
}

// "METHOD /path/glob" entries; METHOD may be `*`.
// THIS app's own policy for the routes of this app (never the platform's `allowed_routes`), and
// deliberately stricter than the platform's glob:
//   *   matches within ONE path segment (never a "/", and at least one character);
//   **  matches across segments (at least one character).
//   So `GET /internal/*` authorises neither `/internal` nor `/internal/`.
// It is matched against the path exactly as it was SENT (undecoded, without the query string), and a
// path that could be read two ways is refused outright: any `%`, `..`, `//`, control character, or
// one that does not start with `/`. Decoded or normalised matching is how `/internal/..%2fadmin`
// gets past a policy written for `/internal/*`.
const globCache = new Map();

function compileGlob(glob) {
  let re = globCache.get(glob);
  if (!re) {
    const body = glob
      .split('**')
      .map((part) => part.split('*').map((lit) => lit.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]+'))
      .join('.+');
    re = new RegExp(`^${body}$`);
    globCache.set(glob, re);
  }
  return re;
}

function safePath(path) {
  if (typeof path !== 'string') return null;
  const p = path.split(/[?#]/)[0];
  // Anything that could be read two ways: %, '..', '//', control characters, ';' path parameters, backslashes
  // (treated as '/' by some servers), the Unicode line separators, and a single-dot segment.
  if (p[0] !== '/' || /[\x00-\x1f\x7f%;\\\u2028\u2029]/.test(p) || p.includes('..') || p.includes('//')) return null;
  if (p.split('/').includes('.')) return null;
  return p;
}

function routeAllowed(routes, method, path) {
  const p = safePath(path);
  if (p === null) return false;
  const m = String(method).toUpperCase();
  return (routes || []).some((entry) => {
    const [em, ...rest] = String(entry).split(' ');
    if (em !== '*' && em !== m) return false;
    return compileGlob(rest.join(' ')).test(p);
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
      if (/[;\\]/.test(r) || (r.match(/\*\*/g) || []).length > 2) throw new Error(`route entry "${r}" for "${service}" uses ';', a backslash, or more than two '**'`);
      if (r.includes('..') || r.includes('//')) throw new Error(`route entry "${r}" for "${service}" contains ".." or "//"`);
      if (r === '* /*' || r === '* /**') throw new Error(`"* /*" for "${service}" would allow everything: list the routes this caller needs`);
    }
  }
}

module.exports = { ServiceKeyResolver, routeAllowed, validatePolicy, safePath, SLUG };
