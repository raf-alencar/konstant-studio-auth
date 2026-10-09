// Offline verification of a Clerk session token. Mirrors the platform's
// app/clerk_jwt.py so a token means the same thing everywhere: RS256 only,
// issuer pinned, exp/iat/sub required, `azp` MANDATORY and must be one of the
// authorized frontend origins, and an `aud` (normally absent on Clerk session
// tokens) must match a configured audience. The JWKS is cached for 5 minutes;
// if a refresh fails the cached copy is used instead of turning a Clerk blip
// into an outage, and a forced refresh for an unknown `kid` is throttled so a
// caller cycling kids cannot turn this into an outbound-request cannon.

const { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, errors } = require('jose');

const CACHE_TTL_MS = 5 * 60 * 1000;
const FORCE_MIN_INTERVAL_MS = 60 * 1000;
const RETRY_AFTER_FAILURE_MS = 10 * 1000; // a JWKS outage must not become a fetch per request
const CLOCK_TOLERANCE_S = 5;
// CR-L2: nothing about the key fetch may be able to hold a request forever.
const REFRESH_DEADLINE_MS = 5 * 1000; // the WHOLE refresh: connect, headers, body, JSON parse
const WAIT_BUDGET_MS = 3 * 1000; // how long ONE request waits for a refresh before it answers 503
const HARD_EXPIRY_MS = 60 * 60 * 1000; // last good keys are never served past this age
const LOG_EVERY_MS = 60 * 1000;

class Denied extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

// Settle with `promise`, or with `onTimeout()`'s outcome after `ms`. The timer is the authority: it does not
// depend on the underlying client honouring an abort signal. Always clears its timer.
function withDeadline(promise, ms, onTimeout) {
  let timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(onTimeout()), ms);
    timer.unref?.();
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}

class ClerkVerifier {
  constructor({ issuer, jwksUrl, authorizedParties, audience }, { fetch, now, monotonic, logger, timeouts = {} }) {
    this.cfg = { issuer, jwksUrl, authorizedParties, audience };
    this.fetch = fetch;
    this.now = now; // wall clock: token validity
    this.monotonic = monotonic ?? now; // cache ages
    this.logger = logger;
    this.t = {
      refreshDeadlineMs: timeouts.refreshDeadlineMs ?? REFRESH_DEADLINE_MS,
      waitBudgetMs: timeouts.waitBudgetMs ?? WAIT_BUDGET_MS,
      hardExpiryMs: timeouts.hardExpiryMs ?? HARD_EXPIRY_MS,
    };
    this.keys = null;
    this.inflight = null; // { promise, startedAt (monotonic), startedWall }
    this.nextAttemptAt = -Infinity;
    this.fetchedAt = 0;
    this.forcedAt = -Infinity;
    this.stats = { lastSuccessAt: null, lastFailureAt: null, lastFailure: null, failures: 0, deadlineHits: 0, wedgeRecoveries: 0, refreshes: 0 };
    this._logged = new Map();
  }

  get configured() {
    return !!(this.cfg.issuer && this.cfg.jwksUrl);
  }

  // Health for an app's /health: ids and times only, never a key or a token. `degraded` when a refresh has been
  // running longer than its deadline (a wedge), or the last success is older than twice the refresh interval, or
  // the keys have never loaded and refreshes are failing.
  status() {
    const t = this.monotonic();
    const inflightAgeMs = this.inflight ? Math.max(0, t - this.inflight.startedAt) : null;
    const lastSuccessAgeMs = this.stats.lastSuccessAt === null ? null : Math.max(0, t - this.fetchedAt);
    let reason = null;
    if (!this.configured) reason = null; // not using Clerk is not degraded
    else if (inflightAgeMs !== null && inflightAgeMs > this.t.refreshDeadlineMs) reason = 'refresh_older_than_deadline';
    else if (lastSuccessAgeMs !== null && lastSuccessAgeMs > 2 * CACHE_TTL_MS) reason = 'last_success_too_old';
    else if (lastSuccessAgeMs === null && this.stats.failures > 0) reason = 'keys_never_loaded';
    return {
      configured: this.configured, degraded: reason !== null, reason,
      lastSuccessAt: this.stats.lastSuccessAt, lastFailureAt: this.stats.lastFailureAt, lastFailure: this.stats.lastFailure,
      lastSuccessAgeMs, inflightAgeMs, keysCached: !!this.keys, failures: this.stats.failures,
      deadlineHits: this.stats.deadlineHits, wedgeRecoveries: this.stats.wedgeRecoveries, refreshes: this.stats.refreshes,
    };
  }

  // One line per kind per minute, with the running counter, so an outage is loud but cannot flood a log.
  _log(kind, message) {
    const t = this.monotonic();
    const prev = this._logged.get(kind);
    if (prev && t - prev.at < LOG_EVERY_MS) {
      prev.suppressed += 1;
      return;
    }
    this._logged.set(kind, { at: t, suppressed: 0 });
    this.logger.warn(`clerk JWKS ${message}${prev?.suppressed ? ` (+${prev.suppressed} more in the last minute)` : ''} [failures=${this.stats.failures} deadlineHits=${this.stats.deadlineHits}]`);
  }

  _usable(t) {
    return this.keys && t - this.fetchedAt < this.t.hardExpiryMs ? this.keys : null;
  }

  // Start (or share) the single refresh. The shared promise ALWAYS settles within the deadline, so the slot
  // cannot stay occupied; a slot found older than the deadline anyway is replaced and counted as a recovery.
  _refresh() {
    const t = this.monotonic();
    if (this.inflight && t - this.inflight.startedAt > this.t.refreshDeadlineMs + 1000) {
      this.stats.wedgeRecoveries += 1;
      this._log('wedge', 'refresh slot was older than its deadline; replaced it');
      this.inflight = null;
    }
    if (this.inflight) return this.inflight.promise;
    const slot = { startedAt: t };
    slot.promise = this._fetchKeys().finally(() => {
      if (this.inflight === slot) this.inflight = null; // never clear a newer slot
    });
    this.inflight = slot;
    this.stats.refreshes += 1;
    return slot.promise;
  }

  async _jwks(force = false) {
    const t = this.monotonic();
    const usable = this._usable(t);
    if (usable && !force && t - this.fetchedAt < CACHE_TTL_MS) return usable;
    if (force && usable && t - this.forcedAt < FORCE_MIN_INTERVAL_MS) return usable;
    // After a failure, keep serving the last good keys (or fail fast with none) instead of retrying on every request.
    if (t < this.nextAttemptAt && !this.inflight) {
      if (usable) return usable;
      throw new Denied('clerk_jwks_unavailable');
    }
    if (force) this.forcedAt = t;
    const refresh = this._refresh();
    refresh.catch(() => {}); // a refresh nobody waits for must not be an unhandled rejection
    // Good keys that are merely past their refresh time keep serving while the refresh runs in the background.
    if (usable && !force) return usable;
    // Otherwise this request waits, but only for its own short budget.
    return withDeadline(refresh, this.t.waitBudgetMs, () => new Denied('clerk_jwks_unavailable'));
  }

  async _fetchKeys() {
    const controller = new AbortController();
    const work = (async () => {
      const resp = await this.fetch(this.cfg.jwksUrl, { redirect: 'error', signal: controller.signal });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const body = await resp.json(); // inside the deadline: a stalled body is a stalled refresh
      return Array.isArray(body?.keys) ? body.keys : [];
    })();
    work.catch(() => {}); // if the deadline wins, a late rejection of `work` is not an unhandled rejection
    try {
      const keys = await withDeadline(work, this.t.refreshDeadlineMs, () => {
        this.stats.deadlineHits += 1;
        controller.abort(); // also tell the client to drop the socket, but the timer, not the client, settles us
        return new Error('refresh deadline exceeded');
      });
      this.keys = keys;
      this.fetchedAt = this.monotonic();
      this.stats.lastSuccessAt = this.now();
      this.nextAttemptAt = -Infinity;
      return keys;
    } catch (err) {
      this.stats.failures += 1;
      this.stats.lastFailureAt = this.now();
      this.stats.lastFailure = String(err?.message || err?.name || 'error').slice(0, 80);
      this._log(err?.message === 'refresh deadline exceeded' ? 'deadline' : 'refresh', `refresh failed: ${this.stats.lastFailure}`);
      this.nextAttemptAt = this.monotonic() + RETRY_AFTER_FAILURE_MS;
      const usable = this._usable(this.monotonic());
      if (!usable) throw new Denied('clerk_jwks_unavailable');
      return usable;
    }
  }

  async verify(token) {
    if (!this.configured) throw new Denied('clerk_not_configured');
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new Denied('token_invalid');
    }
    if (header.alg !== 'RS256') throw new Denied('token_invalid');
    // The issuer is PINNED by configuration and compared EXACTLY (no normalisation: a trailing slash, another
    // scheme, case, a port, a sub- or parent-domain, userinfo or surrounding whitespace is a different
    // issuer). The token's own `iss` is only ever compared with it, never used to decide where to fetch keys,
    // and a mismatch is refused here, BEFORE any network call: a forged token costs no request, not even to
    // the legitimate key server. (Signature and issuer are verified again below.)
    let claimed;
    try {
      claimed = decodeJwt(token).iss;
    } catch {
      throw new Denied('token_invalid');
    }
    if (typeof claimed !== 'string' || claimed !== this.cfg.issuer) throw new Denied('token_invalid');

    let jwk = (await this._jwks()).find((k) => k.kid === header.kid);
    if (!jwk) jwk = (await this._jwks(true)).find((k) => k.kid === header.kid); // key rotation: one throttled refresh
    if (!jwk) throw new Denied('token_invalid');

    let claims;
    try {
      const key = await importJWK(jwk, 'RS256');
      ({ payload: claims } = await jwtVerify(token, key, {
        issuer: this.cfg.issuer,
        algorithms: ['RS256'],
        requiredClaims: ['exp', 'iat', 'sub'],
        clockTolerance: CLOCK_TOLERANCE_S,
        currentDate: new Date(this.now()), // the library's clock, so a test clock and production agree
      }));
    } catch (err) {
      if (err instanceof errors.JWTExpired) throw new Denied('token_expired');
      throw new Denied('token_invalid');
    }

    // A token issued in the future is not valid yet (the platform's verifier refuses it too).
    if (claims.iat > Math.floor(this.now() / 1000) + CLOCK_TOLERANCE_S) throw new Denied('token_invalid');

    // azp is mandatory: a token without one, or from an unlisted origin, is not ours.
    if (!this.cfg.authorizedParties.includes(claims.azp)) throw new Denied('token_invalid');
    if ('aud' in claims) {
      const aud = claims.aud;
      const list = typeof aud === 'string' ? [aud] : Array.isArray(aud) && aud.every((a) => typeof a === 'string') ? aud : null;
      if (!list || this.cfg.audience.length === 0 || !list.some((a) => this.cfg.audience.includes(a))) {
        throw new Denied('token_invalid');
      }
    }
    return claims;
  }
}

module.exports = { ClerkVerifier, Denied };
