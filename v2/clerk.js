// Offline verification of a Clerk session token. Mirrors the platform's
// app/clerk_jwt.py so a token means the same thing everywhere: RS256 only,
// issuer pinned, exp/iat/sub required, `azp` MANDATORY and must be one of the
// authorized frontend origins, and an `aud` (normally absent on Clerk session
// tokens) must match a configured audience. The JWKS is cached for 5 minutes;
// if a refresh fails the cached copy is used instead of turning a Clerk blip
// into an outage, and a forced refresh for an unknown `kid` is throttled so a
// caller cycling kids cannot turn this into an outbound-request cannon.

const { decodeProtectedHeader, importJWK, jwtVerify, errors } = require('jose');

const CACHE_TTL_MS = 5 * 60 * 1000;
const FORCE_MIN_INTERVAL_MS = 60 * 1000;
const RETRY_AFTER_FAILURE_MS = 10 * 1000; // a JWKS outage must not become a fetch per request
const CLOCK_TOLERANCE_S = 5;

class Denied extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

class ClerkVerifier {
  constructor({ issuer, jwksUrl, authorizedParties, audience }, { fetch, now, monotonic, logger }) {
    this.cfg = { issuer, jwksUrl, authorizedParties, audience };
    this.fetch = fetch;
    this.now = now; // wall clock: token validity
    this.monotonic = monotonic ?? now; // cache ages
    this.logger = logger;
    this.keys = null;
    this.inflight = null;
    this.nextAttemptAt = -Infinity;
    this.fetchedAt = 0;
    this.forcedAt = -Infinity;
  }

  get configured() {
    return !!(this.cfg.issuer && this.cfg.jwksUrl);
  }

  async _jwks(force = false) {
    const t = this.monotonic();
    if (this.keys && !force && t - this.fetchedAt < CACHE_TTL_MS) return this.keys;
    if (force && this.keys && t - this.forcedAt < FORCE_MIN_INTERVAL_MS) return this.keys;
    // After a failure, keep serving the last good keys (or fail fast with none) instead of
    // retrying on every request.
    if (t < this.nextAttemptAt) {
      if (this.keys) return this.keys;
      throw new Denied('clerk_jwks_unavailable');
    }
    if (force) this.forcedAt = t;
    // One fetch at a time: concurrent requests share it.
    if (!this.inflight) {
      this.inflight = this._fetchKeys().finally(() => {
        this.inflight = null;
      });
    }
    return this.inflight;
  }

  async _fetchKeys() {
    try {
      const resp = await this.fetch(this.cfg.jwksUrl, { redirect: 'error', signal: AbortSignal.timeout(5000) });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      this.keys = (await resp.json()).keys || [];
      this.fetchedAt = this.monotonic();
      this.nextAttemptAt = -Infinity;
    } catch (err) {
      this.logger.warn(`clerk JWKS refresh failed: ${err.message}`);
      this.nextAttemptAt = this.monotonic() + RETRY_AFTER_FAILURE_MS;
      if (!this.keys) throw new Denied('clerk_jwks_unavailable');
    }
    return this.keys;
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
