// Everything the library needs comes from the options passed to createAuth()
// or from environment variables; nothing is hard-coded, and no secret has a
// default. The Clerk issuer and JWKS URL are public values but still come
// from the environment so each deployment states which Clerk instance it trusts.

class ConfigError extends Error {}

function csv(value) {
  return (value || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function int(value, fallback) {
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

const KNOWN_OPTIONS = new Set([
  'service', 'platformUrl', 'platformKey', 'clerk', 'snapshot', 'pollIntervalSeconds', 'requestTimeoutMs',
  'stepUpMaxAgeMinutes', 'acceptedCallerServices', 'serviceKeyCache', 'upgradeUrl', 'tenantResolver',
  'onEvent', 'now', 'monotonic', 'fetch', 'logger',
]);

// Numeric options are validated at startup: a zero or negative limit is a loop or an
// always-expired cache waiting to happen (maxEntries: 0 would spin the evictor forever).
function positive(name, value, { integer = false, allowZero = false } = {}) {
  const ok = typeof value === 'number' && Number.isFinite(value) && (allowZero ? value >= 0 : value > 0) && (!integer || Number.isInteger(value));
  if (!ok) throw new ConfigError(`${name} must be a ${integer ? 'whole ' : ''}number ${allowZero ? '>= 0' : '> 0'} (got ${JSON.stringify(value)})`);
  return value;
}

// A string where a list belongs is a silent hole: `'abc'.includes('')` is true in JS (an empty `azp`
// would pass an "allowed parties" string), and other languages split a string into characters.
function stringList(name, value) {
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string' || v.trim() === '')) {
    throw new ConfigError(`${name} must be an array of non-empty strings (got ${JSON.stringify(value)})`);
  }
  return value;
}

function resolveConfig(opts = {}, env = process.env) {
  // An option nobody reads is a silent hole (a stale `serviceKeys: 'stub'`, a typo in
  // `acceptedCallerServices`): refuse it instead of ignoring it.
  for (const key of Object.keys(opts)) {
    if (!KNOWN_OPTIONS.has(key)) throw new ConfigError(`unknown option "${key}"`);
  }
  const issuer = opts.clerk?.issuer ?? env.CLERK_ISSUER ?? '';
  const jwksUrl =
    opts.clerk?.jwksUrl ??
    env.CLERK_JWKS_URL ??
    (issuer ? `${issuer.replace(/\/+$/, '')}/.well-known/jwks.json` : '');
  const authorizedParties = stringList('clerk.authorizedParties', opts.clerk?.authorizedParties ?? csv(env.CLERK_AUTHORIZED_PARTIES));
  const audience = stringList('clerk.audience', opts.clerk?.audience ?? csv(env.CLERK_AUDIENCE));

  // Same rule as the platform: without a list of allowed `azp` origins, any
  // token this Clerk instance ever issued (for any of its apps) would be
  // accepted. Refuse to start rather than run that way.
  if ((issuer || jwksUrl) && authorizedParties.length === 0) {
    throw new ConfigError(
      'CLERK_AUTHORIZED_PARTIES is required when Clerk verification is configured (the azp check is mandatory)'
    );
  }

  const platformUrl = (opts.platformUrl ?? env.PLATFORM_API_URL ?? '').replace(/\/+$/, '');
  // Per-service key (stgs_...). INTERNAL_API_KEY is the deprecated shared key;
  // it is only a fallback until the platform's ACCEPT_SHARED_KEY=false cutover.
  const platformKey = opts.platformKey ?? env.PLATFORM_SERVICE_KEY ?? env.INTERNAL_API_KEY ?? '';

  return {
    service: opts.service ?? env.AUTH_SERVICE ?? '',
    platformUrl,
    platformKey,
    clerk: { issuer, jwksUrl, authorizedParties, audience },
    snapshot: {
      ttlSeconds: positive('snapshot.ttlSeconds', opts.snapshot?.ttlSeconds ?? int(env.SNAPSHOT_TTL_SECONDS, 30)),
      staleReadTtlSeconds: positive('snapshot.staleReadTtlSeconds', opts.snapshot?.staleReadTtlSeconds ?? int(env.SNAPSHOT_STALE_READ_TTL_SECONDS, 300), { allowZero: true }),
    },
    pollIntervalSeconds: positive('pollIntervalSeconds', opts.pollIntervalSeconds ?? int(env.AUTH_EVENT_POLL_SECONDS, 5), { allowZero: true }),
    requestTimeoutMs: positive('requestTimeoutMs', opts.requestTimeoutMs ?? 5000),
    stepUpMaxAgeMinutes: positive('stepUpMaxAgeMinutes', opts.stepUpMaxAgeMinutes ?? int(env.AUTH_STEP_UP_MAX_AGE_MINUTES, 10)),
    // Catalog services whose inbound service keys (stgs_) this app accepts. Explicit configuration,
    // never "any": with none, every service key is refused (see service-keys.js).
    acceptedCallerServices: stringList('acceptedCallerServices', opts.acceptedCallerServices ?? csv(env.AUTH_ACCEPTED_CALLER_SERVICES)),
    serviceKeyCache: {
      validTtlSeconds: positive('serviceKeyCache.validTtlSeconds', opts.serviceKeyCache?.validTtlSeconds ?? 60),
      invalidTtlSeconds: positive('serviceKeyCache.invalidTtlSeconds', opts.serviceKeyCache?.invalidTtlSeconds ?? 10),
      maxEntries: positive('serviceKeyCache.maxEntries', opts.serviceKeyCache?.maxEntries ?? 1000, { integer: true }),
      // Invalid answers live in their own small cache so garbage keys can never evict a valid one.
      negativeMaxEntries: positive('serviceKeyCache.negativeMaxEntries', opts.serviceKeyCache?.negativeMaxEntries ?? 256, { integer: true }),
      // At most this many resolutions in flight at once; beyond it the answer is "could not decide" (503).
      maxInflight: positive('serviceKeyCache.maxInflight', opts.serviceKeyCache?.maxInflight ?? 8, { integer: true }),
    },
    upgradeUrl: opts.upgradeUrl ?? env.AUTH_UPGRADE_URL ?? 'https://www.konstant-studio.com/dashboard',
    tenantResolver: opts.tenantResolver ?? null,
    onEvent: opts.onEvent ?? null,
    // Wall clock: token expiry, entitlement windows, membership expiry. Monotonic clock: how old a
    // cache entry is (immune to the clock being stepped). A test that injects only `now` drives both.
    now: opts.now ?? (() => Date.now()),
    monotonic: opts.monotonic ?? opts.now ?? (() => performance.now()),
    fetch: opts.fetch ?? globalThis.fetch,
    logger: opts.logger ?? console,
  };
}

module.exports = { resolveConfig, ConfigError };
