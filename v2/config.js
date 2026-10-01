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
  'onEvent', 'now', 'fetch', 'logger',
]);

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
  const authorizedParties = opts.clerk?.authorizedParties ?? csv(env.CLERK_AUTHORIZED_PARTIES);
  const audience = opts.clerk?.audience ?? csv(env.CLERK_AUDIENCE);

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
      ttlSeconds: opts.snapshot?.ttlSeconds ?? int(env.SNAPSHOT_TTL_SECONDS, 30),
      staleReadTtlSeconds: opts.snapshot?.staleReadTtlSeconds ?? int(env.SNAPSHOT_STALE_READ_TTL_SECONDS, 300),
    },
    pollIntervalSeconds: opts.pollIntervalSeconds ?? int(env.AUTH_EVENT_POLL_SECONDS, 5),
    requestTimeoutMs: opts.requestTimeoutMs ?? 5000,
    stepUpMaxAgeMinutes: opts.stepUpMaxAgeMinutes ?? int(env.AUTH_STEP_UP_MAX_AGE_MINUTES, 10),
    // Catalog services whose inbound service keys (stgs_) this app accepts. Explicit configuration,
    // never "any": with none, every service key is refused (see service-keys.js).
    acceptedCallerServices: opts.acceptedCallerServices ?? csv(env.AUTH_ACCEPTED_CALLER_SERVICES),
    serviceKeyCache: {
      validTtlSeconds: opts.serviceKeyCache?.validTtlSeconds ?? 60,
      invalidTtlSeconds: opts.serviceKeyCache?.invalidTtlSeconds ?? 10,
      maxEntries: opts.serviceKeyCache?.maxEntries ?? 1000,
    },
    upgradeUrl: opts.upgradeUrl ?? env.AUTH_UPGRADE_URL ?? 'https://www.konstant-studio.com/dashboard',
    tenantResolver: opts.tenantResolver ?? null,
    onEvent: opts.onEvent ?? null,
    now: opts.now ?? (() => Date.now()),
    fetch: opts.fetch ?? globalThis.fetch,
    logger: opts.logger ?? console,
  };
}

module.exports = { resolveConfig, ConfigError };
