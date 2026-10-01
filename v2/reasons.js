// Stable machine-readable reasons, shared with the platform's /v1/authorize
// (docs/control-plane.md "How a decision is made") plus the few the library
// itself produces. The HTTP status an adapter answers with follows from the
// reason: a credential problem is a 401, a decision is a 403, and anything
// that means "could not decide" is a 503 so callers retry instead of
// treating it as a verdict.

const UNAUTHENTICATED = new Set([
  'no_credential',
  'key_not_found',
  'key_revoked',
  'key_expired',
  'token_invalid',
  'token_expired',
  'unsupported_credential',
]);

const UNAVAILABLE = new Set([
  'platform_unavailable',
  'clerk_not_configured',
  'clerk_misconfigured',
  'clerk_jwks_unavailable',
  'token_exchange_not_configured',
]);

function statusFor(reason, allow) {
  if (allow) return 200;
  if (UNAUTHENTICATED.has(reason)) return 401;
  if (UNAVAILABLE.has(reason)) return 503;
  return 403;
}

// Offline decisions cannot tell these apart (the snapshot only lists active,
// entitled tenants and active principals), so they answer with the coarser
// reason on the right. Both are denials; only the label differs. The parity
// test treats exactly these pairs as equal and nothing else.
const COARSE_OFFLINE = {
  tenant_not_found: 'not_entitled',
  tenant_inactive: 'not_entitled',
  principal_not_found: 'no_permission',
  principal_disabled: 'no_permission',
};

module.exports = { statusFor, COARSE_OFFLINE, UNAUTHENTICATED, UNAVAILABLE };
