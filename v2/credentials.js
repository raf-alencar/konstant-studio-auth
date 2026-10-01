// What credential did the caller present? The platform's key prefixes say what
// kind of principal a key belongs to (app/principal_keys.py), so a key can
// never be presented as a different kind. Anything that is not a known key is
// handed to Clerk validation, which answers with a clean 401 when it is not a
// valid session token (this is what unblocks the CRM iOS bearer path).

const KEY_KINDS = { stig_: 'mcp', stga_: 'agent', stgg_: 'guest', stgs_: 'service' };
const MIN_KEY_LENGTH = 20; // the platform treats shorter strings as not a key
const PLATFORM_ISS = 'stighive-platform';

function header(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined; // Fetch Headers
  const v = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

function cookie(headers, name) {
  const raw = header(headers, 'cookie');
  if (!raw) return undefined;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return undefined;
}

function keyKindOf(raw) {
  return KEY_KINDS[raw.slice(0, 5)] || null;
}

function looksLikeJwt(raw) {
  return raw.split('.').length === 3;
}

// Audience tokens (POST /v1/tokens/exchange) are JWTs issued by the platform
// itself; they are re-checked live against the source key, never trusted offline.
function isAudienceToken(raw) {
  try {
    const payload = JSON.parse(Buffer.from(raw.split('.')[1], 'base64url').toString('utf8'));
    return payload?.iss === PLATFORM_ISS;
  } catch {
    return false;
  }
}

// -> { type: 'key'|'clerk'|'audience'|'none', raw, keyKind? }
function extract(headers) {
  const apiKey = header(headers, 'x-api-key');
  const auth = header(headers, 'authorization');
  const bearer = auth && /^bearer\s+/i.test(auth) ? auth.replace(/^bearer\s+/i, '').trim() : undefined;

  if (apiKey && keyKindOf(apiKey)) return classify(apiKey);
  if (bearer) return classify(bearer);
  if (apiKey) return { type: 'key', raw: apiKey, keyKind: null }; // not a platform key: key_not_found, not a guess
  const session = cookie(headers, '__session');
  if (session) return classify(session);
  return { type: 'none' };
}

function classify(raw) {
  const keyKind = keyKindOf(raw);
  if (keyKind) return { type: 'key', raw, keyKind: raw.length >= MIN_KEY_LENGTH ? keyKind : null };
  if (looksLikeJwt(raw) && isAudienceToken(raw)) return { type: 'audience', raw };
  return { type: 'clerk', raw }; // includes junk: Clerk validation answers token_invalid
}

module.exports = { extract, classify, header, cookie, keyKindOf };
