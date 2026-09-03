const { clerkMiddleware, getAuth } = require('@clerk/express');

function setupClerk() {
  return clerkMiddleware();
}

function protect(req, res, next) {
  const auth = getAuth(req);
  if (!auth?.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.auth = {
    userId:       auth.userId,
    orgId:        auth.orgId ?? null,
    orgRole:      auth.orgRole ?? null,
    isSuperadmin: auth.sessionClaims?.publicMetadata?.superadmin === true,
  };
  next();
}

function superadminOnly(req, res, next) {
  if (!req.auth?.isSuperadmin) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
}

function getBrandId(req) {
  if (req.auth?.isSuperadmin) {
    return req.query.brand_id ?? null;
  }
  return req.auth?.orgId ?? null;
}

function m2mAuth(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || key !== process.env.INTERNAL_API_KEY) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  req.auth = { userId: 'system', orgId: null, isSuperadmin: true };
  next();
}

function protectOrM2M(req, res, next) {
  if (req.headers['x-api-key']) return m2mAuth(req, res, next);
  return protect(req, res, next);
}

function requireLogin(req, res, next) {
  const auth = getAuth(req);
  if (!auth?.userId) {
    const base = process.env.CLERK_SIGN_IN_URL || 'https://accounts.clerk.dev/sign-in';
    // req.originalUrl is relative (e.g. "/showcase.html?x=1") -- it carries
    // no scheme or host. Clerk's hosted sign-in has no way to know that
    // path belongs to the calling app's own domain, so a bare relative
    // redirect_url resolves against the sign-in page's OWN origin instead
    // (live-observed: a redirect_url of "/showcase.html?..." sent someone
    // back to accounts.<domain>/showcase.html, a 404, not the calling
    // app). Build the full absolute URL the request actually came in on.
    //
    // req.protocol alone reports "http" for every service here, even
    // behind Cloudflare over real https -- Cloudflare's tunnel terminates
    // TLS at the edge and forwards to the app over plain HTTP, and none
    // of these services set Express's `trust proxy`, so req.protocol
    // reflects the literal (internal, plain-HTTP) socket rather than what
    // the browser actually used. Read X-Forwarded-Proto directly instead
    // of depending on every consumer remembering `trust proxy` -- this is
    // the shared middleware, so it should be correct by default for the
    // deployment shape every service here actually has.
    const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
    const returnTo = `${proto}://${req.get('host')}${req.originalUrl}`;
    return res.redirect(`${base}?redirect_url=${encodeURIComponent(returnTo)}`);
  }
  next();
}

// ---------------------------------------------------------------------------
// requireService — service-entitlement gate. Checks the platform API for the
// caller's org. Superadmin / m2m bypass. Wire `protect` (or `protectOrM2M`)
// before this middleware so `req.auth` is populated.
// ---------------------------------------------------------------------------

const ENTITLEMENT_TTL_MS = 60_000;
const _entitlementCache = new Map(); // orgId -> { ts, services: Set<string> }

const NO_ACCESS_BODY = {
  error: 'No access to this service',
  upgrade_url: 'https://www.konstant-studio.com/dashboard',
};

function _isProduction() {
  return process.env.NODE_ENV === 'production';
}

async function _fetchEntitlements(orgId) {
  const baseUrl = process.env.PLATFORM_API_URL;
  if (!baseUrl) return null;
  const apiKey = process.env.INTERNAL_API_KEY || '';
  const url = `${baseUrl.replace(/\/+$/, '')}/entitlements/${encodeURIComponent(orgId)}`;
  try {
    const resp = await fetch(url, {
      method: 'GET',
      headers: { 'X-API-Key': apiKey },
      signal: AbortSignal.timeout(5000),
    });
    if (resp.status === 404) return new Set();
    if (!resp.ok) {
      console.error(`entitlements fetch returned ${resp.status} for org=${orgId}`);
      return null;
    }
    const body = await resp.json();
    if (Array.isArray(body)) return new Set(body);
    return new Set(body?.services || body?.entitlements || []);
  } catch (err) {
    console.error('entitlements fetch failed', err);
    return null;
  }
}

async function _getEntitlements(orgId) {
  const cached = _entitlementCache.get(orgId);
  if (cached && Date.now() - cached.ts < ENTITLEMENT_TTL_MS) {
    return cached.services;
  }
  const services = await _fetchEntitlements(orgId);
  if (services !== null) {
    _entitlementCache.set(orgId, { ts: Date.now(), services });
  }
  return services;
}

function requireService(serviceSlug) {
  return async (req, res, next) => {
    if (!req.auth?.userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (req.auth.isSuperadmin) return next();
    if (!req.auth.orgId) {
      return res.status(403).json(NO_ACCESS_BODY);
    }

    const services = await _getEntitlements(req.auth.orgId);
    if (services === null) {
      if (_isProduction()) {
        console.error(
          `entitlement check failed for org=${req.auth.orgId} service=${serviceSlug} — failing closed`
        );
        return res.status(503).json({ error: 'Entitlement service unavailable' });
      }
      console.warn(
        `entitlement check skipped (dev mode): PLATFORM_API_URL unreachable or unset; org=${req.auth.orgId} service=${serviceSlug}`
      );
      return next();
    }

    if (!services.has(serviceSlug)) {
      return res.status(403).json(NO_ACCESS_BODY);
    }
    next();
  };
}

function _resetEntitlementCache() {
  _entitlementCache.clear();
}

module.exports = {
  setupClerk,
  protect,
  superadminOnly,
  getBrandId,
  m2mAuth,
  protectOrM2M,
  requireLogin,
  requireService,
  _resetEntitlementCache,
};
