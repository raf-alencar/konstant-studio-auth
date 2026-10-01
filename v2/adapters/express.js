// Express/Node adapter.
//
//   const auth = createAuth({ service: 'docs' }).start();
//   app.post('/render',
//     auth.express.requirePermission('docs:render', {
//       tenant: (req) => req.params.tenant,
//       brand:  (req) => req.body?.brand,
//     }),
//     handler);
//
// On success: req.principal (Principal), req.authDecision, and the v1-shaped
// req.auth. On failure: 401 (credential), 403 (decision), 503 (could not decide).

const { resolveScope, denialBody, legacyAuth, cleanRunId } = require('./shared');
const { validatePolicy } = require('../service-keys');

function expressAdapter(core) {
  const cfg = core.config;

  function send(res, d) {
    if (d.status === 401) res.set('WWW-Authenticate', 'Bearer');
    if (d.status === 503) res.set('Retry-After', '5');
    return res.status(d.status).json(denialBody(d, cfg));
  }

  async function run(req, res, next, permission, scope, { approver, stepUp } = {}) {
    try {
      const resource = await resolveScope(scope, req);
      // The x-tenant header is only a HINT, the weakest source of the tenant (see selectTenant).
      if (req.headers['x-tenant']) resource.tenantHint = String(req.headers['x-tenant']);
      const requestId = cleanRunId(req.headers['x-run-id']);
      const args = { headers: req.headers, permission, resource, req, requestId };
      const d = approver ? await core.authorizeApprover({ ...args, stepUp }) : await core.authorize(args);
      if (!d.allow) return send(res, d);
      req.principal = d.principal;
      req.authDecision = d;
      req.auth = legacyAuth(d.principal, d);
      return next();
    } catch (err) {
      cfg.logger.error(`auth middleware: unexpected ${err?.name || 'error'}`);
      return send(res, { status: 503, reason: 'platform_unavailable' });
    }
  }

  return {
    requirePermission: (permission, scope) => (req, res, next) => run(req, res, next, permission, scope),
    // requireApprover('social:approve', { stepUp: true, tenant: ... }) -- the
    // CR's object form requireApprover({ permission, stepUp, ...scope }) works too.
    requireApprover: (permissionOrOpts, maybeOpts) => {
      const opts = typeof permissionOrOpts === 'string' ? { ...maybeOpts, permission: permissionOrOpts } : permissionOrOpts;
      const { permission, stepUp = false, ...scope } = opts;
      return (req, res, next) => run(req, res, next, permission, scope, { approver: true, stepUp });
    },
    // Inbound calls from other internal services (stgs_ keys). `policy` is THIS app's own rule for
    // each accepted caller service: { image: ['POST /internal/render', 'GET /internal/status/*'] }.
    // Deny by default; the platform's allowed_routes for the key are not consulted.
    requireServiceCaller: (policy) => {
      validatePolicy(policy, cfg.acceptedCallerServices);
      return async (req, res, next) => {
        // The path as SENT (undecoded, unnormalised, including the mount prefix), without the query string.
        const rawPath = String(req.originalUrl ?? req.url).split(/[?#]/)[0];
        const d = await core.authorizeServiceCaller({ headers: req.headers, method: req.method, path: rawPath, policy });
        if (!d.allow) return send(res, d);
        req.principal = d.principal;
        req.authDecision = d;
        req.auth = legacyAuth(d.principal, d);
        return next();
      };
    },
    assertTenant: (req, tenantId) => core.assertTenant(req.authDecision, tenantId),
    usageContext: (req) => core.usageContext(req.authDecision, cleanRunId(req.headers['x-run-id'])),
  };
}

module.exports = { expressAdapter };
