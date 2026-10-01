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
const { routeAllowed } = require('../service-keys');

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
      if (!resource.tenant && req.headers['x-tenant']) resource.tenant = String(req.headers['x-tenant']);
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
    // A SERVICE principal may call only the routes in its allow-list; every other
    // principal kind passes through (their gate is requirePermission).
    requireServiceRoute: () => async (req, res, next) => {
      const r = await core.resolvePrincipal({ headers: req.headers });
      if (!r.ok) return send(res, { status: r.status, reason: r.reason });
      if (r.principal.kind === 'service' && !routeAllowed(r.principal.routes, req.method, req.path)) {
        return send(res, { status: 403, reason: 'route_not_allowed' });
      }
      return next();
    },
    assertTenant: (req, tenantId) => core.assertTenant(req.authDecision, tenantId),
    usageContext: (req) => core.usageContext(req.authDecision, cleanRunId(req.headers['x-run-id'])),
  };
}

module.exports = { expressAdapter };
