// Next.js adapter (App Router route handlers, and anything else that speaks
// Web-standard Request/Response). No dependency on Next itself.
//
//   const auth = createAuth({ service: 'crm' });
//   export const GET = auth.next.withPermission('crm:read',
//     { tenant: (req) => req.headers.get('x-tenant') },
//     async (req, ctx, { principal, decision }) => Response.json({ ok: true }));
//
// authorizeRequest() is the same check without the wrapper, for middleware.ts
// or server actions: it returns the decision and never throws.

const { resolveScope, denialBody, legacyAuth, cleanRunId } = require('./shared');
const { validatePolicy } = require('../service-keys');

function nextAdapter(core) {
  const cfg = core.config;

  function deny(d) {
    const headers = { 'content-type': 'application/json' };
    if (d.status === 401) headers['www-authenticate'] = 'Bearer';
    if (d.status === 503) headers['retry-after'] = '5';
    return new Response(JSON.stringify(denialBody(d, cfg)), { status: d.status, headers });
  }

  // Never throws: a scope callback that throws (or anything else unexpected) is a 503, not an allow
  // and not an unhandled error.
  async function authorizeRequest(request, permission, scope, ctx, opts = {}) {
    try {
      return await authorizeRequestUnsafe(request, permission, scope, ctx, opts);
    } catch (err) {
      cfg.logger.error(`auth route wrapper: unexpected ${err?.name || 'error'}`);
      return { allow: false, reason: 'platform_unavailable', status: 503, principal: null, tenantId: null, viaTenant: null, roles: [], sensitive: false, source: 'none', stale: false };
    }
  }

  async function authorizeRequestUnsafe(request, permission, scope, ctx, opts) {
    const resource = await resolveScope(scope, request, ctx);
    const hint = request.headers.get('x-tenant');
    if (hint && !hint.includes(',')) resource.tenantHint = hint; // a repeated header arrives joined: ambiguous, no hint
    const args = {
      headers: request.headers, permission, resource, req: request,
      requestId: cleanRunId(request.headers.get('x-run-id')),
    };
    return opts.approver ? core.authorizeApprover({ ...args, stepUp: opts.stepUp }) : core.authorize(args);
  }

  function wrap(permission, scope, handler, opts) {
    return async (request, ctx) => {
      let d;
      try {
        d = await authorizeRequest(request, permission, scope, ctx, opts);
      } catch (err) {
        cfg.logger.error(`auth route wrapper: unexpected ${err?.name || 'error'}`);
        return deny({ status: 503, reason: 'platform_unavailable' });
      }
      if (!d.allow) return deny(d);
      return handler(request, ctx, { principal: d.principal, decision: d, auth: legacyAuth(d.principal, d) });
    };
  }

  // Inbound call from another internal service: `policy` is this app's own per-caller-service route rule.
  function withServiceCaller(policy, handler) {
    validatePolicy(policy, cfg.acceptedCallerServices);
    return async (request, ctx) => {
      // The path as SENT: URL parsing would normalise `..` away and hide exactly what the policy must see.
      const rawPath = (/^[a-z][a-z0-9+.-]*:\/\/[^/?#]*([^?#]*)/i.exec(request.url) || [])[1] ?? '';
      const d = await core.authorizeServiceCaller({ headers: request.headers, method: request.method, path: rawPath, policy });
      if (!d.allow) return deny(d);
      return handler(request, ctx, { principal: d.principal, decision: d, auth: legacyAuth(d.principal, d) });
    };
  }

  return {
    authorizeRequest,
    deny,
    withServiceCaller,
    withPermission: (permission, scope, handler) => wrap(permission, scope, handler),
    withApprover: (permission, opts, handler) => {
      const { stepUp = false, ...scope } = opts;
      return wrap(permission, scope, handler, { approver: true, stepUp });
    },
  };
}

module.exports = { nextAdapter };
