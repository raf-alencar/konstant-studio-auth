// Against the real C0b2 platform (scratch copy, commit 79f4fce): what it ALREADY does for inbound
// service keys and effective permissions, and what the library makes of it. The shared vectors for
// service keys stay `pending-platform` until the CoS's C0b2 fixes (mandatory expect_service,
// uniform key_not_found) land; nothing here depends on those: the library always sends
// expect_service and answers uniformly whatever specific reason the platform gives, so these
// pass both before and after.

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createAuth } = require('../../v2');
const { context, platformAuthorize, tokenFor, VECTORS } = require('./helpers');

const silent = { error() {}, warn() {}, info() {}, debug() {} };

test('service keys and effective permissions against the scratch platform', async (t) => {
  const ctx = await context();
  if (!ctx) {
    if (process.env.REQUIRE_SCRATCH === '1') assert.fail('REQUIRE_SCRATCH=1 but no scratch platform is running');
    return t.skip('no scratch platform running');
  }
  const build = (extra = {}) => createAuth({
    service: VECTORS.config.service, platformUrl: ctx.state.platform_url, platformKey: ctx.state.service_key,
    clerk: { issuer: ctx.state.issuer, jwksUrl: ctx.state.jwks_url, authorizedParties: [ctx.state.authorized_party] },
    acceptedCallerServices: VECTORS.config.accepted_caller_services, pollIntervalSeconds: 0, logger: silent, ...extra,
  });
  const hdr = (ref) => ({ 'x-api-key': ctx.state.keys[ref] });
  const uniformFailure = { ok: false, reason: 'key_not_found', status: 401 };

  await t.test('an accepted caller service resolves to a service principal (and only that: no platform routes exposed)', async () => {
    const auth = build();
    const r = await auth.resolvePrincipal({ headers: hdr('svc_image_active') });
    assert.equal(r.ok, true);
    assert.deepEqual([r.principal.kind, r.principal.service, r.principal.tenant], ['service', 'image', null]);
    assert.ok(r.principal.keyId);
    assert.equal('routes' in r.principal, false);
    const second = await auth.resolvePrincipal({ headers: hdr('svc_video_active') });
    assert.deepEqual([second.ok, second.principal.service], [true, 'video'], 'the second accepted service is tried after the first does not match');
  });

  await t.test('unknown, revoked, expired and unaccepted keys all give the same uniform answer', async () => {
    const auth = build();
    for (const ref of ['svc_image_revoked', 'svc_image_expired', 'svc_image_unknown', 'svc_docs_active']) {
      assert.deepEqual(await auth.resolvePrincipal({ headers: hdr(ref) }), uniformFailure, ref);
    }
  });

  await t.test('a service principal is denied every tenant-scoped permission, exactly as the platform says', async () => {
    const auth = build();
    const acme = ctx.world.id('tenant', 'acme');
    for (const permission of ['docs:read', 'docs:write', 'docs:delete', 'social:approve']) {
      const [service, action] = permission.split(':');
      const truth = (await platformAuthorize(ctx.state, { credential: ctx.state.keys.svc_image_active, service, action, resource: { tenant_id: acme } })).body;
      assert.equal(truth.allow, false);
      assert.equal(truth.reason, 'service_principal_not_granted', 'platform');
      const d = await auth.authorize({ headers: hdr('svc_image_active'), permission, resource: { tenant: acme } });
      assert.deepEqual([d.allow, d.reason, d.status, d.source], [false, 'service_principal_not_granted', 403, 'none'], permission);
    }
  });

  await t.test('the app\'s own route policy governs a matched caller; the platform\'s allowed_routes do not', async () => {
    const auth = build();
    const app = express();
    app.use(auth.express.requireServiceCaller({ image: ['POST /internal/render'] }));
    app.all('*', (req, res) => res.json({ caller: req.principal.service }));
    const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    t.after(() => server.close());
    const call = (ref, method, path) => fetch(`http://127.0.0.1:${server.address().port}${path}`, { method, headers: hdr(ref) });
    assert.equal((await call('svc_image_active', 'POST', '/internal/render')).status, 200);
    const other = await call('svc_image_active', 'POST', '/v1/authorize'); // a PLATFORM route the key holds
    assert.deepEqual([other.status, (await other.json()).reason], [403, 'route_not_allowed']);
    const video = await call('svc_video_active', 'POST', '/internal/render');
    assert.equal(video.status, 403, 'video is accepted but has no policy here');
    const revoked = await call('svc_image_revoked', 'POST', '/internal/render');
    assert.deepEqual([revoked.status, (await revoked.json()).reason], [401, 'key_not_found']);
  });

  await t.test('effective permissions: permits() agrees with /v1/authorize on every runnable vector', async () => {
    const auth = build();
    let compared = 0;
    for (const c of VECTORS.cases) {
      if (c.pending || c.platform === 'down' || c.parity === false || c.who.token) continue;
      if (!(c.who.clerk || c.who.key)) continue;
      const headers = c.who.clerk ? { authorization: `Bearer ${await tokenFor(ctx, c.who.clerk)}` } : { 'x-api-key': ctx.state.keys[c.who.key] };
      const [service, action] = c.ask.permission.split(':');
      const named = c.ask.tenant || c.ask.resolver_tenant || c.parity_tenant;
      const resource = { ...(c.ask.brand ? { brand: c.ask.brand } : {}), ...(c.ask.domain ? { domain: c.ask.domain } : {}), ...(c.ask.mailbox ? { mailbox: c.ask.mailbox } : {}) };
      const tenant = named ? ctx.world.id('tenant', named) : undefined;

      const truth = (await platformAuthorize(ctx.state, {
        ...(c.who.clerk ? { clerk_token: headers.authorization.slice(7) } : { credential: headers['x-api-key'] }), service, action,
        resource: { ...(tenant ? { tenant_id: tenant } : {}), ...(resource.brand ? { brand_id: resource.brand } : {}), ...(resource.domain ? { domain: resource.domain } : {}), ...(resource.mailbox ? { mailbox: resource.mailbox } : {}) },
      })).body;
      const e = await auth.effectivePermissions({ headers, tenant, service });
      if (!e.ok) { assert.equal(truth.allow, false, `${c.id}: no effective answer but the platform allows`); continue; } // a revoked/unknown key, etc.
      assert.equal(e.permits(c.ask.permission, resource), truth.allow, `${c.id}: effective says ${e.permits(c.ask.permission, resource)}, authorize says ${truth.allow} (${truth.reason})`);
      compared += 1;
    }
    assert.ok(compared >= 30, `only ${compared} cases compared`);
  });

  await t.test('an agent\'s effective permissions never include an approver permission (kind restriction applied by the platform)', async () => {
    const auth = build();
    const e = await auth.effectivePermissions({ headers: hdr('agent_acme_active'), service: 'social' });
    assert.equal(e.ok, true);
    assert.ok(!e.principal.permissions.includes('social:approve'));
    assert.ok(e.principal.permissions.includes('social:write'));
  });
});
