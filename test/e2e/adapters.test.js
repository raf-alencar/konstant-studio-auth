// One sample app per adapter (Express, Next.js route handlers), gated end to
// end by the library against the SCRATCH platform: real tokens, real keys, real
// decisions, real HTTP. This is also what the adoption checklist tells each
// adopting repo to reproduce for its own routes.

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createAuth } = require('../../v2');
const { context, tokenFor, VECTORS } = require('./helpers');

const silent = { error() {}, warn() {}, info() {}, debug() {} };

function build(ctx, extra = {}) {
  return createAuth({
    service: VECTORS.config.service, platformUrl: ctx.state.platform_url, platformKey: ctx.state.service_key,
    clerk: { issuer: ctx.state.issuer, jwksUrl: ctx.state.jwks_url, authorizedParties: [ctx.state.authorized_party] },
    pollIntervalSeconds: 0, logger: silent, ...extra,
  });
}

test('adapters against the scratch platform', async (t) => {
  const ctx = await context();
  if (!ctx) {
    if (process.env.REQUIRE_SCRATCH === '1') assert.fail('REQUIRE_SCRATCH=1 but no scratch platform is running');
    return t.skip('no scratch platform running');
  }
  const acme = ctx.world.id('tenant', 'acme');
  const globex = ctx.world.id('tenant', 'globex');
  const bearer = async (ref, spec) => ({ authorization: `Bearer ${await tokenFor(ctx, ref, spec)}` });

  // ---- Express ---------------------------------------------------------------
  const events = [];
  const auth = build(ctx, { onEvent: (e) => events.push(e) });
  const app = express();
  app.use(express.json());
  const tenantOf = (req) => req.query.tenant;
  app.get('/docs', auth.express.requirePermission('docs:read', { tenant: tenantOf }),
    (req, res) => res.json({ kind: req.principal.kind, tenant: req.authDecision.tenantId, roles: req.principal.roles, legacyUser: req.auth.userId, usage: auth.express.usageContext(req) }));
  app.post('/docs/render', auth.express.requirePermission('docs:render', { tenant: tenantOf, brand: (req) => req.body?.brand }), (req, res) => res.json({ ok: true }));
  app.delete('/docs/:id', auth.express.requirePermission('docs:delete', { tenant: tenantOf }), (req, res) => res.json({ deleted: req.params.id }));
  app.post('/approve', auth.express.requireApprover('social:approve', { stepUp: true, tenant: tenantOf }), (req, res) => res.json({ approved: true }));
  app.get('/by-tenant-assert', auth.express.requirePermission('docs:read', { tenant: tenantOf }), (req, res) => res.json({ same: auth.express.assertTenant(req, req.query.claimed) }));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(() => { server.close(); auth.close(); });
  const call = (path, { headers = {}, method = 'GET', body } = {}) => fetch(base + path, { method, headers: { 'content-type': 'application/json', ...headers }, body: body && JSON.stringify(body) });

  await t.test('express: no credential is a clean 401 with a challenge', async () => {
    const r = await call(`/docs?tenant=${acme}`);
    assert.equal(r.status, 401);
    assert.equal(r.headers.get('www-authenticate'), 'Bearer');
    assert.deepEqual(await r.json(), { error: 'Unauthorized', reason: 'no_credential' });
  });

  await t.test('express: a bearer that is neither a known key nor a valid session is a clean 401 (CRM iOS path)', async () => {
    const r = await call(`/docs?tenant=${acme}`, { headers: { authorization: 'Bearer definitely-not-a-session' } });
    assert.equal(r.status, 401);
    assert.deepEqual(await r.json(), { error: 'Unauthorized', reason: 'token_invalid' });
  });

  await t.test('express: allowed, with the principal, the legacy req.auth shape and the usage actor', async () => {
    const r = await call(`/docs?tenant=${acme}`, { headers: await bearer('alice') });
    assert.equal(r.status, 200);
    const body = await r.json();
    assert.deepEqual([body.kind, body.tenant, body.roles, body.legacyUser], ['human', acme, ['operator'], 'user_alice']);
    assert.deepEqual(body.usage.actor, { kind: 'human', id: 'user_alice' });
    assert.equal(body.usage.tenant_id, acme);
  });

  await t.test('express: wrong tenant 403; tenant from the x-tenant header decides; garbage tenant cannot widen access', async () => {
    assert.equal((await call(`/docs?tenant=${globex}`, { headers: await bearer('alice') })).status, 403);
    assert.equal((await call('/docs', { headers: { ...(await bearer('alice')), 'x-tenant': acme } })).status, 200);
    assert.equal((await call('/docs', { headers: { ...(await bearer('alice')), 'x-tenant': globex } })).status, 403);
    assert.equal((await call('/docs', { headers: { ...(await bearer('alice')), 'x-tenant': 'not-a-uuid' } })).status, 403);
  });

  await t.test('express: scope from the request body (brand) is enforced', async () => {
    const h = await bearer('carol');
    const send = (brand) => call(`/docs/render?tenant=${acme}`, { method: 'POST', headers: h, body: brand ? { brand } : {} });
    assert.equal((await send('brand-a')).status, 200);
    const out = await send('brand-b');
    assert.deepEqual([out.status, (await out.json()).reason], [403, 'out_of_scope']);
    assert.equal((await (await send()).json()).reason, 'scope_required');
  });

  await t.test('express: sensitive actions are decided live', async () => {
    assert.equal((await call(`/docs/42?tenant=${acme}`, { method: 'DELETE', headers: await bearer('amy') })).status, 200);
    const denied = await call(`/docs/42?tenant=${acme}`, { method: 'DELETE', headers: await bearer('alice') });
    assert.deepEqual([denied.status, (await denied.json()).reason], [403, 'no_permission']);
  });

  await t.test('express: requireApprover needs a human, the permission and a recent second factor', async () => {
    const approve = (headers) => call(`/approve?tenant=${acme}`, { method: 'POST', headers });
    const noMfa = await approve(await bearer('dan'));
    assert.deepEqual([noMfa.status, (await noMfa.json()).reason], [403, 'step_up_required']);
    const stale = await approve(await bearer('dan', { extra: { fva: [5, 45] } }));
    assert.equal((await stale.json()).reason, 'step_up_required');
    assert.equal((await approve(await bearer('dan', { extra: { fva: [5, 2] } }))).status, 200);
    const agent = await approve({ 'x-api-key': ctx.state.keys.agent_acme_active });
    assert.deepEqual([agent.status, (await agent.json()).reason], [403, 'principal_kind_restricted']);
  });

  await t.test('express: agent keys work, and a revoked key stops working at once', async () => {
    assert.equal((await call('/docs', { headers: { 'x-api-key': ctx.state.keys.agent_acme_active } })).status, 200);
    const r = await call('/docs', { headers: { 'x-api-key': ctx.state.keys.agent_acme_revoked } });
    assert.deepEqual([r.status, (await r.json()).reason], [401, 'key_revoked']);
  });

  await t.test('express: this app accepts no caller service, so a service key is refused (uniform key_not_found) without asking the platform', async () => {
    const r = await call('/docs', { headers: { 'x-api-key': ctx.state.keys.svc_image_active } });
    assert.deepEqual([r.status, (await r.json()).reason], [401, 'key_not_found']);
  });

  await t.test('express: assertTenant is true only for the tenant the decision was made in', async () => {
    const h = await bearer('alice');
    assert.equal((await (await call(`/by-tenant-assert?tenant=${acme}&claimed=${acme}`, { headers: h })).json()).same, true);
    assert.equal((await (await call(`/by-tenant-assert?tenant=${acme}&claimed=${globex}`, { headers: h })).json()).same, false);
  });

  await t.test('express: platform unreachable fails closed with a 503 and a Retry-After, never an allow', async () => {
    const dead = build(ctx, { platformUrl: 'http://127.0.0.1:9', requestTimeoutMs: 500 });
    const a = express();
    a.get('/docs', dead.express.requirePermission('docs:read', { tenant: tenantOf }), (req, res) => res.json({ ok: true }));
    a.delete('/docs', dead.express.requirePermission('docs:delete', { tenant: tenantOf }), (req, res) => res.json({ ok: true }));
    const s = await new Promise((r) => { const x = a.listen(0, '127.0.0.1', () => r(x)); });
    try {
      const url = `http://127.0.0.1:${s.address().port}/docs?tenant=${acme}`;
      const h = await bearer('amy');
      for (const method of ['GET', 'DELETE']) {
        const r = await fetch(url, { method, headers: h });
        assert.equal(r.status, 503, method);
        assert.equal(r.headers.get('retry-after'), '5');
        assert.equal((await r.json()).reason, 'platform_unavailable');
      }
    } finally { s.close(); dead.close(); }
  });

  await t.test('audit events carry ids and decisions, never a token or a key', async () => {
    assert.ok(events.length >= 10);
    const blob = JSON.stringify(events);
    for (const secret of [...Object.values(ctx.state.keys), ctx.state.service_key, ctx.state.shared_key, await tokenFor(ctx, 'alice')]) {
      assert.ok(!blob.includes(secret), 'secret material in an audit event');
    }
    assert.ok(!/eyJ[A-Za-z0-9_-]{10,}/.test(blob), 'a JWT in an audit event');
    const allowed = events.find((e) => e.allow && e.actor?.id === 'user_alice');
    assert.ok(allowed && allowed.type === 'auth.decision' && allowed.source === 'offline');
  });

  // ---- Next.js route handlers (Web-standard Request/Response) -----------------
  await t.test('next: route handlers gate the same way, including the session cookie and clean 401s', async () => {
    const nauth = build(ctx);
    t.after(() => nauth.close());
    const GET = nauth.next.withPermission('docs:read', { tenant: (req) => new URL(req.url).searchParams.get('tenant') },
      async (req, ctx2, { principal, decision }) => Response.json({ kind: principal.kind, tenant: decision.tenantId }));
    const req = (headers, tenant = acme) => new Request(`http://app.test/api/docs?tenant=${tenant}`, { headers });

    const ok = await GET(req(await bearer('alice')));
    assert.deepEqual([ok.status, await ok.json()], [200, { kind: 'human', tenant: acme }]);

    const viaCookie = await GET(req({ cookie: `other=1; __session=${(await bearer('alice')).authorization.slice(7)}` }));
    assert.equal(viaCookie.status, 200);

    const junk = await GET(req({ authorization: 'Bearer not-a-session' }));
    assert.deepEqual([junk.status, junk.headers.get('www-authenticate'), (await junk.json()).reason], [401, 'Bearer', 'token_invalid']);

    const forbidden = await GET(req(await bearer('alice'), globex));
    assert.equal(forbidden.status, 403);
    const agent = await GET(req({ 'x-api-key': ctx.state.keys.guest_acme_active }, acme));
    assert.equal(agent.status, 200);
  });
});
