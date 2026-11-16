// CR 53a0f327 (select-tenant order). The order is explicit → resolver → default_tenant_id → single
// membership → tenant_choice_required (adapter 409). The Clerk org_id claim is never read for
// selection. The x-tenant header is ignored. Grant-based reachability is enforced by the platform
// (not by the library): a sibling-brand request is denied by /v1/authorize with no_permission.

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createAuth } = require('../v2');
const { VECTORS, World, FakePlatform, newClerkKeys, mintClerkToken } = require('./helpers/world');

const silent = { error() {}, warn() {}, info() {}, debug() {} };
const world = new World();
const ACME = world.id('tenant', 'acme');
const GLOBEX = world.id('tenant', 'globex');
const ROOT = world.id('tenant', 'root');
const ACME_BRAND = world.id('tenant', 'acme_brand');

async function build(over = {}) {
  const keys = await newClerkKeys();
  const fake = new FakePlatform(world, keys, { jwksUrl: 'http://jwks.test/jwks.json' });
  let clock = world.nowMs;
  let mono = 0;
  const auth = createAuth({
    service: 'docs', platformUrl: 'http://platform.test', platformKey: 'stgs_fake-own-key', pollIntervalSeconds: 0,
    clerk: { issuer: VECTORS.config.clerk.issuer, jwksUrl: 'http://jwks.test/jwks.json', authorizedParties: VECTORS.config.clerk.authorized_parties },
    acceptedCallerServices: ['image', 'video'], now: () => clock, monotonic: () => mono, fetch: fake.fetch, logger: silent, ...over,
  });
  const token = (ref, spec) => mintClerkToken(keys, { sub: world.principal(ref).user_id, nowMs: clock, issuer: VECTORS.config.clerk.issuer, azp: VECTORS.config.clerk.authorized_parties[0] }, spec);
  return { auth, fake, keys, token, tick: (s) => { mono += s * 1000; clock += s * 1000; } };
}

// ---- per-branch: explicit ---------------------------------------------------------------------

test('branch explicit: an explicit tenant is used; source=explicit', async () => {
  const { auth, token } = await build();
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('alice')}` }, permission: 'docs:read', resource: { tenant: ACME } });
  assert.deepEqual([d.allow, d.tenantId, d.tenantSource], [true, ACME, 'explicit']);
});

// ---- per-branch: default_tenant_id ------------------------------------------------------------

test('branch default: default_tenant_id is used when no explicit; source=default', async () => {
  const { auth, fake, token } = await build();
  fake.membershipsFor = { [world.principal('bob').user_id]: { default_tenant_id: GLOBEX, memberships: [{ tenant_id: ACME }, { tenant_id: GLOBEX }] } };
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('bob')}` }, permission: 'docs:read' });
  assert.deepEqual([d.tenantId, d.tenantSource], [GLOBEX, 'default']);
});

// ---- per-branch: single_membership ------------------------------------------------------------

test('branch single: a single active membership is used when no explicit and no default; source=single_membership', async () => {
  const { auth, token } = await build();
  // alice has exactly one world membership (acme), so the auto-derived response picks it.
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('alice')}` }, permission: 'docs:read' });
  assert.deepEqual([d.tenantId, d.tenantSource], [ACME, 'single_membership']);
});

// ---- per-branch: tenant_choice_required (adapter 409) -----------------------------------------

test('branch 409: multiple memberships and nothing names one → tenant_choice_required', async () => {
  const { auth, token } = await build();
  // bob has two memberships (acme, globex) with no default: the library cannot pick.
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('bob')}` }, permission: 'docs:read' });
  assert.deepEqual([d.allow, d.reason, d.status], [false, 'tenant_choice_required', 409]);
});

test('adapter 409: Express returns 409 tenant_choice_required', async (t) => {
  const { auth, token } = await build();
  const app = express();
  app.get('/x', auth.express.requirePermission('docs:read', {}), (req, res) => res.json({}));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  t.after(() => server.close());
  const r = await fetch(`http://127.0.0.1:${server.address().port}/x`, { headers: { authorization: `Bearer ${await token('bob')}` } });
  assert.equal(r.status, 409);
  const body = await r.json();
  assert.equal(body.reason, 'tenant_choice_required');
});

test('adapter 409: Next.js (authorizeRequest) returns 409 tenant_choice_required', async () => {
  const { auth, token } = await build();
  const d = await auth.next.authorizeRequest(new Request('http://app.test/x', { headers: { authorization: `Bearer ${await token('bob')}` } }), 'docs:read', {});
  assert.deepEqual([d.allow, d.reason, d.status], [false, 'tenant_choice_required', 409]);
});

// ---- grant allowed / sibling denied -----------------------------------------------------------

test('grant allowed: root member with scope.descendants=true acts on a cl-* brand child (platform allows via /v1/authorize)', async () => {
  const { auth, fake, token } = await build();
  // rafa is a root member with descendants:true; asking about an acme child (acme_brand). Platform allows it.
  fake.live = { allow: true, reason: 'allowed', tenant: 'acme_brand', via_tenant: 'root', principal: fake._principalSummary(world.principal('rafa')), roles: ['owner'] };
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('rafa')}` }, permission: 'docs:read', resource: { tenant: ACME_BRAND } });
  assert.equal(d.allow, true);
  assert.equal(d.tenantSource, 'explicit');
  assert.equal(d.viaTenant, ROOT, 'the grant path (root → acme_brand) surfaced as via_tenant');
});

test('sibling denied (cl-A → cl-B): a member of acme cannot act on globex (platform denies with no_permission)', async () => {
  const { auth, fake, token } = await build();
  // alice is only a member of acme; asking about globex is denied by the platform.
  fake.live = { allow: false, reason: 'no_permission' };
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('alice')}` }, permission: 'docs:read', resource: { tenant: GLOBEX } });
  assert.deepEqual([d.allow, d.reason], [false, 'no_permission']);
});

test('sibling denied (brand → root): a member of only acme_brand cannot act on root (platform denies with no_permission)', async () => {
  const { auth, fake, token } = await build();
  // brandy is a member of the brand child acme_brand ONLY; asking about root goes live and is denied.
  fake.live = { allow: false, reason: 'no_permission' };
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('brandy')}` }, permission: 'docs:read', resource: { tenant: ROOT } });
  assert.deepEqual([d.allow, d.reason], [false, 'no_permission']);
});

// ---- inactive default falls through -----------------------------------------------------------

test('inactive default falls through: an inactive default is absent from the platform response (the join drops it); the library then uses single-membership or 409', async () => {
  const { auth, fake, token } = await build();
  // Bob with two memberships, default would point at an inactive tenant → platform returns null.
  fake.membershipsFor = { [world.principal('bob').user_id]: { default_tenant_id: null, memberships: [{ tenant_id: ACME }, { tenant_id: GLOBEX }] } };
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('bob')}` }, permission: 'docs:read' });
  assert.deepEqual([d.allow, d.reason], [false, 'tenant_choice_required']);
  // And with alice: single membership picks up.
  fake.membershipsFor = { [world.principal('alice').user_id]: { default_tenant_id: null, memberships: [{ tenant_id: ACME }] } };
  const d2 = await auth.authorize({ headers: { authorization: `Bearer ${await token('alice')}` }, permission: 'docs:read' });
  assert.deepEqual([d2.tenantId, d2.tenantSource], [ACME, 'single_membership']);
});

// ---- org_id invariance ------------------------------------------------------------------------

test('org_id invariance: the same selection outcome with and without a Clerk org_id claim on the token', async () => {
  const { auth, token } = await build();
  // alice has a single membership. With and without org_id, same acme.
  const withOrg = await auth.authorize({ headers: { authorization: `Bearer ${await token('alice', { extra: { org_id: 'org_acme' } })}` }, permission: 'docs:read' });
  const withoutOrg = await auth.authorize({ headers: { authorization: `Bearer ${await token('alice')}` }, permission: 'docs:read' });
  assert.deepEqual([withOrg.tenantId, withOrg.tenantSource, withOrg.allow], [ACME, 'single_membership', true]);
  assert.deepEqual([withoutOrg.tenantId, withoutOrg.tenantSource, withoutOrg.allow], [ACME, 'single_membership', true]);
  // Same with a token claiming a completely unrelated org: still the member tenant, not the org.
  const otherOrg = await auth.authorize({ headers: { authorization: `Bearer ${await token('alice', { extra: { org_id: 'org_globex' } })}` }, permission: 'docs:read' });
  assert.deepEqual([otherOrg.tenantId, otherOrg.tenantSource], [ACME, 'single_membership']);
});

test('org_id invariance: effectivePermissions follows the same rule as authorize (same token with and without org_id → identical result)', async () => {
  const { auth, fake, token } = await build();
  const reply = { valid: true, principal: { id: 'p', kind: 'human', user_id: 'user_alice', tenant_id: ACME }, effective: { tenant_id: ACME, reason: null, permissions: [{ permission: 'docs:read', service: 'docs', action: 'read', category: 'read', sensitive: false, scopes: [{ scope: {}, role: 'operator', via_tenant: null }] }] } };
  fake.override = (path, body) => (path === '/v1/principals/resolve' && body && body.include_effective) ? reply : null;
  const withoutOrg = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('alice')}` }, tenant: ACME });
  const withV1 = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('alice', { extra: { org_id: 'org_globex' } })}` }, tenant: ACME });
  const withV2 = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('alice', { extra: { o: { id: 'org_globex', rol: 'admin' } } })}` }, tenant: ACME });
  assert.deepEqual([withoutOrg.ok, withoutOrg.tenantId, withoutOrg.permissions.length], [true, ACME, 1]);
  assert.deepEqual([withV1.ok, withV1.tenantId, withV1.permissions.length], [true, ACME, 1]);
  assert.deepEqual([withV2.ok, withV2.tenantId, withV2.permissions.length], [true, ACME, 1]);
});

// ---- hint refused -----------------------------------------------------------------------------

test('hint refused: the x-tenant header does not move the decision (Express and Next adapters)', async (t) => {
  const { auth, fake, token } = await build();
  fake.membershipsFor = { [world.principal('alice').user_id]: { default_tenant_id: null, memberships: [{ tenant_id: ACME }] } };
  const app = express();
  app.get('/x', auth.express.requirePermission('docs:read', {}), (req, res) => res.json({ tenantId: req.authDecision.tenantId, tenantSource: req.authDecision.tenantSource }));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  t.after(() => server.close());
  const bearer = `Bearer ${await token('alice')}`;
  const r = await (await fetch(`http://127.0.0.1:${server.address().port}/x`, { headers: { authorization: bearer, 'x-tenant': GLOBEX } })).json();
  assert.deepEqual([r.tenantId, r.tenantSource], [ACME, 'single_membership']);
  const nextRes = await auth.next.authorizeRequest(new Request('http://app.test/x', { headers: { authorization: bearer, 'x-tenant': GLOBEX } }), 'docs:read', {});
  assert.deepEqual([nextRes.tenantId, nextRes.tenantSource], [ACME, 'single_membership']);
});

// ---- tenant_audit helper ----------------------------------------------------------------------

test('tenant-audit: service-key only, uniform shape {ok, service, tenant_id, counts, stale}', async () => {
  const { auth, token } = await build();
  const good = await auth.tenantAudit({
    headers: { 'x-api-key': world.rawKey(world.spec.keys.find((k) => k.ref === 'svc_image_active')) },
    tenantId: ACME, counts: { documents: 42 }, stale: false,
  });
  assert.deepEqual([good.ok, good.status, good.service, good.tenant_id, good.counts, good.stale], [true, 200, 'docs', ACME, { documents: 42 }, false]);

  const nokey = await auth.tenantAudit({ headers: {}, tenantId: ACME });
  assert.deepEqual([nokey.ok, nokey.status, nokey.reason], [false, 401, 'no_credential']);

  // A human session is not a service key.
  const human = await auth.tenantAudit({ headers: { authorization: `Bearer ${await token('alice')}` }, tenantId: ACME });
  assert.deepEqual([human.ok, human.status, human.reason], [false, 401, 'service_caller_required']);
});

test('tenant-audit: callerService pins which service key is accepted', async () => {
  const { auth } = await build();
  // svc_image_active is image, not video → route_not_allowed.
  const wrong = await auth.tenantAudit({
    headers: { 'x-api-key': world.rawKey(world.spec.keys.find((k) => k.ref === 'svc_image_active')) },
    callerService: 'video', tenantId: ACME,
  });
  assert.deepEqual([wrong.ok, wrong.status, wrong.reason], [false, 403, 'route_not_allowed']);
});
