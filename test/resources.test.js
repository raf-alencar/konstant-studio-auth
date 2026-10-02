// Resource lookups (C0c2): the mechanics the shared vectors cannot express: index lifetime, bounds,
// hostile snapshots, and the adapter helpers that turn a lookup into a 403/503.

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createAuth, ConfigError } = require('../v2');
const { VECTORS, World, FakePlatform, newClerkKeys, mintClerkToken } = require('./helpers/world');

const silent = { error() {}, warn() {}, info() {}, debug() {} };
const world = new World(JSON.parse(JSON.stringify(VECTORS.world))); // private copy: tests mutate resources
const ACME = world.id('tenant', 'acme');
const GLOBEX = world.id('tenant', 'globex');

async function build(over = {}) {
  const keys = await newClerkKeys();
  const fake = new FakePlatform(world, keys, { jwksUrl: 'http://jwks.test/jwks.json' });
  let mono = 0;
  const logs = [];
  const logger = { ...silent, error: (m) => logs.push(['error', m]), warn: (m) => logs.push(['warn', m]) };
  const auth = createAuth({
    service: 'docs', platformUrl: 'http://platform.test', platformKey: 'stgs_fake-own-key', pollIntervalSeconds: 0,
    clerk: { issuer: VECTORS.config.clerk.issuer, jwksUrl: 'http://jwks.test/jwks.json', authorizedParties: VECTORS.config.clerk.authorized_parties },
    now: () => world.nowMs + mono, monotonic: () => mono, fetch: fake.fetch, logger, ...over,
  });
  const token = (ref) => mintClerkToken(keys, { sub: world.principal(ref).user_id, nowMs: world.nowMs + mono, issuer: VECTORS.config.clerk.issuer, azp: VECTORS.config.clerk.authorized_parties[0] });
  return { auth, fake, token, logs, tick: (s) => { mono += s * 1000; } };
}

const snapshotWith = (tenants) => ({ service: 'docs', version: 1, ttl_seconds: 30, stale_read_ttl_seconds: 300, permissions: [], roles: [], memberships: [], tenants });
const tenant = (id, resources) => ({ id, slug: id, type: 'client', parent_id: null, ancestors: [], org_id: null, plan: null, limits: {}, starts_at: null, ends_at: null, ...(resources === undefined ? {} : { resources }) });

test('the reverse index is built once per snapshot and survives a 304; a new snapshot replaces it', async () => {
  const { auth, fake, tick } = await build();
  await auth.tenantFor('brand', 'brand-a');
  const first = auth.cache.entry.index;
  assert.ok(first, 'built on first use');
  for (let i = 0; i < 50; i++) await auth.tenantFor('brand', 'brand-a');
  await auth.resourcesFor(ACME, 'brand');
  assert.equal(auth.cache.entry.index, first, 'no rebuild per request');

  tick(31); // past the TTL: revalidated with the ETag, nothing changed => 304 => the same entry
  await auth.tenantFor('brand', 'brand-a');
  assert.equal(fake.count('GET', '/v1/authorize/snapshot'), 2);
  assert.equal(auth.cache.entry.index, first, 'a 304 keeps the index');

  world.spec.resources.push({ tenant: 'acme', service: 'docs', kind: 'brand', local_id: 'brand-new', status: 'active' });
  try {
    tick(31);
    assert.equal((await auth.tenantFor('brand', 'brand-new')).tenantId, ACME, 'a changed snapshot is picked up');
    assert.notEqual(auth.cache.entry.index, first, 'and its index is a new one');
  } finally {
    world.spec.resources.pop();
  }
});

test('lookups are refused (unavailable) when the index would exceed maxResources', async () => {
  const { auth, logs } = await build({ maxResources: 3 });
  const r = await auth.tenantFor('brand', 'brand-a');
  assert.deepEqual([r.ok, r.status], [false, 503]);
  assert.ok(logs.some(([, m]) => /larger than 3/.test(m)));
  assert.throws(() => createAuth({ service: 'docs', maxResources: 0, logger: silent }), ConfigError);
});

test('a local id the snapshot gives to two tenants is refused (deny), once logged; other ids still work', async () => {
  const { auth, fake, logs } = await build();
  fake.override = (path) => (path === '/v1/authorize/snapshot' ? snapshotWith([
    tenant(ACME, [{ kind: 'brand', local_id: 'dup' }, { kind: 'brand', local_id: 'fine' }]),
    tenant(GLOBEX, [{ kind: 'brand', local_id: 'dup' }]),
  ]) : undefined);
  assert.equal((await auth.tenantFor('brand', 'dup')).tenantId, null, 'ambiguous ownership is denial');
  assert.equal((await auth.tenantFor('brand', 'fine')).tenantId, ACME);
  assert.equal(logs.filter(([, m]) => /two tenants/.test(m)).length, 1);
  assert.deepEqual((await auth.resourcesFor(GLOBEX, 'brand')).ids, ['dup'], 'the tenant still lists its own rows');
});

test('malformed entries can never grant ownership; a snapshot with SOME tenants lacking the field is unavailable', async () => {
  const { auth, fake } = await build();
  fake.override = (path) => (path === '/v1/authorize/snapshot' ? snapshotWith([
    tenant(ACME, [null, 7, { kind: 5, local_id: 'x' }, { kind: 'brand' }, { kind: 'brand', local_id: ['a'] }, { kind: '', local_id: 'y' }, { kind: 'brand', local_id: 'ok' }]),
  ]) : undefined);
  assert.equal((await auth.tenantFor('brand', 'ok')).tenantId, ACME);
  for (const id of ['x', 'y', 'a']) assert.equal((await auth.tenantFor('brand', id)).tenantId, null);

  const mixed = await build();
  mixed.fake.override = (path) => (path === '/v1/authorize/snapshot' ? snapshotWith([tenant(ACME, [{ kind: 'brand', local_id: 'a' }]), tenant(GLOBEX)]) : undefined);
  assert.deepEqual([(await mixed.auth.tenantFor('brand', 'a')).ok, (await mixed.auth.resourcesFor(ACME, 'brand')).ok], [false, false],
    'one tenant without the field means this platform cannot be trusted to list everyone: unavailable, not "unowned"');
});

test('a snapshot with no tenants at all owns nothing (and is not "unsupported")', async () => {
  const { auth, fake } = await build();
  fake.override = (path) => (path === '/v1/authorize/snapshot' ? snapshotWith([]) : undefined);
  assert.deepEqual(await auth.tenantFor('brand', 'a'), { ok: true, tenantId: null, stale: false });
  assert.deepEqual((await auth.resourcesFor(ACME, 'brand')).ids, []);
});

test('lookups never throw, whatever they are asked', async () => {
  const { auth } = await build();
  for (const bad of [undefined, null, NaN, {}, [], Symbol.iterator, () => 1, 10n ** 30n, 'x'.repeat(100000), Number.MAX_SAFE_INTEGER + 1]) {
    const a = await auth.tenantFor(bad, bad);
    const b = await auth.resourcesFor(bad, bad);
    assert.equal(a.ok === true ? a.tenantId : 'unavail', a.ok === true ? null : 'unavail', String(typeof bad));
    assert.ok(b.ok === false || Array.isArray(b.ids));
  }
});

// ---- adapter helpers ---------------------------------------------------------------------------------------
async function server(auth, t) {
  const app = express();
  const ownedBy = (req) => req.params.id;
  // tenant derived from the object, in the permission check itself
  app.get('/brands/:id', auth.express.requirePermission('docs:read', { tenantOf: { kind: 'brand', id: ownedBy } }), (req, res) => res.json({ tenant: req.authDecision.tenantId, source: req.authDecision.tenantSource }));
  // the tenant is decided elsewhere (explicit route tenant), then the object is checked against it
  app.get('/t/:tenant/brands/:id', auth.express.requirePermission('docs:read', { tenant: (req) => req.params.tenant }), auth.express.requireResourceInTenant('brand', ownedBy), (req, res) => res.json({ ok: true }));
  app.get('/no-decision/:id', auth.express.requireResourceInTenant('brand', ownedBy), (req, res) => res.json({ ok: true }));
  const s = await new Promise((r) => { const x = app.listen(0, '127.0.0.1', () => r(x)); });
  t.after(() => s.close());
  return (path, token) => fetch(`http://127.0.0.1:${s.address().port}${path}`, { headers: token ? { authorization: `Bearer ${token}` } : {} });
}

test('Express tenantOf: the object names the tenant; unowned and unreadable are denied', async (t) => {
  const { auth, token, fake } = await build();
  const get = await server(auth, t);
  const alice = await token('alice');
  const ok = await get('/brands/brand-a', alice);
  assert.deepEqual([ok.status, await ok.json()], [200, { tenant: ACME, source: 'resource' }]);
  const other = await get('/brands/brand-g', alice); // globex's: alice has nothing there
  assert.deepEqual([other.status, (await other.json()).reason], [403, 'no_permission']);
  const unowned = await get('/brands/nope', alice);
  const body = await unowned.json();
  assert.deepEqual([unowned.status, body.reason], [403, 'resource_not_owned']);
  assert.deepEqual(Object.keys(body).sort(), ['error', 'reason'], 'nothing about who owns what leaks in a denial');
  fake.omitResources = true;
  auth.cache.invalidate();
  const down = await get('/brands/brand-a', alice);
  assert.deepEqual([down.status, (await down.json()).reason, down.headers.get('retry-after')], [503, 'platform_unavailable', '5']);
});

test('Express requireResourceInTenant: same tenant passes; another tenant, unowned and unreadable are refused', async (t) => {
  const { auth, token, fake } = await build();
  const get = await server(auth, t);
  const bob = await token('bob'); // a member of acme AND globex
  assert.equal((await get(`/t/${ACME}/brands/brand-a`, bob)).status, 200);
  const mismatch = await get(`/t/${ACME}/brands/brand-g`, bob); // allowed in acme, but the object is globex's
  assert.deepEqual([mismatch.status, (await mismatch.json()).reason], [403, 'tenant_mismatch']);
  const unowned = await get(`/t/${ACME}/brands/nope`, bob);
  assert.deepEqual([unowned.status, (await unowned.json()).reason], [403, 'resource_not_owned']);
  const noDecision = await get('/no-decision/brand-a', bob); // misuse: nothing was decided first
  assert.deepEqual([noDecision.status, (await noDecision.json()).reason], [403, 'tenant_mismatch'], 'refused, never assumed');
  fake.omitResources = true;
  auth.cache.invalidate();
  assert.equal((await get(`/t/${ACME}/brands/brand-a`, bob)).status, 503);
});

test('Express: an id callback that throws is a 503, not an unhandled error or an allow', async (t) => {
  const { auth, token } = await build();
  const app = express();
  app.get('/x', auth.express.requirePermission('docs:read', { tenant: ACME }), auth.express.requireResourceInTenant('brand', () => { throw new Error('app bug'); }), (req, res) => res.json({ ok: true }));
  app.get('/y', auth.express.requirePermission('docs:read', { tenantOf: { kind: 'brand', id: () => { throw new Error('app bug'); } } }), (req, res) => res.json({ ok: true }));
  const s = await new Promise((r) => { const x = app.listen(0, '127.0.0.1', () => r(x)); });
  t.after(() => s.close());
  const h = { authorization: `Bearer ${await token('alice')}` };
  for (const path of ['/x', '/y']) assert.equal((await fetch(`http://127.0.0.1:${s.address().port}${path}`, { headers: h })).status, 503, path);
});

test('Next: tenantOf in the scope and checkResourceInTenant after it', async () => {
  const { auth, token } = await build();
  const idOf = (req) => new URL(req.url).searchParams.get('id');
  const GET = auth.next.withPermission('docs:read', { tenantOf: { kind: 'brand', id: idOf } }, async (req, ctx, { decision }) => Response.json({ tenant: decision.tenantId }));
  const h = { authorization: `Bearer ${await token('alice')}` };
  const ok = await GET(new Request('http://app.test/x?id=brand-a', { headers: h }));
  assert.deepEqual([ok.status, await ok.json()], [200, { tenant: ACME }]);
  assert.equal((await GET(new Request('http://app.test/x?id=nope', { headers: h }))).status, 403);

  const d = await auth.next.authorizeRequest(new Request('http://app.test/x', { headers: h }), 'docs:read', { tenant: ACME });
  assert.equal(await auth.next.checkResourceInTenant(d, 'brand', 'brand-a'), null, 'fine: no response to return');
  const bad = await auth.next.checkResourceInTenant(d, 'brand', 'brand-g');
  assert.equal(bad.status, 403);
});

test('the audit event for a resource-derived tenant says so, and carries no resource id', async () => {
  const events = [];
  const { auth, token } = await build({ onEvent: (e) => events.push(e) });
  await auth.authorize({ headers: { authorization: `Bearer ${await token('alice')}` }, permission: 'docs:read', resource: { tenantOf: { kind: 'brand', localId: 'brand-a' } } });
  assert.equal(events.at(-1).tenant_source, 'resource');
  assert.ok(!JSON.stringify(events).includes('brand-a'), 'local ids stay out of audit events');
});

test('tenantOf is only reached after the credential is verified (an anonymous caller cannot probe ownership)', async () => {
  const { auth, fake } = await build();
  const d = await auth.authorize({ headers: {}, permission: 'docs:read', resource: { tenantOf: { kind: 'brand', localId: 'brand-a' } } });
  assert.deepEqual([d.allow, d.reason], [false, 'no_credential']);
  assert.equal(fake.count('GET', '/v1/authorize/snapshot'), 0);
});

test('the canonical id rule, value by value (what JSON vectors cannot carry)', () => {
  const { normalizeId, normalizeKind } = require('../v2/resources');
  const accepted = [[0, '0'], [42, '42'], [Number.MAX_SAFE_INTEGER, '9007199254740991'], ['x', 'x'], ['  spaced  ', '  spaced  '], ['caf\u00e9', 'caf\u00e9'], ['a'.repeat(200), 'a'.repeat(200)], ['\u{1F600}'.repeat(200), '\u{1F600}'.repeat(200)]];
  for (const [input, out] of accepted) assert.equal(normalizeId(input), out, String(input).slice(0, 10));
  const refused = [-1, -0, 1.5, 1e21, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, 10n, 0n, true, false, null, undefined, {}, [], ['a'], () => 1, Symbol('x'),
    '', 'a'.repeat(201), '\u{1F600}'.repeat(201), 'a\u0000', 'a\u001f', 'a\u007f', 'a\u0080', 'a\u009f', 'a\n', '\ta'];
  for (const input of refused) assert.equal(normalizeId(input), null, String(typeof input));
  for (const k of ['brand', 'a', 'a1_b-c', 'b'.repeat(64)]) assert.equal(normalizeKind(k), k);
  for (const k of ['', 'Brand', '1brand', 'brand!', 'brand\n', 'b'.repeat(65), 'br and', 5, null, undefined, {}]) assert.equal(normalizeKind(k), null, String(k));
});

test('resourcesFor orders by code point whatever order the snapshot lists them in (including characters outside the BMP)', async () => {
  const { auth, fake } = await build();
  fake.override = (path) => (path === '/v1/authorize/snapshot' ? snapshotWith([
    tenant(ACME, [{ kind: 'brand', local_id: '\u{1F600}' }, { kind: 'brand', local_id: 'Ａ' }, { kind: 'brand', local_id: 'b' }, { kind: 'brand', local_id: 'B' }, { kind: 'brand', local_id: 'a' }]),
  ]) : undefined);
  assert.deepEqual((await auth.resourcesFor(ACME, 'brand')).ids, ['B', 'a', 'b', 'Ａ', '\u{1F600}']);
});

test('kinds the registry cannot hold own nothing even if a snapshot lists them', async () => {
  const { auth, fake } = await build();
  fake.override = (path) => (path === '/v1/authorize/snapshot' ? snapshotWith([
    tenant(ACME, [{ kind: 'Brand', local_id: 'x' }, { kind: 'bra nd', local_id: 'x' }, { kind: 'brand', local_id: 'x' }]),
  ]) : undefined);
  assert.equal((await auth.tenantFor('brand', 'x')).tenantId, ACME);
  assert.equal((await auth.tenantFor('Brand', 'x')).tenantId, null, 'asking with an unholdable kind is refused, whatever the snapshot says');
  assert.deepEqual((await auth.resourcesFor(ACME, 'Brand')).ids, []);
});
