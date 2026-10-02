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
  assert.deepEqual([unowned.status, body.reason], [403, 'no_permission']);
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
  assert.deepEqual([mismatch.status, (await mismatch.json()).reason], [403, 'no_permission'], 'the caller is not told that the id exists elsewhere');
  const unowned = await get(`/t/${ACME}/brands/nope`, bob);
  assert.deepEqual([unowned.status, (await unowned.json()).reason], [403, 'no_permission']);
  const noDecision = await get('/no-decision/brand-a', bob); // misuse: nothing was decided first
  assert.deepEqual([noDecision.status, (await noDecision.json()).reason], [403, 'no_permission'], 'refused, never assumed');
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

// ---- CoS verdict 4 ---------------------------------------------------------------------------------------------
test('V4-1: a garbage key learns nothing about ownership: the same 401 for an owned and an unowned id, and the registry is never consulted', async (t) => {
  const { auth, fake } = await build();
  const app = express();
  app.get('/brands/:id', auth.express.requirePermission('docs:read', { tenantOf: { kind: 'brand', id: (req) => req.params.id } }), (req, res) => res.json({}));
  const server = await new Promise((r) => { const x = app.listen(0, '127.0.0.1', () => r(x)); });
  t.after(() => server.close());
  const ask = async (path, key) => { const r = await fetch(`http://127.0.0.1:${server.address().port}${path}`, { headers: { 'x-api-key': key } }); return [r.status, await r.json()]; };
  const garbage = 'stga_' + 'x'.repeat(40);
  const owned = await ask('/brands/brand-a', garbage);
  const unowned = await ask('/brands/nope', garbage);
  assert.deepEqual(owned, [401, { error: 'Unauthorized', reason: 'key_not_found' }]);
  assert.deepEqual(unowned, owned, 'identical: nothing about the id');
  assert.equal(fake.count('GET', '/v1/authorize/snapshot'), 0, 'the registry was not even read for an unverified caller');
  // ...nor does a registry outage turn the credential failure into a 503
  fake.omitResources = true;
  assert.deepEqual(await ask('/brands/brand-a', garbage), owned);
  // audience tokens are deferred to the platform too
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const aud = `${b64({ alg: 'EdDSA' })}.${b64({ iss: 'stighive-platform' })}.c2ln`;
  fake.override = (path) => (path === '/v1/principals/resolve' ? { valid: false, reason: 'token_invalid' } : undefined);
  const r = await fetch(`http://127.0.0.1:${server.address().port}/brands/brand-a`, { headers: { authorization: `Bearer ${aud}` } });
  assert.deepEqual([r.status, (await r.json()).reason], [401, 'token_invalid']);
});

test('V4-2: an authenticated user gets the SAME response for an unowned id and for another tenant\'s id', async (t) => {
  const { auth, token } = await build();
  const app = express();
  app.get('/brands/:id', auth.express.requirePermission('docs:read', { tenantOf: { kind: 'brand', id: (req) => req.params.id } }), (req, res) => res.json({}));
  const server = await new Promise((r) => { const x = app.listen(0, '127.0.0.1', () => r(x)); });
  t.after(() => server.close());
  const h = { authorization: `Bearer ${await token('alice')}` }; // a member of acme only
  const ask = async (id) => { const r = await fetch(`http://127.0.0.1:${server.address().port}/brands/${id}`, { headers: h }); return [r.status, [...r.headers].filter(([k]) => /^(www-authenticate|retry-after)$/.test(k)), await r.json()]; };
  assert.deepEqual(await ask('brand-g'), await ask('does-not-exist'), "globex's brand and a brand nobody owns look the same");
});

test('V4-2: the audit event keeps the distinction; the result does not carry it', async () => {
  const events = [];
  const { auth, token } = await build({ onEvent: (e) => events.push(e) });
  const h = { authorization: `Bearer ${await token('alice')}` };
  const unowned = await auth.authorize({ headers: h, permission: 'docs:read', resource: { tenantOf: { kind: 'brand', localId: 'nope' } } });
  const other = await auth.authorize({ headers: h, permission: 'docs:read', resource: { tenantOf: { kind: 'brand', localId: 'brand-g' } } });
  const conflict = await auth.authorize({ headers: h, permission: 'docs:read', resource: { tenant: ACME, tenantOf: { kind: 'brand', localId: 'brand-g' } } });
  assert.deepEqual([unowned.reason, other.reason, conflict.reason], ['no_permission', 'no_permission', 'no_permission']);
  assert.deepEqual(events.map((e) => e.detail), ['resource_not_owned', null, 'tenant_mismatch']);
  for (const r of [unowned, other, conflict]) assert.ok(!JSON.stringify(r).includes('resource_not_owned') && !JSON.stringify(r).includes('tenant_mismatch'));
  assert.ok(!JSON.stringify(events).includes('brand-g'), 'and still no local ids in the audit');
});

test('V4-3: the post-decision helper refuses stale ownership for a write and serves it for a read', async () => {
  const { auth, fake, token, tick } = await build();
  const h = { authorization: `Bearer ${await token('alice')}` };
  const read = await auth.authorize({ headers: h, permission: 'docs:read', resource: { tenant: ACME } });
  const write = await auth.authorize({ headers: h, permission: 'docs:write', resource: { tenant: ACME } });
  assert.deepEqual([read.category, write.category], ['read', 'write'], 'the decision knows its permission category');
  fake.down = true;
  tick(120); // past the TTL, inside the stale window: the registry answer is stale
  const r = await auth.authorizeResourceInTenant({ decision: read, kind: 'brand', localId: 'brand-a' });
  assert.deepEqual([r.allow, r.stale], [true, true], 'a read is served from the stale answer and says so');
  const w = await auth.authorizeResourceInTenant({ decision: write, kind: 'brand', localId: 'brand-a' });
  assert.deepEqual([w.allow, w.reason, w.status], [false, 'platform_unavailable', 503], 'a write is refused');
  const forced = await auth.authorizeResourceInTenant({ decision: read, kind: 'brand', localId: 'brand-a', write: true });
  assert.equal(forced.allow, false, 'an explicit write flag overrides the decision category');
  const unknown = await auth.authorizeResourceInTenant({ decision: { ...read, category: null }, kind: 'brand', localId: 'brand-a' });
  assert.equal(unknown.allow, false, 'an unknown category counts as a write');
});

test('V4-3: an invalidated snapshot whose refresh fails does not grant the old owner a write', async () => {
  const { auth, fake, token } = await build();
  const h = { authorization: `Bearer ${await token('alice')}` };
  await auth.cache.get();
  auth.cache.invalidate(); // a change event said the registry moved
  fake.down = true; // ...and the refresh fails
  const w = await auth.authorize({ headers: h, permission: 'docs:write', resource: { tenantOf: { kind: 'brand', localId: 'brand-a' } } });
  assert.deepEqual([w.allow, w.reason], [false, 'platform_unavailable']);
  const r = await auth.authorize({ headers: h, permission: 'docs:read', resource: { tenantOf: { kind: 'brand', localId: 'brand-a' } } });
  assert.deepEqual([r.allow, r.stale], [true, true], 'a read still works and is marked stale');
});

test('V4-4: a snapshot tenant without an id makes the snapshot unsupported (it must not read as unowned and let a later tenant take its ids)', async () => {
  const { auth, fake } = await build();
  fake.override = (path) => (path === '/v1/authorize/snapshot' ? snapshotWith([
    { ...tenant('x', [{ kind: 'brand', local_id: 'shared' }]), id: undefined },
    tenant(GLOBEX, [{ kind: 'brand', local_id: 'shared' }]),
  ]) : undefined);
  assert.deepEqual([(await auth.tenantFor('brand', 'shared')).ok, (await auth.resourcesFor(GLOBEX, 'brand')).ok], [false, false]);
  for (const bad of [null, '', 5, {}]) {
    fake.override = (path) => (path === '/v1/authorize/snapshot' ? snapshotWith([{ ...tenant('x', []), id: bad }, tenant(GLOBEX, [])]) : undefined);
    auth.cache.invalidate();
    assert.equal((await auth.tenantFor('brand', 'a')).ok, false, JSON.stringify(bad));
  }
});

test('V4-5: repeated rows count once (toward the cap too) and list once', async () => {
  const { auth, fake } = await build({ maxResources: 3 });
  const row = { kind: 'brand', local_id: 'dup' };
  fake.override = (path) => (path === '/v1/authorize/snapshot' ? snapshotWith([tenant(ACME, [row, row, row, row, row, { kind: 'brand', local_id: 'two' }, { kind: 'brand', local_id: 'three' }])]) : undefined);
  assert.equal((await auth.tenantFor('brand', 'dup')).tenantId, ACME, 'five copies of one row stay under a cap of three');
  assert.deepEqual((await auth.resourcesFor(ACME, 'brand')).ids, ['dup', 'three', 'two']);
});

test('V4-6: the code-point comparator agrees with a reference ordering, and ids are sorted lazily', async () => {
  const { buildIndex, idsOf } = require('../v2/resources');
  const alphabet = ['a', 'B', '\u00e9', '\u0100', '\ud7ff', '\ue000', '\uff21', '\uffff', '\u{10000}', '\u{1F600}', '\u{10FFFF}'];
  let seed = 7;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const ids = new Set();
  while (ids.size < 400) ids.add(Array.from({ length: 1 + Math.floor(rnd() * 3) }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join(''));
  const reference = [...ids].sort((a, b) => { const x = Array.from(a); const y = Array.from(b); for (let i = 0; i < Math.min(x.length, y.length); i++) { const d = x[i].codePointAt(0) - y[i].codePointAt(0); if (d) return d; } return x.length - y.length; });
  const index = buildIndex({ tenants: [{ id: 't', resources: [...ids].map((local_id) => ({ kind: 'k', local_id })) }] }, { maxResources: 1000, logger: silent });
  assert.equal(index.byTenant.get('t').get('k').sorted, false, 'building the index sorts nothing');
  assert.deepEqual(idsOf(index, 't', 'k'), reference);
  assert.equal(index.byTenant.get('t').get('k').sorted, true);
});

test('V4-3: a key-based WRITE is refused on stale ownership even when /v1/authorize still works (only the registry refresh is failing)', async () => {
  const { auth, fake, tick } = await build();
  const key = { 'x-api-key': world.rawKey(world.spec.keys.find((k) => k.ref === 'agent_acme_active')) };
  await auth.cache.get(); // registry loaded
  tick(120); // past the TTL
  // the snapshot route fails, everything else (resolve, authorize) answers
  fake.override = (path) => (path === '/v1/authorize/snapshot' ? new Response('{}', { status: 503 }) : undefined);
  fake.live = { allow: true, reason: 'allowed', tenant: 'acme', roles: ['operator'] };
  const write = await auth.authorize({ headers: key, permission: 'docs:write', resource: { tenantOf: { kind: 'brand', localId: 'brand-a' } } });
  assert.deepEqual([write.allow, write.reason, write.status], [false, 'platform_unavailable', 503], 'the old owner cannot be granted a write');
  assert.equal(fake.count('POST', '/v1/authorize'), 0, 'never even asked the platform to decide on stale ownership');
  const read = await auth.authorize({ headers: key, permission: 'docs:read', resource: { tenantOf: { kind: 'brand', localId: 'brand-a' } } });
  assert.deepEqual([read.allow, read.source, read.stale], [true, 'live', true], 'a read is decided and says the ownership was stale');
});
