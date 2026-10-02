// The CoS review of 011275b (verdict and CR): R1 to R5 and the hardening list. One test per finding,
// each written to FAIL on the code as it was before the fix.

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const http = require('node:http');
const { createAuth, ConfigError } = require('../v2');
const { decideOffline } = require('../v2/decision');
const { SnapshotCache } = require('../v2/snapshot-cache');
const { ClerkVerifier } = require('../v2/clerk');
const { PlatformUnavailable } = require('../v2/platform-client');
const { VECTORS, World, FakePlatform, newClerkKeys, mintClerkToken } = require('./helpers/world');

const silent = { error() {}, warn() {}, info() {}, debug() {} };
const world = new World();
const ACME = world.id('tenant', 'acme');
const GLOBEX = world.id('tenant', 'globex');
const keyOf = (ref) => world.spec.keys.find((k) => k.ref === ref);
const raw = (ref) => world.rawKey(keyOf(ref));

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
  return { auth, fake, keys, token, tick: (s) => { mono += s * 1000; clock += s * 1000; }, jump: (s) => { clock += s * 1000; } };
}
const fakeKey = (i) => 'stgs_' + String(i).padStart(43, '0');

// ---- R1: the x-tenant header cannot move a token off its org's tenant ----------------------------
test('R1: an org-mapped tenant is not moved by an x-tenant header; the header is the weakest source', async () => {
  const { auth, token } = await build();
  const t = await token('bob', { extra: { org_id: 'org_acme' } });
  const d = await auth.authorize({ headers: { authorization: `Bearer ${t}` }, permission: 'docs:read', resource: { tenantHint: GLOBEX } });
  assert.deepEqual([d.allow, d.tenantId, d.tenantSource], [true, ACME, 'org'], 'bob is a member of BOTH, but the token says acme');

  const noOrg = await auth.authorize({ headers: { authorization: `Bearer ${await token('bob')}` }, permission: 'docs:read', resource: { tenantHint: GLOBEX } });
  assert.deepEqual([noOrg.allow, noOrg.tenantId, noOrg.tenantSource], [true, GLOBEX, 'hint'], 'with nothing else naming a tenant the hint is used (and still needs a membership)');

  const explicit = await auth.authorize({ headers: { authorization: `Bearer ${t}` }, permission: 'docs:read', resource: { tenant: GLOBEX, tenantHint: ACME } });
  assert.deepEqual([explicit.tenantId, explicit.tenantSource], [GLOBEX, 'explicit']);
});

test('R1: the tenant resolver beats the hint, and the audit event says where the tenant came from', async () => {
  const events = [];
  const { auth, token } = await build({ tenantResolver: () => GLOBEX, onEvent: (e) => events.push(e) });
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('bob')}` }, permission: 'docs:read', resource: { tenantHint: ACME } });
  assert.deepEqual([d.tenantId, d.tenantSource], [GLOBEX, 'resolver']);
  assert.equal(events.at(-1).tenant_source, 'resolver');
});

test('R1: the v1-shaped req.auth carries no orgId: the only scoping key is tenantId', async (t) => {
  const { auth, token } = await build();
  const app = express();
  app.get('/x', auth.express.requirePermission('docs:read', {}), (req, res) => res.json({ auth: req.auth, decisionTenant: req.authDecision.tenantId }));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  t.after(() => server.close());
  const r = await (await fetch(`http://127.0.0.1:${server.address().port}/x`, {
    headers: { authorization: `Bearer ${await token('bob', { extra: { org_id: 'org_acme', org_role: 'org:admin' } })}`, 'x-tenant': GLOBEX },
  })).json();
  assert.equal('orgId' in r.auth, false);
  assert.equal('orgRole' in r.auth, false);
  assert.deepEqual([r.auth.tenantId, r.auth.clerkOrgId, r.auth.isSuperadmin], [ACME, 'org_acme', false]);
  assert.equal(r.auth.tenantId, r.decisionTenant);
});

// ---- R2: a flood of garbage keys cannot flush good entries or hammer the platform ------------------
test('R2: ~2000 distinct garbage keys cannot evict a valid cached key', async () => {
  const { auth, fake } = await build();
  const good = { 'x-api-key': raw('svc_image_active') };
  assert.equal((await auth.resolvePrincipal({ headers: good })).ok, true);
  const asked = fake.serviceResolves.length;
  for (let i = 0; i < 2000; i++) await auth.resolvePrincipal({ headers: { 'x-api-key': fakeKey(i) } });
  assert.ok(auth.serviceKeys.negative.size <= 256, 'invalid answers live in their own bounded cache');
  const before = fake.serviceResolves.length;
  assert.equal((await auth.resolvePrincipal({ headers: good })).ok, true);
  assert.equal(fake.serviceResolves.length, before, 'the valid entry survived: served from cache, no platform call');
  assert.ok(before > asked, 'the garbage did reach the platform (that is what the other limits are for)');
});

test('R2: the valid cache is LRU: a recently used entry survives, the least recently used goes', async () => {
  const { auth, fake } = await build({ serviceKeyCache: { maxEntries: 2 } });
  const h = (ref) => ({ 'x-api-key': raw(ref) });
  await auth.resolvePrincipal({ headers: h('svc_image_active') });
  await auth.resolvePrincipal({ headers: h('svc_video_active') });
  await auth.resolvePrincipal({ headers: h('svc_image_active') }); // image is now the most recently used
  // a third distinct valid key would have to evict the LRU entry (video), not image
  const spare = { ...keyOf('svc_image_active'), ref: 'svc_image_second' };
  world.keyByRaw.set(world.rawKey(spare), spare);
  await auth.resolvePrincipal({ headers: { 'x-api-key': world.rawKey(spare) } });
  const n = fake.serviceResolves.length;
  await auth.resolvePrincipal({ headers: h('svc_image_active') });
  assert.equal(fake.serviceResolves.length, n, 'image (recently used) is still cached');
  await auth.resolvePrincipal({ headers: h('svc_video_active') });
  assert.ok(fake.serviceResolves.length > n, 'video (least recently used) was evicted');
  world.keyByRaw.delete(world.rawKey(spare));
});

test('R2: a string that cannot be a platform key never reaches the platform', async () => {
  const { auth, fake } = await build();
  for (const bad of ['stgs_short', 'stgs_' + 'a'.repeat(300), 'stgs_' + 'a'.repeat(30) + '!!', 'stgs_' + 'a'.repeat(30) + ' x', 'stgs_' + 'é'.repeat(30)]) {
    const r = await auth.resolvePrincipal({ headers: { 'x-api-key': bad } });
    assert.deepEqual([r.ok, r.reason], [false, 'key_not_found'], bad.slice(0, 20));
  }
  assert.equal(fake.calls.length, 0);
});

test('R2: nonsensical limits are startup errors, and maxEntries: 0 cannot loop', () => {
  const bad = [
    { serviceKeyCache: { maxEntries: 0 } }, { serviceKeyCache: { maxEntries: -1 } }, { serviceKeyCache: { maxEntries: 1.5 } },
    { serviceKeyCache: { validTtlSeconds: 0 } }, { serviceKeyCache: { invalidTtlSeconds: -5 } }, { serviceKeyCache: { negativeMaxEntries: 0 } },
    { serviceKeyCache: { maxInflight: 0 } }, { snapshot: { ttlSeconds: 0 } }, { pollIntervalSeconds: -1 }, { requestTimeoutMs: 0 },
    { stepUpMaxAgeMinutes: 0 }, { snapshot: { ttlSeconds: 'soon' } },
  ];
  for (const o of bad) assert.throws(() => createAuth({ service: 'docs', logger: silent, ...o }), ConfigError, JSON.stringify(o));
});

test('R2: at most maxInflight resolutions at once; beyond that is "could not decide", never a cached verdict', async () => {
  const { auth, fake } = await build({ serviceKeyCache: { maxInflight: 3 } });
  let release;
  fake.gate = new Promise((r) => { release = r; });
  const pending = Array.from({ length: 10 }, (_, i) => auth.resolvePrincipal({ headers: { 'x-api-key': fakeKey(i) } }));
  await new Promise((r) => setImmediate(r));
  release();
  const out = await Promise.all(pending);
  const shed = out.filter((r) => r.reason === 'platform_unavailable');
  assert.equal(shed.length, 7, 'three ran, seven were shed');
  assert.ok(shed.every((r) => r.status === 503));
  const again = await auth.resolvePrincipal({ headers: { 'x-api-key': fakeKey(9) } });
  assert.equal(again.reason, 'key_not_found', 'a shed key was not cached as invalid: asked again, it gets a real answer');
});

test('R2: a platform 429 pauses resolution for its Retry-After and is never turned into a verdict', async () => {
  const { auth, fake, tick } = await build();
  fake.throttleResolve = 7;
  const first = await auth.resolvePrincipal({ headers: { 'x-api-key': raw('svc_image_active') } });
  assert.deepEqual([first.reason, first.status], ['platform_unavailable', 503]);
  const calls = fake.calls.length;
  for (let i = 0; i < 20; i++) await auth.resolvePrincipal({ headers: { 'x-api-key': fakeKey(i) } });
  assert.equal(fake.calls.length, calls, 'no calls while the platform said slow down');
  fake.throttleResolve = 0;
  tick(8);
  const after = await auth.resolvePrincipal({ headers: { 'x-api-key': raw('svc_image_active') } });
  assert.equal(after.ok, true, 'after the pause the real key resolves: the 429 left nothing negative in the cache');
});

// ---- R3: route policy on the path as sent ------------------------------------------------------
function rawRequest(port, method, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

test('R3: Express matches the full original path (mount prefix included) and refuses ambiguous ones', async (t) => {
  const { auth } = await build();
  const app = express();
  // mounted: req.path inside is "/status/1" and would have matched a policy written for "/status/*"
  app.use('/internal', auth.express.requireServiceCaller({ image: ['GET /internal/status/*'] }));
  app.use((req, res) => res.json({ ok: true, path: req.originalUrl }));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  t.after(() => server.close());
  const h = { 'x-api-key': raw('svc_image_active') };
  const port = server.address().port;
  assert.equal((await rawRequest(port, 'GET', '/internal/status/1', h)).status, 200);
  assert.equal((await rawRequest(port, 'GET', '/internal/status/1?x=/../', h)).status, 200, 'query string is not the path');
  for (const bad of ['/internal/status/..%2fadmin', '/internal/status/../x', '/internal//status/1', '/internal/status/a%2fb', '/internal/status/1/extra']) {
    assert.equal((await rawRequest(port, 'GET', bad, h)).status, 403, bad);
  }
});

test('R3: Next keeps the path as sent (an encoded slash stays encoded and is refused)', async () => {
  const { auth } = await build();
  const GET = auth.next.withServiceCaller({ image: ['GET /internal/status/*'] }, async () => Response.json({ ok: true }));
  const h = { 'x-api-key': raw('svc_image_active') };
  assert.equal((await GET(new Request('http://app.test/internal/status/1', { headers: h }))).status, 200);
  assert.equal((await GET(new Request('http://app.test/internal/status/..%2fadmin', { headers: h }))).status, 403);
  assert.equal((await GET(new Request('http://app.test/internal/status/1%2f2', { headers: h }))).status, 403);
  assert.equal((await GET(new Request('http://app.test/internal/status/1?a=%2f', { headers: h }))).status, 200);
});

// ---- R4: booleans mean exactly true / false -----------------------------------------------------
test('R4: a string or number where the platform should say true/false is a malformed answer, never a yes', async () => {
  for (const allow of ['true', 'false', 1, 0, 'yes', {}, [], null]) {
    const { auth, fake, token } = await build();
    fake.override = (path) => (path === '/v1/authorize' ? { allow, reason: 'allowed', tenant_id: ACME, principal: { id: 'p', kind: 'human', user_id: 'user_amy' }, roles: ['admin'] } : undefined);
    const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('amy')}` }, permission: 'docs:delete', resource: { tenant: ACME } });
    assert.deepEqual([d.allow, d.reason], [false, 'platform_unavailable'], JSON.stringify(allow));
  }
});

test('R4: valid must be exactly true: the string "false" is not a valid key', async () => {
  const { auth, fake } = await build();
  fake.override = (path) => (path === '/v1/principals/resolve' ? { valid: 'false', reason: 'key_revoked', principal: { id: 'p', kind: 'agent', tenant_id: ACME } } : undefined);
  const r = await auth.resolvePrincipal({ headers: { 'x-api-key': raw('agent_acme_active') } });
  assert.equal(r.ok, false);
  const s = await auth.resolvePrincipal({ headers: { 'x-api-key': raw('svc_image_active') } });
  assert.equal(s.ok, false, 'and for service keys');
});

test('R4: an allow about a different tenant than the one asked is refused', async () => {
  const { auth, fake, token } = await build();
  fake.override = (path) => (path === '/v1/authorize' ? { allow: true, reason: 'allowed', tenant_id: GLOBEX, principal: { id: 'p', kind: 'human', user_id: 'user_amy' }, roles: ['admin'] } : undefined);
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('amy')}` }, permission: 'docs:delete', resource: { tenant: ACME } });
  assert.deepEqual([d.allow, d.reason], [false, 'platform_unavailable']);
});

// ---- R5: no work on behalf of an unverified credential -------------------------------------------
test('R5: for an audience token neither the tenantResolver nor the org lookup runs, and an allow must name a principal', async () => {
  let resolverCalls = 0;
  const { auth, fake } = await build({ tenantResolver: () => { resolverCalls += 1; return ACME; } });
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const aud = `${b64({ alg: 'EdDSA' })}.${b64({ iss: 'stighive-platform' })}.c2ln`;
  fake.override = (path) => (path === '/v1/authorize' ? { allow: true, reason: 'allowed', tenant_id: ACME, roles: ['viewer'] } : undefined); // an allow with NO principal
  const d = await auth.authorize({ headers: { authorization: `Bearer ${aud}` }, permission: 'docs:read' });
  assert.equal(resolverCalls, 0, 'the app\'s resolver is not run for a credential nobody has verified');
  assert.equal(fake.count('GET', '/v1/authorize/snapshot'), 0, 'no org lookup either');
  assert.deepEqual([d.allow, d.reason], [false, 'platform_unavailable'], 'an allow that identifies no one is not accepted');
});

test('R5: the resolver is not run for key credentials either (the platform has not confirmed them yet)', async () => {
  let resolverCalls = 0;
  const { auth, fake } = await build({ tenantResolver: () => { resolverCalls += 1; return ACME; } });
  fake.live = { allow: true, reason: 'allowed', tenant: 'acme', roles: ['operator'] };
  await auth.authorize({ headers: { 'x-api-key': raw('agent_acme_active') }, permission: 'docs:read' });
  assert.equal(resolverCalls, 0);
});

// ---- hardening --------------------------------------------------------------------------------------
test('JWKS outage: one fetch at a time and a backoff, not a fetch per request', async () => {
  const keys = await newClerkKeys();
  let fetches = 0;
  let mono = 0;
  const failing = async () => { fetches += 1; await new Promise((r) => setTimeout(r, 5)); throw new TypeError('down'); };
  const v = new ClerkVerifier({ issuer: 'https://c.test', jwksUrl: 'http://j.test', authorizedParties: ['x'], audience: [] }, { fetch: failing, now: () => Date.now(), monotonic: () => mono, logger: silent });
  const tok = await mintClerkToken(keys, { sub: 'u', nowMs: Date.now(), issuer: 'https://c.test', azp: 'x' });
  await Promise.all(Array.from({ length: 25 }, () => v.verify(tok).catch(() => {})));
  assert.equal(fetches, 1, 'concurrent callers share one fetch');
  for (let i = 0; i < 50; i++) await v.verify(tok).catch(() => {});
  assert.equal(fetches, 1, 'and during the backoff nobody fetches');
  await assert.rejects(v.verify(tok), { reason: 'clerk_jwks_unavailable' });
  mono += 11_000;
  await v.verify(tok).catch(() => {});
  assert.equal(fetches, 2, 'retried once the backoff passed');
});

test('JWKS outage with keys already cached: the cached keys keep verifying', async () => {
  const keys = await newClerkKeys();
  let ok = true;
  let mono = 0;
  const f = async () => { if (!ok) throw new TypeError('down'); return new Response(JSON.stringify({ keys: [keys.trusted.jwk] })); };
  const v = new ClerkVerifier({ issuer: 'https://c.test', jwksUrl: 'http://j.test', authorizedParties: ['x'], audience: [] }, { fetch: f, now: () => Date.now(), monotonic: () => mono, logger: silent });
  const tok = await mintClerkToken(keys, { sub: 'u', nowMs: Date.now(), issuer: 'https://c.test', azp: 'x' });
  assert.equal((await v.verify(tok)).sub, 'u');
  ok = false;
  mono += 6 * 60_000; // past the 5 minute cache
  assert.equal((await v.verify(tok)).sub, 'u', 'stale keys used rather than turning a Clerk blip into an outage');
});

test('a change event that arrives while a refresh is in flight is not lost to that older request', async () => {
  const gate = { release: null };
  let snapshots = 0;
  const bodies = [{ service: 'docs', version: 1, ttl_seconds: 30, stale_read_ttl_seconds: 300, permissions: [], tenants: [], roles: [], memberships: [] }];
  const client = {
    snapshot: async () => {
      const mine = ++snapshots;
      if (mine === 2) await new Promise((r) => { gate.release = r; }); // the older request is slow
      return { body: { ...bodies[0], version: mine, tenants: [{ id: `t${mine}` }] }, etag: `"e${mine}"` };
    },
    events: async (after) => ({ events: [{ id: after + 1 }], next_cursor: after + 1, head: after + 1 }),
  };
  const cache = new SnapshotCache({ client, service: 'docs', ttlSeconds: 30, staleReadTtlSeconds: 300, now: () => 0, pollIntervalSeconds: 0, logger: silent });
  await cache.refresh(); // snapshot #1
  const slow = cache.refresh(); // snapshot #2 starts (in flight, built BEFORE the change below)
  await new Promise((r) => setImmediate(r));
  const polled = cache.pollOnce(); // a change event arrives now
  await new Promise((r) => setImmediate(r));
  gate.release();
  await slow;
  await polled;
  assert.equal(snapshots, 3, 'a third refresh ran AFTER the event');
  assert.equal(cache.entry.body.tenants[0].id, 't3');
});

test('TTLs use the monotonic clock: stepping the wall clock does not expire or extend a cache', async () => {
  const { auth, fake, jump, tick } = await build();
  await auth.cache.get();
  const n = fake.count('GET', '/v1/authorize/snapshot');
  jump(3600); // the wall clock leaps an hour (NTP step, manual change); no monotonic time passed
  await auth.cache.get();
  assert.equal(fake.count('GET', '/v1/authorize/snapshot'), n, 'still fresh');
  tick(31); // real time passes
  await auth.cache.get();
  assert.ok(fake.count('GET', '/v1/authorize/snapshot') > n, 'refreshed after 30 monotonic seconds');
});

test('the wall clock still governs token validity and windows', async () => {
  const { auth, token, jump } = await build();
  const t = await token('alice');
  const headers = { authorization: `Bearer ${t}` };
  assert.equal((await auth.authorize({ headers, permission: 'docs:read', resource: { tenant: ACME } })).allow, true);
  jump(2 * 3600); // the token (1 h) has expired on the wall clock
  const d = await auth.authorize({ headers, permission: 'docs:read', resource: { tenant: ACME } });
  assert.deepEqual([d.allow, d.reason], [false, 'token_expired']);
});

test('decideOffline refuses a principal kind it cannot read (null, agent, service) instead of matching nothing by accident', () => {
  const snap = { service: 'docs', permissions: [{ action: 'read', category: 'read', sensitive: false }], tenants: [{ id: 't', ancestors: [], starts_at: null, ends_at: null }], roles: [], memberships: [] };
  for (const kind of [null, undefined, 'agent', 'guest', 'service', 'robot']) {
    const d = decideOffline(snap, { userId: 'u', kind }, 'docs', 'read', { tenant: 't' }, Date.now());
    assert.deepEqual([d.allow, d.reason], [false, 'principal_kind_restricted'], String(kind));
  }
});

test('Next: authorizeRequest never throws, even when a scope callback does', async () => {
  const { auth, token } = await build();
  const boom = auth.next.withPermission('docs:read', { tenant: () => { throw new Error('bug in the app'); } }, () => new Response('should not run'));
  const r = await boom(new Request('http://app.test/x', { headers: { authorization: `Bearer ${await token('alice')}` } }));
  assert.equal(r.status, 503);
  const d = await auth.next.authorizeRequest(new Request('http://app.test/x'), 'docs:read', { brand: () => { throw new Error('x'); } });
  assert.deepEqual([d.allow, d.status], [false, 503]);
});

test('step-up denial explains itself: MFA must be enabled and the fva claim present', async (t) => {
  const { auth, token } = await build();
  const app = express();
  app.post('/a', auth.express.requireApprover('social:approve', { stepUp: true, tenant: ACME }), (req, res) => res.json({ ok: 1 }));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  t.after(() => server.close());
  const fakeLive = auth.client; void fakeLive;
  const r = await fetch(`http://127.0.0.1:${server.address().port}/a`, { method: 'POST', headers: { authorization: `Bearer ${await token('dan')}` } });
  // the fake has no live answer queued, so the decision itself fails closed first; the message is exercised via the body builder below
  assert.ok([403, 503].includes(r.status));
  const { denialBody } = require('../v2/adapters/shared');
  const body = denialBody({ status: 403, reason: 'step_up_required' }, { upgradeUrl: 'x' });
  assert.match(body.message, /second-factor/);
  assert.match(body.message, /fva/);
});

// ---- CoS verdict 2: the final fixes -------------------------------------------------------------------
test('V2-1: with an org claim the header is never a fallback: unmapped org => tenant_required, even with no service configured', async () => {
  const none = await build({ service: '' }); // no service => no snapshot to map through
  const t = await none.token('bob', { extra: { org_id: 'org_acme' } });
  const d = await none.auth.authorize({ headers: { authorization: `Bearer ${t}` }, permission: 'docs:read', resource: { tenantHint: GLOBEX } });
  assert.deepEqual([d.allow, d.reason, d.source], [false, 'tenant_required', 'none']);
  assert.equal(none.fake.count('POST', '/v1/authorize'), 0, 'not sent on to the platform with the header either');
});

test('V2-1: an explicit route tenant and the app resolver still win over an org claim (they are app code, not client input)', async () => {
  const { auth, token } = await build({ tenantResolver: () => GLOBEX });
  const t = await token('bob', { extra: { org_id: 'org_dormant' } }); // an org that does not map
  const viaResolver = await auth.authorize({ headers: { authorization: `Bearer ${t}` }, permission: 'docs:read' });
  assert.deepEqual([viaResolver.allow, viaResolver.tenantId, viaResolver.tenantSource], [true, GLOBEX, 'resolver']);
  const explicit = await auth.authorize({ headers: { authorization: `Bearer ${t}` }, permission: 'docs:read', resource: { tenant: ACME } });
  assert.deepEqual([explicit.tenantId, explicit.tenantSource], [ACME, 'explicit']);
});

test('V2-1: effectivePermissions follows the same rule', async () => {
  const { auth, token } = await build();
  const unmapped = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('alice', { extra: { org_id: 'org_dormant' } })}` } });
  assert.deepEqual([unmapped.ok, unmapped.reason, unmapped.permissions], [true, 'tenant_required', []]);
});

test('V2-2: list options must be arrays of non-empty strings (a string passes `includes` and splits into characters)', () => {
  const clerk = (o) => ({ issuer: 'https://c.test', jwksUrl: 'http://j.test', authorizedParties: ['https://a.test'], ...o });
  for (const bad of [{ authorizedParties: 'https://a.test' }, { authorizedParties: [''] }, { authorizedParties: ['  '] }, { authorizedParties: [1] }, { audience: 'x' }, { audience: [''] }]) {
    assert.throws(() => createAuth({ service: 'docs', logger: silent, clerk: clerk(bad) }), ConfigError, JSON.stringify(bad));
  }
  for (const bad of ['image', [''], [1], [null], 'image,video']) {
    assert.throws(() => createAuth({ service: 'docs', logger: silent, acceptedCallerServices: bad }), ConfigError, JSON.stringify(bad));
  }
  assert.doesNotThrow(() => createAuth({ service: 'docs', logger: silent, clerk: clerk({ audience: [] }), acceptedCallerServices: [] }));
});

test('V2-3: invalidate() really expires a cached snapshot, even in the first seconds of the process', async () => {
  const { auth, fake } = await build();
  await auth.cache.get();
  const n = fake.count('GET', '/v1/authorize/snapshot');
  await auth.cache.get();
  assert.equal(fake.count('GET', '/v1/authorize/snapshot'), n, 'fresh before');
  auth.cache.invalidate(); // monotonic clock is at 0 here: the old fetchedAt = 0 would have expired nothing
  await auth.cache.get();
  assert.equal(fake.count('GET', '/v1/authorize/snapshot'), n + 1, 'revalidated at once after invalidate');
  await auth.cache.get();
  assert.equal(fake.count('GET', '/v1/authorize/snapshot'), n + 1, 'and fresh again afterwards (the flag clears)');
});

test('V2-3: an invalidated snapshot whose revalidation fails is still served stale inside the window', async () => {
  const { auth, fake } = await build();
  await auth.cache.get();
  auth.cache.invalidate();
  fake.down = true;
  assert.equal((await auth.cache.get()).state, 'stale');
});

test('V2-3: the signed webhook asks for a FRESH refresh (one that starts after the change)', async () => {
  const crypto = require('node:crypto');
  const { auth } = await build();
  const calls = [];
  auth.cache.refresh = (o) => { calls.push(o); return Promise.resolve(); };
  auth.cache.invalidate = () => calls.push('invalidate');
  const secret = 'whsec_fake-secret-for-tests';
  const body = Buffer.from('{"head":5,"events":[]}');
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = 'v1=' + crypto.createHmac('sha256', secret).update(`${ts}.`).update(body).digest('hex');
  const res = { code: 200, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } };
  auth.eventsWebhook({ secret })({ headers: { 'x-platform-timestamp': ts, 'x-platform-signature': sig }, body }, res);
  assert.equal(res.code, 200);
  assert.deepEqual(calls, ['invalidate', { fresh: true }]);
});

test('V2-5: a malformed resolve reply is "could not decide", never cached as an invalid key', async () => {
  const { auth, fake } = await build();
  let asked = 0;
  fake.override = (path) => { if (path === '/v1/principals/resolve') { asked += 1; return { valid: 'yes' }; } };
  for (let i = 0; i < 3; i++) {
    const r = await auth.resolvePrincipal({ headers: { 'x-api-key': raw('svc_image_active') } });
    assert.deepEqual([r.ok, r.reason, r.status], [false, 'platform_unavailable', 503]);
  }
  assert.ok(asked >= 3, 'asked again each time: nothing was cached');
});

test('V2-5: a repeated x-tenant header is ambiguous: no hint at all (Express and Next)', async (t) => {
  const { auth, token, fake } = await build();
  let body;
  fake.override = (path, b) => { if (path === '/v1/authorize') { body = b; return { allow: false, reason: 'tenant_required' }; } };
  const app = express();
  app.get('/x', auth.express.requirePermission('docs:read', {}), (req, res) => res.json({}));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  t.after(() => server.close());
  const bearer = `Bearer ${await token('bob')}`;
  const send = (headers) => new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: server.address().port, path: '/x', headers }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.end();
  });
  await send({ authorization: bearer, 'x-tenant': [ACME, GLOBEX] }); // sent twice
  assert.equal(body.resource.tenant_id, undefined, 'neither value became a tenant');
  const nextRes = await auth.next.authorizeRequest(new Request('http://app.test/x', { headers: { authorization: bearer, 'x-tenant': `${ACME}, ${GLOBEX}` } }), 'docs:read', {});
  assert.equal(nextRes.tenantSource, null, 'Next: joined repeated header ignored');
});

test('V2-5: effectivePermissions degrades to a 503 instead of throwing (it is informational)', async () => {
  const { auth, token } = await build({ tenantResolver: () => { throw new Error('app bug'); } });
  const r = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('alice')}` } });
  assert.deepEqual([r.ok, r.reason, r.status], [false, 'platform_unavailable', 503]);
});

test('V2-5: policy entries with ";", backslashes or more than two ** are wiring errors', () => {
  const auth = createAuth({ service: 'docs', acceptedCallerServices: ['image'], logger: silent });
  for (const bad of ['GET /internal/a;b', 'GET /internal\\x', 'GET /a/**/b/**/c/**']) {
    assert.throws(() => auth.express.requireServiceCaller({ image: [bad] }), Error, bad);
  }
});
