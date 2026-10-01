// Inbound service keys (stgs_), as the CoS contract note specifies the final platform behaviour
// (mandatory expect_service, uniform key_not_found, bounded resolution cache, no tenant
// permissions, the app's OWN route policy for each accepted caller service).
//
// The shared vectors for these cases ran `pending-platform` until the platform's C0b2 fixes
// (8335387) were accepted; they are now ordinary vectors in the shared runner and, in e2e, run
// against the real platform. This file adds the detail the vectors do not express (cache,
// expect_service sequence, policy helper) against a fake that implements the contract note.

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const { createAuth } = require('../v2');
const { VECTORS, World, FakePlatform, newClerkKeys, mintClerkToken } = require('./helpers/world');

const silent = { error() {}, warn() {}, info() {}, debug() {} };
const world = new World();
const ACCEPTED = VECTORS.config.accepted_caller_services;
const keyOf = (ref) => world.spec.keys.find((k) => k.ref === ref);
const raw = (ref) => world.rawKey(keyOf(ref));

async function build(over = {}) {
  const keys = await newClerkKeys();
  const fake = new FakePlatform(world, keys, { jwksUrl: 'http://jwks.test/jwks.json' });
  let clock = world.nowMs;
  const auth = createAuth({
    service: 'docs', platformUrl: 'http://platform.test', platformKey: 'stgs_fake-own-key', pollIntervalSeconds: 0,
    clerk: { issuer: VECTORS.config.clerk.issuer, jwksUrl: 'http://jwks.test/jwks.json', authorizedParties: VECTORS.config.clerk.authorized_parties },
    acceptedCallerServices: ACCEPTED, now: () => clock, fetch: fake.fetch, logger: silent, ...over,
  });
  return { auth, fake, keys, advance: (s) => { clock += s * 1000; }, now: () => clock };
}
const headers = (ref) => ({ 'x-api-key': raw(ref) });
const uniform = (d) => [d.allow, d.reason, d.status];

test('the service-key vectors, once more through the contract-note fake', async (t) => {
  for (const c of VECTORS.cases.filter((x) => x.who.key && keyOf(x.who.key).kind === 'service')) {
    await t.test(c.id, async () => {
      const { auth, fake } = await build();
      const exp = c.expect;
      if (c.resolve_only) {
        const r = await auth.resolvePrincipal({ headers: headers(c.who.key) });
        if (exp.allow) {
          assert.equal(r.ok, true);
          assert.deepEqual([r.principal.kind, r.principal.service, r.principal.tenant], [exp.principal.kind, exp.principal.service, exp.principal.tenant]);
          assert.equal('routes' in r.principal, false, "the platform's allowed_routes must not be exposed as this app's policy");
        } else {
          assert.deepEqual([r.ok, r.reason, r.status], [false, exp.reason, exp.status]);
        }
      } else {
        const d = await auth.authorize({ headers: headers(c.who.key), permission: c.ask.permission, resource: { tenant: world.id('tenant', c.ask.tenant) } });
        assert.deepEqual([d.allow, d.reason, d.status], [exp.allow, exp.reason, exp.status]);
        assert.equal(fake.count('POST', '/v1/authorize'), 0, 'decided locally: a service principal has no tenant permissions');
      }
    });
  }
});

test('every resolution names the caller service it expects: each accepted service, never "any"', async () => {
  const { auth, fake } = await build();
  await auth.resolvePrincipal({ headers: headers('svc_video_active') });
  assert.deepEqual(fake.serviceResolves, ['image', 'video'], 'tried in the configured order; stops at the match');
  assert.ok(fake.serviceResolves.every((e) => ACCEPTED.includes(e)));
});

test('uniform failure: unknown, revoked, expired and unaccepted keys are indistinguishable', async () => {
  const { auth } = await build();
  const answers = [];
  for (const ref of ['svc_image_revoked', 'svc_image_expired', 'svc_image_unknown', 'svc_docs_active']) {
    answers.push(await auth.resolvePrincipal({ headers: headers(ref) }));
  }
  assert.ok(answers.every((a) => JSON.stringify(a) === JSON.stringify(answers[0])), 'identical results');
  assert.deepEqual([answers[0].ok, answers[0].reason, answers[0].status], [false, 'key_not_found', 401]);
});

test('with no acceptedCallerServices every service key is refused, and the platform is never asked', async () => {
  const { auth, fake } = await build({ acceptedCallerServices: [] });
  const r = await auth.resolvePrincipal({ headers: headers('svc_image_active') });
  assert.deepEqual([r.ok, r.reason], [false, 'key_not_found']);
  assert.equal(fake.calls.length, 0);
});

test('a bad accepted-service slug is a startup error', () => {
  assert.throws(() => createAuth({ service: 'docs', acceptedCallerServices: ['Image Studio'] }), /not a catalog service slug/);
});

test('resolution cache: valid 60 s, invalid 10 s, keyed by a hash, never the credential, and bounded', async () => {
  const { auth, fake, advance } = await build();
  const asked = () => fake.serviceResolves.length;

  await auth.resolvePrincipal({ headers: headers('svc_image_active') });
  const first = asked();
  await auth.resolvePrincipal({ headers: headers('svc_image_active') });
  assert.equal(asked(), first, 'valid resolution served from the cache');
  advance(59);
  await auth.resolvePrincipal({ headers: headers('svc_image_active') });
  assert.equal(asked(), first);
  advance(2);
  await auth.resolvePrincipal({ headers: headers('svc_image_active') });
  assert.ok(asked() > first, 'refreshed after 60 s');

  const before = asked();
  await auth.resolvePrincipal({ headers: headers('svc_image_revoked') });
  const afterFirstInvalid = asked();
  await auth.resolvePrincipal({ headers: headers('svc_image_revoked') });
  assert.equal(asked(), afterFirstInvalid, 'invalid resolution cached');
  advance(11);
  await auth.resolvePrincipal({ headers: headers('svc_image_revoked') });
  assert.ok(asked() > afterFirstInvalid, 'invalid resolution re-asked after 10 s');
  assert.ok(afterFirstInvalid > before);

  // the credential itself is never a key or a value in the cache
  const dump = JSON.stringify([...auth.serviceKeys.cache.entries()]);
  for (const ref of ['svc_image_active', 'svc_image_revoked']) assert.ok(!dump.includes(raw(ref)), 'raw credential in the cache');
  assert.ok([...auth.serviceKeys.cache.keys()].every((k) => /^[0-9a-f]{64}$/.test(k)), 'sha256 keys');
});

test('resolution cache never outlives the key: capped at its expiry', async () => {
  const { auth, fake, advance, now } = await build();
  fake.serviceKeyExpiresAt = new Date(now() + 20_000).toISOString();
  await auth.resolvePrincipal({ headers: headers('svc_image_active') });
  const n = fake.serviceResolves.length;
  advance(25);
  await auth.resolvePrincipal({ headers: headers('svc_image_active') });
  assert.ok(fake.serviceResolves.length > n, 'asked again once the key expired, not after 60 s');
});

test('resolution cache is bounded: garbage keys cannot grow memory', async () => {
  const { auth } = await build({ serviceKeyCache: { maxEntries: 5 } });
  for (let i = 0; i < 50; i++) {
    await auth.resolvePrincipal({ headers: { 'x-api-key': 'stgs_' + String(i).padStart(40, '0') } });
  }
  assert.ok(auth.serviceKeys.cache.size <= 5);
});

test('a platform outage is not cached as a verdict', async () => {
  const { auth, fake } = await build();
  fake.down = true;
  const r = await auth.resolvePrincipal({ headers: headers('svc_image_active') });
  assert.deepEqual([r.ok, r.reason, r.status], [false, 'platform_unavailable', 503]);
  fake.down = false;
  assert.equal((await auth.resolvePrincipal({ headers: headers('svc_image_active') })).ok, true, 'recovers at once: nothing negative was cached');
});

test('concurrent presentations of one key share a single resolution', async () => {
  const { auth, fake } = await build();
  await Promise.all(Array.from({ length: 10 }, () => auth.resolvePrincipal({ headers: headers('svc_image_active') })));
  assert.equal(fake.serviceResolves.length, 1);
});

test('the platform answering for a different service than asked is not trusted', async () => {
  const { auth, fake } = await build();
  const realFetch = fake.fetch;
  // A platform (or a bug) that ignores expect_service and says the key belongs to "video":
  const lying = async (url, init) => {
    const r = await realFetch(url, init);
    if (String(url).endsWith('/v1/principals/resolve')) {
      const body = await r.json();
      if (body.principal) body.principal.service = 'video';
      return new Response(JSON.stringify(body), { status: 200 });
    }
    return r;
  };
  auth.client.fetch = lying;
  const r = await auth.resolvePrincipal({ headers: headers('svc_image_active') });
  assert.equal(r.ok, false, 'the answer must match the service we asked about');
});

test('service-caller policy: the app\'s own routes per accepted caller, deny by default', async (t) => {
  const { auth } = await build();
  const app = express();
  app.use(auth.express.requireServiceCaller({ image: ['POST /internal/render', 'GET /internal/status/*'], video: ['GET /internal/status/*'] }));
  app.all('*', (req, res) => res.json({ caller: req.principal.service, as: req.auth.userId }));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  t.after(() => server.close());
  const call = (ref, method, path) => fetch(`http://127.0.0.1:${server.address().port}${path}`, { method, headers: ref ? headers(ref) : {} });

  assert.deepEqual(await (await call('svc_image_active', 'POST', '/internal/render')).json(), { caller: 'image', as: 'service:image' });
  assert.equal((await call('svc_image_active', 'GET', '/internal/status/42')).status, 200);
  const wrongMethod = await call('svc_image_active', 'GET', '/internal/render');
  assert.deepEqual([wrongMethod.status, (await wrongMethod.json()).reason], [403, 'route_not_allowed']);
  const otherCaller = await call('svc_video_active', 'POST', '/internal/render');
  assert.deepEqual([otherCaller.status, (await otherCaller.json()).reason], [403, 'route_not_allowed'], 'a different accepted caller does not inherit image\'s routes');
  const unaccepted = await call('svc_docs_active', 'GET', '/internal/status/1');
  assert.deepEqual([unaccepted.status, (await unaccepted.json()).reason], [401, 'key_not_found']);
  const anon = await call(null, 'GET', '/internal/status/1');
  assert.deepEqual([anon.status, (await anon.json()).reason], [401, 'no_credential']);
});

test('service-caller policy ignores the key\'s platform allowed_routes, and refuses non-service callers', async () => {
  const { auth, keys } = await build();
  // svc_image_active holds "POST /v1/authorize" on the PLATFORM; that must not open this app's route of the same name.
  const d = await auth.authorizeServiceCaller({ headers: headers('svc_image_active'), method: 'POST', path: '/v1/authorize', policy: { image: [] } });
  assert.deepEqual([d.allow, d.reason], [false, 'route_not_allowed']);
  const token = await mintClerkToken(keys, { sub: 'user_alice', nowMs: world.nowMs, issuer: VECTORS.config.clerk.issuer, azp: VECTORS.config.clerk.authorized_parties[0] });
  const human = await auth.authorizeServiceCaller({ headers: { authorization: `Bearer ${token}` }, method: 'GET', path: '/internal/x', policy: { image: ['GET /internal/*'] } });
  assert.deepEqual([human.allow, human.reason, human.status], [false, 'service_caller_required', 403]);
});

test('a policy that could never match, or that allows everything, is a wiring error', () => {
  const auth = createAuth({ service: 'docs', acceptedCallerServices: ['image'], logger: silent });
  assert.throws(() => auth.express.requireServiceCaller({ video: ['GET /x'] }), /not in acceptedCallerServices/);
  assert.throws(() => auth.express.requireServiceCaller({ image: ['* /*'] }), /allow everything/);
  assert.throws(() => auth.express.requireServiceCaller({ image: 'GET /x' }), /list of/);
  assert.throws(() => auth.next.withServiceCaller({ image: ['nonsense'] }, () => {}), /bad route entry/);
});

test('audit events name the caller service and never carry the key', async () => {
  const events = [];
  const { auth } = await build({ onEvent: (e) => events.push(e) });
  await auth.authorize({ headers: headers('svc_image_active'), permission: 'docs:read', resource: { tenant: world.id('tenant', 'acme') } });
  await auth.authorizeServiceCaller({ headers: headers('svc_image_active'), method: 'GET', path: '/x', policy: { image: ['GET /x'] } });
  assert.equal(events.length, 2);
  assert.ok(events.every((e) => e.caller_service === 'image' && e.actor.kind === 'system' && e.actor.key_prefix === 'stgs_'));
  assert.ok(!JSON.stringify(events).includes(raw('svc_image_active')));
});
