// Runs the shared vectors (test-vectors/vectors.json) against the library with a
// fake platform. The Python suite runs the very same file. `pending-platform`
// cases are skipped with their reason: they describe the end state once the
// platform resolves service keys, and are deliberately not asserted against the stub.

const test = require('node:test');
const assert = require('node:assert/strict');
const { createAuth } = require('../v2');
const { VECTORS, World, FakePlatform, newClerkKeys, mintClerkToken } = require('./helpers/world');
const { COARSE_OFFLINE } = require('../v2/reasons');

const silent = { error() {}, warn() {}, info() {}, debug() {} };
const JWKS_URL = 'http://jwks.vectors.test/jwks.json';
const world = new World();

async function setup(c, keys) {
  const fake = new FakePlatform(world, keys, { jwksUrl: JWKS_URL });
  let clock = world.nowMs;
  const idOf = (ref) => world.id('tenant', ref);
  const auth = createAuth({
    service: VECTORS.config.service,
    platformUrl: 'http://platform.vectors.test',
    platformKey: 'stgs_fake-service-key-for-tests',
    clerk: { issuer: VECTORS.config.clerk.issuer, jwksUrl: JWKS_URL, authorizedParties: VECTORS.config.clerk.authorized_parties },
    snapshot: { ttlSeconds: VECTORS.config.snapshot_ttl_seconds, staleReadTtlSeconds: VECTORS.config.stale_read_ttl_seconds },
    pollIntervalSeconds: 0,
    now: () => clock,
    fetch: fake.fetch,
    logger: silent,
    tenantResolver: c.ask.resolver_tenant ? () => idOf(c.ask.resolver_tenant) : null,
  });
  return { fake, auth, advance: (s) => { clock += s * 1000; }, now: () => clock };
}

async function headersFor(c, keys, now) {
  const who = c.who;
  if (who.clerk) {
    const token = await mintClerkToken(keys, { sub: world.principal(who.clerk).user_id, nowMs: now, issuer: VECTORS.config.clerk.issuer, azp: VECTORS.config.clerk.authorized_parties[0] }, who.token);
    return { authorization: `Bearer ${token}` };
  }
  if (who.key) return { 'x-api-key': world.rawKey(world.spec.keys.find((k) => k.ref === who.key)) };
  if (who.bearer) return { authorization: `Bearer ${who.bearer}` };
  return {};
}

function resourceFor(c) {
  const r = {};
  if (c.ask.tenant) r.tenant = world.id('tenant', c.ask.tenant);
  if (c.ask.tenant_raw) r.tenant = c.ask.tenant_raw;
  if (c.ask.brand) r.brand = c.ask.brand;
  if (c.ask.domain) r.domain = c.ask.domain;
  if (c.ask.mailbox) r.mailbox = c.ask.mailbox;
  return r;
}

test('shared vectors', async (t) => {
  const keys = await newClerkKeys();
  for (const c of VECTORS.cases) {
    if (c.pending) {
      await t.test(c.id, { skip: c.pending }, () => {});
      continue;
    }
    await t.test(c.id, async () => {
      const { fake, auth, advance, now } = await setup(c, keys);
      const exp = c.expect;
      fake.live = exp;

      if (c.cache_age_s != null) {
        await auth.cache.get(); // prime while the platform is up, then let the consumer's clock run
        advance(c.cache_age_s);
      }
      if (c.platform === 'down') fake.down = true;
      fake.calls.length = 0;

      const d = await auth.authorize({ headers: await headersFor(c, keys, c.cache_age_s != null ? now() - c.cache_age_s * 1000 : now()), permission: c.ask.permission, resource: resourceFor(c) });

      const coarse = exp.offline_reason;
      assert.equal(d.allow, exp.allow, `allow (reason ${d.reason})`);
      assert.equal(d.reason, coarse ?? exp.reason);
      assert.equal(d.status, exp.status);
      assert.equal(d.source, exp.source);
      assert.equal(d.stale, !!exp.stale);
      if (!coarse) assert.equal(d.tenantId, world.id('tenant', exp.tenant));
      assert.equal(d.viaTenant, world.id('tenant', exp.via_tenant));
      if (exp.allow) assert.deepEqual([...d.roles].sort(), exp.roles);
      if (exp.sensitive !== undefined && !coarse) assert.equal(d.sensitive, !!exp.sensitive);

      // Who decided: offline/none means the platform's authorize endpoint was never asked; a live
      // decision is exactly one call (and no separate resolve). Skipped when the platform is down,
      // where the library correctly TRIES the call and it fails.
      if (c.platform !== 'down') {
        assert.equal(fake.count('POST', '/v1/authorize'), exp.source === 'live' ? 1 : 0, 'authorize calls');
        assert.equal(fake.count('POST', '/v1/principals/resolve'), 0, 'decisions never need a separate resolve');
      }
    });
  }
});

test('offline denials use only the documented coarse reasons', () => {
  for (const c of VECTORS.cases.filter((x) => x.expect.offline_reason)) {
    assert.equal(COARSE_OFFLINE[c.expect.reason], c.expect.offline_reason, c.id);
  }
});
