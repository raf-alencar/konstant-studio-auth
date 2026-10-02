// Runs the shared vectors (test-vectors/vectors.json) against the library with a
// fake platform. The Python suite runs the very same file. `pending-platform`
// cases are skipped with their reason: they describe the end state once the
// platform resolves service keys, and are deliberately not asserted against the stub.

const test = require('node:test');
const assert = require('node:assert/strict');
const { createAuth } = require('../v2');
const { extract } = require('../v2/credentials');
const { routeAllowed } = require('../v2/service-keys');
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
    acceptedCallerServices: VECTORS.config.accepted_caller_services,
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
  if (c.ask.tenant_hint) r.tenantHint = world.id('tenant', c.ask.tenant_hint);
  if (c.ask.tenant_of) r.tenantOf = { kind: c.ask.tenant_of.kind, localId: c.ask.tenant_of.local_id };
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
      const isServiceKey = !!c.who.key && world.spec.keys.find((k) => k.ref === c.who.key).kind === 'service';
      if (c.resolve_only) {
        // identity only: the library asked each accepted caller service, and every failure is the same uniform answer
        const r = await auth.resolvePrincipal({ headers: await headersFor(c, keys, now()) });
        if (exp.allow) {
          assert.equal(r.ok, true);
          assert.deepEqual([r.principal.kind, r.principal.service, r.principal.tenant], [exp.principal.kind, exp.principal.service, exp.principal.tenant]);
          assert.equal('routes' in r.principal, false, "the platform's allowed_routes are not exposed as this app's policy");
        } else {
          assert.deepEqual([r.ok, r.reason, r.status], [false, exp.reason, exp.status]);
        }
        return;
      }
      fake.live = c.who.clerk ? { ...exp, principal: fake._principalSummary(world.principal(c.who.clerk)) } : exp; // a real platform names who an allow is for

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
      assert.equal(d.source, exp.source ?? 'none');
      assert.equal(d.stale, !!exp.stale);
      if (exp.tenant_source !== undefined) assert.equal(d.tenantSource, exp.tenant_source);
      if (!coarse) assert.equal(d.tenantId, world.id('tenant', exp.tenant));
      assert.equal(d.viaTenant, world.id('tenant', exp.via_tenant));
      if (exp.allow) assert.deepEqual([...d.roles].sort(), exp.roles);
      if (exp.sensitive !== undefined && !coarse) assert.equal(d.sensitive, !!exp.sensitive);

      // Who decided: offline/none means the platform's authorize endpoint was never asked; a live
      // decision is exactly one call (and no separate resolve). Skipped when the platform is down,
      // where the library correctly TRIES the call and it fails.
      if (c.platform !== 'down') {
        assert.equal(fake.count('POST', '/v1/authorize'), exp.source === 'live' ? 1 : 0, 'authorize calls');
        if (!isServiceKey) assert.equal(fake.count('POST', '/v1/principals/resolve'), 0, 'decisions never need a separate resolve');
      }
    });
  }
});

test('offline denials use only the documented coarse reasons', () => {
  for (const c of VECTORS.cases.filter((x) => x.expect.offline_reason)) {
    assert.equal(COARSE_OFFLINE[c.expect.reason], c.expect.offline_reason, c.id);
  }
});

// ---- credential extraction: both languages must read a request the same way -----------------
function asHeaders(spec) {
  // A list value is a header sent more than once; Express and Fetch Headers hand that over joined with ", ".
  return Object.fromEntries(Object.entries(spec).map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : v]));
}

test('shared extraction vectors', async (t) => {
  for (const c of VECTORS.extraction.cases) {
    await t.test(c.id, () => {
      const got = extract(asHeaders(c.headers));
      assert.equal(got.type, c.expect.type);
      if ('key_kind' in c.expect) assert.equal(got.keyKind, c.expect.key_kind);
    });
    await t.test(`${c.id} (Fetch Headers)`, () => {
      const h = new Headers();
      for (const [k, v] of Object.entries(c.headers)) for (const one of [].concat(v)) h.append(k, one);
      const got = extract(h);
      assert.equal(got.type, c.expect.type);
      if ('key_kind' in c.expect) assert.equal(got.keyKind, c.expect.key_kind);
    });
  }
});

test('extraction never throws, whatever the headers hold', () => {
  const nasty = ['%', '%%', '%E0%A4%A', '\u0000', 'a'.repeat(100000), '=', ';;;', '__session=', '__session=%'];
  for (const v of nasty) {
    assert.doesNotThrow(() => extract({ cookie: v }));
    assert.doesNotThrow(() => extract({ cookie: `__session=${v}` }));
    assert.doesNotThrow(() => extract({ authorization: v, 'x-api-key': v }));
  }
});

// ---- the app's route policy: both languages pin the same path semantics ---------------------
test('shared route-policy vectors', async (t) => {
  for (const c of VECTORS.route_policy.cases) {
    await t.test(c.id, () => assert.equal(routeAllowed(c.routes, c.method, c.path), c.allow, `${c.method} ${JSON.stringify(c.path)}`));
  }
});

// ---- resource lookups (platform C0f): who owns a service-local id? -----------------------------------------
// Vector arguments that JSON cannot carry natively: {"$type": "int"|"bigint"|"float", "value": "<text>"}.
// Node has no float/int distinction (and no int past 2^53 without BigInt): `int` and `float` become Numbers
// (so an out-of-range int is a Number the rule refuses), `bigint` becomes a BigInt.
function decodeArg(v) {
  if (v && typeof v === 'object' && !Array.isArray(v) && '$type' in v) {
    return v.$type === 'bigint' ? BigInt(v.value) : Number(v.value);
  }
  return v;
}

test('shared lookup vectors', async (t) => {
  const keys = await newClerkKeys();
  for (const c of VECTORS.lookups.cases) {
    await t.test(c.id, async () => {
      const { fake, auth, advance } = await setup({ ask: {} }, keys);
      const mode = c.snapshot || 'fresh';
      if (mode === 'no-resources-field') fake.omitResources = true;
      if (mode === 'stale' || mode === 'beyond-stale') {
        await auth.cache.get(); // primed while the platform is up
        advance(mode === 'stale' ? 120 : 400);
      }
      if (mode !== 'fresh' && mode !== 'no-resources-field') fake.down = true;

      const a = c.args;
      const tenant = a.tenant_raw ?? (a.tenant ? world.id('tenant', a.tenant) : undefined);
      const got = c.call === 'tenantFor' ? await auth.tenantFor(decodeArg(a.kind), decodeArg(a.local_id)) : await auth.resourcesFor(tenant, decodeArg(a.kind));

      const e = c.expect;
      assert.equal(got.ok, e.ok);
      if (!e.ok) return assert.deepEqual([got.reason, got.status], [e.reason, e.status]);
      if (c.call === 'tenantFor') assert.equal(got.tenantId, e.tenant === null ? null : world.id('tenant', e.tenant));
      else assert.deepEqual(got.ids, e.ids);
      assert.equal(got.stale, e.stale);
    });
  }
});
