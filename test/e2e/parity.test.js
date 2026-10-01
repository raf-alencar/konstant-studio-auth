// Parity: the library's decision must equal the platform's /v1/authorize
// decision, for every shared vector, against a SCRATCH copy of the C0b branch on
// a scratch database (scripts/scratch_platform.py). A divergence is a library
// bug (or a documented platform gap), never silently accepted.
//
//   python scripts/scratch_platform.py start --platform-dir <copy> --database-url <local cptest*>
//   npm run test:e2e
//
// Skips when no scratch platform is running, unless REQUIRE_SCRATCH=1 (CI / acceptance).

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('child_process');
const { createAuth } = require('../../v2');
const { COARSE_OFFLINE } = require('../../v2/reasons');
const { context, platformAuthorize, tokenFor, VECTORS } = require('./helpers');

const silent = { error() {}, warn() {}, info() {}, debug() {} };

function libraryFor(ctx, extra = {}) {
  return createAuth({
    service: VECTORS.config.service, platformUrl: ctx.state.platform_url, platformKey: ctx.state.service_key,
    clerk: { issuer: ctx.state.issuer, jwksUrl: ctx.state.jwks_url, authorizedParties: [ctx.state.authorized_party] },
    pollIntervalSeconds: 0, logger: silent, ...extra,
  });
}

async function credential(ctx, c) {
  const who = c.who;
  if (who.clerk) return { headers: { authorization: `Bearer ${await tokenFor(ctx, who.clerk, who.token)}` } };
  if (who.key) return { headers: { 'x-api-key': ctx.state.keys[who.key] } };
  if (who.bearer) return { headers: { authorization: `Bearer ${who.bearer}` } };
  return { headers: {} };
}

function resourceOf(ctx, c) {
  const r = {};
  if (c.ask.tenant) r.tenant = ctx.world.id('tenant', c.ask.tenant);
  if (c.ask.brand) r.brand = c.ask.brand;
  if (c.ask.domain) r.domain = c.ask.domain;
  if (c.ask.mailbox) r.mailbox = c.ask.mailbox;
  return r;
}

// The same question put to the platform directly.
function truthBody(c, resource, headers) {
  const [kind, raw] = headers.authorization ? ['clerk_token', headers.authorization.replace(/^Bearer /, '')] : ['credential', headers['x-api-key']];
  const [service, action] = c.ask.permission.split(':');
  return {
    [kind]: raw, service, action,
    resource: { ...(resource.tenant ? { tenant_id: resource.tenant } : {}), ...(resource.brand ? { brand_id: resource.brand } : {}),
      ...(resource.domain ? { domain: resource.domain } : {}), ...(resource.mailbox ? { mailbox: resource.mailbox } : {}) },
  };
}

const psql = (ctx, sql) => execFileSync('psql', [ctx.state.database_url, '-v', 'ON_ERROR_STOP=1', '-qAt', '-c', sql]).toString();

test('parity with the scratch platform', async (t) => {
  const ctx = await context();
  if (!ctx) {
    if (process.env.REQUIRE_SCRATCH === '1') assert.fail('REQUIRE_SCRATCH=1 but no scratch platform is running');
    return t.skip('no scratch platform running (scripts/scratch_platform.py start)');
  }

  await t.test('the fixture world builds the same snapshot the platform serves', async () => {
    const resp = await fetch(`${ctx.state.platform_url}/v1/authorize/snapshot?service=docs`, { headers: { 'X-API-Key': ctx.state.service_key } });
    assert.equal(resp.status, 200);
    const real = await resp.json();
    // The world's windows and expiries are offsets from the moment the scratch DB was seeded.
    const seeded = ctx.world.constructor;
    const atSeed = new seeded(undefined, { includeTransient: false });
    atSeed.nowMs = ctx.state.seeded_at_ms;
    const built = atSeed.snapshot('docs');

    const roleSlug = new Map([...real.roles, ...built.roles].map((r) => [r.id, r.slug]));
    const norm = (s) => ({
      permissions: [...s.permissions].sort((a, b) => a.action.localeCompare(b.action)),
      tenants: s.tenants.map((x) => ({ id: x.id, type: x.type, org_id: x.org_id, parent_id: x.parent_id, ancestors: x.ancestors, plan: x.plan,
        starts: x.starts_at ? Date.parse(x.starts_at) : null, ends: x.ends_at ? Date.parse(x.ends_at) : null })).sort((a, b) => a.id.localeCompare(b.id)),
      roles: s.roles.map((r) => ({ slug: r.slug, tenant_id: r.tenant_id, permissions: r.permissions })).sort((a, b) => (a.slug + a.tenant_id).localeCompare(b.slug + b.tenant_id)),
      memberships: s.memberships.map((m) => ({ who: m.kind === 'human' ? m.user_id : m.principal_id, kind: m.kind, tenant_id: m.tenant_id, role: roleSlug.get(m.role_id), scope: m.scope,
        expires: m.expires_at ? Date.parse(m.expires_at) : null })).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
      rules: s.rules,
    });
    // Timestamps are offsets from "now" on two different clocks (this test's and the database's):
    // equal to within a couple of minutes is equal. Everything else must match exactly.
    const [r, b] = [norm(real), norm(built)];
    const near = (x, y) => (x === null && y === null) || Math.abs(x - y) < 120000;
    r.tenants.forEach((x, i) => { assert.ok(near(x.starts, b.tenants[i].starts) && near(x.ends, b.tenants[i].ends), `window of ${x.id}`); x.starts = x.ends = b.tenants[i].starts = b.tenants[i].ends = 0; });
    r.memberships.forEach((x, i) => { assert.ok(near(x.expires, b.memberships[i].expires), `expiry of ${x.who}`); x.expires = b.memberships[i].expires = 0; });
    assert.deepEqual(r, b);
  });

  for (const c of VECTORS.cases) {
    if (c.pending || c.platform === 'down' || c.parity === false) {
      await t.test(c.id, { skip: c.pending || c.parity_note || 'needs a down platform: covered by the unit vectors' }, () => {});
      continue;
    }
    await t.test(c.id, async () => {
      const exp = c.expect;
      const { headers } = await credential(ctx, c);
      const resource = resourceOf(ctx, c);
      // The platform has no tenant resolver: the tenant an adopter's resolver would supply is stated explicitly.
      // ...and the tenant an org claim maps to is stated explicitly too (vector field parity_tenant).
      const named = c.ask.resolver_tenant || c.parity_tenant;
      const asked = named ? { ...resource, tenant: ctx.world.id('tenant', named) } : resource;
      const truth = (await platformAuthorize(ctx.state, truthBody(c, asked, headers))).body;
      assert.equal(truth.reason, exp.reason, 'the vector must state what the platform really answers');
      assert.equal(truth.allow, exp.allow);

      const auth = libraryFor(ctx, { tenantResolver: c.ask.resolver_tenant ? () => ctx.world.id('tenant', c.ask.resolver_tenant) : null });
      const lib = await auth.authorize({ headers, permission: c.ask.permission, resource });
      auth.close();

      assert.equal(lib.allow, truth.allow, `library said ${lib.reason}, platform said ${truth.reason}`);
      assert.equal(lib.reason, lib.source === 'offline' ? COARSE_OFFLINE[truth.reason] ?? truth.reason : truth.reason);
      assert.equal(lib.source, exp.source);
      if (truth.allow) {
        assert.equal(lib.tenantId, truth.tenant_id);
        assert.equal(lib.viaTenant, truth.via_tenant);
        assert.deepEqual([...lib.roles].sort(), [...truth.roles].sort());
      }
      if (!COARSE_OFFLINE[truth.reason] && truth.tenant_id !== null) assert.equal(lib.tenantId, truth.tenant_id);
    });
  }

  await t.test('a membership revoked in the platform reaches the library through the change feed', async () => {
    const auth = libraryFor(ctx);
    const read = async () => (await auth.authorize({
      headers: { authorization: `Bearer ${await tokenFor(ctx, 'alice')}` }, permission: 'docs:read', resource: { tenant: ctx.world.id('tenant', 'acme') },
    }));
    assert.equal((await read()).allow, true);
    assert.equal(await auth.cache.pollOnce(), false, 'no change yet: nothing to refresh');

    psql(ctx, `UPDATE stighive_platform.memberships SET status = 'revoked' WHERE principal_id = (SELECT id FROM stighive_platform.principals WHERE user_id = 'user_alice')`);
    try {
      assert.equal((await read()).allow, true, 'still cached inside the TTL: that is the window the feed closes');
      assert.equal(await auth.cache.pollOnce(), true, 'the feed reported the change');
      const after = await read();
      assert.equal(after.allow, false);
      assert.equal(after.reason, 'no_permission');
    } finally {
      psql(ctx, `UPDATE stighive_platform.memberships SET status = 'active' WHERE principal_id = (SELECT id FROM stighive_platform.principals WHERE user_id = 'user_alice')`);
      auth.close();
    }
  });

  await t.test('revalidation uses ETag: an unchanged snapshot answers 304', async () => {
    const statuses = [];
    const auth = libraryFor(ctx, { fetch: async (...a) => { const r = await fetch(...a); if (String(a[0]).includes('/snapshot')) statuses.push(r.status); return r; } });
    await auth.cache.refresh();
    await auth.cache.refresh();
    assert.deepEqual(statuses, [200, 304]);
    auth.close();
  });

  await t.test('a revoked agent key is refused immediately (key checks are never cached)', async () => {
    const auth = libraryFor(ctx);
    const headers = { 'x-api-key': ctx.state.keys.agent_acme_active };
    assert.equal((await auth.authorize({ headers, permission: 'docs:read' })).allow, true);
    psql(ctx, `UPDATE stighive_platform.principal_keys SET revoked_at = now() WHERE name = 'agent_acme_active'`);
    try {
      const d = await auth.authorize({ headers, permission: 'docs:read' });
      assert.deepEqual([d.allow, d.reason, d.status], [false, 'key_revoked', 401]);
    } finally {
      psql(ctx, `UPDATE stighive_platform.principal_keys SET revoked_at = NULL WHERE name = 'agent_acme_active'`);
      auth.close();
    }
  });
});
