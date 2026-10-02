// The real tenant-resource registry (platform C0f, scratch copy of the pinned commit): every lookup vector is
// answered by the library AND checked against the platform's own reverse lookup, and a service registers,
// conflicts and retires rows through the platform's API exactly as a real service would.

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('child_process');
const { createAuth } = require('../../v2');
const { context, VECTORS } = require('./helpers');

const silent = { error() {}, warn() {}, info() {}, debug() {} };
const psql = (ctx, sql) => execFileSync('psql', [ctx.state.database_url, '-v', 'ON_ERROR_STOP=1', '-qAt', '-c', sql]).toString();

function decodeArg(v) {
  if (v && typeof v === 'object' && !Array.isArray(v) && '$type' in v) return v.$type === 'bigint' ? BigInt(v.value) : Number(v.value);
  return v;
}

test('the real registry', async (t) => {
  const ctx = await context();
  if (!ctx) {
    if (process.env.REQUIRE_SCRATCH === '1') assert.fail('REQUIRE_SCRATCH=1 but no scratch platform is running');
    return t.skip('no scratch platform running');
  }
  const build = () => createAuth({
    service: VECTORS.config.service, platformUrl: ctx.state.platform_url, platformKey: ctx.state.service_key,
    clerk: { issuer: ctx.state.issuer, jwksUrl: ctx.state.jwks_url, authorizedParties: [ctx.state.authorized_party] },
    acceptedCallerServices: VECTORS.config.accepted_caller_services, pollIntervalSeconds: 0, logger: silent,
  });
  const api = async (method, path, body, key = ctx.state.service_key) => {
    const r = await fetch(`${ctx.state.platform_url}${path}`, { method, headers: { 'X-API-Key': key, 'Content-Type': 'application/json' }, body: body && JSON.stringify(body) });
    return { status: r.status, body: await r.json().catch(() => null) };
  };
  const tid = (ref) => ctx.world.id('tenant', ref);

  // The platform's own answer to "who owns this local id for my service?" (reverse lookup) and "what does this tenant have?".
  const platformOwner = async (kind, localId) => {
    const r = await api('GET', `/v1/resources?kind=${encodeURIComponent(kind)}&local_id=${encodeURIComponent(localId)}`);
    return r.status === 200 && r.body.length === 1 ? r.body[0].tenant_id : null; // 422 (cannot be held) is "nobody"
  };
  const platformIds = async (tenant, kind) => {
    const r = await api('GET', `/v1/resources?tenant_id=${tenant}&kind=${encodeURIComponent(kind)}&limit=1000`);
    return r.status === 200 ? r.body.map((x) => x.local_id) : [];
  };
  const byCodePoint = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

  await t.test('every lookup vector agrees with the platform\'s own registry answers', async () => {
    let compared = 0;
    for (const c of VECTORS.lookups.cases) {
      if (c.snapshot) continue; // stale / down / no-field modes need a platform that is not answering
      const auth = build();
      const a = c.args;
      const kind = decodeArg(a.kind);
      const localId = decodeArg(a.local_id);
      if (c.call === 'tenantFor') {
        const got = await auth.tenantFor(kind, localId);
        assert.equal(got.ok, true, c.id);
        assert.equal(got.tenantId, c.expect.tenant === null ? null : tid(c.expect.tenant), `${c.id}: library vs vector`);
        // The platform's truth, only where the value is a plain registry string (a number or odd type is the library's rule).
        if (typeof kind === 'string' && (typeof localId === 'string' || (typeof localId === 'number' && Number.isSafeInteger(localId) && localId >= 0))) {
          const truth = await platformOwner(kind, String(localId));
          assert.equal(got.tenantId, truth, `${c.id}: library vs the platform's reverse lookup`);
          compared += 1;
        }
      } else {
        const tenant = a.tenant_raw ?? (a.tenant ? tid(a.tenant) : undefined);
        const got = await auth.resourcesFor(tenant, kind);
        assert.deepEqual(got.ids, c.expect.ids, `${c.id}: library vs vector`);
        if (typeof tenant === 'string' && /^[0-9a-f-]{36}$/.test(tenant) && typeof kind === 'string' && kind) {
          assert.deepEqual([...got.ids].sort(byCodePoint), (await platformIds(tenant, kind)).sort(byCodePoint), `${c.id}: library vs the platform's list`);
          compared += 1;
        }
      }
      auth.close();
    }
    assert.ok(compared >= 25, `only ${compared} cases were compared with the platform itself`);
  });

  await t.test('the observable id rules: the registry really holds the strings the refused values would have matched', async () => {
    for (const s of ['9007199254740993', '-1', '1.5', 'true', 'café']) {
      const kind = s === 'café' ? 'brand' : 'account';
      assert.equal(await platformOwner(kind, s), tid('acme'), `${kind}:${s} is registered for acme in the real registry`);
    }
    const auth = build();
    for (const v of [9007199254740993, -1, 1.5, true, 10n ** 16n]) assert.equal((await auth.tenantFor('account', v)).tenantId, null, String(v));
    auth.close();
  });

  await t.test('a service registers through the platform API, conflicts, is refused for an unentitled tenant, retires; the library follows through the change feed', async () => {
    const auth = build();
    const id = `e2e-${Date.now()}`;
    try {
      await auth.cache.get(); // snapshot loaded: the change feed starts from here
      assert.equal((await auth.tenantFor('brand', id)).tenantId, null);

      const created = await api('POST', '/v1/resources', { tenant_id: tid('acme'), kind: 'brand', local_id: id });
      assert.equal(created.status, 201);
      assert.equal((await api('POST', '/v1/resources', { tenant_id: tid('acme'), kind: 'brand', local_id: id })).status, 200, 'idempotent');
      assert.equal(await auth.cache.pollOnce(), true, 'the registration is a change event: the library refreshes');
      assert.equal((await auth.tenantFor('brand', id)).tenantId, tid('acme'));

      const conflict = await api('POST', '/v1/resources', { tenant_id: tid('globex'), kind: 'brand', local_id: id });
      assert.equal(conflict.status, 409, 'another tenant cannot claim an active id');
      assert.ok(!JSON.stringify(conflict.body).includes(tid('acme')), 'the response never names the current owner');
      auth.cache.invalidate();
      assert.equal((await auth.tenantFor('brand', id)).tenantId, tid('acme'), 'ownership did not move');

      const unentitled = await api('POST', '/v1/resources', { tenant_id: tid('dormant'), kind: 'brand', local_id: `${id}-d` });
      assert.equal(unentitled.status, 403, 'one answer for a tenant that is not entitled');
      assert.equal((await api('POST', '/v1/resources', { tenant_id: tid('acme'), kind: 'Bad Kind', local_id: id })).status, 422, 'a value the registry cannot hold is a 422, never a 500');

      // retire (an operator action): the id is freed and the library stops reporting it
      psql(ctx, `UPDATE stighive_platform.tenant_resources SET status='retired', retired_at=now() WHERE service='docs' AND kind='brand' AND local_id='${id}'`);
      auth.cache.invalidate();
      assert.equal((await auth.tenantFor('brand', id)).tenantId, null, 'a retired resource is absent from the snapshot');
      assert.equal((await api('POST', '/v1/resources', { tenant_id: tid('globex'), kind: 'brand', local_id: id })).status, 201, 'and the freed id can be claimed by another tenant');
      auth.cache.invalidate();
      assert.equal((await auth.tenantFor('brand', id)).tenantId, tid('globex'));
    } finally {
      psql(ctx, `DELETE FROM stighive_platform.tenant_resources WHERE service='docs' AND local_id LIKE 'e2e-%'`);
      auth.close();
    }
  });

  await t.test('another service\'s rows and unentitled tenants\' rows are invisible to this service, in the real snapshot too', async () => {
    const snap = await (await fetch(`${ctx.state.platform_url}/v1/authorize/snapshot?service=docs`, { headers: { 'X-API-Key': ctx.state.service_key } })).json();
    const all = snap.tenants.flatMap((x) => x.resources.map((r) => r.local_id));
    assert.ok(!all.includes('ops@client.example'), 'the mail service\'s row is not in the docs snapshot');
    assert.ok(!all.includes('brand-dormant'), 'a tenant not entitled to docs is not in the snapshot, nor are its rows');
    assert.ok(!all.includes('brand-old'), 'a retired row is absent');
    assert.ok(snap.tenants.every((x) => Array.isArray(x.resources)), 'every entitled tenant carries the list (empty when none)');
  });
});
