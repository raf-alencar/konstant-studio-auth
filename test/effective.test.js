// Effective permissions (platform C0b2: POST /v1/principals/resolve with include_effective) and
// Clerk organization -> tenant mapping from the snapshot's org_id.

const test = require('node:test');
const assert = require('node:assert/strict');
const { createAuth } = require('../v2');
const { VECTORS, World, FakePlatform, newClerkKeys, mintClerkToken } = require('./helpers/world');

const silent = { error() {}, warn() {}, info() {}, debug() {} };
const world = new World();
const ACME = world.id('tenant', 'acme');
const GLOBEX = world.id('tenant', 'globex');

async function build(over = {}) {
  const keys = await newClerkKeys();
  const fake = new FakePlatform(world, keys, { jwksUrl: 'http://jwks.test/jwks.json' });
  let clock = world.nowMs;
  const calls = [];
  const wrapped = async (url, init = {}) => {
    if (String(url).endsWith('/v1/principals/resolve') && init.body && JSON.parse(init.body).include_effective) {
      const body = JSON.parse(init.body);
      calls.push(body);
      if (fake.down) throw new TypeError('down');
      if (fake.effectiveReply) return new Response(JSON.stringify(fake.effectiveReply(body)), { status: 200 });
    }
    return fake.fetch(url, init);
  };
  const auth = createAuth({
    service: 'docs', platformUrl: 'http://platform.test', platformKey: 'stgs_fake-own-key', pollIntervalSeconds: 0,
    clerk: { issuer: VECTORS.config.clerk.issuer, jwksUrl: 'http://jwks.test/jwks.json', authorizedParties: VECTORS.config.clerk.authorized_parties },
    acceptedCallerServices: ['image'], now: () => clock, fetch: wrapped, logger: silent, ...over,
  });
  const token = (ref, spec) => mintClerkToken(keys, { sub: world.principal(ref).user_id, nowMs: clock, issuer: VECTORS.config.clerk.issuer, azp: VECTORS.config.clerk.authorized_parties[0] }, spec);
  return { auth, fake, calls, token, advance: (s) => { clock += s * 1000; } };
}

const eff = (permissions, over = {}) => ({ valid: true, key_id: null,
  principal: { id: 'p1', kind: 'human', user_id: 'user_alice', tenant_id: null }, effective: { tenant_id: ACME, reason: null, permissions, ...over } });
const perm = (permission, scopes) => {
  const [service, action] = permission.split(':');
  return { permission, service, action, category: 'write', sensitive: false, scopes };
};

test('effective permissions: the request names the tenant and service, the Clerk token is verified first and forwarded', async () => {
  const { auth, fake, calls, token } = await build();
  fake.effectiveReply = () => eff([perm('docs:read', [{ scope: {}, role: 'operator', via_tenant: null }])]);
  const r = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('alice')}` }, tenant: ACME, service: 'docs' });
  assert.equal(r.ok, true);
  assert.deepEqual(r.principal.permissions, ['docs:read']);
  assert.equal(r.tenantId, ACME);
  assert.deepEqual([calls[0].tenant_id, calls[0].service, calls[0].include_effective, typeof calls[0].clerk_token], [ACME, 'docs', true, 'string']);

  const bad = await auth.effectivePermissions({ headers: { authorization: 'Bearer not-a-session' }, tenant: ACME });
  assert.deepEqual([bad.ok, bad.reason, bad.status], [false, 'token_invalid', 401]);
  assert.equal(calls.length, 1, 'a token that fails local verification never reaches the platform');
});

test('permits(): allowed iff SOME scope entry admits the resource (the platform\'s documented rule)', async () => {
  const { auth, fake, token } = await build();
  fake.effectiveReply = () => eff([perm('mail:send', [
    { scope: { domains: ['Client.Example'] }, role: 'operator', via_tenant: null },
    { scope: { mailboxes: ['ops@other.example'], domains: ['other.example'] }, role: 'operator', via_tenant: null },
  ]), perm('docs:read', [{ scope: {}, role: 'viewer', via_tenant: null }]), perm('docs:write', [{ scope: { colour: ['red'] }, role: 'x', via_tenant: null }])]);
  const r = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('alice')}` }, tenant: ACME });
  assert.equal(r.permits('mail:send', { domain: 'client.example' }), true, 'case-insensitive');
  assert.equal(r.permits('mail:send', { domain: 'other.example' }), false, 'that scope also needs the mailbox');
  assert.equal(r.permits('mail:send', { domain: 'other.example', mailbox: 'OPS@other.example' }), true, 'a second scope entry widens');
  assert.equal(r.permits('mail:send', {}), false, 'a restricted dimension that is not named admits nothing');
  assert.equal(r.permits('docs:read', {}), true, 'an unrestricted scope admits everything');
  assert.equal(r.permits('docs:write', {}), false, 'an unknown scope key admits nothing');
  assert.equal(r.permits('docs:delete', {}), false, 'not held');
  assert.deepEqual(r.principal.permissions, ['docs:read', 'docs:write', 'mail:send']);
});

test('effective permissions that cannot be computed come back empty with the platform\'s reason', async () => {
  const { auth, fake, token } = await build();
  fake.effectiveReply = () => eff([], { tenant_id: null, reason: 'tenant_required' });
  const r = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('bob')}` } });
  assert.deepEqual([r.ok, r.reason, r.permissions, r.permits('docs:read', {})], [true, 'tenant_required', [], false]);
});

test('effective permissions: a service principal holds none; platform trouble is a 503, never an empty allow', async () => {
  const { auth, fake, token } = await build();
  const svc = await auth.effectivePermissions({ headers: { 'x-api-key': world.rawKey(world.spec.keys.find((k) => k.ref === 'svc_image_active')) } });
  assert.deepEqual([svc.ok, svc.reason, svc.permits('docs:read', {})], [true, 'service_principal_not_granted', false]);

  fake.effectiveReply = () => ({ valid: true, principal: { id: 'p', kind: 'human' } }); // no `effective`
  const malformed = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('alice')}` }, tenant: ACME });
  assert.deepEqual([malformed.ok, malformed.reason, malformed.status], [false, 'platform_unavailable', 503]);
  fake.down = true;
  const down = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('alice')}` }, tenant: ACME });
  assert.deepEqual([down.ok, down.status], [false, 503]);
  const garbage = await auth.effectivePermissions({ headers: { authorization: `Bearer ${await token('alice')}` }, tenant: 'not-a-uuid' });
  assert.deepEqual([garbage.reason], ['tenant_not_found']);
});

test('org mapping: the adopter\'s tenantResolver wins over the Clerk org claim', async () => {
  const { auth, token } = await build({ tenantResolver: () => GLOBEX });
  const d = await auth.authorize({ headers: { authorization: `Bearer ${await token('bob', { extra: { org_id: 'org_acme' } })}` }, permission: 'docs:read' });
  assert.equal(d.tenantId, GLOBEX, 'resolver, not org_acme');
  assert.equal(d.source, 'offline');
});

test('org mapping is for humans: an agent key is bound to its own tenant whatever header claims an org', async () => {
  const { auth, fake } = await build();
  fake.live = { allow: true, reason: 'allowed', tenant: 'acme', roles: ['operator'] };
  const d = await auth.authorize({
    headers: { 'x-api-key': world.rawKey(world.spec.keys.find((k) => k.ref === 'agent_acme_active')), authorization: 'Bearer x.y.z' },
    permission: 'docs:read',
  });
  assert.deepEqual([d.allow, d.source], [true, 'live']);
  assert.equal(fake.count('GET', '/v1/authorize/snapshot'), 0, 'no snapshot lookup for a key principal');
});

test('org mapping uses a stale snapshot (it only names a tenant), but never when there is none', async () => {
  const { auth, fake, token, advance } = await build();
  await auth.cache.get();
  advance(120); // past the TTL, inside the stale-read window
  fake.down = true;
  const t = await token('bob', { extra: { org_id: 'org_acme' } });
  const stale = await auth.authorize({ headers: { authorization: `Bearer ${t}` }, permission: 'docs:read' });
  assert.deepEqual([stale.allow, stale.tenantId, stale.stale], [true, ACME, true]);

  const cold = await build();
  cold.fake.down = true;
  const none = await cold.auth.authorize({ headers: { authorization: `Bearer ${await cold.token('bob', { extra: { org_id: 'org_acme' } })}` }, permission: 'docs:read' });
  assert.deepEqual([none.allow, none.reason], [false, 'platform_unavailable']);
});

test('Clerk v1 and v2 token shapes both feed the legacy req.auth', async () => {
  const { auth, token } = await build();
  const v1 = await auth.resolvePrincipal({ headers: { authorization: `Bearer ${await token('alice', { extra: { org_id: 'org_acme', org_role: 'org:admin' } })}` } });
  const v2 = await auth.resolvePrincipal({ headers: { authorization: `Bearer ${await token('alice', { extra: { o: { id: 'org_acme', rol: 'admin' } } })}` } });
  assert.deepEqual([v1.principal.claims.org_id, v1.principal.claims.org_role], ['org_acme', 'org:admin']);
  assert.deepEqual([v2.principal.claims.org_id, v2.principal.claims.org_role], ['org_acme', 'admin']);
});
