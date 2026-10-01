// Unit tests for the parts the shared vectors do not reach.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { scopeAllows } = require('../v2/decision');
const { routeAllowed } = require('../v2/service-keys');
const { verifySignature } = require('../v2/events-webhook');
const { resolveConfig, ConfigError } = require('../v2/config');
const { SnapshotCache } = require('../v2/snapshot-cache');
const { PlatformUnavailable } = require('../v2/platform-client');
const { extract } = require('../v2/credentials');
const { createAuth } = require('../v2');

const silent = { error() {}, warn() {}, info() {}, debug() {} };

test('scope: every dimension, fail-closed on the unexpected', () => {
  assert.equal(scopeAllows({}, {}), null, 'no restriction');
  assert.equal(scopeAllows({ mailboxes: ['Info@Client.Example'] }, { mailbox: 'info@client.example' }), null);
  assert.equal(scopeAllows({ mailboxes: ['a@x.test'] }, { mailbox: 'b@x.test' }), 'out_of_scope');
  assert.equal(scopeAllows({ mailboxes: ['a@x.test'] }, {}), 'scope_required');
  assert.equal(scopeAllows({ brand_ids: ['b1'], domains: ['d.test'] }, { brand: 'b1' }), 'scope_required', 'every restricted dimension must be named');
  assert.equal(scopeAllows({ brand_ids: ['b1'], domains: ['d.test'] }, { brand: 'b1', domain: 'd.test' }), null);
  assert.equal(scopeAllows({ brandIds: ['b1'] }, { brand: 'b1' }), 'out_of_scope', 'an unknown key is never read as "no restriction"');
  assert.equal(scopeAllows({ brand_ids: 'b1' }, { brand: 'b1' }), 'out_of_scope', 'a malformed dimension');
  assert.equal(scopeAllows([], {}), 'out_of_scope');
  assert.equal(scopeAllows(null, {}), 'out_of_scope');
  assert.equal(scopeAllows({ brand_ids: ['b1'] }, { brand: '' }), 'scope_required');
});

test('app route policy: * is one path segment, ** is many, matched on the path as sent', () => {
  const routes = ['GET /internal/status/*', 'POST /internal/render', '* /internal/events/**', 'DELETE /internal/jobs/*/cancel'];
  assert.equal(routeAllowed(routes, 'get', '/internal/status/42'), true, 'method is case-insensitive');
  assert.equal(routeAllowed(routes, 'GET', '/internal/status/42/extra'), false, '* never crosses a "/"');
  assert.equal(routeAllowed(routes, 'POST', '/internal/render'), true);
  assert.equal(routeAllowed(routes, 'POST', '/internal/render/'), false, 'no prefix or trailing-slash guessing');
  assert.equal(routeAllowed(routes, 'PATCH', '/internal/events/a/b/c'), true, '* method, ** crosses segments');
  assert.equal(routeAllowed(routes, 'DELETE', '/internal/jobs/9/cancel'), true, '* inside the path');
  assert.equal(routeAllowed(routes, 'DELETE', '/internal/jobs/9/x/cancel'), false);
  assert.equal(routeAllowed(routes, 'GET', '/internal/status/42?x=1'), true, 'the query string is not part of the path');
  assert.equal(routeAllowed(['GET /a.b'], 'GET', '/aXb'), false, 'glob characters other than * are literal');
  assert.equal(routeAllowed([], 'GET', '/'), false, 'deny by default');
  assert.equal(routeAllowed(undefined, 'GET', '/'), false);
});

test('app route policy refuses any path that can be read two ways', () => {
  const routes = ['GET /internal/**', 'GET /internal/status/*'];
  for (const bad of ['/internal/../admin', '/internal/status/..%2fadmin', '/internal/status/%2e%2e/x', '/internal//status/1',
    '/internal/status/a%2fb', '/internal/status/\u0000', '/internal/status/\n1', 'internal/status/1', '', '/internal/status/a..b']) {
    assert.equal(routeAllowed(routes, 'GET', bad), false, JSON.stringify(bad));
  }
});

test('config: Clerk without authorized parties refuses to start; no hard-coded secret defaults', () => {
  assert.throws(() => resolveConfig({ clerk: { issuer: 'https://clerk.example.test' } }, {}), ConfigError);
  assert.throws(() => resolveConfig({}, { CLERK_JWKS_URL: 'https://clerk.example.test/jwks.json' }), ConfigError);
  const c = resolveConfig({}, { CLERK_ISSUER: 'https://clerk.example.test', CLERK_AUTHORIZED_PARTIES: 'https://a.test, https://b.test' });
  assert.deepEqual(c.clerk.authorizedParties, ['https://a.test', 'https://b.test']);
  assert.equal(c.clerk.jwksUrl, 'https://clerk.example.test/.well-known/jwks.json');
  const bare = resolveConfig({}, {});
  assert.equal(bare.platformKey, '');
  assert.equal(bare.clerk.issuer, '');
  assert.equal(resolveConfig({}, { INTERNAL_API_KEY: 'k' }).platformKey, 'k', 'deprecated shared key is only a fallback');
  assert.equal(resolveConfig({}, { INTERNAL_API_KEY: 'k', PLATFORM_SERVICE_KEY: 's' }).platformKey, 's', 'a per-service key wins');
});

test('without Clerk configured, a session token is refused (never trusted unverified)', async () => {
  const auth = createAuth({ service: 'docs', platformUrl: 'http://platform.test', platformKey: 'k', logger: silent, pollIntervalSeconds: 0, fetch: async () => { throw new Error('no network'); } });
  const d = await auth.authorize({ headers: { authorization: 'Bearer a.b.c' }, permission: 'docs:read', resource: { tenant: 't' } });
  assert.deepEqual([d.allow, d.reason, d.status], [false, 'clerk_not_configured', 503]);
});

test('credential extraction: header precedence, cookie, junk', () => {
  assert.deepEqual(extract({}), { type: 'none' });
  assert.equal(extract({ 'x-api-key': 'stga_' + 'a'.repeat(30) }).keyKind, 'agent');
  assert.equal(extract({ 'x-api-key': 'stga_' + 'a'.repeat(30), authorization: 'Bearer a.b.c' }).type, 'key', 'a platform key header wins');
  assert.equal(extract({ authorization: 'Bearer a.b.c' }).type, 'clerk');
  assert.equal(extract({ authorization: 'bearer   a.b.c ' }).raw, 'a.b.c');
  assert.equal(extract({ cookie: 'x=1; __session=a.b.c' }).raw, 'a.b.c');
  assert.equal(extract({ 'x-api-key': 'legacy-shared-key' }).keyKind, null, 'the legacy shared key is not a v2 credential');
  assert.equal(extract({ 'x-api-key': 'stga_short' }).keyKind, null, 'too short to be a key');
  assert.equal(extract({ authorization: 'Basic abc' }).type, 'none');
  assert.equal(extract(new Headers({ authorization: 'Bearer x.y.z' })).raw, 'x.y.z', 'Fetch Headers');
});

test('event webhook signature: valid, tampered, stale, wrong secret', () => {
  const secret = 'whsec_fake-secret-for-tests';
  const body = Buffer.from('{"head":5,"events":[]}');
  const now = 1_790_000_000_000;
  const ts = String(now / 1000);
  const sig = 'v1=' + crypto.createHmac('sha256', secret).update(`${ts}.`).update(body).digest('hex');
  const check = (over = {}) => verifySignature({ secret, timestamp: ts, signature: sig, rawBody: body, nowMs: now, ...over });
  assert.equal(check(), true);
  assert.equal(check({ rawBody: Buffer.from('{"head":6,"events":[]}') }), false);
  assert.equal(check({ secret: 'whsec_other' }), false);
  assert.equal(check({ nowMs: now + 301_000 }), false, 'older than 5 minutes');
  assert.equal(check({ signature: 'v1=zz' }), false);
  assert.equal(check({ timestamp: undefined }), false);
});

function fakeClient() {
  const c = { calls: [], fail: false, etag: '"v1"', body: { service: 'docs', version: 1, ttl_seconds: 30, stale_read_ttl_seconds: 300, permissions: [], tenants: [], roles: [], memberships: [] }, feed: [] };
  c.snapshot = async (service, etag) => {
    c.calls.push(['snapshot', etag]);
    await new Promise((r) => setImmediate(r));
    if (c.fail) throw new PlatformUnavailable('down');
    return etag === c.etag ? { notModified: true } : { body: structuredClone(c.body), etag: c.etag };
  };
  c.events = async (after) => { c.calls.push(['events', after]); if (c.fail) throw new PlatformUnavailable('down'); const e = c.feed; c.feed = []; return { events: e, next_cursor: after + e.length, head: after + e.length }; };
  return c;
}

test('snapshot cache: ETag revalidation, single flight, retry backoff, stale window', async () => {
  const client = fakeClient();
  let now = 1_000_000;
  const cache = new SnapshotCache({ client, service: 'docs', ttlSeconds: 30, staleReadTtlSeconds: 300, now: () => now, pollIntervalSeconds: 0, logger: silent });

  // single flight: ten concurrent cold reads, one fetch
  await Promise.all(Array.from({ length: 10 }, () => cache.get()));
  assert.equal(client.calls.filter((c) => c[0] === 'snapshot').length, 1);

  // inside the TTL: no traffic
  now += 29_000;
  assert.equal((await cache.get()).state, 'fresh');
  assert.equal(client.calls.filter((c) => c[0] === 'snapshot').length, 1);

  // past the TTL: revalidate with the ETag; 304 keeps the entry and restarts its age
  now += 2_000;
  assert.equal((await cache.get()).state, 'fresh');
  assert.deepEqual(client.calls.at(-1), ['snapshot', '"v1"']);
  assert.equal((await cache.get()).ageSeconds, 0);

  // platform down: stale reads inside the window, with a one-second retry backoff (not a timeout per request)
  client.fail = true;
  now += 31_000;
  const before = client.calls.length;
  const stale = await cache.get();
  assert.deepEqual([stale.state, stale.ageSeconds], ['stale', 31]);
  await cache.get();
  await cache.get();
  assert.equal(client.calls.length - before, 1, 'backoff: one attempt, not one per request');
  now += 1_500;
  await cache.get();
  assert.equal(client.calls.length - before, 2, 'retries after the backoff');

  // beyond the stale-read window nothing may be answered from the cache
  now += 300_000;
  assert.equal((await cache.get()).state, 'none');

  // recovery
  client.fail = false;
  now += 2_000;
  assert.equal((await cache.get()).state, 'fresh');
});

test('snapshot cache: a change event triggers an immediate refresh; quiet feed does not', async () => {
  const client = fakeClient();
  const now = 1_000_000;
  const cache = new SnapshotCache({ client, service: 'docs', ttlSeconds: 30, staleReadTtlSeconds: 300, now: () => now, pollIntervalSeconds: 0, logger: silent });
  await cache.get();
  assert.equal(await cache.pollOnce(), false);
  client.etag = '"v2"';
  client.body = { ...client.body, version: 2, tenants: [{ id: 't' }] };
  client.feed = [{ id: 2, kind: 'membership' }];
  assert.equal(await cache.pollOnce(), true);
  assert.equal(cache.entry.body.tenants.length, 1, 'the new snapshot is in place well inside the TTL');
});

test('an unexpected error inside a decision is a denial, never an allow', async () => {
  const auth = createAuth({ service: 'docs', platformUrl: 'http://p.test', platformKey: 'k', logger: silent, pollIntervalSeconds: 0,
    tenantResolver: () => { throw new Error('resolver bug'); }, fetch: async () => { throw new Error('x'); } });
  const d = await auth.authorize({ headers: { 'x-api-key': 'stga_' + 'a'.repeat(30) }, permission: 'docs:read' });
  assert.equal(d.allow, false);
  const d2 = await auth.authorize({ headers: { 'x-api-key': 'stga_' + 'a'.repeat(30) }, permission: 'not-a-permission' });
  assert.deepEqual([d2.allow, d2.reason], [false, 'unknown_permission']);
});

test('a change event is not lost when the refresh it triggers fails', async () => {
  const client = fakeClient();
  const now = 1_000_000;
  const cache = new SnapshotCache({ client, service: 'docs', ttlSeconds: 30, staleReadTtlSeconds: 300, now: () => now, pollIntervalSeconds: 0, logger: silent });
  await cache.get();
  client.etag = '"v2"';
  client.body = { ...client.body, version: 2, tenants: [{ id: 'new' }] };
  const event = { id: 2, kind: 'membership' };
  client.feed = [event];
  const realSnapshot = client.snapshot;
  client.snapshot = async () => { throw new PlatformUnavailable('blip'); };
  await assert.rejects(cache.pollOnce(), PlatformUnavailable);
  client.snapshot = realSnapshot;
  client.feed = [event]; // the platform serves the same event again: the cursor did not move past it
  assert.equal(await cache.pollOnce(), true);
  assert.equal(cache.entry.body.tenants[0].id, 'new');
});

test('unparseable timestamps in a snapshot deny instead of being skipped', () => {
  const { decideOffline } = require('../v2/decision');
  const snap = (over = {}) => ({
    service: 'docs', permissions: [{ action: 'read', category: 'read', sensitive: false }],
    tenants: [{ id: 't1', ancestors: [], starts_at: null, ends_at: null, ...over.tenant }],
    roles: [{ id: 'r1', slug: 'viewer', tenant_id: null, permissions: ['docs:read'] }],
    memberships: [{ principal_id: 'p', user_id: 'u1', kind: 'human', tenant_id: 't1', role_id: 'r1', scope: {}, expires_at: null, ...over.membership }],
  });
  const ask = (s) => decideOffline(s, { userId: 'u1', kind: 'human' }, 'docs', 'read', { tenant: 't1' }, Date.now());
  assert.equal(ask(snap()).allow, true);
  assert.equal(ask(snap({ tenant: { ends_at: 'garbage' } })).allow, false);
  assert.equal(ask(snap({ tenant: { starts_at: 'garbage' } })).allow, false);
  assert.equal(ask(snap({ membership: { expires_at: 'garbage' } })).allow, false);
});

test('an empty tenant string is "no tenant": the platform decides, not an empty-tenant offline guess', async () => {
  const calls = [];
  const auth = createAuth({ service: 'docs', platformUrl: 'http://p.test', platformKey: 'k', logger: silent, pollIntervalSeconds: 0,
    fetch: async (url) => { calls.push(String(url)); throw new TypeError('down'); } });
  const d = await auth.authorize({ headers: { 'x-api-key': 'stga_' + 'a'.repeat(30) }, permission: 'docs:read', resource: { tenant: '' } });
  assert.equal(d.allow, false);
  assert.ok(calls.some((u) => u.endsWith('/v1/authorize')), 'asked the platform');
  assert.ok(!calls.some((u) => u.includes('/snapshot')), 'did not decide offline');
});

test('a malformed resolve reply cannot identify anyone and does not throw', async () => {
  const auth = createAuth({ service: 'docs', platformUrl: 'http://p.test', platformKey: 'k', logger: silent, pollIntervalSeconds: 0,
    fetch: async () => new Response(JSON.stringify({ valid: true }), { status: 200 }) });
  const r = await auth.resolvePrincipal({ headers: { 'x-api-key': 'stga_' + 'a'.repeat(30) } });
  assert.deepEqual([r.ok, r.reason, r.status], [false, 'platform_unavailable', 503]);
});

test('run id from the caller is bounded and printable before it reaches an audit event', () => {
  const { cleanRunId } = require('../v2/adapters/shared');
  assert.equal(cleanRunId(undefined), undefined);
  assert.equal(cleanRunId('run-123'), 'run-123');
  assert.equal(cleanRunId('a\r\nb\u0000cé'), 'abc', 'control characters and non-ASCII are dropped (no log/header injection)');
  assert.equal(cleanRunId('x'.repeat(500)).length, 128);
  assert.equal(cleanRunId('\n\n'), undefined);
});

test('an unknown option is a startup error, not silently ignored (a stale or misspelled setting must not be a hole)', () => {
  assert.throws(() => createAuth({ service: 'docs', serviceKeys: 'stub' }), /unknown option "serviceKeys"/);
  assert.throws(() => createAuth({ service: 'docs', acceptedCallerService: ['image'] }), /unknown option/);
});
