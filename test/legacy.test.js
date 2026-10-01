// Compatibility: the three current adopters (social-konstant-studio admin,
// stighive-character-console, image-konstant-studio's Python sibling) must
// keep working untouched. These tests pin the v1 surface: the export list the
// adopters destructure, and the behaviour of every v1 middleware, so a change
// that alters one fails here before it reaches an adopter.

const test = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');

// Stub @clerk/express (no network, no keys): getAuth reads what the test put on req.
const clerkStub = { clerkMiddleware: () => (req, res, next) => next(), getAuth: (req) => req.__clerk || {} };
const realLoad = Module._load;
Module._load = function (request, ...rest) {
  return request === '@clerk/express' ? clerkStub : realLoad.call(this, request, ...rest);
};
process.env.KSA_SILENCE_DEPRECATIONS = '1';
const lib = require('../index.js');
const webhooks = require('../webhooks.js');
Module._load = realLoad;

function res() {
  const r = { code: 200, body: undefined, redirected: undefined };
  r.status = (c) => { r.code = c; return r; };
  r.json = (b) => { r.body = b; return r; };
  r.redirect = (u) => { r.redirected = u; return r; };
  return r;
}
const run = (mw, req) => new Promise((resolve) => {
  const r = res();
  const p = mw(req, r, () => resolve({ next: true, res: r, req }));
  Promise.resolve(p).then(() => resolve({ next: false, res: r, req }));
});

test('export surface: everything v1 exported is still exported, as a function', () => {
  const baseline = ['setupClerk', 'protect', 'superadminOnly', 'getBrandId', 'm2mAuth', 'protectOrM2M', 'requireLogin', 'requireService', '_resetEntitlementCache'];
  for (const name of baseline) assert.equal(typeof lib[name], 'function', name);
  // the subpath social-konstant-studio mounts as an Express router
  assert.equal(typeof webhooks, 'function');
  assert.equal(typeof webhooks.events.on, 'function');
});

test('v2 is reachable from the root, lazily', () => {
  assert.equal(typeof lib.createAuth, 'function');
  assert.equal(typeof require('../v2').createAuth, 'function');
});

test('protect: 401 without a session; sets req.auth from the Clerk session', async () => {
  assert.equal((await run(lib.protect, { __clerk: {} })).res.code, 401);
  const ok = await run(lib.protect, { __clerk: { userId: 'u1', orgId: 'org_1', orgRole: 'org:admin', sessionClaims: { publicMetadata: { superadmin: true } } } });
  assert.deepEqual(ok.req.auth, { userId: 'u1', orgId: 'org_1', orgRole: 'org:admin', isSuperadmin: true });
});

test('superadminOnly and getBrandId (incl. the 2026-09 superadmin-with-org fix)', async () => {
  assert.equal((await run(lib.superadminOnly, { auth: { isSuperadmin: false } })).res.code, 403);
  assert.equal((await run(lib.superadminOnly, { auth: { isSuperadmin: true } })).next, true);
  const g = (auth, query = {}) => lib.getBrandId({ auth, query });
  assert.equal(g({ isSuperadmin: false, orgId: 'org_a' }), 'org_a');
  assert.equal(g({ isSuperadmin: false, orgId: 'org_a' }, { brand_id: 'x' }), 'org_a', 'a client can never override');
  assert.equal(g({ isSuperadmin: true, orgId: 'org_a' }), 'org_a');
  assert.equal(g({ isSuperadmin: true, orgId: 'org_a' }, { brand_id: 'x' }), 'x');
  assert.equal(g({ isSuperadmin: true, orgId: null }), null);
});

test('m2mAuth / protectOrM2M: INTERNAL_API_KEY behaves as before', async () => {
  process.env.INTERNAL_API_KEY = 'fake-shared-key';
  const bad = await run(lib.m2mAuth, { headers: { 'x-api-key': 'nope' } });
  assert.deepEqual([bad.res.code, bad.res.body], [401, { error: 'Invalid API key' }]);
  assert.equal((await run(lib.m2mAuth, { headers: {} })).res.code, 401);
  const good = await run(lib.m2mAuth, { headers: { 'x-api-key': 'fake-shared-key' } });
  assert.deepEqual(good.req.auth, { userId: 'system', orgId: null, isSuperadmin: true });
  const either = await run(lib.protectOrM2M, { headers: { 'x-api-key': 'fake-shared-key' }, __clerk: {} });
  assert.equal(either.req.auth.userId, 'system');
  assert.equal((await run(lib.protectOrM2M, { headers: {}, __clerk: {} })).res.code, 401);
});

test('requireLogin redirects to an ABSOLUTE return URL on the original scheme and host', async () => {
  process.env.CLERK_SIGN_IN_URL = 'https://accounts.example.test/sign-in';
  const r = await run(lib.requireLogin, {
    __clerk: {}, headers: { 'x-forwarded-proto': 'https, http' }, protocol: 'http', originalUrl: '/showcase.html?x=1',
    get: (h) => (h === 'host' ? 'app.example.test' : undefined),
  });
  assert.equal(r.res.redirected, `https://accounts.example.test/sign-in?redirect_url=${encodeURIComponent('https://app.example.test/showcase.html?x=1')}`);
  assert.equal((await run(lib.requireLogin, { __clerk: { userId: 'u1' } })).next, true);
});

test('requireService: entitlement gate semantics are unchanged', async () => {
  const realFetch = globalThis.fetch;
  const entitled = { current: ['social'], status: 200 };
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return new Response(JSON.stringify({ org_id: 'o', services: entitled.current }), { status: entitled.status }); };
  process.env.PLATFORM_API_URL = 'http://platform.example.test';
  try {
    const gate = lib.requireService('social');
    const asOrg = (orgId) => ({ auth: { userId: 'u', orgId, isSuperadmin: false } });

    lib._resetEntitlementCache();
    assert.equal((await run(gate, asOrg('org_a'))).next, true);
    await run(gate, asOrg('org_a'));
    assert.equal(calls, 1, 'cached for 60s per org');

    const denied = await run(lib.requireService('video'), asOrg('org_a'));
    assert.equal(denied.res.code, 403);
    assert.deepEqual(denied.res.body, { error: 'No access to this service', upgrade_url: 'https://www.konstant-studio.com/dashboard' });

    assert.equal((await run(gate, { auth: { userId: 'u', orgId: null, isSuperadmin: false } })).res.code, 403, 'no org => no access');
    assert.equal((await run(gate, { auth: { userId: 'u', isSuperadmin: true } })).next, true, 'superadmin bypasses');
    assert.equal((await run(gate, {})).res.code, 401);

    // platform unreachable: dev allows, production fails closed (503)
    lib._resetEntitlementCache();
    globalThis.fetch = async () => { throw new Error('down'); };
    const prevEnv = process.env.NODE_ENV;
    delete process.env.NODE_ENV;
    assert.equal((await run(gate, asOrg('org_b'))).next, true);
    process.env.NODE_ENV = 'production';
    assert.equal((await run(gate, asOrg('org_c'))).res.code, 503);
    process.env.NODE_ENV = prevEnv;
    if (prevEnv === undefined) delete process.env.NODE_ENV;
  } finally {
    globalThis.fetch = realFetch;
    lib._resetEntitlementCache();
  }
});

test('Clerk webhook router: unsigned delivery is refused, a missing secret is a 500', async () => {
  const express = require('express');
  const app = express();
  app.use('/webhooks/clerk', webhooks);
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const url = `http://127.0.0.1:${server.address().port}/webhooks/clerk`;
  try {
    delete process.env.CLERK_WEBHOOK_SECRET;
    const post = () => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.equal((await post()).status, 500);
    process.env.CLERK_WEBHOOK_SECRET = 'whsec_' + Buffer.from('fake-secret-for-tests').toString('base64');
    assert.equal((await post()).status, 400);
  } finally {
    server.close();
    delete process.env.CLERK_WEBHOOK_SECRET;
  }
});

test('deprecations warn once, with a code, and change nothing else', async () => {
  const seen = [];
  const onWarning = (w) => seen.push(w.code);
  process.on('warning', onWarning);
  delete process.env.KSA_SILENCE_DEPRECATIONS;
  process.env.INTERNAL_API_KEY = 'fake-shared-key';
  try {
    // fresh module instance so the once-per-process set is empty
    delete require.cache[require.resolve('../index.js')];
    Module._load = function (request, ...rest) { return request === '@clerk/express' ? clerkStub : realLoad.call(this, request, ...rest); };
    const fresh = require('../index.js');
    Module._load = realLoad;
    await run(fresh.m2mAuth, { headers: { 'x-api-key': 'fake-shared-key' } });
    await run(fresh.m2mAuth, { headers: { 'x-api-key': 'fake-shared-key' } });
    fresh.requireService('social');
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(seen.sort(), ['KSA_DEP_M2M', 'KSA_DEP_REQUIRE_SERVICE']);
  } finally {
    process.off('warning', onWarning);
    process.env.KSA_SILENCE_DEPRECATIONS = '1';
  }
});
