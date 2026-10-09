// CR-L2: a stuck Clerk key fetch must never hang a request. REAL local servers that stall in each way the
// CR lists, the REAL global fetch, small deadlines. Each mode must (a) answer waiting requests within their
// own wait budget with clerk_jwks_unavailable, (b) clear the single-flight slot, (c) recover on the next
// attempt once the server behaves. 127.0.0.1 only; keys and tokens are generated per run and never printed.

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const http = require('node:http');
const dns = require('node:dns');
const express = require('express');
const { performance } = require('node:perf_hooks');
const { ClerkVerifier, Denied } = require('../v2/clerk');
const { createAuth } = require('../v2');
const { VECTORS, newClerkKeys, mintClerkToken } = require('./helpers/world');

const silent = { error() {}, warn() {}, info() {}, debug() {} };
const ISSUER = VECTORS.config.clerk.issuer;
const AZP = VECTORS.config.clerk.authorized_parties[0];
const T = { refreshDeadlineMs: 400, waitBudgetMs: 250, hardExpiryMs: 60 * 60 * 1000 };
const MARGIN = 350; // scheduling slack on a loaded machine

const MODES = ['accept-silent', 'headers-then-stall', 'body-trickle', 'tls-stall', 'dns-never', 'keepalive-half-dead', 'client-ignores-abort'];

function healthyServer(goodBody) {
  const sockets = new Set();
  const server = http.createServer((req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(goodBody); });
  server.on('connection', (c) => { sockets.add(c); c.on('close', () => sockets.delete(c)); });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    url: `http://127.0.0.1:${server.address().port}/jwks.json`, close() { for (const c of sockets) c.destroy(); server.close(); },
  })));
}

function stallServer(mode) {
  const sockets = new Set();
  let requests = 0;
  const httpd = http.createServer((req, res) => {
    requests++;
    if (mode === 'body-trickle') { res.writeHead(200, { 'content-type': 'application/json' }); res.write('{"keys":['); const t = setInterval(() => res.write(' '), 50); res.on('close', () => clearInterval(t)); return; }
    if (mode === 'keepalive-half-dead' && requests === 1) { res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"keys":[]}'); } // then silence on the reused socket
    // otherwise: say nothing
  });
  httpd.on('connection', (c) => { sockets.add(c); c.on('close', () => sockets.delete(c)); c.on('error', () => {}); });
  const raw = net.createServer((c) => {
    sockets.add(c); c.on('close', () => sockets.delete(c)); c.on('error', () => {});
    if (mode === 'headers-then-stall') c.once('data', () => { requests++; c.write('HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100000\r\n\r\n{"keys":['); });
  });
  const server = (mode === 'accept-silent' || mode === 'tls-stall' || mode === 'headers-then-stall') ? raw : httpd;
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    url: `${mode === 'tls-stall' ? 'https' : 'http'}://127.0.0.1:${server.address().port}/jwks.json`,
    get requests() { return requests; },
    close() { for (const c of sockets) c.destroy(); server.close(); },
  })));
}

async function rig(mode, over = {}) {
  const keys = await newClerkKeys();
  const good = JSON.stringify({ keys: [keys.trusted.jwk] });
  const srv = await stallServer(mode);
  const healthy = await healthyServer(good);
  if (mode === 'keepalive-half-dead') await (await fetch(srv.url)).json(); // the pooled socket is now 'half dead': the server will never answer on it again
  let skew = 0;
  const monotonic = () => performance.now() + skew;
  let url = srv.url;
  let fetchImpl = globalThis.fetch;
  if (mode === 'dns-never') { url = 'http://never-resolves.invalid/jwks.json'; }
  if (mode === 'client-ignores-abort') fetchImpl = () => new Promise(() => {}); // a client that honours neither signal nor timeout
  const v = new ClerkVerifier({ issuer: ISSUER, jwksUrl: url, authorizedParties: [AZP], audience: [] },
    { fetch: (...a) => fetchImpl(...a), now: () => Date.now(), monotonic, logger: over.logger ?? silent, timeouts: over.timeouts ?? T });
  const token = () => mintClerkToken(keys, { sub: 'user_x', nowMs: Date.now(), issuer: ISSUER, azp: AZP }, {});
  const realLookup = dns.lookup;
  if (mode === 'dns-never') dns.lookup = () => {}; // resolution never answers
  return {
    v, srv, healthy, token, keys, skew: (ms) => { skew += ms; }, fix() { dns.lookup = realLookup; fetchImpl = globalThis.fetch; v.cfg.jwksUrl = healthy.url; },
    done() { dns.lookup = realLookup; srv.close(); healthy.close(); },
  };
}
const timed = async (p) => { const t0 = performance.now(); let out; try { out = { ok: await p }; } catch (e) { out = { err: e }; } return { ...out, ms: performance.now() - t0 }; };

for (const mode of MODES) {
  test(`stall mode ${mode}: waiting requests answer 503-class within their budget, the slot clears, the next attempt recovers`, async () => {
    const r = await rig(mode);
    try {
      const a = await timed(r.v.verify(await r.token()));
      assert.ok(a.err instanceof Denied && a.err.reason === 'clerk_jwks_unavailable', `${mode}: ${a.err?.message}`);
      assert.ok(a.ms < T.waitBudgetMs + MARGIN, `${mode}: request waited ${a.ms | 0} ms`);
      // the refresh itself is bounded by the deadline, and then the slot is free
      await new Promise((res) => setTimeout(res, T.refreshDeadlineMs + MARGIN));
      assert.equal(r.v.inflight, null, `${mode}: slot still occupied`);
      assert.ok(r.v.status().failures >= 1 && r.v.status().lastFailure, 'the failure is recorded');
      // back-off applies: an immediate retry fails fast without a new attempt
      const before = r.v.stats.refreshes;
      const b = await timed(r.v.verify(await r.token()));
      assert.ok(b.err?.reason === 'clerk_jwks_unavailable' && b.ms < 100 && r.v.stats.refreshes === before, `${mode}: back-off not applied`);
      // the server recovers; after the back-off the next request starts a fresh attempt and succeeds
      r.fix(); r.skew(11_000);
      const c = await timed(r.v.verify(await r.token()));
      assert.ok(c.ok?.sub === 'user_x', `${mode}: did not recover (${c.err?.message})`);
    } finally { r.done(); }
  });
}

test('many concurrent requests during a stall all answer within the wait budget, with one refresh', async () => {
  const r = await rig('accept-silent');
  try {
    const tok = await r.token();
    const results = await Promise.all(Array.from({ length: 80 }, () => timed(r.v.verify(tok))));
    for (const x of results) {
      assert.equal(x.err?.reason, 'clerk_jwks_unavailable');
      assert.ok(x.ms < T.waitBudgetMs + MARGIN, `one request waited ${x.ms | 0} ms`);
    }
    assert.equal(r.v.stats.refreshes, 1, 'one shared refresh, not one per request');
  } finally { r.done(); }
});

test('a stall while cached keys are valid does not interrupt service; past the hard expiry it fails closed', async () => {
  const r = await rig('accept-silent', { timeouts: { ...T, hardExpiryMs: 30 * 60 * 1000 } });
  try {
    r.fix(); // healthy first: prime the cache
    assert.ok((await r.v.verify(await r.token())).sub);
    // the key server now stalls; the keys are past their refresh time: requests keep being served at once
    r.v.cfg.jwksUrl = r.srv.url;
    r.skew(6 * 60 * 1000);
    const t = await timed(r.v.verify(await r.token()));
    assert.ok(t.ok?.sub, 'cached keys keep serving');
    assert.ok(t.ms < 100, `served in ${t.ms | 0} ms, not after the refresh`);
    await new Promise((res) => setTimeout(res, T.refreshDeadlineMs + MARGIN));
    assert.equal(r.v.inflight, null);
    // still inside the hard expiry after the failed refresh: still served
    r.skew(11_000);
    assert.ok((await r.v.verify(await r.token())).sub);
    // past the hard expiry: never served again
    r.skew(31 * 60 * 1000);
    const e = await timed(r.v.verify(await r.token()));
    assert.equal(e.err?.reason, 'clerk_jwks_unavailable', 'fails closed past the hard expiry');
  } finally { r.done(); }
});

test('status(): degraded when a refresh outlives its deadline, or the last success is too old; healthy otherwise', async () => {
  const r = await rig('accept-silent');
  try {
    assert.equal(r.v.status().degraded, false, 'not used yet is not degraded');
    r.v.fetch = () => new Promise(() => {}); // never settles, ignores everything
    r.v._refresh().catch(() => {}); // start a refresh
    r.v.t.refreshDeadlineMs = -1; // pretend the deadline is already behind us without waiting
    await new Promise((res) => setTimeout(res, 5));
    const s = r.v.status();
    assert.equal(s.degraded, true);
    assert.equal(s.reason, 'refresh_older_than_deadline');
    assert.ok(s.inflightAgeMs >= 0);
    assert.ok(!JSON.stringify(s).includes('BEGIN'), 'no key material in the status');
  } finally { r.done(); }
  const ok = await rig('accept-silent');
  try {
    ok.fix();
    await ok.v.verify(await ok.token());
    assert.equal(ok.v.status().degraded, false);
    ok.skew(11 * 60 * 1000);
    assert.equal(ok.v.status().degraded, true);
    assert.equal(ok.v.status().reason, 'last_success_too_old');
  } finally { ok.done(); }
});

test('a slot found older than its deadline is replaced and counted (wedge recovery)', async () => {
  const r = await rig('accept-silent');
  try {
    r.v.inflight = { startedAt: r.v.monotonic() - 60_000, promise: new Promise(() => {}) }; // a wedged slot from a bug or a runtime fault
    r.fix();
    const x = await timed(r.v.verify(await r.token()));
    assert.ok(x.ok?.sub, 'a fresh attempt ran');
    assert.equal(r.v.stats.wedgeRecoveries, 1);
  } finally { r.done(); }
});

test('failures are logged, but at most once a minute per kind, with a counter', async () => {
  const lines = [];
  const r = await rig('accept-silent', { logger: { ...silent, warn: (m) => lines.push(m) } });
  try {
    for (let i = 0; i < 4; i++) { await r.v.verify(await r.token()).catch(() => {}); await new Promise((res) => setTimeout(res, T.refreshDeadlineMs + 50)); r.skew(11_000); }
    const mine = lines.filter((l) => l.includes('refresh failed'));
    assert.equal(mine.length, 1, `logged ${mine.length} times`);
    assert.match(mine[0], /failures=\d/);
    assert.ok(!/eyJ|BEGIN/.test(lines.join('\n')), 'no token or key in a log line');
  } finally { r.done(); }
});

// ---- log mode never delays a request ---------------------------------------------------------------------------
test('log mode: a decision whose dependencies stall never holds the request (shadowPermission lets it through)', async () => {
  const keys = await newClerkKeys();
  const hang = () => new Promise(() => {}); // platform AND key server never answer, and ignore the abort
  const auth = createAuth({
    service: 'docs', platformUrl: 'http://platform.test', platformKey: 'stgs_fake', pollIntervalSeconds: 0,
    clerk: { issuer: ISSUER, jwksUrl: 'http://jwks.test/j', authorizedParties: [AZP] }, fetch: hang, logger: silent,
    shadowWaitMs: 200, decisionDeadlineMs: 600, jwksTimeouts: T,
  });
  const app = express();
  app.get('/x', auth.express.shadowPermission('docs:read', { tenant: () => 't' }), (req, res) => res.json({ reached: true, decided: !!req.authDecision }));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  try {
    const token = await mintClerkToken(keys, { sub: 'user_x', nowMs: Date.now(), issuer: ISSUER, azp: AZP }, {});
    const t0 = performance.now();
    const resp = await fetch(`http://127.0.0.1:${server.address().port}/x`, { headers: { authorization: `Bearer ${token}` } });
    const ms = performance.now() - t0;
    assert.equal(resp.status, 200);
    assert.deepEqual(await resp.json(), { reached: true, decided: false });
    assert.ok(ms < 200 + MARGIN, `log mode held the request ${ms | 0} ms`);
    // enforce mode: the same stall is a bounded 503 `timeout`-class answer, never a hang
    const d = await timed(auth.authorize({ headers: { authorization: `Bearer ${token}` }, permission: 'docs:read', resource: { tenantHint: 't' } }));
    assert.equal(d.ok.allow, false);
    assert.equal(d.ok.status, 503);
    assert.ok(d.ms < 600 + MARGIN, `enforce decision took ${d.ms | 0} ms`);
    assert.equal(typeof auth.clerkStatus().degraded, 'boolean', 'status accessor is exposed');
  } finally { server.close(); auth.close(); }
});
