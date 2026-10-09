// CR-L1 Node audit, empirical: the v1 Node entry points (setupClerk / protect / superadminOnly) delegate to the
// REAL @clerk/express. A forged token whose `iss` names an attacker's key server, signed by the attacker and
// claiming superadmin, must be refused and must cause NO request to the address the token names. Clerk is
// pointed at a local recording server (CLERK_API_URL, 127.0.0.1) with fake keys; nothing else is contacted.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { SignJWT, exportJWK } = require('jose');

process.env.KSA_SILENCE_DEPRECATIONS = '1';
const express = require('express');
const lib = require('../index.js');

function recorder(handler) {
  const requests = [];
  const server = http.createServer((req, res) => { requests.push(`${req.method} ${req.url}`); handler(req, res); });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    requests, url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => server.close(r)),
  })));
}

test('v1 Node: a forged token naming an attacker issuer is refused and nothing it names is fetched', async () => {
  const attacker = await recorder((req, res) => { res.setHeader('content-type', 'application/json'); res.end('{"keys":[]}'); });
  const clerkApi = await recorder((req, res) => { res.setHeader('content-type', 'application/json'); res.end('{"keys":[]}'); });
  const pk = 'pk_test_' + Buffer.from('legit.clerk.accounts.dev$').toString('base64');
  Object.assign(process.env, { CLERK_SECRET_KEY: 'sk_test_fake', CLERK_PUBLISHABLE_KEY: pk, CLERK_API_URL: clerkApi.url });
  delete process.env.CLERK_JWT_KEY;

  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  attacker.jwks = { keys: [jwk] };
  const forged = await new SignJWT({ azp: attacker.url, sid: 'sess_x', public_metadata: { superadmin: true }, publicMetadata: { superadmin: true } })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'JWT', jku: `${attacker.url}/jwks.json` })
    .setIssuer(attacker.url).setSubject('user_victim').setIssuedAt().setExpirationTime('10m').sign(privateKey);

  const app = express();
  app.use(lib.setupClerk());
  app.get('/me', lib.protect, (req, res) => res.json(req.auth));
  app.get('/admin', lib.protect, lib.superadminOnly, (req, res) => res.json({ ok: true }));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const path of ['/me', '/admin']) {
      const r = await fetch(base + path, { headers: { authorization: `Bearer ${forged}` }, redirect: 'manual' });
      assert.ok([401, 403].includes(r.status) || r.status === 307, `${path} answered ${r.status}`);
      assert.notEqual(r.status, 200);
    }
    assert.deepEqual(attacker.requests, [], 'the address named by the token was contacted');
  } finally {
    await new Promise((r) => server.close(r));
    await attacker.close();
    await clerkApi.close();
  }
});

test('v1 Node: no exported entry point reads the token issuer or fetches from a token-supplied URL', () => {
  const fs = require('node:fs');
  const src = fs.readFileSync(require.resolve('../index.js'), 'utf8') + fs.readFileSync(require.resolve('../webhooks.js'), 'utf8');
  assert.ok(!/\.iss\b|decodeJwt|jwks\.json|get_unverified/.test(src), 'legacy Node code must not touch the token issuer');
  const fetches = [...src.matchAll(/fetch\(([^,)]+)/g)].map((m) => m[1].trim());
  assert.deepEqual(fetches, ['url'], 'the only outbound fetch is the entitlement lookup');
  assert.ok(/PLATFORM_API_URL/.test(src) && !/req\.|auth\./.test(src.match(/const baseUrl[^\n]*/)[0]), 'its base URL comes from the environment');
});
