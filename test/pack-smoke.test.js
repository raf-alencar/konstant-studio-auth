// Pack-and-install smoke test: builds the tarball exactly as an adopter's
// `npm install github:...` would see it, installs it into a scratch project,
// and loads it with the imports the current adopters use. Catches a `files`
// list that forgets something (a file that works in the checkout but is not
// shipped). Needs network for the dependency install, so it is its own script:
//   npm run test:smoke

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

test('the packed package loads the way the three adopters load it', { timeout: 300000 }, () => {
  const root = path.join(__dirname, '..');
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ksa-pack-'));
  try {
    const out = execFileSync('npm', ['pack', '--json', '--pack-destination', work], { cwd: root }).toString();
    const [{ filename, files }] = JSON.parse(out);
    const shipped = new Set(files.map((f) => f.path));
    for (const must of ['index.js', 'webhooks.js', 'v2/index.js', 'v2/auth.js', 'v2/adapters/express.js', 'v2/adapters/next.js', 'test-vectors/vectors.json', 'README.md', 'CHANGELOG.md']) {
      assert.ok(shipped.has(must), `${must} is missing from the package`);
    }
    assert.ok(![...shipped].some((p) => p.startsWith('test/') || p.startsWith('.scratch') || p.includes('node_modules')), 'the package ships test or scratch files');

    fs.writeFileSync(path.join(work, 'package.json'), JSON.stringify({ name: 'adopter-smoke', version: '0.0.0', private: true }));
    execFileSync('npm', ['install', '--no-audit', '--no-fund', path.join(work, filename)], { cwd: work, stdio: 'pipe' });

    const script = `
      // what social-konstant-studio/admin/server.js imports
      const { setupClerk, protect, protectOrM2M, superadminOnly, requireLogin, requireService, getBrandId } = require('@konstant-studio/auth');
      const clerkWebhooks = require('@konstant-studio/auth/webhooks');
      // what stighive-character-console/server.js imports
      const cc = require('@konstant-studio/auth');
      for (const f of [setupClerk, protect, protectOrM2M, superadminOnly, requireLogin, requireService, getBrandId, cc.m2mAuth]) if (typeof f !== 'function') throw new Error('v1 export missing');
      if (typeof clerkWebhooks !== 'function' || typeof clerkWebhooks.events.on !== 'function') throw new Error('webhooks subpath broken');
      // v2, both entry points, and its vectors for adopters' acceptance tests
      const v2 = require('@konstant-studio/auth/v2');
      if (typeof v2.createAuth !== 'function' || cc.createAuth !== v2.createAuth) throw new Error('v2 entry broken');
      const vectors = require('@konstant-studio/auth/test-vectors/vectors.json');
      if (!Array.isArray(vectors.cases) || vectors.cases.length < 40) throw new Error('vectors not shipped');
      const auth = v2.createAuth({ service: 'docs', pollIntervalSeconds: 0 });
      if (typeof auth.express.requirePermission !== 'function' || typeof auth.next.withPermission !== 'function') throw new Error('adapters missing');
      console.log('adopter smoke ok');
    `;
    const res = execFileSync('node', ['-e', script], { cwd: work, env: { ...process.env, KSA_SILENCE_DEPRECATIONS: '1' } }).toString();
    assert.match(res, /adopter smoke ok/);
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
});
