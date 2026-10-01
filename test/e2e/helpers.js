// Shared by the e2e tests: reads the state file written by scripts/scratch_platform.py
// (a scratch copy of the C0b platform branch on a scratch database) and builds
// libraries and credentials against it. Everything in it is fake and per-run.

const fs = require('fs');
const path = require('path');
const { importPKCS8 } = require('jose');
const { World, VECTORS, newClerkKeys, mintClerkToken } = require('../helpers/world');

const STATE_PATH = process.env.SCRATCH_STATE || path.join(__dirname, '..', '..', '.scratch', 'state.json');

function loadState() {
  if (!fs.existsSync(STATE_PATH)) return null;
  return JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
}

async function context() {
  const state = loadState();
  if (!state) return null;
  const world = new World(undefined, { includeTransient: false });
  world.nowMs = Date.now(); // the platform evaluates windows and expiries against its own clock
  const foreign = (await newClerkKeys()).foreign;
  const keys = { trusted: { kid: state.clerk_kid, privateKey: await importPKCS8(state.clerk_private_key_pem, 'RS256') }, foreign };
  return { state, world, keys };
}

// What the platform itself says, asked directly with the shared scratch key.
async function platformAuthorize(state, body) {
  const resp = await fetch(`${state.platform_url}/v1/authorize`, {
    method: 'POST', headers: { 'X-API-Key': state.shared_key, 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: resp.status, body: await resp.json() };
}

function tokenFor(ctx, ref, spec) {
  return mintClerkToken(ctx.keys, {
    sub: ctx.world.principal(ref).user_id, nowMs: Date.now(),
    issuer: ctx.state.issuer, azp: ctx.state.authorized_party,
  }, spec);
}

module.exports = { loadState, context, platformAuthorize, tokenFor, VECTORS };
