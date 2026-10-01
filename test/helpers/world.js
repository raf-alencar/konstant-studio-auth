// Test support: turns test-vectors/vectors.json's `world` into what the
// platform would serve (snapshot, key resolution) and mints Clerk tokens, all
// with fake data generated per run. The snapshot builder mirrors
// app/snapshot.py on the C0b branch; the e2e parity test compares it against the
// real platform's snapshot for the same world, so drift here is caught.

const crypto = require('crypto');
const { generateKeyPair, exportJWK, SignJWT } = require('jose');

const VECTORS = require('../../test-vectors/vectors.json');

function uuid5(namespace, name) {
  const ns = Buffer.from(namespace.replace(/-/g, ''), 'hex');
  const h = crypto.createHash('sha1').update(ns).update(name).digest();
  h[6] = (h[6] & 0x0f) | 0x50;
  h[8] = (h[8] & 0x3f) | 0x80;
  const x = h.subarray(0, 16).toString('hex');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}

const ROLE_CATEGORIES = {
  viewer: ['read'],
  operator: ['read', 'write'],
  approver: ['read', 'approve'],
  admin: ['read', 'write', 'manage'],
};

class World {
  // `transient` rows exist only to exercise the consumer's clock inside a cached snapshot (they
  // expire within seconds); they cannot be seeded into a real database, so e2e worlds omit them.
  constructor(spec = VECTORS.world, { includeTransient = true } = {}) {
    if (!includeTransient) {
      const keep = (x) => !x.transient;
      spec = { ...spec, tenants: spec.tenants.filter(keep), entitlements: spec.entitlements.filter(keep),
        principals: spec.principals.filter(keep), memberships: spec.memberships.filter(keep) };
    }
    this.spec = spec;
    this.nowMs = Date.parse(spec.now);
    this.id = (kind, ref) => (ref == null ? null : uuid5(spec.namespace, `${kind}:${ref}`));
    this.tenantRef = new Map(spec.tenants.map((t) => [this.id('tenant', t.ref), t.ref]));
    // Fake raw keys: deterministic, obviously not real.
    this.rawKey = (key) => {
      const prefix = { agent: 'stga_', guest: 'stgg_', service: 'stgs_' }[key.kind];
      return prefix + crypto.createHash('sha256').update(`fake:${key.ref}`).digest('hex');
    };
    this.keyByRaw = new Map(spec.keys.map((k) => [this.rawKey(k), k]));
  }

  principal(ref) { return this.spec.principals.find((p) => p.ref === ref); }

  allRoles() {
    const system = Object.keys(ROLE_CATEGORIES).concat('owner').map((slug) => ({ slug, tenant: null, ref: slug }));
    return [...system, ...this.spec.roles.map((r) => ({ ...r }))];
  }

  rolePermissions(role) {
    if (role.slug === 'owner') return [...new Set(this.spec.catalog.map((p) => `${p.service}:*`))];
    if (role.permissions) return role.permissions;
    const cats = ROLE_CATEGORIES[role.slug];
    return this.spec.catalog.filter((p) => cats.includes(p.category)).map((p) => `${p.service}:${p.action}`);
  }

  // What GET /v1/authorize/snapshot?service=<service> returns for this world at `nowMs`.
  snapshot(service, { version = 100, ttl = 30, stale = 300 } = {}) {
    const s = this.spec;
    const tenantById = new Map(s.tenants.map((t) => [t.ref, t]));
    const ancestors = (ref) => {
      const out = [];
      for (let p = tenantById.get(ref).parent; p; p = tenantById.get(p).parent) out.push(p);
      return out;
    };
    const iso = (offsetS) => (offsetS == null ? null : new Date(this.nowMs + offsetS * 1000).toISOString());

    const entitled = s.entitlements.filter((e) => e.service === service && e.state === 'on' && tenantById.get(e.tenant).status === 'active');
    const tenants = entitled
      .map((e) => ({ e, t: tenantById.get(e.tenant) }))
      .sort((a, b) => a.t.ref.localeCompare(b.t.ref))
      .map(({ e, t }) => ({
        id: this.id('tenant', t.ref), slug: t.ref, type: t.type,
        parent_id: this.id('tenant', t.parent), ancestors: ancestors(t.ref).map((a) => this.id('tenant', a)),
        plan: e.plan ?? null, limits: {}, starts_at: iso(e.starts_in_s), ends_at: iso(e.ends_in_s),
      }));
    const tenantIds = new Set(entitled.map((e) => e.tenant));
    const relevant = new Set(tenantIds);
    for (const ref of tenantIds) ancestors(ref).forEach((a) => relevant.add(a));

    const roles = this.allRoles()
      .filter((r) => r.tenant === null || tenantIds.has(r.tenant))
      .map((r) => ({ r, perms: this.rolePermissions(r).filter((p) => p.split(':')[0] === service).sort() }))
      .filter(({ perms }) => perms.length)
      .map(({ r, perms }) => ({ id: this.id('role', r.ref), slug: r.slug, tenant_id: this.id('tenant', r.tenant), permissions: perms }));
    const roleIds = new Set(roles.map((r) => r.id));

    const memberships = s.memberships
      .filter((m) => {
        const p = this.principal(m.principal);
        return p && !p.no_principal && (p.status ?? 'active') === 'active' && (m.status ?? 'active') === 'active'
          && (m.expires_in_s == null || m.expires_in_s > 0)
          && relevant.has(m.tenant) && roleIds.has(this.id('role', m.role));
      })
      .map((m) => {
        const p = this.principal(m.principal);
        return {
          principal_id: this.id('principal', p.ref), user_id: p.kind === 'human' ? p.user_id : null, kind: p.kind,
          tenant_id: this.id('tenant', m.tenant), role_id: this.id('role', m.role),
          scope: m.scope ?? {}, expires_at: iso(m.expires_in_s),
        };
      });

    return {
      service, version, ttl_seconds: ttl, stale_read_ttl_seconds: stale,
      fail_closed: { stale_serves_categories: ['read'], always_live: ['sensitive actions', 'agent and guest key checks', 'revocation questions'] },
      rules: { guest_allowed_categories: ['read'], agent_denied_categories: ['approve'] },
      permissions: s.catalog.filter((p) => p.service === service).map(({ action, category, sensitive }) => ({ action, category, sensitive })),
      tenants, roles, memberships,
    };
  }
}

// ---- Clerk tokens ------------------------------------------------------------

async function newClerkKeys() {
  const make = async (kid) => {
    const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
    return { kid, privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' } };
  };
  return { trusted: await make('kid-trusted'), foreign: await make('kid-foreign') };
}

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

// spec fields (all optional): exp_in_s, iat_in_s, nbf_in_s, azp (null = omit), iss, aud, kid, alg, sign_with, extra (more claims, e.g. fva)
async function mintClerkToken(keys, { sub, nowMs, issuer, azp }, spec = {}) {
  const iat = Math.floor(nowMs / 1000);
  const claims = { sub, iat: iat + (spec.iat_in_s ?? 0) };
  if (spec.nbf_in_s !== undefined) claims.nbf = iat + spec.nbf_in_s;
  claims.exp = iat + (spec.exp_in_s ?? 3600);
  claims.iss = spec.iss ?? issuer;
  if (spec.azp !== null) claims.azp = spec.azp ?? azp;
  if (spec.aud) claims.aud = spec.aud;
  Object.assign(claims, spec.extra || {});
  if (spec.alg === 'none') return `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u(claims)}.`;
  if (spec.alg === 'HS256') {
    return new SignJWT(claims).setProtectedHeader({ alg: 'HS256', kid: keys.trusted.kid }).sign(crypto.randomBytes(32));
  }
  const signer = spec.sign_with === 'foreign' ? keys.foreign : keys.trusted;
  return new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid: spec.kid ?? signer.kid, typ: 'JWT' }).sign(signer.privateKey);
}

// ---- fake platform ------------------------------------------------------------

// Answers over an injected fetch (no sockets). `live` is what POST /v1/authorize
// returns for a valid credential: the vector's platform-truth answer.
class FakePlatform {
  constructor(world, keys, { jwksUrl }) {
    this.world = world;
    this.keys = keys;
    this.jwksUrl = jwksUrl;
    this.down = false;
    this.live = null;
    this.calls = [];
    this.snapshotVersion = 100;
    this.fetch = this.fetch.bind(this);
  }

  count(method, path) { return this.calls.filter((c) => c.method === method && c.path === path).length; }

  _json(body, status = 200, headers = {}) {
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  }

  _principalSummary(p) {
    return { id: this.world.id('principal', p.ref), kind: p.kind, user_id: p.kind === 'human' ? p.user_id : null, tenant_id: this.world.id('tenant', p.tenant) };
  }

  async fetch(url, init = {}) {
    const u = new URL(url);
    const method = (init.method || 'GET').toUpperCase();
    if (url === this.jwksUrl) return this._json({ keys: [this.keys.trusted.jwk] });
    this.calls.push({ method, path: u.pathname });
    if (this.down) throw new TypeError('fetch failed');
    const body = init.body ? JSON.parse(init.body) : {};

    if (method === 'GET' && u.pathname === '/v1/authorize/snapshot') {
      const snap = this.world.snapshot(u.searchParams.get('service'), { version: this.snapshotVersion });
      const etag = `"${crypto.createHash('sha256').update(JSON.stringify({ ...snap, version: 0 })).digest('hex').slice(0, 32)}"`;
      if (init.headers?.['If-None-Match'] === etag) return new Response(null, { status: 304, headers: { etag } });
      return this._json(snap, 200, { etag });
    }
    if (method === 'GET' && u.pathname === '/v1/events') {
      return this._json({ events: this.events || [], next_cursor: Number(u.searchParams.get('after')) + (this.events?.length || 0), head: this.snapshotVersion });
    }

    const cred = body.credential;
    const key = cred ? this.world.keyByRaw.get(cred) : null;
    const keyProblem = cred && (!key || key.state === 'unknown' ? 'key_not_found' : { revoked: 'key_revoked', expired: 'key_expired' }[key.state]);
    if (u.pathname === '/v1/principals/resolve') {
      if (cred && keyProblem) return this._json({ valid: false, reason: keyProblem });
      if (cred && key.kind === 'service') return this._json({ valid: false, reason: 'unsupported_credential' }); // C0b: not resolvable
      return this._json({ valid: true, principal: this._principalSummary(this.world.principal(key.principal)), key_id: key ? this.world.id('key', key.ref) : null });
    }
    if (u.pathname === '/v1/authorize') {
      if (cred && keyProblem) return this._json({ allow: false, reason: keyProblem });
      if (cred && key.kind === 'service') return this._json({ allow: false, reason: 'unsupported_credential' });
      const e = this.live;
      const w = this.world;
      const principal = key ? this._principalSummary(w.principal(key.principal)) : e.principal || null;
      return this._json({
        allow: e.allow, reason: e.reason, tenant_id: w.id('tenant', e.tenant), via_tenant: w.id('tenant', e.via_tenant),
        principal, sensitive: !!e.sensitive, roles: e.roles || [],
      });
    }
    return this._json({ detail: 'not found' }, 404);
  }
}

module.exports = { VECTORS, World, FakePlatform, newClerkKeys, mintClerkToken, uuid5 };
