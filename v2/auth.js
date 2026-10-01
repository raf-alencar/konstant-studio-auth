// createAuth(): one object per service that turns a request's credential into a
// Principal and answers "may this principal do service:action here?".
//
// Never throws for an auth failure: every outcome is a result object
//   { allow, reason, status, principal, tenantId, viaTenant, roles, sensitive, source }
// so adapters map it to a response without try/catch, and a bug cannot turn
// into an accidental allow. `source` says who decided: 'offline' (from the
// cached snapshot), 'live' (POST /v1/authorize) or 'none' (stopped earlier).
//
// What is decided where (CoS amendment, section 3):
//   offline  human Clerk session, this service's own non-sensitive permission,
//            tenant named by the caller;
//   live     everything else: sensitive actions, agent/guest/MCP keys, other
//            services' permissions, and any check with no tenant named (so the
//            platform, not a guess here, answers tenant_required).
// Platform unreachable: sensitive and key checks fail closed; read checks may
// be served from a bounded-age cache; other routine checks fail closed.

const { resolveConfig } = require('./config');
const { statusFor } = require('./reasons');
const { PlatformClient, PlatformUnavailable } = require('./platform-client');
const { SnapshotCache } = require('./snapshot-cache');
const { ClerkVerifier, Denied } = require('./clerk');
const { extract } = require('./credentials');
const { decideOffline } = require('./decision');
const { ServiceKeyResolver, routeAllowed } = require('./service-keys');
const { scopeAllows } = require('./decision');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACTOR_KIND = { human: 'human', agent: 'agent', guest: 'guest', service: 'system' };

class Principal {
  constructor(fields) {
    Object.assign(
      this,
      { kind: null, id: null, userId: null, tenant: null, ancestry: [], roles: [], permissions: [],
        keyId: null, keyPrefix: null, source: null, service: null, claims: null },
      fields
    );
  }

  // Actor for usage events (event contract: "Usage ledger design"): ids only, never a key or token.
  actor() {
    const a = { kind: ACTOR_KIND[this.kind] || 'system', id: this.id };
    if (this.keyPrefix) a.key_prefix = this.keyPrefix;
    return a;
  }
}

function parsePermission(permission) {
  const i = typeof permission === 'string' ? permission.indexOf(':') : -1;
  if (i <= 0 || i === permission.length - 1) return null;
  return { service: permission.slice(0, i), action: permission.slice(i + 1) };
}

function createAuth(opts = {}) {
  const cfg = resolveConfig(opts);
  const client = new PlatformClient({
    baseUrl: cfg.platformUrl, key: cfg.platformKey, fetch: cfg.fetch,
    timeoutMs: cfg.requestTimeoutMs, logger: cfg.logger,
  });
  ServiceKeyResolver.validateAccepted(cfg.acceptedCallerServices); // a bad slug is a startup error
  const serviceKeys = new ServiceKeyResolver({
    client, accepted: cfg.acceptedCallerServices, now: cfg.now, logger: cfg.logger, ...cfg.serviceKeyCache,
  });
  const clerk = new ClerkVerifier(cfg.clerk, { fetch: cfg.fetch, now: cfg.now, logger: cfg.logger });
  const cache = cfg.service
    ? new SnapshotCache({
        client, service: cfg.service, ttlSeconds: cfg.snapshot.ttlSeconds,
        staleReadTtlSeconds: cfg.snapshot.staleReadTtlSeconds, now: cfg.now,
        pollIntervalSeconds: cfg.pollIntervalSeconds, logger: cfg.logger,
      })
    : null;

  function emit(event) {
    if (!cfg.onEvent) return;
    try {
      cfg.onEvent(event);
    } catch (err) {
      cfg.logger.warn(`auth event sink failed: ${err.message}`); // an audit sink must never break a request
    }
  }

  function result(fields) {
    const allow = !!fields.allow;
    return {
      allow, reason: fields.reason, status: statusFor(fields.reason, allow),
      principal: fields.principal ?? null, tenantId: fields.tenantId ?? null,
      viaTenant: fields.viaTenant ?? null, roles: fields.roles ?? [],
      sensitive: !!fields.sensitive, source: fields.source ?? 'none',
      stale: !!fields.stale,
    };
  }

  // The audit event carries ids and the decision only: never a credential,
  // header, token or request body.
  function audited(res, permission, requestId) {
    emit({
      type: 'auth.decision', ts: new Date(cfg.now()).toISOString(), service: cfg.service || null,
      permission, allow: res.allow, reason: res.reason, source: res.source, stale: res.stale,
      tenant_id: res.tenantId, via_tenant: res.viaTenant,
      caller_service: res.principal?.kind === 'service' ? res.principal.service : null,
      actor: res.principal ? res.principal.actor() : null,
      key_id: res.principal?.keyId ?? null, run_id: requestId ?? null,
    });
    return res;
  }

  // ---- principal resolution -------------------------------------------------

  // -> { principal } | { denied: reason }
  async function principalFrom(cred) {
    if (cred.type === 'none') return { denied: 'no_credential' };

    if (cred.type === 'clerk') {
      try {
        const claims = await clerk.verify(cred.raw);
        return {
          principal: new Principal({
            kind: 'human', id: claims.sub, userId: claims.sub, source: 'clerk',
            // Clerk's v1 session token carries org_id/org_role, the v2 token carries them as o.{id,rol}.
            claims: { azp: claims.azp, org_id: claims.org_id ?? claims.o?.id ?? null, org_role: claims.org_role ?? claims.o?.rol ?? null, fva: claims.fva ?? null },
          }),
        };
      } catch (err) {
        if (err instanceof Denied) return { denied: err.reason };
        throw err;
      }
    }

    if (cred.type === 'audience') {
      // Never trusted offline: authority and revocation are re-checked by the platform on every use.
      return { principal: new Principal({ kind: 'human', source: 'audience_token' }), deferToPlatform: true };
    }

    // keys
    if (!cred.keyKind) return { denied: 'key_not_found' };
    if (cred.keyKind === 'service') {
      try {
        const sp = await serviceKeys.resolve(cred.raw);
        return {
          principal: new Principal({
            kind: 'service', id: sp.id, service: sp.service, keyId: sp.keyId, keyPrefix: 'stgs_', source: 'platform_key',
          }),
        };
      } catch (err) {
        if (err instanceof Denied) return { denied: err.reason }; // key_not_found (uniform) or platform_unavailable
        throw err;
      }
    }
    // agent / guest / mcp keys: only the platform knows; resolved and decided live.
    return { principal: new Principal({ kind: null, source: 'platform_key', keyPrefix: cred.raw.slice(0, 5) }), deferToPlatform: true };
  }

  // POST /v1/principals/resolve for keys, so identity is available without a decision.
  async function resolvePrincipal({ headers, credential } = {}) {
    const cred = credential ?? extract(headers);
    const found = await principalFrom(cred);
    if (found.denied) return { ok: false, reason: found.denied, status: statusFor(found.denied, false) };
    if (!found.deferToPlatform) return { ok: true, principal: found.principal };
    try {
      const body = cred.type === 'audience' ? { audience_token: cred.raw } : { credential: cred.raw };
      const res = await client.resolve(body);
      if (!res.valid) return { ok: false, reason: res.reason, status: statusFor(res.reason, false) };
      if (!res.principal) return { ok: false, reason: 'platform_unavailable', status: 503 }; // malformed reply: cannot identify anyone
      return { ok: true, principal: fromPlatformSummary(res.principal, res.key_id, found.principal) };
    } catch (err) {
      if (err instanceof PlatformUnavailable) return { ok: false, reason: 'platform_unavailable', status: 503 };
      throw err;
    }
  }

  function fromPlatformSummary(p, keyId, base) {
    return new Principal({
      ...base, kind: p.kind, id: p.user_id ?? p.id, userId: p.user_id ?? null,
      tenant: p.tenant_id ?? null, keyId: keyId ?? null,
    });
  }

  // ---- decisions ------------------------------------------------------------

  // Which tenant is this request about? In order: the explicit argument (an `x-tenant` header
  // is passed in as one by the adapters); the adopter's tenantResolver; then the Clerk
  // organization in the session token, mapped through the snapshot's tenant.org_id. The
  // mapping is identity, not authority: whatever tenant comes out, the decision still has to
  // find the user's membership in it (an org the user does not belong to is denied, never
  // silently swapped for one they do). With none, the platform answers tenant_required.
  async function selectTenant(explicit, principal, req) {
    if (explicit) return explicit; // '' is no tenant
    if (principal.kind !== 'human') return null;
    if (cfg.tenantResolver) {
      const t = (await cfg.tenantResolver(req, principal)) ?? null;
      if (t) return t;
    }
    const orgId = principal.claims?.org_id;
    if (orgId && cache) {
      const snap = await cache.get(); // a stale snapshot is fine here: it only names a tenant
      if (snap.state !== 'none') return snap.snapshot.tenants.find((t) => t.org_id === orgId)?.id ?? null;
    }
    return null;
  }

  async function live(cred, principal, parsed, resource) {
    const body = {
      service: parsed.service, action: parsed.action,
      resource: {
        ...(resource.tenant ? { tenant_id: resource.tenant } : {}),
        ...(resource.brand ? { brand_id: resource.brand } : {}),
        ...(resource.domain ? { domain: resource.domain } : {}),
        ...(resource.mailbox ? { mailbox: resource.mailbox } : {}),
      },
      ...(cred.type === 'clerk' ? { clerk_token: cred.raw } : cred.type === 'audience' ? { audience_token: cred.raw } : { credential: cred.raw }),
    };
    let res;
    try {
      res = await client.authorize(body);
    } catch (err) {
      if (err instanceof PlatformUnavailable) return result({ allow: false, reason: 'platform_unavailable', principal });
      throw err;
    }
    let p = principal;
    if (res.principal) p = fromPlatformSummary(res.principal, null, principal);
    if (res.allow) { p.tenant = res.tenant_id ?? null; p.roles = res.roles ?? []; }
    return result({
      allow: res.allow, reason: res.reason, principal: p, tenantId: res.tenant_id,
      viaTenant: res.via_tenant, roles: res.roles, sensitive: res.sensitive, source: 'live',
    });
  }

  // Decision without the audit event (so wrappers that add checks emit exactly one). `headers` is anything with .get() or a plain object;
  // `credential` (from extract()) may be passed instead when the caller already parsed it.
  async function decide({ headers, credential, permission, resource = {}, req } = {}) {
    try {
      const parsed = parsePermission(permission);
      const cred = credential ?? extract(headers);
      if (!parsed) return result({ allow: false, reason: 'unknown_permission' });

      const found = await principalFrom(cred);
      if (found.denied) return result({ allow: false, reason: found.denied });
      const principal = found.principal;

      // A service principal holds no tenant permissions: a tenant is not part of one, and the platform
      // grants it nothing (it answers service_principal_not_granted, so this offline answer is the same).
      // Who a service caller is allowed to be on THIS app's routes is requireServiceCaller's job.
      if (principal.kind === 'service') {
        return result({ allow: false, reason: 'service_principal_not_granted', principal });
      }

      let tenant = await selectTenant(resource.tenant, principal, req);
      // The platform's tenant ids are UUIDs. A caller-supplied value that is not one can never name a
      // tenant: answer it here as a denial instead of sending it on and reporting the platform's 422
      // as an outage (a client mistake must not look like platform_unavailable).
      if (tenant && !UUID_RE.test(String(tenant))) return result({ allow: false, reason: 'tenant_not_found', principal });
      const scoped = { ...resource, tenant };

      const offlineEligible =
        cred.type === 'clerk' && cache && parsed.service === cfg.service && tenant !== null;
      if (!offlineEligible) return await live(cred, principal, parsed, scoped);

      const snap = await cache.get();
      if (snap.state === 'none') {
        return result({ allow: false, reason: 'platform_unavailable', principal });
      }
      const perm = snap.snapshot.permissions.find((p) => p.action === parsed.action);
      if (perm?.sensitive) return await live(cred, principal, parsed, scoped);
      if (snap.state === 'stale' && perm && perm.category !== 'read') {
        return result({ allow: false, reason: 'platform_unavailable', principal });
      }

      const d = decideOffline(snap.snapshot, principal, parsed.service, parsed.action, scoped, cfg.now());
      const p = new Principal({ ...principal, tenant: d.tenantId, ancestry: d.ancestry ?? [], roles: d.roles, permissions: d.permissions });
      return result({
          allow: d.allow, reason: d.reason, principal: p, tenantId: d.tenantId, viaTenant: d.viaTenant,
          roles: d.roles, sensitive: d.sensitive, source: 'offline', stale: snap.state === 'stale',
        });
    } catch (err) {
      // A bug must never read as an allow. Log the class only (messages can echo input).
      cfg.logger.error(`auth: unexpected ${err?.name || 'error'} while deciding`);
      return result({ allow: false, reason: 'platform_unavailable' });
    }
  }

  async function authorize(args = {}) {
    return audited(await decide(args), args.permission, args.requestId);
  }

  // requireApprover: a human who holds the permission AND, when stepUp is set,
  // has a recent second-factor verification. Clerk session tokens carry `fva`
  // (minutes since [first, second] factor, -1 when none); this is the claim
  // the step-up rule reads. It has NOT been confirmed against this Clerk
  // instance's token shape (the CR leaves JWT-template limits unverified):
  // if `fva` is absent, step-up is denied, never assumed.
  function checkStepUp(res) {
    const fva = res.principal?.claims?.fva;
    const second = Array.isArray(fva) ? fva[1] : null;
    return typeof second === 'number' && second >= 0 && second <= cfg.stepUpMaxAgeMinutes;
  }

  async function authorizeApprover(args = {}) {
    const { stepUp = false, ...rest } = args;
    let res = await decide(rest);
    if (res.allow && res.principal?.kind !== 'human') {
      res = result({ ...res, allow: false, reason: 'principal_kind_restricted' });
    } else if (res.allow && stepUp && !checkStepUp(res)) {
      res = result({ ...res, allow: false, reason: 'step_up_required' });
    }
    return audited(res, args.permission, args.requestId);
  }

  // A request-supplied tenant id must be the tenant the decision was made in.
  function assertTenant(res, tenantId) {
    return !!(res?.allow && res.tenantId && res.tenantId === tenantId);
  }

  // Context for usage events: who acted, for which tenant, and the run id to propagate.
  function usageContext(res, requestId) {
    return {
      tenant_id: res?.tenantId ?? null,
      actor: res?.principal ? res.principal.actor() : { kind: 'system', id: null },
      run_id: requestId ?? null,
    };
  }

  // ---- effective permissions (platform C0b2) -------------------------------------
  //
  // What the platform says this principal may do in a tenant, computed by the same code path as
  // /v1/authorize, so a caller (a UI deciding which buttons to show, a service listing what an agent
  // can reach) need not re-implement the rules. `permits(permission, resource)` applies the documented
  // matching rule: allowed iff SOME scope entry admits the resource (each of brand_ids / domains /
  // mailboxes present must contain the request's brand / domain / mailbox, case-insensitive; an
  // absent key is unrestricted; an unknown key admits nothing). This is information, not a gate:
  // enforcement is authorize(), which asks the platform (or the parity-tested snapshot) per request.
  async function effectivePermissions({ headers, credential, tenant, service, req } = {}) {
    const cred = credential ?? extract(headers);
    const found = await principalFrom(cred);
    if (found.denied) return { ok: false, reason: found.denied, status: statusFor(found.denied, false) };
    const principal = found.principal;
    const none = (reason, extra = {}) => ({ ok: true, principal, tenantId: null, reason, permissions: [], permits: () => false, ...extra });
    if (principal.kind === 'service') return none('service_principal_not_granted');

    const chosen = await selectTenant(tenant, principal, req);
    if (chosen && !UUID_RE.test(String(chosen))) return none('tenant_not_found');
    const body = {
      include_effective: true,
      ...(chosen ? { tenant_id: chosen } : {}),
      ...(service ? { service } : {}),
      ...(cred.type === 'clerk' ? { clerk_token: cred.raw } : cred.type === 'audience' ? { audience_token: cred.raw } : { credential: cred.raw }),
    };
    let res;
    try {
      res = await client.resolve(body);
    } catch (err) {
      if (err instanceof PlatformUnavailable) return { ok: false, reason: 'platform_unavailable', status: 503 };
      throw err;
    }
    if (!res.valid) return { ok: false, reason: res.reason, status: statusFor(res.reason, false) };
    if (!res.principal || !res.effective) return { ok: false, reason: 'platform_unavailable', status: 503 };
    const p = fromPlatformSummary(res.principal, res.key_id, principal);
    const eff = res.effective;
    p.tenant = eff.tenant_id ?? null;
    p.permissions = (eff.permissions || []).map((e) => e.permission).sort();
    const permits = (permission, resource = {}) => {
      const entry = (eff.permissions || []).find((e) => e.permission === permission);
      return !!entry && entry.scopes.some((sc) => scopeAllows(sc.scope, resource) === null);
    };
    return { ok: true, principal: p, tenantId: p.tenant, reason: eff.reason ?? null, permissions: eff.permissions || [], permits };
  }

  // ---- service callers ------------------------------------------------------------
  //
  // An inbound call from another internal service. A matched service key proves WHICH service is
  // calling (and only that); what it may do on this app's routes is this app's own policy:
  //   policy = { '<caller service>': ['METHOD /path/glob', ...] }   (deny by default)
  // The platform's allowed_routes for the key are routes on the platform's API and play no part here.
  async function authorizeServiceCaller({ headers, credential, method, path, policy } = {}) {
    try {
      const cred = credential ?? extract(headers);
      const found = await principalFrom(cred);
      let res;
      if (found.denied) res = result({ allow: false, reason: found.denied });
      else if (found.principal.kind !== 'service') res = result({ allow: false, reason: 'service_caller_required', principal: found.principal });
      else if (!routeAllowed(policy?.[found.principal.service], method, path)) res = result({ allow: false, reason: 'route_not_allowed', principal: found.principal });
      else res = result({ allow: true, reason: 'allowed', principal: found.principal, source: 'live' });
      return audited(res, 'service_caller', undefined);
    } catch (err) {
      cfg.logger.error(`auth: unexpected ${err?.name || 'error'} while deciding`);
      return audited(result({ allow: false, reason: 'platform_unavailable' }), 'service_caller', undefined);
    }
  }

  const core = {
    config: cfg, client, cache, clerk, serviceKeys,
    authorize, authorizeApprover, resolvePrincipal, effectivePermissions, authorizeServiceCaller, assertTenant, usageContext,
    start() { cache?.startPolling(); return core; },
    close() { cache?.stop(); },
  };
  return core;
}

module.exports = { createAuth, Principal, parsePermission };
