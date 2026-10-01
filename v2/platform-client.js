// Thin client for the control plane's runtime API (docs/control-plane.md in
// stighive-platform, branch feat/control-plane-c0a-c0b). Only what the library
// needs: authorize, resolve, snapshot, events. Request bodies hold credentials,
// so nothing here logs a body, a header or a URL query.

class PlatformUnavailable extends Error {}

class PlatformClient {
  constructor({ baseUrl, key, fetch, timeoutMs, logger }) {
    this.baseUrl = baseUrl;
    this.key = key;
    this.fetch = fetch;
    this.timeoutMs = timeoutMs;
    this.logger = logger;
  }

  async _request(method, path, { body, headers } = {}) {
    if (!this.baseUrl) throw new PlatformUnavailable('PLATFORM_API_URL is not configured');
    let resp;
    try {
      resp = await this.fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          'X-API-Key': this.key,
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          ...headers,
        },
        body: body ? JSON.stringify(body) : undefined,
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new PlatformUnavailable(`platform unreachable (${err?.name || 'error'})`);
    }
    // 401/403 here mean the platform refused OUR key: the deployment is
    // misconfigured, so no decision is possible. Fail closed, and say why.
    if (resp.status === 401 || resp.status === 403) {
      this.logger.error(`platform refused this service's key (HTTP ${resp.status}) for ${method} ${path.split('?')[0]}`);
      throw new PlatformUnavailable(`platform refused the service key (${resp.status})`);
    }
    if (resp.status >= 500) throw new PlatformUnavailable(`platform error ${resp.status}`);
    return resp;
  }

  async snapshot(service, etag) {
    const resp = await this._request('GET', `/v1/authorize/snapshot?service=${encodeURIComponent(service)}`, {
      headers: etag ? { 'If-None-Match': etag } : {},
    });
    if (resp.status === 304) return { notModified: true };
    if (!resp.ok) throw new PlatformUnavailable(`snapshot HTTP ${resp.status}`);
    return { body: await resp.json(), etag: resp.headers.get('etag') };
  }

  async events(after, limit = 200) {
    const resp = await this._request('GET', `/v1/events?after=${after}&limit=${limit}`);
    if (!resp.ok) throw new PlatformUnavailable(`events HTTP ${resp.status}`);
    return resp.json();
  }

  async authorize(payload) {
    const resp = await this._request('POST', '/v1/authorize', { body: payload });
    if (!resp.ok) throw new PlatformUnavailable(`authorize HTTP ${resp.status}`);
    return resp.json();
  }

  async resolve(payload) {
    const resp = await this._request('POST', '/v1/principals/resolve', { body: payload });
    if (!resp.ok) throw new PlatformUnavailable(`resolve HTTP ${resp.status}`);
    return resp.json();
  }
}

module.exports = { PlatformClient, PlatformUnavailable };
