"""Thin client for the control plane's runtime API (docs/control-plane.md in
stighive-platform, branch feat/control-plane-c0a-c0b). Only what the library
needs: authorize, resolve, snapshot, events. Request bodies hold credentials,
so nothing here logs a body, a header or a URL query.
"""

import json
from urllib.parse import quote


class PlatformUnavailable(Exception):
    pass


class PlatformThrottled(PlatformUnavailable):
    """The platform said "slow down" (HTTP 429). Not a verdict about anyone's credential: callers
    back off for retry_after_ms and answer platform_unavailable meanwhile."""

    def __init__(self, retry_after_ms):
        super().__init__("platform throttled this service")
        self.retry_after_ms = retry_after_ms


MAX_RETRY_AFTER_MS = 30_000
DEFAULT_RETRY_AFTER_MS = 5_000


class PlatformClient:
    def __init__(self, base_url, key, http, timeout_ms, logger):
        self.base_url = base_url
        self.key = key
        self.http = http  # httpx.AsyncClient
        self.timeout = timeout_ms / 1000
        self.logger = logger

    async def _request(self, method, path, body=None, headers=None):
        if not self.base_url:
            raise PlatformUnavailable("PLATFORM_API_URL is not configured")
        hdrs = {"X-API-Key": self.key}
        if body is not None:
            hdrs["Content-Type"] = "application/json"
        hdrs.update(headers or {})
        try:
            # json= would also set the header; sending bytes keeps the body exactly as Node's JSON.stringify.
            resp = await self.http.request(
                method,
                f"{self.base_url}{path}",
                headers=hdrs,
                content=json.dumps(body).encode() if body is not None else None,
                timeout=self.timeout,
                follow_redirects=False,
            )
        except Exception as err:  # noqa: BLE001 - any transport failure means "could not decide"
            raise PlatformUnavailable(f"platform unreachable ({type(err).__name__})") from None
        # Node uses redirect:'error'; a redirect could carry the key to another host, so it is a failure here too.
        if 300 <= resp.status_code < 400 and resp.status_code != 304:
            raise PlatformUnavailable(f"platform redirected ({resp.status_code})")
        # 401/403 here mean the platform refused OUR key: the deployment is
        # misconfigured, so no decision is possible. Fail closed, and say why.
        if resp.status_code in (401, 403):
            self.logger.error(
                f"platform refused this service's key (HTTP {resp.status_code}) for {method} {path.split('?')[0]}"
            )
            raise PlatformUnavailable(f"platform refused the service key ({resp.status_code})")
        if resp.status_code == 429:
            try:
                secs = float(resp.headers.get("retry-after"))
            except (TypeError, ValueError):
                secs = 0
            raise PlatformThrottled(min(secs * 1000, MAX_RETRY_AFTER_MS) if secs > 0 and secs == secs else DEFAULT_RETRY_AFTER_MS)
        if resp.status_code >= 500:
            raise PlatformUnavailable(f"platform error {resp.status_code}")
        return resp

    async def snapshot(self, service, etag=None):
        resp = await self._request(
            "GET",
            f"/v1/authorize/snapshot?service={quote(service, safe='')}",
            headers={"If-None-Match": etag} if etag else {},
        )
        if resp.status_code == 304:
            return {"not_modified": True}
        if not resp.is_success:
            raise PlatformUnavailable(f"snapshot HTTP {resp.status_code}")
        return {"body": resp.json(), "etag": resp.headers.get("etag")}

    async def events(self, after, limit=200):
        resp = await self._request("GET", f"/v1/events?after={after}&limit={limit}")
        if not resp.is_success:
            raise PlatformUnavailable(f"events HTTP {resp.status_code}")
        return resp.json()

    async def authorize(self, payload):
        resp = await self._request("POST", "/v1/authorize", body=payload)
        if not resp.is_success:
            raise PlatformUnavailable(f"authorize HTTP {resp.status_code}")
        return resp.json()

    async def resolve(self, payload):
        resp = await self._request("POST", "/v1/principals/resolve", body=payload)
        if not resp.is_success:
            raise PlatformUnavailable(f"resolve HTTP {resp.status_code}")
        return resp.json()
