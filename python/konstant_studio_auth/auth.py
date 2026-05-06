"""FastAPI dependencies that mirror the Node middleware in `index.js`.

Same contract: validate Clerk JWT (or X-API-Key for M2M), return an `AuthState`
with `user_id`, `org_id`, `org_role`, and `is_superadmin`. `get_brand_id(auth)`
returns the brand id (`org_id`) for clients and `None` for the superadmin
(meaning "all brands"). All gates raise standard FastAPI HTTPExceptions on
failure (401 Unauthorized, 403 Forbidden) — matching the JSON error responses
the Node package returns.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional, Set

import httpx
from fastapi import Depends, Header, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt
from jose.exceptions import JWTError

logger = logging.getLogger(__name__)


@dataclass
class AuthState:
    user_id: str
    org_id: Optional[str]
    org_role: Optional[str]
    is_superadmin: bool


_JWKS_CACHE: dict[str, dict] = {}
_bearer_scheme = HTTPBearer(auto_error=False)


async def _get_jwks(issuer: str) -> dict:
    cached = _JWKS_CACHE.get(issuer)
    if cached is not None:
        return cached
    url = f"{issuer.rstrip('/')}/.well-known/jwks.json"
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        jwks = resp.json()
    _JWKS_CACHE[issuer] = jwks
    return jwks


async def _verify_clerk_jwt(token: str) -> dict:
    try:
        unverified = jwt.get_unverified_claims(token)
        headers = jwt.get_unverified_header(token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    issuer = unverified.get("iss")
    if not issuer:
        raise HTTPException(status_code=401, detail="Missing issuer claim")

    jwks = await _get_jwks(issuer)
    kid = headers.get("kid")
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key is None:
        raise HTTPException(status_code=401, detail="JWT signing key not found")

    try:
        return jwt.decode(
            token,
            key,
            algorithms=[headers.get("alg", "RS256")],
            issuer=issuer,
            options={"verify_aud": False},
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def _claims_to_auth_state(claims: dict) -> AuthState:
    public_metadata = (
        claims.get("public_metadata")
        or claims.get("publicMetadata")
        or {}
    )
    return AuthState(
        user_id=claims.get("sub") or claims.get("user_id") or "",
        org_id=claims.get("org_id") or claims.get("orgId"),
        org_role=claims.get("org_role") or claims.get("orgRole"),
        is_superadmin=public_metadata.get("superadmin") is True,
    )


def _extract_token(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials],
) -> Optional[str]:
    if creds and creds.scheme.lower() == "bearer":
        return creds.credentials
    return request.cookies.get("__session")


async def clerk_protect(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
) -> AuthState:
    """Validate the Clerk JWT and return AuthState. Raises 401 on failure.

    Token is read from the `Authorization: Bearer <jwt>` header or the
    `__session` cookie that Clerk's frontend SDK sets.
    """
    token = _extract_token(request, creds)
    if not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    claims = await _verify_clerk_jwt(token)
    auth = _claims_to_auth_state(claims)
    if not auth.user_id:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return auth


def get_brand_id(auth: AuthState) -> Optional[str]:
    """Return the brand id to scope DB queries by.

    Superadmin (Raf): `None` — meaning "all brands". Host services that
    need a per-request override (the Node package's `?brand_id=` query
    param) should read it from the request themselves.

    Client: their `org_id`, never overrideable.
    """
    if auth.is_superadmin:
        return None
    return auth.org_id


async def m2m_auth(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> AuthState:
    """API-key auth for workers and n8n. Raises 401 if the key is wrong.

    Returns an AuthState with `user_id="system"` and `is_superadmin=True`,
    matching the Node package's behaviour.
    """
    expected = os.getenv("INTERNAL_API_KEY")
    if not x_api_key or not expected or x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return AuthState(
        user_id="system",
        org_id=None,
        org_role=None,
        is_superadmin=True,
    )


async def protect_or_m2m(
    request: Request,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_scheme),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> AuthState:
    """Try the Clerk JWT first, fall back to X-API-Key. Raises 401 if neither valid."""
    token = _extract_token(request, creds)
    if token:
        try:
            claims = await _verify_clerk_jwt(token)
            auth = _claims_to_auth_state(claims)
            if auth.user_id:
                return auth
        except HTTPException:
            pass

    expected = os.getenv("INTERNAL_API_KEY")
    if x_api_key and expected and x_api_key == expected:
        return AuthState(
            user_id="system",
            org_id=None,
            org_role=None,
            is_superadmin=True,
        )

    raise HTTPException(status_code=401, detail="Unauthorized")


async def superadmin_only(
    auth: AuthState = Depends(clerk_protect),
) -> AuthState:
    """Restrict route to users with `public_metadata.superadmin === true`."""
    if not auth.is_superadmin:
        raise HTTPException(status_code=403, detail="Forbidden")
    return auth


# ---------------------------------------------------------------------------
# Service entitlement gate — checks the platform API to confirm the caller's
# org has access to the named service. Superadmin and m2m bypass.
# ---------------------------------------------------------------------------

_ENTITLEMENT_TTL_SECONDS = 60
_entitlement_cache: dict[str, tuple[float, Set[str]]] = {}

_NO_ACCESS_DETAIL = {
    "error": "No access to this service",
    "upgrade_url": "https://www.konstant-studio.com/dashboard",
}


def _is_production() -> bool:
    return any(
        os.getenv(var) == "production"
        for var in ("NODE_ENV", "PYTHON_ENV", "ENVIRONMENT", "ENV")
    )


async def _fetch_entitlements(org_id: str) -> Optional[Set[str]]:
    """Returns the set of service slugs the org has access to, or `None` if
    the platform API is unreachable / unconfigured (caller decides policy)."""
    base_url = os.getenv("PLATFORM_API_URL")
    if not base_url:
        return None
    api_key = os.getenv("INTERNAL_API_KEY", "")
    url = f"{base_url.rstrip('/')}/entitlements/{org_id}"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url, headers={"X-API-Key": api_key})
        if resp.status_code == 404:
            return set()
        resp.raise_for_status()
        body = resp.json()
        if isinstance(body, list):
            return set(body)
        if isinstance(body, dict):
            return set(body.get("services") or body.get("entitlements") or [])
        return set()
    except Exception:
        logger.exception("entitlements fetch failed for org=%s", org_id)
        return None


async def _get_entitlements(org_id: str) -> Optional[Set[str]]:
    cached = _entitlement_cache.get(org_id)
    if cached is not None:
        ts, services = cached
        if time.time() - ts < _ENTITLEMENT_TTL_SECONDS:
            return services
    services = await _fetch_entitlements(org_id)
    if services is not None:
        _entitlement_cache[org_id] = (time.time(), services)
    return services


def require_service(service_slug: str):
    """Factory: returns a FastAPI dependency that confirms the caller's org
    is entitled to `service_slug` via the platform API.

    Behaviour:
      - Superadmin (human or m2m) bypasses the check.
      - Org not entitled → 403 with `{ error, upgrade_url }`.
      - `PLATFORM_API_URL` unset or unreachable → warn + allow in dev, deny
        in production (any of `NODE_ENV`, `PYTHON_ENV`, `ENVIRONMENT`, `ENV`
        equal to `"production"`).
      - Per-org result is cached in-process for 60s.

    Accepts both a Clerk session and `X-API-Key` (m2m). m2m always bypasses
    because `m2m_auth` returns `is_superadmin=True`.
    """
    async def _check(auth: AuthState = Depends(protect_or_m2m)) -> AuthState:
        if auth.is_superadmin:
            return auth
        if not auth.org_id:
            raise HTTPException(status_code=403, detail=_NO_ACCESS_DETAIL)

        services = await _get_entitlements(auth.org_id)
        if services is None:
            if _is_production():
                logger.error(
                    "entitlement check failed for org=%s service=%s — failing closed",
                    auth.org_id, service_slug,
                )
                raise HTTPException(
                    status_code=503,
                    detail="Entitlement service unavailable",
                )
            logger.warning(
                "entitlement check skipped (dev mode): PLATFORM_API_URL unreachable or unset; org=%s service=%s",
                auth.org_id, service_slug,
            )
            return auth

        if service_slug not in services:
            raise HTTPException(status_code=403, detail=_NO_ACCESS_DETAIL)
        return auth

    return _check


def _reset_entitlement_cache() -> None:
    """Test hook — clear the in-process cache."""
    _entitlement_cache.clear()
