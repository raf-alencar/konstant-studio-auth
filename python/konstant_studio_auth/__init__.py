"""@konstant-studio/auth — FastAPI / Python edition.

Mirrors the Node package contract in this repo's root `index.js` and
`webhooks.js`. See `python/README.md` for usage.
"""

from .auth import (
    AuthState,
    clerk_protect,
    get_brand_id,
    m2m_auth,
    protect_or_m2m,
    require_service,
    superadmin_only,
)
from .webhooks import on as on_webhook_event
from .webhooks import router as webhooks_router

__all__ = [
    "AuthState",
    "clerk_protect",
    "get_brand_id",
    "m2m_auth",
    "protect_or_m2m",
    "require_service",
    "superadmin_only",
    "webhooks_router",
    "on_webhook_event",
]

__version__ = "0.1.0"
