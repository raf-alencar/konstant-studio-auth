"""FastAPI router that mirrors the Node webhook router in `webhooks.js`.

Same contract: verify the Svix signature using `CLERK_WEBHOOK_SECRET`,
ack with `200 {"received": true}`, and dispatch the event to handlers
registered via `on(event_type, handler)`. Subscribe to `"*"` to receive
every event.

The router exposes a single route — POST `/webhooks/clerk` — so host
services mount it with `app.include_router(webhooks_router)` and the
full path is already wired up.
"""

from __future__ import annotations

import inspect
import logging
import os
from typing import Any, Awaitable, Callable, Dict, List, Optional, Union

from fastapi import APIRouter, Header, HTTPException, Request
from svix.webhooks import Webhook, WebhookVerificationError

logger = logging.getLogger(__name__)

EventHandler = Callable[..., Union[None, Awaitable[None]]]

_handlers: Dict[str, List[EventHandler]] = {}


def on(event_type: str, handler: Optional[EventHandler] = None):
    """Subscribe a handler to a Clerk webhook event type.

    Decorator form (preferred):

        @on_webhook_event("user.created")
        async def handle(data: dict): ...

    Direct call:

        on("user.created", handle)

    Use `event_type="*"` to receive every event — the handler receives
    the full event dict (with `type` and `data`) instead of just `data`.
    """
    def _register(fn: EventHandler) -> EventHandler:
        _handlers.setdefault(event_type, []).append(fn)
        return fn

    if handler is None:
        return _register
    return _register(handler)


async def _invoke(handler: EventHandler, *args: Any) -> None:
    try:
        sig = inspect.signature(handler)
        n = len(sig.parameters)
        result = handler(*args[:n])
        if inspect.isawaitable(result):
            await result
    except Exception:
        logger.exception("clerk webhook handler raised")


async def _dispatch(event_type: str, data: Any, event: dict) -> None:
    for handler in list(_handlers.get(event_type, [])):
        await _invoke(handler, data, event)
    for handler in list(_handlers.get("*", [])):
        await _invoke(handler, event)


router = APIRouter()


@router.post("/webhooks/clerk")
async def _clerk_webhook(
    request: Request,
    svix_id: str = Header(..., alias="svix-id"),
    svix_timestamp: str = Header(..., alias="svix-timestamp"),
    svix_signature: str = Header(..., alias="svix-signature"),
):
    secret = os.getenv("CLERK_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(
            status_code=500,
            detail="CLERK_WEBHOOK_SECRET not configured",
        )

    body = await request.body()
    try:
        wh = Webhook(secret)
        event = wh.verify(
            body,
            {
                "svix-id": svix_id,
                "svix-timestamp": svix_timestamp,
                "svix-signature": svix_signature,
            },
        )
    except WebhookVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Invalid webhook payload")

    event_type = event.get("type") or ""
    data = event.get("data")
    await _dispatch(event_type, data, event)

    return {"received": True}
