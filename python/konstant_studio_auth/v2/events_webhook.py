"""Optional: receive the platform's signed change-event webhooks instead of (or
as well as) polling. A webhook is only a HINT to refresh the snapshot; the
refresh itself goes through the normal ETag path, so a forged or replayed
delivery can at worst cause one extra conditional GET. Signature scheme
(docs/control-plane.md "Change events"):
  X-Platform-Timestamp: <unix seconds>
  X-Platform-Signature: v1=<hex hmac-sha256 over "<timestamp>.<raw body>">
"""

import hashlib
import hmac
import math
import time

TOLERANCE_SECONDS = 300


def verify_signature(secret, timestamp, signature, raw_body, now_ms=None):
    if not secret or not timestamp or not signature:
        return False
    now_ms = time.time() * 1000 if now_ms is None else now_ms
    try:
        ts = float(timestamp)
    except (TypeError, ValueError):
        return False
    if not math.isfinite(ts) or abs(now_ms / 1000 - ts) > TOLERANCE_SECONDS:
        return False
    if isinstance(raw_body, str):
        raw_body = raw_body.encode()
    if isinstance(secret, str):
        secret = secret.encode()
    mac = hmac.new(secret, f"{timestamp}.".encode() + raw_body, hashlib.sha256).hexdigest()
    given = str(signature)
    if given.startswith("v1="):
        given = given[3:]
    return hmac.compare_digest(mac, given.lower())
