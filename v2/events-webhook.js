// Optional: receive the platform's signed change-event webhooks instead of (or
// as well as) polling. A webhook is only a HINT to refresh the snapshot; the
// refresh itself goes through the normal ETag path, so a forged or replayed
// delivery can at worst cause one extra conditional GET. Signature scheme
// (docs/control-plane.md "Change events"):
//   X-Platform-Timestamp: <unix seconds>
//   X-Platform-Signature: v1=<hex hmac-sha256 over "<timestamp>.<raw body>">

const crypto = require('crypto');

const TOLERANCE_SECONDS = 300;

function verifySignature({ secret, timestamp, signature, rawBody, nowMs = Date.now() }) {
  if (!secret || !timestamp || !signature) return false;
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(nowMs / 1000 - ts) > TOLERANCE_SECONDS) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${timestamp}.`).update(rawBody).digest('hex');
  const given = String(signature).replace(/^v1=/, '');
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(given, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Express handler; mount with express.raw({ type: 'application/json' }) in front.
function eventsWebhookHandler(core, { secret }) {
  return (req, res) => {
    const ok = verifySignature({
      secret,
      timestamp: req.headers['x-platform-timestamp'],
      signature: req.headers['x-platform-signature'],
      rawBody: req.body,
    });
    if (!ok) return res.status(401).json({ error: 'Invalid signature' });
    core.cache?.invalidate();
    core.cache?.refresh().catch(() => {}); // best effort: the next check revalidates anyway
    return res.json({ received: true });
  };
}

module.exports = { verifySignature, eventsWebhookHandler };
