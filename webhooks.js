const express = require('express');
const { EventEmitter } = require('events');
const { Webhook } = require('svix');

const events = new EventEmitter();
const router = express.Router();

router.post(
  '/',
  express.raw({ type: 'application/json' }),
  (req, res) => {
    const secret = process.env.CLERK_WEBHOOK_SECRET;
    if (!secret) {
      return res.status(500).json({ error: 'CLERK_WEBHOOK_SECRET not configured' });
    }

    let event;
    try {
      const wh = new Webhook(secret);
      event = wh.verify(req.body, {
        'svix-id':        req.headers['svix-id'],
        'svix-timestamp': req.headers['svix-timestamp'],
        'svix-signature': req.headers['svix-signature'],
      });
    } catch (err) {
      return res.status(400).json({ error: 'Invalid webhook signature' });
    }

    events.emit(event.type, event.data, event);
    events.emit('*', event);

    res.json({ received: true });
  }
);

router.events = events;

module.exports = router;
