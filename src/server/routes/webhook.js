'use strict';

const crypto = require('crypto');
const express = require('express');
const { webhookLimiter } = require('../middleware/rateLimit');
const { getSession, saveAttribution } = require('../store');

const router = express.Router();

// ─── Stripe ───────────────────────────────────────────────────────────────────

/**
 * POST /stripe/webhook
 * Verifies Stripe signature and processes checkout/payment events.
 * Uses raw body (set by express.raw in server/index.js).
 */
router.post('/stripe/webhook', webhookLimiter, async (req, res) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) {
    console.error('[appear] STRIPE_WEBHOOK_SECRET not set');
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  const sig = req.headers['stripe-signature'];
  if (!sig) {
    return res.status(400).json({ error: 'Missing stripe-signature header' });
  }

  let event;
  try {
    // Lazy-load stripe to allow server to start without STRIPE_SECRET_KEY if not using Stripe
    const Stripe = require('stripe');
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2023-10-16' });
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
  } catch (err) {
    console.warn('[appear] Stripe signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }

  try {
    if (
      event.type === 'checkout.session.completed' ||
      event.type === 'payment_intent.succeeded'
    ) {
      await handleStripePayment(event);
    }
    // Acknowledge all events Stripe sends, even unhandled ones
    return res.json({ received: true });
  } catch (err) {
    console.error('[appear] Stripe webhook processing error:', err.message);
    return res.status(500).json({ error: 'Processing error' });
  }
});

async function handleStripePayment(event) {
  let sessionId, amount, currency, paymentId;

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    sessionId = session.metadata && session.metadata.appear_session_id;
    amount = session.amount_total;      // in cents
    currency = session.currency;
    paymentId = session.id;
  } else if (event.type === 'payment_intent.succeeded') {
    const pi = event.data.object;
    sessionId = pi.metadata && pi.metadata.appear_session_id;
    amount = pi.amount_received;
    currency = pi.currency;
    paymentId = pi.id;
  }

  if (!sessionId) {
    // No appear session attached — not attributable, not an error
    return;
  }

  const visit = getSession(sessionId);
  if (!visit) {
    console.log(`[appear] Stripe: no session found for ${sessionId}`);
    return;
  }

  const attribution = saveAttribution(paymentId, sessionId, visit, {
    provider: 'stripe',
    payment_id: paymentId,
    amount: amount ? amount / 100 : 0,  // convert cents to dollars
    currency: currency || 'usd',
    event_type: event.type,
  });

  console.log(`[appear] Attributed Stripe payment ${paymentId} to ${visit.engine} (${sessionId})`);
  return attribution;
}

// ─── LemonSqueezy ─────────────────────────────────────────────────────────────

/**
 * POST /lemonsqueezy/webhook
 * Verifies LemonSqueezy HMAC-SHA256 signature and processes order events.
 */
router.post('/lemonsqueezy/webhook', webhookLimiter, express.json({ limit: '10kb' }), (req, res) => {
  const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
  if (!secret) {
    console.error('[appear] LEMONSQUEEZY_WEBHOOK_SECRET not set');
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  const sig = req.headers['x-signature'];
  if (!sig) {
    return res.status(400).json({ error: 'Missing x-signature header' });
  }

  // Verify HMAC-SHA256 signature
  let rawBody;
  try {
    rawBody = JSON.stringify(req.body);
  } catch (_) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  const sigBuf = Buffer.from(sig, 'hex');
  const expectedBuf = Buffer.from(expected, 'hex');

  if (sigBuf.length !== expectedBuf.length) {
    return res.status(400).json({ error: 'Invalid signature' });
  }

  let valid;
  try {
    valid = crypto.timingSafeEqual(sigBuf, expectedBuf);
  } catch (_) {
    valid = false;
  }

  if (!valid) {
    console.warn('[appear] LemonSqueezy signature verification failed');
    return res.status(400).json({ error: 'Invalid signature' });
  }

  try {
    const eventName = req.headers['x-event-name'];

    if (eventName === 'order_created') {
      handleLemonSqueezyOrder(req.body);
    }

    return res.json({ received: true });
  } catch (err) {
    console.error('[appear] LemonSqueezy webhook processing error:', err.message);
    return res.status(500).json({ error: 'Processing error' });
  }
});

function handleLemonSqueezyOrder(payload) {
  const meta = payload.meta || {};
  const data = payload.data || {};
  const attributes = data.attributes || {};

  const sessionId = meta.custom_data && meta.custom_data.appear_session_id;
  if (!sessionId) return;

  const visit = getSession(sessionId);
  if (!visit) {
    console.log(`[appear] LemonSqueezy: no session found for ${sessionId}`);
    return;
  }

  const paymentId = String(data.id || '');
  const amount = attributes.total ? attributes.total / 100 : 0;
  const currency = attributes.currency || 'usd';

  const attribution = saveAttribution(paymentId, sessionId, visit, {
    provider: 'lemonsqueezy',
    payment_id: paymentId,
    amount,
    currency,
    event_type: 'order_created',
  });

  console.log(`[appear] Attributed LemonSqueezy order ${paymentId} to ${visit.engine} (${sessionId})`);
  return attribution;
}

module.exports = router;
