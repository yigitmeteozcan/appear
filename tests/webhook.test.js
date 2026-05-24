'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');

// ─── LemonSqueezy signature tests (pure crypto, no server needed) ─────────────

describe('LemonSqueezy HMAC-SHA256 signature verification', () => {
  const SECRET = 'test-webhook-secret-1234';

  function signPayload(payload, secret) {
    const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return crypto.createHmac('sha256', secret).update(body).digest('hex');
  }

  test('valid signature passes', () => {
    const payload = { meta: { event_name: 'order_created' }, data: { id: '42' } };
    const body = JSON.stringify(payload);
    const sig = signPayload(body, SECRET);

    const expected = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
    const sigBuf = Buffer.from(sig, 'hex');
    const expectedBuf = Buffer.from(expected, 'hex');

    assert.equal(sigBuf.length, expectedBuf.length);
    assert.ok(crypto.timingSafeEqual(sigBuf, expectedBuf));
  });

  test('invalid signature fails', () => {
    const payload = { meta: {}, data: {} };
    const body = JSON.stringify(payload);
    const badSig = 'a'.repeat(64); // wrong signature

    const expected = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
    const sigBuf = Buffer.from(badSig, 'hex');
    const expectedBuf = Buffer.from(expected, 'hex');

    assert.equal(sigBuf.length, expectedBuf.length);
    assert.ok(!crypto.timingSafeEqual(sigBuf, expectedBuf));
  });

  test('tampered payload fails verification', () => {
    const payload = { meta: {}, data: { id: '1', amount: 100 } };
    const originalBody = JSON.stringify(payload);
    const sig = signPayload(originalBody, SECRET);

    // Tamper with the payload
    const tamperedPayload = { meta: {}, data: { id: '1', amount: 999 } };
    const tamperedBody = JSON.stringify(tamperedPayload);

    const expected = crypto.createHmac('sha256', SECRET).update(tamperedBody).digest('hex');
    const sigBuf = Buffer.from(sig, 'hex');
    const expectedBuf = Buffer.from(expected, 'hex');

    assert.ok(!crypto.timingSafeEqual(sigBuf, expectedBuf));
  });

  test('wrong secret fails verification', () => {
    const payload = { meta: {}, data: {} };
    const body = JSON.stringify(payload);
    const sigWithWrongSecret = signPayload(body, 'wrong-secret');
    const expectedWithCorrectSecret = crypto.createHmac('sha256', SECRET).update(body).digest('hex');

    const sigBuf = Buffer.from(sigWithWrongSecret, 'hex');
    const expectedBuf = Buffer.from(expectedWithCorrectSecret, 'hex');

    assert.ok(!crypto.timingSafeEqual(sigBuf, expectedBuf));
  });
});

// ─── Timing-safe comparison tests ────────────────────────────────────────────

describe('Constant-time API key comparison', () => {
  test('identical keys return true', () => {
    const key = 'my-secret-api-key-abc123';
    const a = Buffer.from(key);
    const b = Buffer.from(key);
    assert.ok(crypto.timingSafeEqual(a, b));
  });

  test('different keys of same length return false', () => {
    const key1 = 'aaaaaaaaaaaaaaaaaaaaaaaa';
    const key2 = 'bbbbbbbbbbbbbbbbbbbbbbbb';
    const a = Buffer.from(key1);
    const b = Buffer.from(key2);
    assert.ok(!crypto.timingSafeEqual(a, b));
  });
});

// ─── In-memory store tests ─────────────────────────────────────────────────────

describe('In-memory store', () => {
  let store;

  before(() => {
    // Ensure no DATABASE_URL set
    delete process.env.DATABASE_URL;
    delete process.env.API_KEY; // will be set per test
    store = require('../src/server/store');
    store.initStore();
  });

  test('saves and retrieves a session', () => {
    const visitData = {
      session_id: 'test-session-001',
      engine: 'chatgpt',
      source: 'referrer',
      referrer: 'https://chatgpt.com',
      page_url: 'https://example.com',
      timestamp: new Date().toISOString(),
    };

    store.saveSession('test-session-001', visitData);
    const retrieved = store.getSession('test-session-001');

    assert.ok(retrieved);
    assert.equal(retrieved.engine, 'chatgpt');
    assert.equal(retrieved.session_id, 'test-session-001');
  });

  test('returns null for unknown session', () => {
    const result = store.getSession('does-not-exist-xyz');
    assert.equal(result, null);
  });

  test('saves and reflects attribution in stats', () => {
    const visitData = {
      session_id: 'test-session-002',
      engine: 'perplexity',
      source: 'referrer',
    };

    store.saveSession('test-session-002', visitData);
    store.saveAttribution('payment-001', 'test-session-002', visitData, {
      provider: 'stripe',
      payment_id: 'payment-001',
      amount: 29,
      currency: 'usd',
    });

    const stats = store.getStats();
    assert.ok(stats.total_attributions >= 1);
    assert.ok(stats.total_revenue >= 29);
    assert.ok(stats.revenue_by_engine.perplexity >= 29);
  });

  test('stats includes recent_attributions array', () => {
    const stats = store.getStats();
    assert.ok(Array.isArray(stats.recent_attributions));
  });
});

// ─── HTTP integration tests ───────────────────────────────────────────────────

describe('HTTP endpoints', () => {
  let server;
  let baseUrl;

  before(async () => {
    process.env.API_KEY = 'test-api-key-integration';
    process.env.ALLOWED_ORIGINS = 'https://example.com';

    // Import fresh app
    const app = require('../src/server/index.js');
    server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();
    baseUrl = `http://127.0.0.1:${port}`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  test('GET /health returns 200', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.ok, true);
  });

  test('GET /appear/stats without auth returns 401', async () => {
    const res = await fetch(`${baseUrl}/appear/stats`);
    assert.equal(res.status, 401);
  });

  test('GET /appear/stats with valid API key returns 200', async () => {
    const res = await fetch(`${baseUrl}/appear/stats`, {
      headers: { 'x-api-key': 'test-api-key-integration' },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(typeof body.total_sessions === 'number');
    assert.ok(typeof body.total_attributions === 'number');
  });

  test('POST /appear/event with valid payload returns 202', async () => {
    const payload = {
      session_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      engine: 'chatgpt',
      source: 'referrer',
      referrer: 'https://chatgpt.com',
      page_url: 'https://example.com/page',
      timestamp: new Date().toISOString(),
    };

    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 202);
    const body = await res.json();
    assert.equal(body.ok, true);
  });

  test('POST /appear/event with invalid engine returns 400', async () => {
    const payload = {
      session_id: 'valid-session-id',
      engine: 'evil-engine',
      source: 'referrer',
      page_url: 'https://example.com',
      timestamp: new Date().toISOString(),
    };

    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 400);
  });

  test('POST /appear/event with unknown fields returns 400', async () => {
    const payload = {
      session_id: 'valid-session-id',
      engine: 'chatgpt',
      source: 'referrer',
      page_url: 'https://example.com',
      timestamp: new Date().toISOString(),
      injected_field: '<script>alert(1)</script>',
    };

    const res = await fetch(`${baseUrl}/appear/event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.equal(res.status, 400);
  });

  test('POST /stripe/webhook without signature returns 400', async () => {
    // Set required env var
    process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test';
    process.env.STRIPE_SECRET_KEY = 'sk_test_fake';

    const res = await fetch(`${baseUrl}/stripe/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'checkout.session.completed' }),
    });

    assert.equal(res.status, 400);
  });

  test('POST /lemonsqueezy/webhook without signature returns 400', async () => {
    process.env.LEMONSQUEEZY_WEBHOOK_SECRET = 'test-ls-secret';

    const res = await fetch(`${baseUrl}/lemonsqueezy/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ meta: {}, data: {} }),
    });

    assert.equal(res.status, 400);
  });

  test('unknown route returns 404', async () => {
    const res = await fetch(`${baseUrl}/not-a-real-route`);
    assert.equal(res.status, 404);
  });
});
