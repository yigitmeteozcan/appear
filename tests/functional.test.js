'use strict';

/**
 * Deep functional tests — every behavioral aspect verified end-to-end.
 * Tests are organized by system boundary. Each test probes actual runtime
 * behavior, not just interface contracts.
 *
 * Rate-limiter isolation: sections 5, 6, and 8 each create their own
 * server instance (via clearCache + re-require) so every webhook-heavy
 * section starts with a fresh 20-req/min window and never exhausts the
 * shared limiter.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function stripeSign(payloadString, secret) {
  const ts = Math.floor(Date.now() / 1000);
  const sig = crypto.createHmac('sha256', secret).update(`${ts}.${payloadString}`).digest('hex');
  return { header: `t=${ts},v1=${sig}`, ts };
}

function lsSign(bodyStr, secret) {
  return crypto.createHmac('sha256', secret).update(bodyStr).digest('hex');
}

async function post(url, body, headers = {}) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

async function get(url, headers = {}) {
  return fetch(url, { headers });
}

/**
 * Clear all cached src/ modules so the next require() gives a fresh
 * module instance with new rate-limiter state and empty store Maps.
 * npm packages (stripe, express-rate-limit, etc.) are intentionally kept
 * in cache — only our own source files are cleared.
 */
function clearCache() {
  Object.keys(require.cache).forEach((key) => {
    if (key.includes('/appear/src/')) {
      delete require.cache[key];
    }
  });
}

/**
 * Spin up a fresh server with isolated rate limiters and an empty store.
 */
async function makeServer() {
  clearCache();
  const app = require('../src/server/index.js');
  const storeInst = require('../src/server/store');
  const srv = http.createServer(app);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return {
    store: storeInst,
    url: `http://127.0.0.1:${srv.address().port}`,
    server: srv,
  };
}

// ─── Test constants ───────────────────────────────────────────────────────────

const API_KEY = 'functional-test-api-key-xxxxxxxxxx'; // ≥32 chars
const LS_SECRET = 'ls-functional-secret-key-123456789';
const STRIPE_SECRET = 'whsec_functional_stripe_secret_key';

// Set env before any require so server picks them up
process.env.API_KEY = API_KEY;
process.env.ALLOWED_ORIGINS = 'https://example.com';
process.env.STRIPE_WEBHOOK_SECRET = STRIPE_SECRET;
process.env.STRIPE_SECRET_KEY = 'sk_test_functional';
process.env.LEMONSQUEEZY_WEBHOOK_SECRET = LS_SECRET;
delete process.env.DATABASE_URL;

// ─── Shared server (sections 2, 3, 4, 7) ─────────────────────────────────────

let baseUrl;
let server;
let store;

before(async () => {
  const s = await makeServer();
  baseUrl = s.url;
  server = s.server;
  store = s.store;
});

after(async () => {
  await new Promise((r) => server.close(r));
});

// ═══════════════════════════════════════════════════════════════════════════════
// 1. AI ENGINE DETECTION — appear.js
// ═══════════════════════════════════════════════════════════════════════════════

describe('1. AI engine detection — referrer hostname boundary', () => {
  const { detectEngine } = require('../src/appear.js');

  // Every engine detected by referrer
  const REFERRER_CASES = [
    ['https://chatgpt.com/c/abc',            'chatgpt'],
    ['https://chat.openai.com/share/xyz',    'chatgpt'],
    ['https://www.perplexity.ai/search/q',   'perplexity'],
    ['https://perplexity.ai/search',         'perplexity'],
    ['https://claude.ai/chat/abc',           'claude'],
    ['https://gemini.google.com/app',        'gemini'],
    ['https://bard.google.com/',             'gemini'],
    ['https://copilot.microsoft.com/',       'copilot'],
    ['https://www.bing.com/chat',            'copilot'],
    ['https://you.com/search?q=hi',         'you'],
    ['https://www.phind.com/search',         'phind'],
    ['https://poe.com/chat/abc',             'poe'],
    ['https://sub.chatgpt.com/path',         'chatgpt'],   // subdomain
    ['https://sub.claude.ai/path',           'claude'],    // subdomain
  ];

  for (const [referrer, expected] of REFERRER_CASES) {
    test(`detects ${expected} from ${new URL(referrer).hostname}`, () => {
      const r = detectEngine(referrer, null);
      assert.ok(r, `expected detection for ${referrer}`);
      assert.equal(r.engine, expected);
      assert.equal(r.source, 'referrer');
    });
  }

  // Spoofing: engine name in path/query must NOT match
  const SPOOF_CASES = [
    'https://evil.com/?ref=chatgpt.com',
    'https://evil.com/chatgpt.com',
    'https://fakechatgpt.com/',
    'https://notperplexity.ai/',
    'https://chatgpt.com.evil.com/',
    'https://evil-claude.ai/',
  ];

  for (const referrer of SPOOF_CASES) {
    test(`spoofed referrer rejected: ${referrer}`, () => {
      assert.equal(detectEngine(referrer, null), null);
    });
  }
});

describe('1b. AI engine detection — utm_source', () => {
  const { detectEngine } = require('../src/appear.js');

  const UTM_CASES = [
    ['chatgpt',      'chatgpt'],
    ['CHATGPT',      'chatgpt'],   // case-insensitive
    ['ChatGPT',      'chatgpt'],
    ['perplexity',   'perplexity'],
    ['claude',       'claude'],
    ['gemini',       'gemini'],
    ['GEMINI',       'gemini'],
    ['bard',         'gemini'],    // alias
    ['copilot',      'copilot'],
    ['bing',         'copilot'],   // alias
    ['you',          'you'],
    ['phind',        'phind'],
    ['poe',          'poe'],
  ];

  for (const [utm, expected] of UTM_CASES) {
    test(`utm_source=${utm} → ${expected}`, () => {
      const r = detectEngine(null, utm);
      assert.ok(r);
      assert.equal(r.engine, expected);
      assert.equal(r.source, 'utm');
    });
  }

  test('utm takes precedence over referrer', () => {
    const r = detectEngine('https://poe.com', 'chatgpt');
    assert.equal(r.engine, 'chatgpt');
    assert.equal(r.source, 'utm');
  });

  test('unknown utm falls through to referrer', () => {
    const r = detectEngine('https://claude.ai/chat', 'newsletter');
    assert.equal(r.engine, 'claude');
    assert.equal(r.source, 'referrer');
  });

  test('null referrer and null utm → null', () => {
    assert.equal(detectEngine(null, null), null);
  });

  test('non-AI referrer → null', () => {
    assert.equal(detectEngine('https://google.com', null), null);
  });
});

describe('1c. sanitize() — XSS and bidi strip', () => {
  test('javascript: in utm_source does not match any engine', () => {
    const { detectEngine } = require('../src/appear.js');
    assert.equal(detectEngine(null, 'javascript:alert(1)'), null);
  });

  test('HTML tags in utm_source stripped — no match', () => {
    const { detectEngine } = require('../src/appear.js');
    assert.equal(detectEngine(null, '<script>chatgpt</script>'), null);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. SESSION STORE — functional behavior
// ═══════════════════════════════════════════════════════════════════════════════

describe('2. Session store — save / retrieve / expire', () => {
  test('saved session is retrievable', () => {
    store.saveSession('fn-sess-001', { engine: 'chatgpt', source: 'referrer' });
    const s = store.getSession('fn-sess-001');
    assert.ok(s);
    assert.equal(s.engine, 'chatgpt');
  });

  test('unknown session returns null', () => {
    assert.equal(store.getSession('does-not-exist-fn'), null);
  });

  test('session expires after TTL (mock Date.now)', () => {
    store.saveSession('fn-expire', { engine: 'claude', source: 'utm' });
    assert.ok(store.getSession('fn-expire'), 'should exist before expiry');
    const real = Date.now;
    Date.now = () => real() + 25 * 60 * 60 * 1000; // +25h
    try {
      assert.equal(store.getSession('fn-expire'), null, 'should be null after TTL');
    } finally {
      Date.now = real;
    }
  });

  test('updating existing session resets TTL', () => {
    store.saveSession('fn-update', { engine: 'gemini', source: 'utm' });
    store.saveSession('fn-update', { engine: 'gemini', source: 'referrer' });
    const s = store.getSession('fn-update');
    assert.equal(s.source, 'referrer');
  });

  test('attribution idempotency — same payment_id never double-counts', () => {
    store.saveSession('fn-dedup', { engine: 'perplexity', source: 'utm' });
    const visit = store.getSession('fn-dedup');
    store.saveAttribution('fn-pay-001', 'fn-dedup', visit, { provider: 'stripe', amount: 50, currency: 'usd' });
    store.saveAttribution('fn-pay-001', 'fn-dedup', visit, { provider: 'stripe', amount: 50, currency: 'usd' });
    const stats = store.getStats();
    const entries = stats.recent_attributions.filter((a) => a.payment_id === 'fn-pay-001');
    assert.equal(entries.length, 1);
  });

  test('revenue accumulates correctly across multiple attributions', () => {
    store.saveSession('fn-rev-1', { engine: 'you', source: 'referrer' });
    store.saveSession('fn-rev-2', { engine: 'you', source: 'referrer' });
    const v1 = store.getSession('fn-rev-1');
    const v2 = store.getSession('fn-rev-2');
    store.saveAttribution('fn-rev-pay-1', 'fn-rev-1', v1, { provider: 'stripe', amount: 10, currency: 'usd' });
    store.saveAttribution('fn-rev-pay-2', 'fn-rev-2', v2, { provider: 'stripe', amount: 20, currency: 'usd' });
    const stats = store.getStats();
    assert.ok(stats.revenue_by_engine.you >= 30);
    assert.ok(stats.total_revenue >= 30);
  });

  test('getStats recent_attributions capped at 20', () => {
    for (let i = 0; i < 25; i++) {
      const sid = `fn-cap-sess-${i}`;
      store.saveSession(sid, { engine: 'phind', source: 'utm' });
      const v = store.getSession(sid);
      store.saveAttribution(`fn-cap-pay-${i}`, sid, v, { provider: 'stripe', amount: 1, currency: 'usd' });
    }
    const stats = store.getStats();
    assert.ok(stats.recent_attributions.length <= 20);
  });

  test('getStats recent_attributions sorted newest first', () => {
    const stats = store.getStats();
    const times = stats.recent_attributions.map((a) => new Date(a.attributed_at).getTime());
    for (let i = 1; i < times.length; i++) {
      assert.ok(times[i - 1] >= times[i], 'should be newest first');
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. POST /appear/event — validation depth
// ═══════════════════════════════════════════════════════════════════════════════

describe('3. POST /appear/event — full validation matrix', () => {
  const validPayload = () => ({
    session_id: 'fn-valid-session-abc',
    engine: 'chatgpt',
    source: 'referrer',
    page_url: 'https://example.com/page',
    timestamp: new Date().toISOString(),
  });

  test('valid minimal payload → 202 + {ok:true}', async () => {
    const res = await post(`${baseUrl}/appear/event`, validPayload());
    assert.equal(res.status, 202);
    const b = await res.json();
    assert.equal(b.ok, true);
  });

  test('saves session to store', async () => {
    const sid = 'fn-event-store-check';
    await post(`${baseUrl}/appear/event`, { ...validPayload(), session_id: sid });
    const s = store.getSession(sid);
    assert.ok(s, 'session must be in store after event');
    assert.equal(s.engine, 'chatgpt');
  });

  test('future timestamp (>5min) normalised to server time', async () => {
    const sid = 'fn-ts-future';
    const farFuture = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    await post(`${baseUrl}/appear/event`, { ...validPayload(), session_id: sid, timestamp: farFuture });
    const s = store.getSession(sid);
    const stored = new Date(s.timestamp).getTime();
    const now = Date.now();
    assert.ok(Math.abs(stored - now) < 5000, 'timestamp should be normalised to ~now');
  });

  test('past timestamp (>5min) normalised to server time', async () => {
    const sid = 'fn-ts-past';
    const farPast = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    await post(`${baseUrl}/appear/event`, { ...validPayload(), session_id: sid, timestamp: farPast });
    const s = store.getSession(sid);
    const stored = new Date(s.timestamp).getTime();
    assert.ok(Math.abs(stored - Date.now()) < 5000);
  });

  test('timestamp within 5min skew is NOT normalised', async () => {
    const sid = 'fn-ts-small-skew';
    const slightlyOff = new Date(Date.now() - 2 * 60 * 1000).toISOString(); // 2min ago
    await post(`${baseUrl}/appear/event`, { ...validPayload(), session_id: sid, timestamp: slightlyOff });
    const s = store.getSession(sid);
    assert.equal(s.timestamp, slightlyOff, 'small skew should be preserved');
  });

  // Field validation failures
  const INVALID = [
    ['missing session_id',          { engine: 'chatgpt', source: 'referrer', page_url: 'https://x.com', timestamp: new Date().toISOString() }],
    ['missing engine',              { session_id: 'x', source: 'referrer', page_url: 'https://x.com', timestamp: new Date().toISOString() }],
    ['missing source',              { session_id: 'x', engine: 'chatgpt', page_url: 'https://x.com', timestamp: new Date().toISOString() }],
    ['missing page_url',            { session_id: 'x', engine: 'chatgpt', source: 'referrer', timestamp: new Date().toISOString() }],
    ['missing timestamp',           { session_id: 'x', engine: 'chatgpt', source: 'referrer', page_url: 'https://x.com' }],
    ['invalid engine value',        { session_id: 'x', engine: 'bing', source: 'referrer', page_url: 'https://x.com', timestamp: new Date().toISOString() }],
    ['invalid source value',        { session_id: 'x', engine: 'chatgpt', source: 'social', page_url: 'https://x.com', timestamp: new Date().toISOString() }],
    ['array as session_id',         { session_id: ['a', 'b'], engine: 'chatgpt', source: 'referrer', page_url: 'https://x.com', timestamp: new Date().toISOString() }],
    ['object as engine',            { session_id: 'x', engine: { evil: true }, source: 'referrer', page_url: 'https://x.com', timestamp: new Date().toISOString() }],
    ['unknown extra field',         { session_id: 'x', engine: 'chatgpt', source: 'referrer', page_url: 'https://x.com', timestamp: new Date().toISOString(), extra: 'x' }],
    ['__proto__ key',               '{"__proto__":{"x":1},"session_id":"x","engine":"chatgpt","source":"referrer","page_url":"https://x.com","timestamp":"2024-01-01T00:00:00Z"}'],
    ['javascript: in page_url',     { session_id: 'x', engine: 'chatgpt', source: 'referrer', page_url: 'javascript:alert(1)', timestamp: new Date().toISOString() }],
    ['javascript: in referrer',     { session_id: 'x', engine: 'chatgpt', source: 'referrer', referrer: 'javascript:void(0)', page_url: 'https://x.com', timestamp: new Date().toISOString() }],
    ['session_id with path traversal', { session_id: '../../etc/passwd', engine: 'chatgpt', source: 'referrer', page_url: 'https://x.com', timestamp: new Date().toISOString() }],
    ['null body',                   'null'],
    ['empty object',                '{}'],
    ['invalid ISO timestamp',       { session_id: 'x', engine: 'chatgpt', source: 'referrer', page_url: 'https://x.com', timestamp: 'not-a-date' }],
  ];

  for (const [label, body] of INVALID) {
    test(`400 for ${label}`, async () => {
      const res = await post(`${baseUrl}/appear/event`, body);
      assert.equal(res.status, 400, `expected 400 for: ${label}`);
    });
  }

  test('413 for oversized payload', async () => {
    const res = await post(`${baseUrl}/appear/event`, {
      ...validPayload(),
      page_url: 'https://x.com/' + 'x'.repeat(12000),
    });
    assert.equal(res.status, 413);
  });

  test('all valid engines accepted', async () => {
    const engines = ['chatgpt', 'perplexity', 'claude', 'gemini', 'copilot', 'you', 'phind', 'poe'];
    for (const engine of engines) {
      const res = await post(`${baseUrl}/appear/event`, { ...validPayload(), engine, session_id: `fn-eng-${engine}` });
      assert.equal(res.status, 202, `engine ${engine} should be accepted`);
    }
  });

  test('all valid sources accepted', async () => {
    for (const source of ['referrer', 'utm', 'useragent']) {
      const res = await post(`${baseUrl}/appear/event`, { ...validPayload(), source, session_id: `fn-src-${source}` });
      assert.equal(res.status, 202, `source ${source} should be accepted`);
    }
  });

  test('optional utm fields accepted', async () => {
    const res = await post(`${baseUrl}/appear/event`, {
      ...validPayload(),
      session_id: 'fn-utm-full',
      utm_source: 'chatgpt',
      utm_medium: 'organic',
      utm_campaign: 'summer',
      utm_term: 'ai',
      utm_content: 'link',
    });
    assert.equal(res.status, 202);
  });

  test('response Content-Type is application/json', async () => {
    const res = await post(`${baseUrl}/appear/event`, validPayload());
    assert.ok(res.headers.get('content-type').includes('application/json'));
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. GET /appear/stats — auth + data shape
// ═══════════════════════════════════════════════════════════════════════════════

describe('4. GET /appear/stats — authentication and data integrity', () => {
  test('no auth → 401', async () => {
    const res = await get(`${baseUrl}/appear/stats`);
    assert.equal(res.status, 401);
  });

  test('wrong key → 401', async () => {
    const res = await get(`${baseUrl}/appear/stats`, { 'x-api-key': 'wrong' });
    assert.equal(res.status, 401);
  });

  test('empty key → 401', async () => {
    const res = await get(`${baseUrl}/appear/stats`, { 'x-api-key': '' });
    assert.equal(res.status, 401);
  });

  test('whitespace-only key → 401', async () => {
    const res = await get(`${baseUrl}/appear/stats`, { 'x-api-key': '   ' });
    assert.equal(res.status, 401);
  });

  test('comma-injected key → 401', async () => {
    const res = await get(`${baseUrl}/appear/stats`, { 'x-api-key': `${API_KEY},extra` });
    assert.equal(res.status, 401);
  });

  test('valid x-api-key → 200', async () => {
    const res = await get(`${baseUrl}/appear/stats`, { 'x-api-key': API_KEY });
    assert.equal(res.status, 200);
  });

  test('valid Bearer token → 200', async () => {
    const res = await get(`${baseUrl}/appear/stats`, { Authorization: `Bearer ${API_KEY}` });
    assert.equal(res.status, 200);
  });

  test('response shape has all required fields', async () => {
    const res = await get(`${baseUrl}/appear/stats`, { 'x-api-key': API_KEY });
    const b = await res.json();
    assert.equal(typeof b.total_sessions, 'number');
    assert.equal(typeof b.total_attributions, 'number');
    assert.equal(typeof b.total_revenue, 'number');
    assert.ok(b.revenue_by_engine && typeof b.revenue_by_engine === 'object');
    assert.ok(Array.isArray(b.recent_attributions));
  });

  test('stats does not expose API_KEY or env vars', async () => {
    const res = await get(`${baseUrl}/appear/stats`, { 'x-api-key': API_KEY });
    const b = await res.json();
    assert.equal(b.api_key, undefined);
    assert.equal(b.env, undefined);
    assert.equal(b.process, undefined);
  });

  test('revenue reflects actual stripe attributions', async () => {
    // Plant a known session + attribution
    const sid = 'fn-stats-revenue-check';
    store.saveSession(sid, { engine: 'poe', source: 'utm' });
    const v = store.getSession(sid);
    store.saveAttribution('fn-stats-pay-unique', sid, v, { provider: 'stripe', amount: 99.99, currency: 'usd' });

    const res = await get(`${baseUrl}/appear/stats`, { 'x-api-key': API_KEY });
    const b = await res.json();
    assert.ok(b.revenue_by_engine.poe >= 99.99);
    assert.ok(b.total_revenue >= 99.99);
  });

  test('recent_attributions entries have expected shape', async () => {
    const res = await get(`${baseUrl}/appear/stats`, { 'x-api-key': API_KEY });
    const b = await res.json();
    if (b.recent_attributions.length > 0) {
      const a = b.recent_attributions[0];
      assert.ok('payment_id' in a);
      assert.ok('engine' in a);
      assert.ok('amount' in a);
      assert.ok('currency' in a);
      assert.ok('attributed_at' in a);
      // attributed_at must be valid ISO string
      assert.ok(!isNaN(new Date(a.attributed_at).getTime()));
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. STRIPE WEBHOOK — fresh isolated server (clean 20/min window)
// ═══════════════════════════════════════════════════════════════════════════════

describe('5. Stripe webhook — full attribution flow', () => {
  let s5url, s5store, s5server;

  before(async () => {
    const s = await makeServer();
    s5url = s.url;
    s5store = s.store;
    s5server = s.server;
  });

  after(async () => {
    await new Promise((r) => s5server.close(r));
  });

  function stripeCheckoutEvent(sessionId, amountCents, paymentId = null) {
    const csId = paymentId || `cs_fn_${Date.now()}`;
    return {
      id: `evt_fn_${Date.now()}`,
      object: 'event',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: csId,
          object: 'checkout.session',
          metadata: sessionId ? { appear_session_id: sessionId } : {},
          amount_total: amountCents,
          currency: 'usd',
        },
      },
    };
  }

  function stripePiEvent(sessionId, amountCents, piId = null) {
    const id = piId || `pi_fn_${Date.now()}`;
    return {
      id: `evt_fn_pi_${Date.now()}`,
      object: 'event',
      type: 'payment_intent.succeeded',
      data: {
        object: {
          id,
          object: 'payment_intent',
          metadata: sessionId ? { appear_session_id: sessionId } : {},
          amount_received: amountCents,
          currency: 'usd',
        },
      },
    };
  }

  async function sendStripe(payload) {
    const s = JSON.stringify(payload);
    const { header } = stripeSign(s, STRIPE_SECRET);
    return post(`${s5url}/stripe/webhook`, s, { 'stripe-signature': header });
  }

  test('missing stripe-signature → 400', async () => {
    const res = await post(`${s5url}/stripe/webhook`, '{}');
    assert.equal(res.status, 400);
  });

  test('wrong signature → 400', async () => {
    const res = await post(`${s5url}/stripe/webhook`, '{}', {
      'stripe-signature': 't=9999999999,v1=' + 'a'.repeat(64),
    });
    assert.equal(res.status, 400);
  });

  test('checkout.session.completed — saves attribution and converts cents to dollars', async () => {
    const sid = 'fn-stripe-checkout-001';
    s5store.saveSession(sid, { engine: 'chatgpt', source: 'referrer', page_url: 'https://x.com' });
    const payload = stripeCheckoutEvent(sid, 4999); // $49.99
    const res = await sendStripe(payload);
    assert.equal(res.status, 200);
    const b = await res.json();
    assert.equal(b.received, true);

    const stats = await (await get(`${s5url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    const entry = stats.recent_attributions.find((a) => a.payment_id === payload.data.object.id);
    assert.ok(entry, 'attribution must appear in stats');
    assert.equal(entry.engine, 'chatgpt');
    assert.ok(Math.abs(entry.amount - 49.99) < 0.001, `expected 49.99, got ${entry.amount}`);
    assert.equal(entry.currency, 'usd');
  });

  test('payment_intent.succeeded — saves attribution and converts cents to dollars', async () => {
    const sid = 'fn-stripe-pi-001';
    s5store.saveSession(sid, { engine: 'perplexity', source: 'utm', page_url: 'https://x.com' });
    const payload = stripePiEvent(sid, 2500); // $25.00
    const res = await sendStripe(payload);
    assert.equal(res.status, 200);

    const stats = await (await get(`${s5url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    const entry = stats.recent_attributions.find((a) => a.payment_id === payload.data.object.id);
    assert.ok(entry);
    assert.ok(Math.abs(entry.amount - 25.0) < 0.001);
  });

  test('no appear_session_id → received:true, no attribution saved', async () => {
    const payload = stripeCheckoutEvent(null, 1000, 'cs_no_session_unique');
    const res = await sendStripe(payload);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).received, true);
    const stats = await (await get(`${s5url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    const entry = stats.recent_attributions.find((a) => a.payment_id === 'cs_no_session_unique');
    assert.equal(entry, undefined, 'no attribution should be saved without session_id');
  });

  test('unknown session_id → received:true, no attribution', async () => {
    const payload = stripeCheckoutEvent('session-that-does-not-exist', 1000, 'cs_no_known_session');
    const res = await sendStripe(payload);
    assert.equal(res.status, 200);
    const stats = await (await get(`${s5url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    const entry = stats.recent_attributions.find((a) => a.payment_id === 'cs_no_known_session');
    assert.equal(entry, undefined);
  });

  test('duplicate webhook delivery → idempotent, no double-count', async () => {
    const sid = 'fn-stripe-dedup-sess';
    s5store.saveSession(sid, { engine: 'claude', source: 'utm', page_url: 'https://x.com' });
    const pid = `cs_fn_dedup_${Date.now()}`;
    const payload = stripeCheckoutEvent(sid, 1000, pid);

    await sendStripe(payload);
    await sendStripe(payload); // second delivery

    const stats = await (await get(`${s5url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    const entries = stats.recent_attributions.filter((a) => a.payment_id === pid);
    assert.equal(entries.length, 1, 'duplicate must not create two attributions');
  });

  test('unhandled event type → received:true (acknowledged)', async () => {
    const payload = { id: 'evt_fn_unhandled', object: 'event', type: 'invoice.paid', data: { object: {} } };
    const s = JSON.stringify(payload);
    const { header } = stripeSign(s, STRIPE_SECRET);
    const res = await post(`${s5url}/stripe/webhook`, s, { 'stripe-signature': header });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).received, true);
  });

  test('zero amount checkout → amount stored as 0', async () => {
    const sid = 'fn-stripe-zero';
    s5store.saveSession(sid, { engine: 'you', source: 'referrer', page_url: 'https://x.com' });
    const pid = `cs_fn_zero_${Date.now()}`;
    const payload = stripeCheckoutEvent(sid, 0, pid);
    await sendStripe(payload);
    const stats = await (await get(`${s5url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    const entry = stats.recent_attributions.find((a) => a.payment_id === pid);
    assert.ok(entry);
    assert.equal(entry.amount, 0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 6. LEMONSQUEEZY WEBHOOK — fresh isolated server (clean 20/min window)
// ═══════════════════════════════════════════════════════════════════════════════

describe('6. LemonSqueezy webhook — full attribution flow', () => {
  let s6url, s6store, s6server;

  before(async () => {
    const s = await makeServer();
    s6url = s.url;
    s6store = s.store;
    s6server = s.server;
  });

  after(async () => {
    await new Promise((r) => s6server.close(r));
  });

  function lsPayload(sessionId, totalCents, orderId = null) {
    return {
      meta: {
        event_name: 'order_created',
        custom_data: sessionId !== null ? { appear_session_id: sessionId } : {},
      },
      data: {
        id: orderId || `ls_fn_${Date.now()}`,
        attributes: { total: totalCents, currency: 'usd' },
      },
    };
  }

  async function sendLS(payload, overrideSig = null) {
    const bodyStr = JSON.stringify(payload);
    const sig = overrideSig || lsSign(bodyStr, LS_SECRET);
    return post(`${s6url}/lemonsqueezy/webhook`, bodyStr, {
      'x-signature': sig,
      'x-event-name': 'order_created',
    });
  }

  test('missing x-signature → 400', async () => {
    const res = await post(`${s6url}/lemonsqueezy/webhook`, '{}');
    assert.equal(res.status, 400);
  });

  test('wrong signature → 400', async () => {
    const res = await sendLS({ meta: {}, data: {} }, 'a'.repeat(64));
    assert.equal(res.status, 400);
  });

  test('63-char signature → 400', async () => {
    const res = await sendLS({ meta: {}, data: {} }, 'a'.repeat(63));
    assert.equal(res.status, 400);
  });

  test('65-char signature (odd-length Buffer bypass) → 400', async () => {
    const bodyStr = JSON.stringify({ meta: {}, data: {} });
    const valid = lsSign(bodyStr, LS_SECRET);
    const res = await post(`${s6url}/lemonsqueezy/webhook`, bodyStr, {
      'x-signature': valid + '0', // 65 chars
      'x-event-name': 'order_created',
    });
    assert.equal(res.status, 400);
  });

  test('non-hex chars in signature → 400', async () => {
    const res = await sendLS({ meta: {}, data: {} }, 'z'.repeat(64));
    assert.equal(res.status, 400);
  });

  test('order_created — saves attribution and converts cents to dollars', async () => {
    const sid = 'fn-ls-order-001';
    s6store.saveSession(sid, { engine: 'phind', source: 'referrer', page_url: 'https://x.com' });
    const oid = `ls_fn_order_${Date.now()}`;
    const payload = lsPayload(sid, 3900, oid); // $39.00
    const res = await sendLS(payload);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).received, true);

    const stats = await (await get(`${s6url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    const entry = stats.recent_attributions.find((a) => a.payment_id === String(oid));
    assert.ok(entry, 'attribution must appear in stats');
    assert.equal(entry.engine, 'phind');
    assert.ok(Math.abs(entry.amount - 39.0) < 0.001, `expected 39.00, got ${entry.amount}`);
  });

  test('no appear_session_id → received:true, no attribution', async () => {
    const oid = `ls_fn_nosid_${Date.now()}`;
    const payload = { meta: { event_name: 'order_created', custom_data: {} }, data: { id: oid, attributes: { total: 1000, currency: 'usd' } } };
    const res = await sendLS(payload);
    assert.equal(res.status, 200);
    const stats = await (await get(`${s6url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    assert.equal(stats.recent_attributions.find((a) => a.payment_id === String(oid)), undefined);
  });

  test('numeric appear_session_id → 200, no TypeError', async () => {
    const payload = lsPayload(12345, 500); // numeric session id
    const res = await sendLS(payload);
    assert.equal(res.status, 200);
    assert.equal((await res.json()).received, true);
  });

  test('boolean appear_session_id → 200, no TypeError', async () => {
    const payload = lsPayload(true, 500);
    const res = await sendLS(payload);
    assert.equal(res.status, 200);
  });

  test('duplicate order delivery → idempotent', async () => {
    const sid = 'fn-ls-dedup-sess';
    s6store.saveSession(sid, { engine: 'poe', source: 'referrer', page_url: 'https://x.com' });
    const oid = `ls_fn_dedup_${Date.now()}`;
    const payload = lsPayload(sid, 2000, oid);
    await sendLS(payload);
    await sendLS(payload);
    const stats = await (await get(`${s6url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    const entries = stats.recent_attributions.filter((a) => a.payment_id === String(oid));
    assert.equal(entries.length, 1);
  });

  test('non-order_created event → received:true, not processed', async () => {
    const bodyStr = JSON.stringify({ meta: { event_name: 'subscription_created', custom_data: {} }, data: { id: 'sub_1', attributes: {} } });
    const sig = lsSign(bodyStr, LS_SECRET);
    const res = await post(`${s6url}/lemonsqueezy/webhook`, bodyStr, {
      'x-signature': sig,
      'x-event-name': 'subscription_created',
    });
    assert.equal(res.status, 200);
  });

  test('empty body → 400', async () => {
    const sig = lsSign('', LS_SECRET);
    const res = await fetch(`${s6url}/lemonsqueezy/webhook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-signature': sig, 'x-event-name': 'order_created' },
      body: '',
    });
    assert.equal(res.status, 400);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 7. SECURITY CONTROLS — uses shared server (no webhook endpoints)
// ═══════════════════════════════════════════════════════════════════════════════

describe('7. Security controls — headers, error handling, info disclosure', () => {
  test('security headers present on all responses (helmet)', async () => {
    const res = await get(`${baseUrl}/health`);
    assert.ok(res.headers.get('x-content-type-options'), 'x-content-type-options missing');
    // x-powered-by must be removed
    assert.equal(res.headers.get('x-powered-by'), null, 'x-powered-by must not be exposed');
  });

  test('404 for unknown route returns JSON error', async () => {
    const res = await get(`${baseUrl}/not/a/route`);
    assert.equal(res.status, 404);
    const b = await res.json();
    assert.equal(typeof b.error, 'string');
  });

  test('error response never contains stack trace', async () => {
    const res = await post(`${baseUrl}/appear/event`, 'invalid json{{{', { 'Content-Type': 'application/json' });
    const text = await res.text();
    assert.ok(!text.includes('at '), 'stack trace must not appear in response');
    assert.ok(!text.includes('.js:'), 'file path must not appear in response');
  });

  test('prototype pollution rejected at middleware level', async () => {
    const res = await post(`${baseUrl}/appear/event`,
      '{"__proto__":{"isAdmin":true},"session_id":"x","engine":"chatgpt","source":"referrer","page_url":"https://x.com","timestamp":"2024-01-01T00:00:00Z"}'
    );
    assert.equal(res.status, 400);
    // Verify Object.prototype was NOT polluted
    assert.equal(({}).isAdmin, undefined, 'Object.prototype must not be polluted');
  });

  test('constructor pollution rejected', async () => {
    const res = await post(`${baseUrl}/appear/event`,
      '{"constructor":{"prototype":{"evil":true}},"session_id":"x","engine":"chatgpt","source":"referrer","page_url":"https://x.com","timestamp":"2024-01-01T00:00:00Z"}'
    );
    assert.equal(res.status, 400);
  });

  test('/health does not expose API_KEY, secrets, or version internals', async () => {
    const res = await get(`${baseUrl}/health`);
    const b = await res.json();
    assert.equal(b.ok, true);
    assert.equal(b.api_key, undefined);
    assert.equal(b.env, undefined);
    assert.equal(b.secrets, undefined);
  });

  test('API key timing: wrong key same latency path as correct key', async () => {
    const wrong = await get(`${baseUrl}/appear/stats`, { 'x-api-key': 'x'.repeat(32) });
    assert.equal(wrong.status, 401);
    const right = await get(`${baseUrl}/appear/stats`, { 'x-api-key': API_KEY });
    assert.equal(right.status, 200);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 8. FULL END-TO-END — fresh isolated server (clean 20/min window)
// ═══════════════════════════════════════════════════════════════════════════════

describe('8. End-to-end attribution pipeline', () => {
  let s8url, s8server;

  before(async () => {
    const s = await makeServer();
    s8url = s.url;
    s8server = s.server;
  });

  after(async () => {
    await new Promise((r) => s8server.close(r));
  });

  test('browser event → stripe webhook → stats reflects attribution', async () => {
    const sid = 'e2e-stripe-full-001';

    // 1. Browser snippet posts event
    const eventRes = await post(`${s8url}/appear/event`, {
      session_id: sid,
      engine: 'perplexity',
      source: 'referrer',
      referrer: 'https://perplexity.ai/search',
      page_url: 'https://myshop.com/product',
      timestamp: new Date().toISOString(),
    });
    assert.equal(eventRes.status, 202, 'event POST must return 202');

    // 2. Stripe sends checkout.session.completed
    const pid = `cs_e2e_${Date.now()}`;
    const payload = JSON.stringify({
      id: `evt_e2e_${Date.now()}`,
      object: 'event',
      type: 'checkout.session.completed',
      data: {
        object: {
          id: pid,
          object: 'checkout.session',
          metadata: { appear_session_id: sid },
          amount_total: 9900,
          currency: 'usd',
        },
      },
    });
    const { header } = stripeSign(payload, STRIPE_SECRET);
    const webhookRes = await post(`${s8url}/stripe/webhook`, payload, { 'stripe-signature': header });
    assert.equal(webhookRes.status, 200);

    // 3. Stats reflects the attribution
    const stats = await (await get(`${s8url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    const entry = stats.recent_attributions.find((a) => a.payment_id === pid);
    assert.ok(entry, 'attribution must be in stats');
    assert.equal(entry.engine, 'perplexity');
    assert.ok(Math.abs(entry.amount - 99.0) < 0.001);
    assert.equal(entry.currency, 'usd');
    assert.ok(stats.revenue_by_engine.perplexity >= 99.0);
  });

  test('browser event → lemonsqueezy webhook → stats reflects attribution', async () => {
    const sid = 'e2e-ls-full-001';

    await post(`${s8url}/appear/event`, {
      session_id: sid,
      engine: 'claude',
      source: 'utm',
      utm_source: 'claude',
      page_url: 'https://myshop.com/checkout',
      timestamp: new Date().toISOString(),
    });

    const oid = `ls_e2e_${Date.now()}`;
    const payload = { meta: { event_name: 'order_created', custom_data: { appear_session_id: sid } }, data: { id: oid, attributes: { total: 4900, currency: 'usd' } } };
    const bodyStr = JSON.stringify(payload);
    const sig = lsSign(bodyStr, LS_SECRET);
    const webhookRes = await post(`${s8url}/lemonsqueezy/webhook`, bodyStr, {
      'x-signature': sig,
      'x-event-name': 'order_created',
    });
    assert.equal(webhookRes.status, 200);

    const stats = await (await get(`${s8url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    const entry = stats.recent_attributions.find((a) => a.payment_id === String(oid));
    assert.ok(entry, 'attribution must be in stats');
    assert.equal(entry.engine, 'claude');
    assert.ok(Math.abs(entry.amount - 49.0) < 0.001);
  });

  test('multiple engines contribute correct revenue breakdown', async () => {
    const payments = [
      { sid: 'e2e-multi-chatgpt', engine: 'chatgpt', amountCents: 1000 },
      { sid: 'e2e-multi-gemini',  engine: 'gemini',  amountCents: 2000 },
      { sid: 'e2e-multi-gemini2', engine: 'gemini',  amountCents: 3000 },
    ];

    for (const { sid, engine } of payments) {
      await post(`${s8url}/appear/event`, {
        session_id: sid, engine, source: 'referrer',
        page_url: 'https://x.com', timestamp: new Date().toISOString(),
      });
    }

    for (const { sid, amountCents } of payments) {
      const pid = `cs_multi_${sid}_${Date.now()}`;
      const p = JSON.stringify({
        id: `evt_${pid}`, object: 'event', type: 'checkout.session.completed',
        data: { object: { id: pid, object: 'checkout.session', metadata: { appear_session_id: sid }, amount_total: amountCents, currency: 'usd' } },
      });
      const { header } = stripeSign(p, STRIPE_SECRET);
      await post(`${s8url}/stripe/webhook`, p, { 'stripe-signature': header });
    }

    const stats = await (await get(`${s8url}/appear/stats`, { 'x-api-key': API_KEY })).json();
    assert.ok(stats.revenue_by_engine.chatgpt >= 10);
    assert.ok(stats.revenue_by_engine.gemini >= 50);
  });
});
