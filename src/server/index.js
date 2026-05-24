'use strict';

// Validate required environment variables before anything else
const REQUIRED_VARS = ['API_KEY'];
const missing = REQUIRED_VARS.filter((v) => !process.env[v]);
if (missing.length > 0) {
  console.error(`[appear] Missing required environment variables: ${missing.join(', ')}`);
  console.error('[appear] Copy .env.example to .env and fill in the values');
  process.exit(1);
}

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { initStore } = require('./store');
const eventsRouter = require('./routes/events');
const webhookRouter = require('./routes/webhook');
const statsRouter = require('./routes/stats');

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);

// ─── CORS ─────────────────────────────────────────────────────────────────────

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean)
  : [];

app.use(
  cors({
    origin: (origin, cb) => {
      // Allow server-to-server (no origin header) only for webhook routes
      // handled separately; for browser routes, enforce allowlist
      if (!origin) return cb(null, false);
      if (allowedOrigins.length === 0) return cb(null, false);
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(null, false);
    },
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
    maxAge: 86400,
  })
);

// ─── Security headers ─────────────────────────────────────────────────────────

app.use(helmet());

// ─── Body parsing ─────────────────────────────────────────────────────────────

// Stripe and LemonSqueezy both require the raw body for signature verification — mount BEFORE json()
app.use(
  '/stripe/webhook',
  express.raw({ type: 'application/json', limit: '1mb' })
);
app.use(
  '/lemonsqueezy/webhook',
  express.raw({ type: 'application/json', limit: '10kb' })
);

// All other routes get JSON parsing with a tight limit
app.use(express.json({ limit: '10kb' }));

// ─── Prototype pollution guard ─────────────────────────────────────────────────
// If a client sends {"__proto__": ...} or {"constructor": ...}, express's JSON
// parser can pollute Object.prototype.  Reject such requests immediately after
// body parsing so the risk never reaches route handlers.
app.use((req, res, next) => {
  if (req.body && typeof req.body === 'object') {
    const dangerous = ['__proto__', 'constructor', 'prototype'];
    const keys = Object.keys(req.body);
    if (keys.some((k) => dangerous.includes(k))) {
      return res.status(400).json({ error: 'Invalid request body' });
    }
  }
  next();
});

// ─── Trust proxy (for rate limiting behind Railway/Render) ────────────────────
app.set('trust proxy', 1);

// ─── Routes ───────────────────────────────────────────────────────────────────

app.use('/appear', eventsRouter);
app.use('/appear', statsRouter);
app.use('/', webhookRouter);

// Health check (unauthenticated, no sensitive data)
app.get('/health', (req, res) => {
  res.json({ ok: true, version: '0.1.0' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Generic error handler — never expose stack traces
app.use((err, req, res, _next) => {
  console.error('[appear] Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Start (only when run directly, not when require()d by tests) ────────────

initStore();

if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`[appear] Server listening on port ${PORT}`);
  });

  function shutdown(signal) {
    console.log(`[appear] ${signal} received, shutting down gracefully`);
    server.close(() => {
      console.log('[appear] HTTP server closed');
      process.exit(0);
    });

    setTimeout(() => {
      console.error('[appear] Forced shutdown after timeout');
      process.exit(1);
    }, 10_000).unref();
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

module.exports = app; // for testing
