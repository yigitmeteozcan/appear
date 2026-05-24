'use strict';

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * In-memory store with optional SQLite persistence.
 * If DATABASE_URL env var is set, uses better-sqlite3.
 */

let db = null; // SQLite db handle, if enabled

// In-memory maps (always populated, even when SQLite is enabled — SQLite is the durable layer)
const sessions = new Map();       // session_id -> visit event
const attributions = new Map();   // payment_id -> { visit, payment, attributed_at }

function initStore() {
  const dbPath = process.env.DATABASE_URL;
  if (dbPath) {
    try {
      const Database = require('better-sqlite3');
      db = new Database(dbPath);
      db.pragma('journal_mode = WAL');
      db.pragma('foreign_keys = ON');

      db.exec(`
        CREATE TABLE IF NOT EXISTS sessions (
          session_id TEXT PRIMARY KEY,
          data TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attributions (
          payment_id TEXT PRIMARY KEY,
          session_id TEXT NOT NULL,
          visit_data TEXT NOT NULL,
          payment_data TEXT NOT NULL,
          attributed_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_attributions_session ON attributions(session_id);
      `);

      // Load active sessions into memory
      const now = Date.now();
      const rows = db.prepare('SELECT session_id, data FROM sessions WHERE expires_at > ?').all(now);
      for (const row of rows) {
        try {
          sessions.set(row.session_id, JSON.parse(row.data));
        } catch (_) {}
      }

      console.log(`[appear] SQLite store initialized: ${dbPath} (${rows.length} sessions loaded)`);
    } catch (err) {
      console.error('[appear] Failed to initialize SQLite, falling back to in-memory:', err.message);
      db = null;
    }
  } else {
    console.log('[appear] Using in-memory store (set DATABASE_URL for SQLite persistence)');
  }

  // Purge expired sessions every 10 minutes
  setInterval(purgeExpired, 10 * 60 * 1000).unref();
}

const MAX_SESSIONS = 100_000;

// Cap attributions to prevent unbounded memory growth under payment floods.
// 500k records ≈ 200 MB at ~400 bytes per record — reasonable upper bound.
const MAX_ATTRIBUTIONS = 500_000;

function saveSession(sessionId, visitData) {
  // When the cap is hit, silently drop new sessions (DoS mitigation).
  // Existing sessions can still be updated. Warn operators so they know.
  if (sessions.size >= MAX_SESSIONS && !sessions.has(sessionId)) {
    console.warn('[appear] sessions cap reached — new session dropped');
    return;
  }

  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;

  sessions.set(sessionId, { ...visitData, _expires_at: expiresAt });

  if (db) {
    try {
      db.prepare(`
        INSERT INTO sessions (session_id, data, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET data = excluded.data, expires_at = excluded.expires_at
      `).run(sessionId, JSON.stringify(visitData), now, expiresAt);
    } catch (err) {
      console.error('[appear] SQLite saveSession error:', err.message);
    }
  }
}

function getSession(sessionId) {
  const entry = sessions.get(sessionId);
  if (!entry) return null;
  if (entry._expires_at && Date.now() > entry._expires_at) {
    sessions.delete(sessionId);
    return null;
  }
  return entry;
}

function saveAttribution(paymentId, sessionId, visitData, paymentData) {
  // Prevent unbounded growth — silently drop when cap is reached.
  // Duplicate payment_ids are allowed to update (idempotent re-delivery).
  if (attributions.size >= MAX_ATTRIBUTIONS && !attributions.has(paymentId)) {
    console.warn('[appear] attributions cap reached — new attribution dropped');
    return null;
  }

  const now = Date.now();
  const record = {
    payment_id: paymentId,
    session_id: sessionId,
    visit: visitData,
    payment: paymentData,
    attributed_at: now,
  };

  attributions.set(paymentId, record);

  if (db) {
    try {
      db.prepare(`
        INSERT OR IGNORE INTO attributions (payment_id, session_id, visit_data, payment_data, attributed_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(paymentId, sessionId, JSON.stringify(visitData), JSON.stringify(paymentData), now);
    } catch (err) {
      console.error('[appear] SQLite saveAttribution error:', err.message);
    }
  }

  return record;
}

function getStats() {
  const now = Date.now();
  let activeSessions = 0;

  for (const [, v] of sessions) {
    if (!v._expires_at || now < v._expires_at) activeSessions++;
  }

  const allAttributions = Array.from(attributions.values());

  // Revenue by engine
  const revenueByEngine = {};
  let totalRevenue = 0;

  for (const attr of allAttributions) {
    const engine = attr.visit && attr.visit.engine ? attr.visit.engine : 'unknown';
    const amount = attr.payment && attr.payment.amount ? attr.payment.amount : 0;
    revenueByEngine[engine] = (revenueByEngine[engine] || 0) + amount;
    totalRevenue += amount;
  }

  // Recent attributions (last 20)
  const recent = allAttributions
    .sort((a, b) => b.attributed_at - a.attributed_at)
    .slice(0, 20)
    .map((a) => ({
      payment_id: a.payment_id,
      engine: a.visit && a.visit.engine,
      amount: a.payment && a.payment.amount,
      currency: a.payment && a.payment.currency,
      attributed_at: new Date(a.attributed_at).toISOString(),
    }));

  return {
    total_sessions: activeSessions,
    total_attributions: allAttributions.length,
    total_revenue: totalRevenue,
    revenue_by_engine: revenueByEngine,
    recent_attributions: recent,
  };
}

function purgeExpired() {
  const now = Date.now();
  for (const [id, v] of sessions) {
    if (v._expires_at && now > v._expires_at) {
      sessions.delete(id);
    }
  }
  if (db) {
    try {
      db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now);
    } catch (_) {}
  }
}

module.exports = { initStore, saveSession, getSession, saveAttribution, getStats };
