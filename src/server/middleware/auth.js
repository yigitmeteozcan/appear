'use strict';

const crypto = require('crypto');

/**
 * API key authentication middleware.
 * Accepts Bearer token in Authorization header OR x-api-key header.
 * Uses constant-time comparison to prevent timing attacks.
 */
function requireApiKey(req, res, next) {
  const apiKey = process.env.API_KEY;

  // Checked at startup, but guard anyway
  if (!apiKey) {
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  let provided = null;

  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    provided = authHeader.slice(7).trim();
  } else if (req.headers['x-api-key']) {
    provided = req.headers['x-api-key'].trim();
  }

  if (!provided) {
    return res.status(401).json({ error: 'Missing API key' });
  }

  try {
    // HMAC-SHA256 both values with a fixed context key before comparing.
    // This normalises buffer lengths to 32 bytes regardless of input length,
    // eliminating the timing-observable early-exit that occurs when the caller
    // sends a key shorter or longer than the stored key.  The `padEnd` trick
    // used previously still leaked the stored key's length via the a.length
    // !== b.length short-circuit path.
    const hmac = (val) => crypto.createHmac('sha256', 'appear-auth').update(val).digest();
    const valid = crypto.timingSafeEqual(hmac(provided), hmac(apiKey));
    if (!valid) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
  } catch (_) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  next();
}

module.exports = { requireApiKey };
