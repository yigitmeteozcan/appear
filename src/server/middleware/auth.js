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
    const a = Buffer.from(provided.padEnd(apiKey.length));
    const b = Buffer.from(apiKey);
    // Buffers must be same length for timingSafeEqual
    if (a.length !== b.length) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
    const valid = crypto.timingSafeEqual(a, b);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid API key' });
    }
  } catch (_) {
    return res.status(401).json({ error: 'Invalid API key' });
  }

  next();
}

module.exports = { requireApiKey };
