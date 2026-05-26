'use strict';

const express = require('express');
const { requireApiKey } = require('../middleware/auth');
const { statsLimiter } = require('../middleware/rateLimit');
const { getStats } = require('../store');

const router = express.Router();

/**
 * GET /appear/stats
 * Returns attribution stats. Requires API key.
 */
// Rate limiter is applied before auth so brute-force auth attempts are also throttled.
router.get('/stats', statsLimiter, requireApiKey, (req, res) => {
  try {
    const stats = getStats();
    return res.json(stats);
  } catch (_) {
    return res.status(500).json({ error: 'Internal error' });
  }
});

module.exports = router;
