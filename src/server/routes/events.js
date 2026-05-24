'use strict';

const express = require('express');
const { requireApiKey } = require('../middleware/auth');
const { eventLimiter } = require('../middleware/rateLimit');
const { validateEvent, rejectUnknownEventFields, handleValidationErrors } = require('../middleware/validate');
const { saveSession } = require('../store');

const router = express.Router();

/**
 * POST /appear/event
 * Receives an AI visit event from the browser snippet.
 * No auth required so the browser can POST directly.
 * Rate limited and fully validated.
 */
router.post(
  '/event',
  eventLimiter,
  rejectUnknownEventFields,
  validateEvent,
  handleValidationErrors,
  (req, res) => {
    try {
      const event = req.body;

      // Normalize timestamp to server time if it's wildly off (>5 min skew)
      const clientTs = new Date(event.timestamp).getTime();
      const now = Date.now();
      const skewMs = Math.abs(now - clientTs);
      if (skewMs > 5 * 60 * 1000) {
        event.timestamp = new Date().toISOString();
      }

      saveSession(event.session_id, event);

      return res.status(202).json({ ok: true });
    } catch (_) {
      return res.status(500).json({ error: 'Internal error' });
    }
  }
);

module.exports = router;
