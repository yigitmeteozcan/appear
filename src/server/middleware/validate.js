'use strict';

const { body, validationResult } = require('express-validator');

const MAX_LEN = 500;

// Allowed fields for AI visit events — reject unknown fields to prevent injection
const EVENT_ALLOWED_FIELDS = new Set([
  'session_id', 'engine', 'source', 'referrer', 'page_url', 'timestamp',
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'user_agent',
]);

const KNOWN_ENGINES = new Set([
  'chatgpt', 'perplexity', 'claude', 'gemini', 'copilot', 'you', 'phind', 'poe',
]);

// Express-validator chain for the /appear/event endpoint
const validateEvent = [
  body('session_id')
    .isString().withMessage('session_id must be a string')
    .trim()
    .isLength({ min: 1, max: 128 }).withMessage('session_id length invalid')
    .matches(/^[a-zA-Z0-9_\-]+$/).withMessage('session_id contains invalid characters'),

  body('engine')
    .isString().withMessage('engine must be a string')
    .trim()
    .isIn([...KNOWN_ENGINES]).withMessage('engine value not recognized'),

  body('source')
    .isString().withMessage('source must be a string')
    .trim()
    .isIn(['referrer', 'utm', 'useragent']).withMessage('source must be referrer, utm, or useragent'),

  body('referrer')
    .optional()
    .isString()
    .trim()
    .isLength({ max: MAX_LEN }),

  body('page_url')
    .isString().withMessage('page_url must be a string')
    .trim()
    .isLength({ min: 1, max: MAX_LEN }),

  body('timestamp')
    .isISO8601().withMessage('timestamp must be a valid ISO 8601 date'),

  body('utm_source').optional().isString().trim().isLength({ max: MAX_LEN }),
  body('utm_medium').optional().isString().trim().isLength({ max: MAX_LEN }),
  body('utm_campaign').optional().isString().trim().isLength({ max: MAX_LEN }),
  body('utm_term').optional().isString().trim().isLength({ max: MAX_LEN }),
  body('utm_content').optional().isString().trim().isLength({ max: MAX_LEN }),
  body('user_agent').optional().isString().trim().isLength({ max: MAX_LEN }),
];

function rejectUnknownFields(allowedFields) {
  return (req, res, next) => {
    const unknown = Object.keys(req.body).filter((k) => !allowedFields.has(k));
    if (unknown.length > 0) {
      return res.status(400).json({ error: 'Unexpected fields in request' });
    }
    next();
  };
}

function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ error: 'Validation failed', details: errors.array().map((e) => e.msg) });
  }
  next();
}

module.exports = {
  validateEvent,
  rejectUnknownEventFields: rejectUnknownFields(EVENT_ALLOWED_FIELDS),
  handleValidationErrors,
};
