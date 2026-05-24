'use strict';

const rateLimit = require('express-rate-limit');

function createLimiter(max, windowMs, message) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: message || 'Too many requests' },
    // Don't expose limit details in error response
    skipFailedRequests: false,
  });
}

// 60 req/min per IP for event ingestion
const eventLimiter = createLimiter(60, 60 * 1000, 'Rate limit exceeded');

// 20 req/min per IP for webhook endpoints
const webhookLimiter = createLimiter(20, 60 * 1000, 'Rate limit exceeded');

// 30 req/min per IP for stats endpoint
const statsLimiter = createLimiter(30, 60 * 1000, 'Rate limit exceeded');

module.exports = { eventLimiter, webhookLimiter, statsLimiter };
