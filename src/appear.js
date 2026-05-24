/**
 * appear.js — AI traffic attribution browser snippet
 * Zero dependencies. Drop-in. Privacy-first.
 *
 * Usage:
 *   Appear.init({ webhookUrl: 'https://your-server.com/appear/event' });
 */
(function (global) {
  'use strict';

  // --- Constants ---
  const VERSION = '0.1.0';
  const SESSION_KEY = '__appear_sid';
  const EVENTS_KEY = '__appear_events';
  const MAX_STRING_LEN = 500;
  const DEFAULT_MAX_STORED = 50;

  // AI engine detection rules: ordered by specificity
  const AI_ENGINES = [
    { name: 'chatgpt',    pattern: /chatgpt\.com|chat\.openai\.com/i },
    { name: 'perplexity', pattern: /perplexity\.ai/i },
    { name: 'claude',     pattern: /claude\.ai/i },
    { name: 'gemini',     pattern: /gemini\.google\.com|bard\.google\.com/i },
    { name: 'copilot',    pattern: /copilot\.microsoft\.com|bing\.com\/chat/i },
    { name: 'you',        pattern: /you\.com/i },
    { name: 'phind',      pattern: /phind\.com/i },
    { name: 'poe',        pattern: /poe\.com/i },
  ];

  // utm_source values that map to engines
  const UTM_ENGINE_MAP = {
    chatgpt: 'chatgpt',
    'chat.openai': 'chatgpt',
    perplexity: 'perplexity',
    claude: 'claude',
    gemini: 'gemini',
    bard: 'gemini',
    copilot: 'copilot',
    bing: 'copilot',
    you: 'you',
    phind: 'phind',
    poe: 'poe',
  };

  // --- Utilities ---

  function sanitize(val) {
    if (val == null) return '';
    var s = String(val)
      .replace(/<[^>]*>/g, '')        // strip HTML/script tags
      .replace(/javascript:/gi, '')   // strip javascript: URIs
      .replace(/[^\x20-\x7E  -￿]/g, '') // printable only
      .trim()
      .slice(0, MAX_STRING_LEN);
    return s;
  }

  function safeGet(fn, fallback) {
    try { return fn(); } catch (e) { return fallback; }
  }

  function generateId() {
    if (global.crypto && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    // Fallback for browsers that have crypto.getRandomValues but not randomUUID
    // (e.g. pre-2021 Safari). Math.random() is NOT a CSPRNG — use getRandomValues.
    if (global.crypto && crypto.getRandomValues) {
      var bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      // Set version 4 bits (bits 12-15 of time_hi_and_version = 0100)
      bytes[6] = (bytes[6] & 0x0f) | 0x40;
      // Set variant bits (bits 6-7 of clock_seq_hi = 10)
      bytes[8] = (bytes[8] & 0x3f) | 0x80;
      function hex(b, offset, len) {
        var s = '';
        for (var i = offset; i < offset + len; i++) {
          s += ('0' + bytes[i].toString(16)).slice(-2);
        }
        return s;
      }
      return [
        hex(bytes, 0, 4), '-', hex(bytes, 4, 2), '-', hex(bytes, 6, 2), '-',
        hex(bytes, 8, 2), '-', hex(bytes, 10, 6),
      ].join('');
    }
    // Last-resort fallback for very old environments without any crypto API.
    // Not cryptographically random, but prevents hard crashes.
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  function isValidHttpsUrl(url) {
    if (typeof url !== 'string') return false;
    try {
      var u = new URL(url);
      return u.protocol === 'https:';
    } catch (e) {
      return false;
    }
  }

  function getUtmParams() {
    var params = {};
    try {
      var search = new URLSearchParams(global.location.search);
      ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'].forEach(function (k) {
        var v = search.get(k);
        if (v) params[k] = sanitize(v);
      });
    } catch (e) {}
    return params;
  }

  // --- Engine detection ---

  function detectEngine(referrer, utmSource) {
    // 1. Check utm_source first (explicit signal)
    if (utmSource) {
      var key = utmSource.toLowerCase().replace(/[^a-z0-9.]/g, '');
      if (UTM_ENGINE_MAP[key]) {
        return { engine: UTM_ENGINE_MAP[key], source: 'utm' };
      }
    }

    // 2. Check referrer URL
    if (referrer) {
      for (var i = 0; i < AI_ENGINES.length; i++) {
        if (AI_ENGINES[i].pattern.test(referrer)) {
          return { engine: AI_ENGINES[i].name, source: 'referrer' };
        }
      }
    }

    return null;
  }

  // --- Session management (sessionStorage only) ---

  function getOrCreateSession() {
    var sid = safeGet(function () { return sessionStorage.getItem(SESSION_KEY); }, null);
    if (!sid) {
      sid = generateId();
      safeGet(function () { sessionStorage.setItem(SESSION_KEY, sid); }, null);
    }
    return sid;
  }

  function loadStoredEvents(maxStored) {
    try {
      var raw = sessionStorage.getItem(EVENTS_KEY);
      if (!raw) return [];
      var events = JSON.parse(raw);
      if (!Array.isArray(events)) return [];
      return events.slice(0, maxStored);
    } catch (e) {
      return [];
    }
  }

  function persistEvent(event, maxStored) {
    try {
      var events = loadStoredEvents(maxStored);
      events.unshift(event);
      sessionStorage.setItem(EVENTS_KEY, JSON.stringify(events.slice(0, maxStored)));
    } catch (e) {}
  }

  // --- Main Appear object ---

  var _config = null;
  var _events = [];
  var _initialized = false;

  var Appear = {
    version: VERSION,

    /**
     * Initialize Appear.
     * @param {Object} config
     * @param {string} config.webhookUrl        Required. Must be https.
     * @param {Function} [config.onDetect]      Called when an AI visit is detected.
     * @param {boolean} [config.debug]          Log to console when true.
     * @param {boolean} [config.sendUserAgent]  Include user agent. Default false.
     * @param {number}  [config.maxStoredEvents] Max events in sessionStorage. Default 50.
     */
    init: function (config) {
      try {
        if (_initialized) return;
        _initialized = true;

        if (!config || typeof config !== 'object') {
          _log('warn', 'Appear.init: config object required');
          return;
        }

        if (!isValidHttpsUrl(config.webhookUrl)) {
          _log('warn', 'Appear.init: webhookUrl must be a valid https URL');
          return;
        }

        _config = {
          webhookUrl: config.webhookUrl,
          onDetect: typeof config.onDetect === 'function' ? config.onDetect : null,
          debug: config.debug === true,
          sendUserAgent: config.sendUserAgent === true,
          maxStoredEvents: typeof config.maxStoredEvents === 'number' && config.maxStoredEvents > 0
            ? Math.min(config.maxStoredEvents, 200)
            : DEFAULT_MAX_STORED,
        };

        _events = loadStoredEvents(_config.maxStoredEvents);

        var detection = Appear.detect();
        if (detection) {
          _send(detection);
        }
      } catch (e) {
        // Never throw to host page
      }
    },

    /**
     * Detect AI engine from current page context.
     * Returns detection object or null.
     */
    detect: function () {
      try {
        var referrer = safeGet(function () { return sanitize(document.referrer); }, '');
        var utm = getUtmParams();
        var result = detectEngine(referrer, utm.utm_source);
        if (!result) return null;

        var maxLen = MAX_STRING_LEN;
        var detection = {
          session_id:  getOrCreateSession(),
          engine:      sanitize(result.engine).slice(0, 50),
          source:      sanitize(result.source).slice(0, 20),
          referrer:    referrer.slice(0, maxLen),
          page_url:    sanitize(safeGet(function () { return location.href; }, '')).slice(0, maxLen),
          timestamp:   new Date().toISOString(),
          utm_source:      utm.utm_source   || '',
          utm_medium:      utm.utm_medium   || '',
          utm_campaign:    utm.utm_campaign || '',
          utm_term:        utm.utm_term     || '',
          utm_content:     utm.utm_content  || '',
        };

        if (_config && _config.sendUserAgent) {
          detection.user_agent = sanitize(safeGet(function () { return navigator.userAgent; }, '')).slice(0, maxLen);
        }

        return detection;
      } catch (e) {
        return null;
      }
    },

    /**
     * Return all events stored in this session.
     */
    getEvents: function () {
      return _events.slice();
    },

    /**
     * Clear stored events from sessionStorage.
     */
    clearEvents: function () {
      _events = [];
      try { sessionStorage.removeItem(EVENTS_KEY); } catch (e) {}
    },
  };

  // --- Internal ---

  function _log(level, msg) {
    if (_config && _config.debug && global.console) {
      console[level]('[appear]', msg);
    }
  }

  function _send(detection) {
    try {
      persistEvent(detection, _config.maxStoredEvents);
      _events.unshift(detection);
      if (_events.length > _config.maxStoredEvents) {
        _events = _events.slice(0, _config.maxStoredEvents);
      }

      if (_config.onDetect) {
        try { _config.onDetect(detection); } catch (e) {}
      }

      _log('log', 'AI visit detected: ' + detection.engine + ' via ' + detection.source);

      fetch(_config.webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(detection),
        keepalive: true,
      }).then(function (res) {
        if (!res.ok) {
          _log('warn', 'Event send failed: ' + res.status);
        }
      }).catch(function (err) {
        _log('warn', 'Event send error: ' + err.message);
      });
    } catch (e) {
      // Silent in production
    }
  }

  // Expose to global scope
  global.Appear = Appear;

  // Also expose detectEngine for server-side use / testing
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { Appear: Appear, detectEngine: detectEngine };
  }
}(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this));
