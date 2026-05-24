'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

// Import the detectEngine function from the browser snippet via CommonJS export
const { detectEngine } = require('../src/appear.js');

describe('AI engine detection — referrer', () => {
  const cases = [
    ['https://chatgpt.com/c/abc123', null, 'chatgpt', 'referrer'],
    ['https://chat.openai.com/share/xyz', null, 'chatgpt', 'referrer'],
    ['https://www.perplexity.ai/search/something', null, 'perplexity', 'referrer'],
    ['https://claude.ai/chat/abc', null, 'claude', 'referrer'],
    ['https://gemini.google.com/app', null, 'gemini', 'referrer'],
    ['https://bard.google.com/', null, 'gemini', 'referrer'],
    ['https://copilot.microsoft.com/', null, 'copilot', 'referrer'],
    ['https://www.bing.com/chat', null, 'copilot', 'referrer'],
    ['https://you.com/search?q=hello', null, 'you', 'referrer'],
    ['https://www.phind.com/search', null, 'phind', 'referrer'],
    ['https://poe.com/chat/abc', null, 'poe', 'referrer'],
  ];

  for (const [referrer, utm, expectedEngine, expectedSource] of cases) {
    test(`detects ${expectedEngine} from referrer: ${referrer}`, () => {
      const result = detectEngine(referrer, utm);
      assert.ok(result, `Expected detection for ${referrer}`);
      assert.equal(result.engine, expectedEngine);
      assert.equal(result.source, expectedSource);
    });
  }
});

describe('AI engine detection — utm_source', () => {
  const cases = [
    [null, 'chatgpt', 'chatgpt', 'utm'],
    [null, 'perplexity', 'perplexity', 'utm'],
    [null, 'claude', 'claude', 'utm'],
    [null, 'gemini', 'gemini', 'utm'],
    [null, 'bard', 'gemini', 'utm'],
    [null, 'copilot', 'copilot', 'utm'],
    [null, 'bing', 'copilot', 'utm'],
    [null, 'you', 'you', 'utm'],
    [null, 'phind', 'phind', 'utm'],
    [null, 'poe', 'poe', 'utm'],
  ];

  for (const [referrer, utm, expectedEngine, expectedSource] of cases) {
    test(`detects ${expectedEngine} from utm_source=${utm}`, () => {
      const result = detectEngine(referrer, utm);
      assert.ok(result, `Expected detection for utm_source=${utm}`);
      assert.equal(result.engine, expectedEngine);
      assert.equal(result.source, expectedSource);
    });
  }
});

describe('Non-AI referrers — should return null', () => {
  const nonAiReferrers = [
    'https://google.com/search?q=example',
    'https://twitter.com/user/status/123',
    'https://reddit.com/r/programming',
    'https://news.ycombinator.com/',
    'https://github.com/user/repo',
    'https://example.com',
    '',
    null,
  ];

  for (const referrer of nonAiReferrers) {
    test(`returns null for non-AI referrer: ${referrer || '(empty)'}`, () => {
      const result = detectEngine(referrer, null);
      assert.equal(result, null);
    });
  }
});

describe('utm_source takes precedence over referrer', () => {
  test('utm_source=chatgpt overrides a non-AI referrer', () => {
    const result = detectEngine('https://google.com', 'chatgpt');
    assert.ok(result);
    assert.equal(result.engine, 'chatgpt');
    assert.equal(result.source, 'utm');
  });

  test('utm_source=perplexity overrides a different AI referrer', () => {
    const result = detectEngine('https://poe.com/chat/abc', 'perplexity');
    assert.ok(result);
    assert.equal(result.engine, 'perplexity');
    assert.equal(result.source, 'utm');
  });
});

describe('Unknown utm_source falls through to referrer', () => {
  test('unknown utm_source still detects from referrer', () => {
    const result = detectEngine('https://chatgpt.com/c/abc', 'newsletter');
    assert.ok(result);
    assert.equal(result.engine, 'chatgpt');
    assert.equal(result.source, 'referrer');
  });
});
