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

describe('AI engine detection — referrer with path/query', () => {
  test('perplexity with /search path and query string', () => {
    const result = detectEngine('https://perplexity.ai/search?q=foo', null);
    assert.ok(result);
    assert.equal(result.engine, 'perplexity');
    assert.equal(result.source, 'referrer');
  });

  test('chatgpt with long path', () => {
    const result = detectEngine('https://chatgpt.com/c/some-conversation-id', null);
    assert.ok(result);
    assert.equal(result.engine, 'chatgpt');
    assert.equal(result.source, 'referrer');
  });
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

describe('Mixed-case utm_source — case-insensitive match', () => {
  // detectEngine calls utmSource.toLowerCase() so mixed-case must match
  test('utm_source=CHATGPT (all caps) detects chatgpt', () => {
    const result = detectEngine(null, 'CHATGPT');
    assert.ok(result);
    assert.equal(result.engine, 'chatgpt');
    assert.equal(result.source, 'utm');
  });

  test('utm_source=ChatGPT (title case) detects chatgpt', () => {
    const result = detectEngine(null, 'ChatGPT');
    assert.ok(result);
    assert.equal(result.engine, 'chatgpt');
    assert.equal(result.source, 'utm');
  });

  test('utm_source=Perplexity (title case) detects perplexity', () => {
    const result = detectEngine(null, 'Perplexity');
    assert.ok(result);
    assert.equal(result.engine, 'perplexity');
    assert.equal(result.source, 'utm');
  });

  test('utm_source=GEMINI (all caps) detects gemini', () => {
    const result = detectEngine(null, 'GEMINI');
    assert.ok(result);
    assert.equal(result.engine, 'gemini');
    assert.equal(result.source, 'utm');
  });
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

describe('Malformed/injection utm_source — should return null', () => {
  test('utm_source with HTML injection <script> returns null', () => {
    const result = detectEngine(null, '<script>alert(1)</script>');
    assert.equal(result, null);
  });

  test('utm_source with javascript: URI returns null', () => {
    const result = detectEngine(null, 'javascript:alert(1)');
    assert.equal(result, null);
  });

  test('utm_source with empty string returns null', () => {
    const result = detectEngine(null, '');
    assert.equal(result, null);
  });

  test('utm_source with spaces only returns null', () => {
    const result = detectEngine(null, '   ');
    assert.equal(result, null);
  });
});

describe('Malformed referrer — should not throw', () => {
  test('non-URL string referrer returns null without throwing', () => {
    assert.doesNotThrow(() => {
      const result = detectEngine('not-a-url', null);
      assert.equal(result, null);
    });
  });

  test('triple-colon referrer returns null without throwing', () => {
    assert.doesNotThrow(() => {
      const result = detectEngine(':::', null);
      assert.equal(result, null);
    });
  });

  test('empty referrer returns null without throwing', () => {
    assert.doesNotThrow(() => {
      const result = detectEngine('', null);
      assert.equal(result, null);
    });
  });

  test('null referrer returns null without throwing', () => {
    assert.doesNotThrow(() => {
      const result = detectEngine(null, null);
      assert.equal(result, null);
    });
  });
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

describe('Referrer spoofing — hostname boundary enforcement', () => {
  test('evil.com with chatgpt.com in path returns null', () => {
    const result = detectEngine('https://evil.com/page?ref=chatgpt.com', null);
    assert.equal(result, null, 'chatgpt.com in query string must not spoof detection');
  });

  test('fakechatgpt.com returns null', () => {
    const result = detectEngine('https://fakechatgpt.com/', null);
    assert.equal(result, null, 'subdomain prefix must not match chatgpt.com');
  });

  test('notperplexity.ai returns null', () => {
    const result = detectEngine('https://notperplexity.ai/', null);
    assert.equal(result, null, 'different TLD prefix must not match perplexity.ai');
  });

  test('subdomain of chatgpt.com is detected correctly', () => {
    const result = detectEngine('https://sub.chatgpt.com/', null);
    assert.ok(result, 'legitimate subdomain of chatgpt.com should be detected');
    assert.equal(result.engine, 'chatgpt');
  });
});
