'use strict';
const test = require('node:test');
const assert = require('node:assert');

// Import the REAL esc() from the shipped ES module (js/escape.mjs), so this
// suite tests the shipped code directly (not a copy).
const { esc } = require('../public/js/escape.mjs');

test('esc encodes &, <, >, " and \' (from index.html source)', () => {
  assert.strictEqual(esc('&'), '&amp;');
  assert.strictEqual(esc('<'), '&lt;');
  assert.strictEqual(esc('>'), '&gt;');
  assert.strictEqual(esc('"'), '&quot;');
  assert.strictEqual(esc("'"), '&#39;');
  assert.strictEqual(esc(null), '');
  assert.strictEqual(esc(undefined), '');
  assert.strictEqual(esc(0), '0');
});

test('attribute-injection payloads are neutralized', () => {
  const out = esc('" onmouseover="alert(1)');
  assert.ok(!out.includes('"'), 'no raw double-quote can terminate the attribute');
  assert.strictEqual(out, '&quot; onmouseover=&quot;alert(1)');
});

test('Bob\'s "Best" Plumbing round-trips to an attribute-safe encoding', () => {
  const out = esc('Bob\'s "Best" Plumbing');
  assert.strictEqual(out, 'Bob&#39;s &quot;Best&quot; Plumbing');
  assert.ok(!/["'<>]/.test(out), 'no raw quote/angle chars remain');
});
