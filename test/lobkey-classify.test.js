'use strict';
process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value';

const test = require('node:test');
const assert = require('node:assert');
const { lobKeyEnv: serverClassify } = require('../server.js');

// The server classifier lives in lib/config.js (re-exported by server.js); the
// frontend classifier is the shipped ES module js/lobkey.mjs. One classifier per
// side, imported directly so this suite pins the SHIPPED logic on both sides and
// asserts they agree case-for-case.
const { lobKeyEnv: frontendClassify } = require('../public/js/lobkey.mjs');

// One classification rule everywhere: a normalized key is Test only if it
// starts with test_. Anything else, including unknown prefixes, is Live, so a
// key that spends real postage can never wear a reassuring Test badge. Both
// classifiers must agree case-for-case.
const CASES = [
  ['test_abc', 'test'],
  ['  test_abc  ', 'test'],       // whitespace-padded test key still shows Test
  ['live_abc', 'live'],
  [' live_abc', 'live'],          // the leading-whitespace key that spent live postage as "Test"
  ['live_abc  ', 'live'],
  ['sk_abc', 'live'],             // unknown prefix must never display as Test
  ['LIVE_ABC', 'live'],
  ['', null],
  ['   ', null],
  [null, null],
  [undefined, null],
];

test('server lobKeyEnv: trims, then classifies non-test_ as live', () => {
  for (const [input, expected] of CASES) {
    assert.strictEqual(serverClassify(input), expected, 'server classify ' + JSON.stringify(input));
  }
});

test('frontend lobKeyEnv matches the server rule case-for-case', () => {
  for (const [input, expected] of CASES) {
    assert.strictEqual(frontendClassify(input), expected, 'frontend classify ' + JSON.stringify(input));
  }
});

// isLive() itself is DOM-coupled app glue (it reads apiKey()/usingServerKey()/
// serverKeyEnv), so it is not a pure importable module. Its wiring, including the
// Phase 0 regression that a leading-whitespace " live_" key must display as Live
// and that an unknown prefix reads as Live, is characterized end-to-end against
// the real page in test/browser/key-classification.spec.js. The classification
// rule it delegates to (frontend lobKeyEnv, trimming included) is pinned above.
