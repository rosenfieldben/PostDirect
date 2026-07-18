'use strict';
process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { lobKeyEnv: serverClassify } = require('../server.js');

// Extract the REAL lobKeyEnv() and isLive from public/index.html and evaluate
// them, so this suite tests the shipped frontend logic (same brace-matched
// extraction as derive-status.test.js).
const SRC = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
function fnSrc(name) {
  const m = new RegExp('function\\s+' + name + '\\s*\\(').exec(SRC);
  if (!m) throw new Error('function not found in index.html: ' + name);
  let i = SRC.indexOf('{', m.index), depth = 0;
  for (; i < SRC.length; i++) { const c = SRC[i]; if (c === '{') depth++; else if (c === '}' && --depth === 0) { i++; break; } }
  return SRC.slice(m.index, i);
}
function line(re) { const m = re.exec(SRC); if (!m) throw new Error('not found in index.html: ' + re); return m[0]; }
const { lobKeyEnv: frontendClassify } =
  (new Function(fnSrc('lobKeyEnv') + '\nreturn { lobKeyEnv };'))();

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

test('isLive classifies the SAME trimmed value that is sent to Lob', () => {
  // Evaluate the shipped isLive with its collaborators stubbed the way the
  // page defines them: apiKey() trims the input, and isLive must classify
  // that trimmed value (never the raw field).
  const isLiveSrc = line(/const isLive = [^\n]*;/);
  const makeIsLive = (rawInput, usingServer, serverEnv) => (new Function(
    'usingServerKey', 'serverKeyEnv', 'lobKeyEnv', 'apiKey',
    isLiveSrc + '\nreturn isLive;'
  ))(() => usingServer, serverEnv, frontendClassify, () => String(rawInput).trim());

  assert.strictEqual(makeIsLive(' live_abc', false, null)(), true,
    'leading-whitespace live key must display as Live');
  assert.strictEqual(makeIsLive('sk_abc', false, null)(), true,
    'unknown prefix must take the live-mode path');
  assert.strictEqual(makeIsLive('  test_abc  ', false, null)(), false,
    'whitespace-padded test key still shows Test');
  assert.strictEqual(makeIsLive('', true, 'live')(), true, 'server key env: live');
  assert.strictEqual(makeIsLive('', true, 'test')(), false, 'server key env: test');
});
