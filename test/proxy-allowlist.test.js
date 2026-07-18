'use strict';
// Item 5: the proxy allowlist as a pure, table-driven contract. proxyRequestAllowed
// decides, from (method, path) alone, whether an /api/lob call is one of the exact
// Lob endpoints this app uses. The integration proxy.test.js proves a rejected
// call is answered 404 locally and never forwarded; this suite pins the rule
// itself, including that the query string can never smuggle a disallowed path.
const test = require('node:test');
const assert = require('node:assert');
const { proxyRequestAllowed } = require('../lib/proxy');

const ALLOWED = [
  ['POST', '/v1/letters'],
  ['GET', '/v1/letters'],
  ['GET', '/v1/letters?limit=100'],
  ['GET', '/v1/letters?limit=100&after=abc123'],
  ['GET', '/v1/letters/ltr_abc123'],
  ['GET', '/v1/letters/ltr_XyZ0'],
  ['DELETE', '/v1/letters/ltr_abc123'],
  ['POST', '/v1/us_verifications'],
];

const DENIED = [
  // Money-moving / financial endpoints the app never uses.
  ['GET', '/v1/checks'],
  ['POST', '/v1/checks'],
  ['GET', '/v1/bank_accounts'],
  ['POST', '/v1/bank_accounts'],
  // Other Lob resources.
  ['POST', '/v1/postcards'],
  ['POST', '/v1/self_mailers'],
  ['GET', '/v1/addresses'],
  // Wrong method on an allowed path.
  ['PUT', '/v1/letters'],
  ['DELETE', '/v1/letters'],            // cancel needs an id
  ['POST', '/v1/letters/ltr_abc123'],   // create is on the collection, not an id
  ['GET', '/v1/us_verifications'],      // verify is POST-only
  // Malformed / non-matching letter ids.
  ['GET', '/v1/letters/not-an-id'],
  ['GET', '/v1/letters/ltr_'],          // needs at least one id char
  ['GET', '/v1/letters/ltr_abc/extra'],
  ['DELETE', '/v1/letters/abc123'],     // missing ltr_ prefix
  // Query string cannot smuggle an allowed path past the gate.
  ['GET', '/v1/checks?x=/v1/letters'],
  ['POST', '/v1/bank_accounts?/v1/us_verifications'],
  // Path-traversal-ish and prefix tricks.
  ['GET', '/v1/lettersX'],
  ['GET', '/v1/letters/../checks'],
  // Junk.
  ['GET', ''],
  ['GET', '/'],
  ['FOO', '/v1/letters'],
];

test('every call the app makes is allowed', () => {
  for (const [m, p] of ALLOWED) {
    assert.strictEqual(proxyRequestAllowed(m, p), true, m + ' ' + p + ' should be allowed');
  }
});

test('everything else is denied (method, path, query-smuggling, malformed ids)', () => {
  for (const [m, p] of DENIED) {
    assert.strictEqual(proxyRequestAllowed(m, p), false, m + ' ' + p + ' should be denied');
  }
});

test('nullish and non-string paths do not throw and are denied', () => {
  assert.strictEqual(proxyRequestAllowed('GET', null), false);
  assert.strictEqual(proxyRequestAllowed('GET', undefined), false);
});
