'use strict';
// Item 6: IP canonicalization for the per-IP rate-limit bucket. The former
// ipBucket sliced the first four COLON-separated hextets, so the same /64 wore
// different keys depending on textual form ('2001:db8::1' vs its expanded
// spelling), which let a client vary the spelling to dodge the per-/64 cap.
// canonicalizeIp now folds every form to one canonical text, and ipBucket
// computes the /64 from that. Table-driven so each case is a single line.
const test = require('node:test');
const assert = require('node:assert');
const { canonicalizeIp, ipBucket } = require('../lib/ratelimit');

// canonicalizeIp: input -> canonical text.
const CANON = [
  // IPv4 passes through unchanged.
  ['1.2.3.4', '1.2.3.4'],
  ['10.0.0.9', '10.0.0.9'],
  // IPv4-mapped IPv6 -> dotted IPv4 (it identifies an IPv4 client).
  ['::ffff:1.2.3.4', '1.2.3.4'],
  ['::ffff:192.168.0.1', '192.168.0.1'],
  ['::FFFF:255.255.255.255', '255.255.255.255'],
  // RFC 5952 canonical text for IPv6: lowercase, no leading zeros, longest zero
  // run collapsed to '::' (leftmost on ties).
  ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
  ['2001:DB8::1', '2001:db8::1'],
  ['2001:db8:0:0:0:0:0:1', '2001:db8::1'],
  ['2001:db8::1', '2001:db8::1'],
  ['0:0:0:0:0:0:0:0', '::'],
  ['::', '::'],
  ['0:0:0:0:0:0:0:1', '::1'],
  ['fe80::1', 'fe80::1'],
  // Longest zero run wins (len 3 over len 2).
  ['2001:0:0:1:0:0:0:1', '2001:0:0:1::1'],
  // Tie: two equal-length (len 2) zero runs -> the LEFTMOST is compressed.
  ['1:0:0:2:0:0:2:1', '1::2:0:0:2:1'],
  // A single zero group is NOT compressed (RFC 5952).
  ['2001:db8:0:1:1:1:1:1', '2001:db8:0:1:1:1:1:1'],
  // Zone id is dropped.
  ['fe80::1%eth0', 'fe80::1'],
  // Garbage passes through unchanged, never throws.
  ['unknown', 'unknown'],
  ['not:an:ip', 'not:an:ip'],
  ['2001:db8:::1', '2001:db8:::1'],   // two '::' is invalid -> unchanged
  ['12345::1', '12345::1'],           // group > 4 hex digits -> unchanged
  ['2001:db8::1::2', '2001:db8::1::2'],
  ['', ''],
];

// ipBucket: input -> bucket key. IPv6 keys on the canonical /64; IPv4 (and
// v4-mapped) keys on the whole address; garbage keys on itself.
const BUCKET = [
  ['1.2.3.4', '1.2.3.4'],
  ['::ffff:1.2.3.4', '1.2.3.4'],
  ['2001:db8::1', '2001:db8::/64'],
  ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::/64'],
  ['2001:DB8:0:0:dead:beef:0:1', '2001:db8::/64'],
  ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'],
  ['fe80::1', 'fe80::/64'],
  ['::1', '::/64'],
  ['unknown', 'unknown'],
  ['not:an:ip', 'not:an:ip'],
  [undefined, 'unknown'],
  [null, 'unknown'],
];

test('canonicalizeIp folds every textual form to one canonical string', () => {
  for (const [input, expected] of CANON) {
    assert.strictEqual(canonicalizeIp(input), expected, JSON.stringify(input));
  }
});

test('ipBucket keys IPv6 on the canonical /64, IPv4 on the whole address', () => {
  for (const [input, expected] of BUCKET) {
    assert.strictEqual(ipBucket(input), expected, JSON.stringify(input));
  }
});

test('every spelling of one /64 collapses to a single bucket key', () => {
  const forms = [
    '2001:db8::1',
    '2001:0db8:0000:0000:0000:0000:0000:0001',
    '2001:DB8::dead:beef',
    '2001:db8:0:0:1:2:3:4',
    '2001:db8::ffff',
  ];
  const keys = new Set(forms.map(ipBucket));
  assert.strictEqual(keys.size, 1, 'all forms of one /64 must map to one key: ' + [...keys].join(', '));
  assert.strictEqual([...keys][0], '2001:db8::/64');
});

test('two distinct /64s never collide, and neither throws on odd input', () => {
  assert.notStrictEqual(ipBucket('2001:db8::1'), ipBucket('2001:db9::1'));
  assert.doesNotThrow(() => ipBucket('::ffff:junk'));
  assert.doesNotThrow(() => ipBucket(':::::'));
});
