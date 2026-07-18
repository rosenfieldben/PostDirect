'use strict';
const test = require('node:test');
const assert = require('node:assert');

// Import the REAL verificationVerdict()/correctedAddress() from the shipped ES
// module (js/address.mjs), so this suite tests the shipped logic directly.
const { verificationVerdict, correctedAddress } = require('../public/js/address.mjs');

test('verdict: each Lob deliverability value maps to the right level', () => {
  assert.strictEqual(verificationVerdict({ deliverability: 'deliverable' }).level, 'ok');
  assert.strictEqual(verificationVerdict({ deliverability: 'deliverable_unnecessary_unit' }).level, 'warn');
  assert.strictEqual(verificationVerdict({ deliverability: 'deliverable_incorrect_unit' }).level, 'warn');
  assert.strictEqual(verificationVerdict({ deliverability: 'deliverable_missing_unit' }).level, 'warn');
  const blocked = verificationVerdict({ deliverability: 'undeliverable' });
  assert.strictEqual(blocked.level, 'blocked');
  assert.strictEqual(blocked.label, 'Undeliverable');
});

test('verdict: API errors and unknown values fail OPEN (level error, never blocked)', () => {
  assert.strictEqual(verificationVerdict(null).level, 'error');
  assert.strictEqual(verificationVerdict(undefined).level, 'error');
  const apiErr = verificationVerdict({ error: { message: 'Your API key is not valid.' } });
  assert.strictEqual(apiErr.level, 'error');
  assert.ok(apiErr.note.includes('not valid'), 'surfaces the upstream message');
  // A deliverability value this code doesn't know about must not block sends.
  assert.strictEqual(verificationVerdict({ deliverability: 'some_future_value' }).level, 'error');
});

const LOB_RESP = {
  deliverability: 'deliverable',
  primary_line: '185 BERRY ST STE 6100',
  secondary_line: '',
  components: { city: 'SAN FRANCISCO', state: 'CA', zip_code: '94107' },
};

test('correctedAddress: pure case/whitespace differences are NOT a correction', () => {
  const typed = { line1: '185 berry st   ste 6100', line2: '', city: 'san francisco', state: 'ca', zip: '94107' };
  const { corrected, differs } = correctedAddress(typed, LOB_RESP);
  assert.strictEqual(differs, false);
  assert.strictEqual(corrected.line1, '185 BERRY ST STE 6100');
});

test('correctedAddress: real standardization differences ARE a correction', () => {
  const typed = { line1: '185 Berry Street, Suite 6100', line2: '', city: 'San Francisco', state: 'California', zip: '94107' };
  const { differs } = correctedAddress(typed, LOB_RESP);
  assert.strictEqual(differs, true);
});

test('correctedAddress: missing response fields become empty strings, not crashes', () => {
  const typed = { line1: '1 Main St', line2: '', city: 'Nowhere', state: 'ZZ', zip: '00000' };
  const { corrected, differs } = correctedAddress(typed, { deliverability: 'deliverable' });
  assert.deepStrictEqual(corrected, { line1: '', line2: '', city: '', state: '', zip: '' });
  assert.strictEqual(differs, true);
});
