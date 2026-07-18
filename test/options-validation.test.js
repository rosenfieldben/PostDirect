'use strict';
// Item 5: option and schedule validation. Pure client helpers extracted from
// public/index.html (same brace-matched technique as the other client tests):
// validateSendDate, replyMailFields, isSharedOptionError, notAttemptedEntries.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
function fnSrc(name) {
  const m = new RegExp('(?:async\\s+)?function\\s+' + name + '\\s*\\(').exec(SRC);
  if (!m) throw new Error('function not found in index.html: ' + name);
  let i = SRC.indexOf('{', m.index), depth = 0;
  for (; i < SRC.length; i++) { const c = SRC[i]; if (c === '{') depth++; else if (c === '}' && --depth === 0) { i++; break; } }
  return SRC.slice(m.index, i);
}
// validateSendDate and the picker share SEND_DATE_MAX_DAYS and use parseLobDate.
const CONSTS = 'const SEND_DATE_MAX_DAYS = 180;\n';
const NAMES = ['parseLobDate', 'validateSendDate', 'replyMailFields', 'isSharedOptionError', 'notAttemptedEntries'];
const {
  validateSendDate, replyMailFields, isSharedOptionError, notAttemptedEntries,
} = (new Function(CONSTS + NAMES.map(fnSrc).join('\n') + '\nreturn { ' + NAMES.join(', ') + ' };'))();

test('validateSendDate: empty is allowed (send immediately)', () => {
  assert.strictEqual(validateSendDate('', '2026-07-18').ok, true);
  assert.strictEqual(validateSendDate(undefined, '2026-07-18').ok, true);
});

test('validateSendDate: today is rejected, tomorrow accepted, 180 days accepted, 181 rejected', () => {
  const today = '2026-07-18';
  assert.strictEqual(validateSendDate('2026-07-18', today).ok, false, 'today rejected');
  assert.strictEqual(validateSendDate('2026-07-17', today).ok, false, 'past rejected');
  assert.strictEqual(validateSendDate('2026-07-19', today).ok, true, 'tomorrow accepted');
  // today + 180 days.
  const max = new Date(2026, 6, 18 + 180);
  const pad = (x) => String(x).padStart(2, '0');
  const maxStr = max.getFullYear() + '-' + pad(max.getMonth() + 1) + '-' + pad(max.getDate());
  assert.strictEqual(validateSendDate(maxStr, today).ok, true, '180 days accepted (' + maxStr + ')');
  const over = new Date(2026, 6, 18 + 181);
  const overStr = over.getFullYear() + '-' + pad(over.getMonth() + 1) + '-' + pad(over.getDate());
  assert.strictEqual(validateSendDate(overStr, today).ok, false, '181 days rejected (' + overStr + ')');
});

test('validateSendDate: month and year boundaries via calendar math', () => {
  // Last day of a month: the next day is tomorrow and must be accepted.
  assert.strictEqual(validateSendDate('2026-08-01', '2026-07-31').ok, true, 'crosses into August');
  // Year boundary.
  assert.strictEqual(validateSendDate('2027-01-01', '2026-12-31').ok, true, 'crosses into next year');
  assert.strictEqual(validateSendDate('2026-12-31', '2026-12-31').ok, false, 'today (year end) rejected');
});

test('validateSendDate: malformed values are rejected', () => {
  assert.strictEqual(validateSendDate('not-a-date', '2026-07-18').ok, false);
  assert.strictEqual(validateSendDate('2026-13-40', '2026-07-18').ok, false);
  assert.strictEqual(validateSendDate('07/19/2026', '2026-07-18').ok, false);
});

test('replyMailFields: a reply envelope is IMPOSSIBLE without the coupled perforation', () => {
  // Unchecked: neither field is emitted.
  assert.deepStrictEqual(replyMailFields(false), []);
  // Checked: both fields are emitted together, and the payload can never carry
  // a return envelope without perforated_page.
  const fields = replyMailFields(true);
  const asObj = Object.fromEntries(fields);
  assert.strictEqual(asObj.return_envelope, 'true');
  assert.strictEqual(asObj.perforated_page, '1');
  const hasEnvelope = fields.some((f) => f[0] === 'return_envelope');
  const hasPerf = fields.some((f) => f[0] === 'perforated_page');
  assert.strictEqual(hasEnvelope, hasPerf, 'return envelope and perforation are coupled: both or neither');
});

test('isSharedOptionError: shared-option 422s halt, recipient-specific ones do not', () => {
  // Shared options -> true (halt the batch).
  assert.strictEqual(isSharedOptionError('send_date must be a future date'), true);
  assert.strictEqual(isSharedOptionError('mail_type is invalid'), true);
  assert.strictEqual(isSharedOptionError('extra_service certified requires first class mail'), true);
  assert.strictEqual(isSharedOptionError('perforated_page must be 1 when return_envelope is set'), true);
  assert.strictEqual(isSharedOptionError('use_type is required'), true);
  // A shared-option error that ALSO names the recipient still halts: the bare
  // word "recipient" must not suppress the halt (regression guard for the
  // false-negative where 25 identical failures would otherwise be collected).
  assert.strictEqual(isSharedOptionError('send_date is invalid for recipient John Doe'), true);
  assert.strictEqual(isSharedOptionError('mail_type not allowed for this recipient'), true);
  // Recipient-specific -> false (keep going; only that letter failed). Only a
  // to[...] / to.... field path counts as per-letter.
  assert.strictEqual(isSharedOptionError('to.address_line1 is required'), false);
  assert.strictEqual(isSharedOptionError('to[address_zip] is not a valid zip'), false);
  assert.strictEqual(isSharedOptionError('recipient address is undeliverable'), false);
  // A recipient FIELD error that happens to contain a shared-option word stays
  // per-letter because it names a to[...] path.
  assert.strictEqual(isSharedOptionError('to[address_line1] has an invalid color code'), false);
  // Unrelated errors -> false (no halt on an unknown error).
  assert.strictEqual(isSharedOptionError('rate limited, try again'), false);
  assert.strictEqual(isSharedOptionError(''), false);
});

test('notAttemptedEntries: marks exactly the letters after the halt index, distinct from a rejection', () => {
  const rs = [{ id: 1, name: 'A' }, { id: 2, name: 'B' }, { id: 3, name: 'C' }, { id: 4, name: 'D' }];
  // A shared option was rejected on letter 2 (index 1): letters 3 and 4 were not attempted.
  const na = notAttemptedEntries(rs, 1);
  assert.strictEqual(na.length, 2);
  assert.deepStrictEqual(na.map((r) => r.recipient.id), [3, 4]);
  for (const r of na) {
    assert.strictEqual(r.success, false);
    assert.strictEqual(r.notAttempted, true, 'flagged not-attempted, distinct from a Lob rejection');
    assert.match(r.error, /Not attempted/);
    assert.match(r.error, /letter 2/);
  }
  // A halt on the LAST letter leaves nothing not-attempted.
  assert.deepStrictEqual(notAttemptedEntries(rs, 3), []);
});
