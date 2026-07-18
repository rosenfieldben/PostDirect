'use strict';
// The whole point of parseLobDate is timezone behavior, so this suite pins TZ
// itself (Node re-reads process.env.TZ on the next Date operation on POSIX).
// Both zones are west of UTC, where the old new Date('YYYY-MM-DD') parse
// rendered the previous day.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// Extract the REAL parseLobDate()/formatShortDate() from public/index.html and
// evaluate them, so this suite tests the shipped logic (same brace-matched
// extraction as derive-status.test.js).
const SRC = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
function fnSrc(name) {
  const m = new RegExp('function\\s+' + name + '\\s*\\(').exec(SRC);
  if (!m) throw new Error('function not found in index.html: ' + name);
  let i = SRC.indexOf('{', m.index), depth = 0;
  for (; i < SRC.length; i++) { const c = SRC[i]; if (c === '{') depth++; else if (c === '}' && --depth === 0) { i++; break; } }
  return SRC.slice(m.index, i);
}
const { parseLobDate, formatShortDate, deriveStatus } =
  (new Function(fnSrc('parseLobDate') + '\n' + fnSrc('formatShortDate') + '\n' + fnSrc('deriveStatus') +
    '\nreturn { parseLobDate, formatShortDate, deriveStatus };'))();

const ORIGINAL_TZ = process.env.TZ;
function restoreTz() {
  if (ORIGINAL_TZ === undefined) delete process.env.TZ;
  else process.env.TZ = ORIGINAL_TZ;
}

test('date-only strings are calendar dates in negative-UTC-offset zones', () => {
  try {
    for (const tz of ['America/New_York', 'America/Los_Angeles']) {
      process.env.TZ = tz;
      // Guard against a platform that ignores the TZ switch: July 17 must be
      // in daylight time west of UTC, or the assertions below prove nothing.
      assert.ok(new Date(2026, 6, 17).getTimezoneOffset() > 0, tz + ' is west of UTC');
      const d = parseLobDate('2026-07-17');
      assert.deepStrictEqual(
        [d.getFullYear(), d.getMonth(), d.getDate()], [2026, 6, 17],
        '2026-07-17 must be July 17 local in ' + tz + ' (the UTC parse rendered July 16)'
      );
      assert.strictEqual(d.getTime(), new Date(2026, 6, 17).getTime(),
        'parsed as LOCAL midnight, so date comparisons use the calendar day');
      // Day-number assertions rather than the full string: toLocaleDateString
      // with an undefined locale renders in the machine's default locale.
      const rendered = formatShortDate('2026-07-17');
      assert.match(rendered, /17/, 'renders the 17th in ' + tz + ' (got ' + rendered + ')');
      assert.match(rendered, /2026/, 'renders the year in ' + tz);
      assert.doesNotMatch(rendered, /16/, 'must not render the previous day in ' + tz);
    }
  } finally {
    restoreTz();
  }
});

test('full timestamps pass through unchanged', () => {
  const iso = '2026-07-17T15:30:00.000Z';
  assert.strictEqual(parseLobDate(iso).getTime(), Date.parse(iso));
  const offset = '2026-07-17T15:30:00-04:00';
  assert.strictEqual(parseLobDate(offset).getTime(), Date.parse(offset));
});

test('deriveStatus compares a date-only expected_delivery_date by local calendar day', () => {
  const realNow = Date.now;
  try {
    process.env.TZ = 'America/New_York';
    assert.ok(new Date(2026, 6, 17).getTimezoneOffset() > 0, 'TZ switch honored');
    // 2026-07-17T02:00:00Z is 22:00 on July 16 in New York: the expected date is
    // still in the FUTURE locally. The old UTC-midnight parse put expected at
    // 2026-07-17T00:00:00Z, already past, which under the item-4 labels would
    // wrongly flip it to the "no delivery confirmation" (past-estimate) branch.
    // With the local-calendar parse it stays a plain "Created".
    Date.now = () => Date.parse('2026-07-17T02:00:00Z');
    const status = deriveStatus({
      date_sent: '2026-07-11T12:00:00.000Z',
      expected_delivery_date: '2026-07-17',
    });
    assert.deepStrictEqual(status, { label: 'Created', variant: 'progress' },
      'expected date is still future locally, so it is not yet past-estimate');
    assert.doesNotMatch(status.label, /no delivery confirmation/);
  } finally {
    Date.now = realNow;
    restoreTz();
  }
});

test('garbage input stays an Invalid Date and formatShortDate falls back to the raw string', () => {
  assert.ok(isNaN(parseLobDate('not-a-date').getTime()));
  assert.strictEqual(formatShortDate('not-a-date'), 'not-a-date');
  assert.strictEqual(formatShortDate(''), '');
  assert.strictEqual(formatShortDate(null), '');
});

test('malformed date-only shapes fall back to new Date(s), never a rolled-over calendar date', () => {
  assert.ok(isNaN(parseLobDate('2026-13-05').getTime()), 'month 13 must not roll into 2027');
  assert.ok(isNaN(parseLobDate('2026-00-10').getTime()), 'month 00 must not roll into 2025');
  assert.strictEqual(formatShortDate('2026-13-05'), '2026-13-05', 'renders the raw string');
  // V8's lenient fallback parser accepts Feb 30 (as March 2); the guard keeps
  // that raw-parse behavior instead of introducing its own rollover.
  assert.strictEqual(parseLobDate('2026-02-30').getTime(), new Date('2026-02-30').getTime());
  // Years below 100 keep the old UTC parse rather than mapping into 19xx.
  assert.strictEqual(parseLobDate('0099-05-05').getUTCFullYear(), 99);
});
