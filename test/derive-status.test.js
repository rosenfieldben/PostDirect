'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// Extract the REAL deriveStatus()/formatShortDate() from public/index.html and
// evaluate them, so this suite tests the shipped logic. deriveStatus reads the
// real Date.now() internally, so the date-based branches use dates expressed
// RELATIVE to Date.now() (consistent to within test runtime).
const SRC = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
function fnSrc(name) {
  const m = new RegExp('function\\s+' + name + '\\s*\\(').exec(SRC);
  if (!m) throw new Error('function not found in index.html: ' + name);
  let i = SRC.indexOf('{', m.index), depth = 0;
  for (; i < SRC.length; i++) { const c = SRC[i]; if (c === '{') depth++; else if (c === '}' && --depth === 0) { i++; break; } }
  return SRC.slice(m.index, i);
}
const { deriveStatus } =
  (new Function(fnSrc('parseLobDate') + '\n' + fnSrc('formatShortDate') + '\n' + fnSrc('deriveStatus') + '\nreturn { deriveStatus, formatShortDate };'))();

const ev = (name, time) => ({ name, time: time || '2026-06-01T00:00:00Z' });
const DAY = 24 * 3600 * 1000;
const now = () => Date.now();

test('tracking-event regex ladder maps to the right {label, variant}', () => {
  assert.deepStrictEqual(deriveStatus({ tracking_events: [ev('Delivered')] }), { label: 'Delivered', variant: 'success' });
  assert.deepStrictEqual(deriveStatus({ tracking_events: [ev('Returned to Sender')] }), { label: 'Returned', variant: 'error' });
  assert.deepStrictEqual(deriveStatus({ tracking_events: [ev('Out for Delivery')] }), { label: 'Out for delivery', variant: 'progress' });
  // Item 4: "Processed for delivery" is now the strongest confirmation for
  // ordinary First-Class mail and is a SUCCESS variant, not "Out for delivery".
  assert.deepStrictEqual(deriveStatus({ tracking_events: [ev('Package processed for delivery')] }), { label: 'Processed for delivery', variant: 'success' });
  assert.deepStrictEqual(deriveStatus({ tracking_events: [ev('Re-Routed')] }), { label: 'Re-routed', variant: 'progress' });
  assert.deepStrictEqual(deriveStatus({ tracking_events: [ev('Arrived in local area')] }), { label: 'In local area', variant: 'progress' });
  assert.deepStrictEqual(deriveStatus({ tracking_events: [ev('In Transit to Next Facility')] }), { label: 'In transit', variant: 'progress' });
  assert.deepStrictEqual(deriveStatus({ tracking_events: [ev('Mailed')] }), { label: 'Mailed', variant: 'progress' });
  assert.deepStrictEqual(deriveStatus({ tracking_events: [ev('Carrier note we do not recognize')] }), { label: 'Carrier note we do not recognize', variant: 'progress' });
});

test('latest event (by time) wins, regardless of array order', () => {
  const events = [ev('Mailed', '2026-06-01T00:00:00Z'), ev('Delivered', '2026-06-04T00:00:00Z')];
  assert.deepStrictEqual(deriveStatus({ tracking_events: events }), { label: 'Delivered', variant: 'success' });
  assert.deepStrictEqual(deriveStatus({ tracking_events: events.slice().reverse() }), { label: 'Delivered', variant: 'success' });
});

test('pre-event states take precedence (fetch_error, deleted)', () => {
  assert.deepStrictEqual(deriveStatus({ fetch_error: 'boom', tracking_events: [ev('Delivered')] }), { label: 'Status unavailable', variant: 'muted' });
  assert.deepStrictEqual(deriveStatus({ deleted: true, tracking_events: [ev('Delivered')] }), { label: 'Canceled', variant: 'muted' });
});

test('date-based fallback when there are no tracking events (item 4: no success from timestamps)', () => {
  const scheduled = deriveStatus({ send_date: new Date(now() + 3 * DAY).toISOString() });
  assert.strictEqual(scheduled.variant, 'muted');
  assert.ok(scheduled.label.startsWith('Scheduled'), 'label: ' + scheduled.label);

  // A fresh create is "Created", never "Mailed" and never a success variant.
  const fresh = deriveStatus({ date_sent: new Date(now() - 3600 * 1000).toISOString() });
  assert.deepStrictEqual(fresh, { label: 'Created', variant: 'progress' });

  // A passed delivery estimate with no events is NOT a success: it is reported
  // as unconfirmed. "Delivered (est.)" is gone entirely.
  const passedEstimate = deriveStatus({ date_sent: new Date(now() - 5 * DAY).toISOString(), expected_delivery_date: new Date(now() - DAY).toISOString() });
  assert.strictEqual(passedEstimate.variant, 'muted', 'not a success variant');
  assert.match(passedEstimate.label, /no delivery confirmation/);
  assert.doesNotMatch(passedEstimate.label, /Delivered \(est\.\)/);

  // Nothing scheduled, nothing passed: simply "Created".
  assert.deepStrictEqual(deriveStatus({ date_sent: new Date(now() - 5 * DAY).toISOString() }), { label: 'Created', variant: 'progress' });
});

test('no timestamp combination ever yields a success variant (item 4 invariant)', () => {
  const cases = [
    { date_sent: new Date(now()).toISOString() },
    { date_sent: new Date(now() - 30 * DAY).toISOString() },
    { date_sent: new Date(now() - 30 * DAY).toISOString(), expected_delivery_date: new Date(now() - 10 * DAY).toISOString() },
    { send_date: new Date(now() + DAY).toISOString() },
  ];
  for (const c of cases) {
    assert.notStrictEqual(deriveStatus(c).variant, 'success', JSON.stringify(c) + ' must not be success');
  }
  // Only a genuine delivery-class EVENT produces success.
  assert.strictEqual(deriveStatus({ tracking_events: [ev('Delivered')] }).variant, 'success');
  assert.strictEqual(deriveStatus({ tracking_events: [ev('Processed for delivery')] }).variant, 'success');
});
