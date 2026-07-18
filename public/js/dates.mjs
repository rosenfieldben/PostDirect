'use strict';
// Date parsing and honest lifecycle-status derivation (pure, no DOM).
// Extracted verbatim from the former inline <script> in public/index.html so
// the browser app and the Node unit tests share ONE source of truth (the unit
// tests import this module directly instead of re-parsing the HTML).

  // ═══ Status derivation from Lob fields ═══
  // Lob sends date-only strings for some fields (expected_delivery_date,
  // send_date). new Date('YYYY-MM-DD') is UTC midnight per spec, which
  // renders and compares as the PREVIOUS day anywhere west of UTC, so
  // date-only strings are parsed as local calendar dates via the local-time
  // constructor. Timestamps (and anything else) pass through to new Date.
  function parseLobDate(s) {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(s == null ? '' : s).trim());
    if (m) {
      const d = new Date(+m[1], +m[2] - 1, +m[3]);
      // Round-trip check: the multi-argument constructor never yields Invalid
      // Date, it rolls out-of-range components over (month 13 becomes next
      // January) and maps years below 100 into 19xx. Anything that does not
      // round-trip falls through to new Date(s), keeping the old
      // Invalid-Date fallback for malformed strings.
      if (d.getFullYear() === +m[1] && d.getMonth() === +m[2] - 1 && d.getDate() === +m[3]) return d;
    }
    return new Date(s);
  }

  function formatShortDate(s) {
    if (!s) return '';
    const d = parseLobDate(s);
    if (isNaN(d.getTime())) return s;
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  }

  // Honest lifecycle labels. USPS does not confirm final delivery for ordinary
  // First-Class mail, so the terminal event Lob reports is usually "Processed
  // for delivery", not a true "Delivered". Two rules follow: labels never
  // promise more than the event Lob actually reported, and NO success state is
  // ever inferred from timestamps alone (a create is not "Mailed"; a passed
  // delivery estimate with no delivery event is unconfirmed, not delivered).
  function deriveStatus(letter) {
    if (letter.fetch_error) return { label: 'Status unavailable', variant: 'muted' };
    if (letter.deleted) return { label: 'Canceled', variant: 'muted' };
    const events = Array.isArray(letter.tracking_events) ? letter.tracking_events : [];
    if (events.length > 0) {
      const sorted = events.slice().sort((a, b) => new Date(a.time || a.date_created || 0) - new Date(b.time || b.date_created || 0));
      const latest = sorted[sorted.length - 1];
      const name = (latest.name || latest.type || '').toLowerCase();
      if (/delivered/.test(name)) return { label: 'Delivered', variant: 'success' };
      if (/returned/.test(name)) return { label: 'Returned', variant: 'error' };
      // "Processed for delivery" is the strongest confirmation available for
      // ordinary First-Class mail, so it is the success terminal.
      if (/processed.*delivery/.test(name)) return { label: 'Processed for delivery', variant: 'success' };
      if (/out for delivery/.test(name)) return { label: 'Out for delivery', variant: 'progress' };
      if (/re.?routed/.test(name)) return { label: 'Re-routed', variant: 'progress' };
      if (/local area/.test(name)) return { label: 'In local area', variant: 'progress' };
      if (/in.?transit/.test(name)) return { label: 'In transit', variant: 'progress' };
      if (/mailed/.test(name)) return { label: 'Mailed', variant: 'progress' };
      return { label: latest.name || 'In progress', variant: 'progress' };
    }
    // No tracking events: a future send date is "Scheduled"; a passed delivery
    // estimate is reported as unconfirmed (never a success); everything else is
    // simply "Created". No timestamp ever yields a success variant.
    const now = Date.now();
    const send = letter.send_date ? parseLobDate(letter.send_date).getTime() : null;
    const expected = letter.expected_delivery_date ? parseLobDate(letter.expected_delivery_date).getTime() : null;
    if (send && send > now + 60000) return { label: 'Scheduled · ' + formatShortDate(letter.send_date), variant: 'muted' };
    if (expected && now > expected) return { label: 'Expected by ' + formatShortDate(letter.expected_delivery_date) + ', no delivery confirmation', variant: 'muted' };
    return { label: 'Created', variant: 'progress' };
  }

export { parseLobDate, formatShortDate, deriveStatus };
