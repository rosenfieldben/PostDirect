'use strict';
// Duplicate-send confirmation against the durable server record (global fetch/confirm).
// Extracted verbatim from the former inline <script> in public/index.html so
// the browser app and the Node unit tests share ONE source of truth (the unit
// tests import this module directly instead of re-parsing the HTML).

  // Consult the durable server record for prior sends of each fingerprint and,
  // on any hit, ask the operator to confirm. Warn, never block: the operator
  // may legitimately resend (this tool's philosophy is to inform, not refuse,
  // established by the anti-lockout decision). A network hiccup on the check
  // never blocks the send. Returns true to proceed, false to cancel.
  async function confirmDuplicateSends(rs, fingerprints) {
    // Check every recipient's fingerprint in PARALLEL (was one serial round trip
    // per recipient before the first letter fired). Promise.all preserves order,
    // so the hits list stays in recipient order.
    const checks = await Promise.all(rs.map(async (recipient, i) => {
      try {
        const resp = await fetch('/api/sends?fingerprint=' + encodeURIComponent(fingerprints[i]), { method: 'GET' });
        if (!resp.ok) return null;
        const j = await resp.json();
        if (j && Array.isArray(j.sends) && j.sends.length) return { recipient, sends: j.sends };
      } catch (e) { /* check failed: do not block the send */ }
      return null;
    }));
    const hits = checks.filter(Boolean);
    if (!hits.length) return true;
    const describe = (h) => {
      const s = h.sends[h.sends.length - 1];
      let when = 'a prior date';
      try { if (s && s.date) when = new Date(s.date).toLocaleString(); } catch (e) { /* keep default */ }
      const times = h.sends.length > 1 ? (h.sends.length + ' prior sends, most recently ') : 'a prior send ';
      return '• ' + (h.recipient.name || 'recipient') + ': ' + times + 'on ' + when + ' (' + (s && s.letterId ? s.letterId : 'unknown id') + ')';
    };
    return confirm(
      'Possible duplicate send.\n\n' + hits.map(describe).join('\n') +
      '\n\nAn identical letter to these recipients was already recorded on this account. ' +
      'Within 24 hours an identical resubmit is de-duplicated by Lob (the same letter); after that it is a NEW piece of physical mail. ' +
      'Send anyway?'
    );
  }

export { confirmDuplicateSends };
