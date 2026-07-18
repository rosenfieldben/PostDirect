'use strict';
// Address normalization, USPS-correction diffing, and verification verdicts (pure).
// Extracted verbatim from the former inline <script> in public/index.html so
// the browser app and the Node unit tests share ONE source of truth (the unit
// tests import this module directly instead of re-parsing the HTML).

  // Byte-for-byte mirror of server.js normalizeAddressForHash (pinned by a
  // cross-implementation test). Sent as X-PD-Recipient-Hash on letter creation
  // so the proof export can correlate a verification (hashed server-side from
  // the SAME typed address) to this letter without depending on how Lob echoes
  // the recipient back in its response.
  function normalizeAddressForHash(a) {
    const norm = (s) => String(s == null ? '' : s).toUpperCase().replace(/\s+/g, ' ').trim();
    const zip5 = norm(a && a.zip).replace(/[^0-9].*$/, '').slice(0, 5);
    return [norm(a && a.line1), norm(a && a.line2), norm(a && a.city), norm(a && a.state), zip5].join('|');
  }

  // USPS-standardized address from a verification response, plus whether it
  // differs from what was typed. Case and whitespace are ignored in the
  // comparison: USPS standardization is all-caps, and a pure case change
  // isn't worth a correction prompt.
  function correctedAddress(typed, data) {
    const comp = (data && data.components) || {};
    const corrected = {
      line1: (data && data.primary_line) || '',
      line2: (data && data.secondary_line) || '',
      city: comp.city || '',
      state: comp.state || '',
      zip: comp.zip_code || '',
    };
    const norm = s => String(s == null ? '' : s).toUpperCase().replace(/\s+/g, ' ').trim();
    const differs = ['line1', 'line2', 'city', 'state', 'zip'].some(k => norm(corrected[k]) !== norm(typed[k]));
    return { corrected, differs };
  }

  // ═══ Address verification (Lob US Verifications) ═══
  // Map a Lob POST /v1/us_verifications response onto a UI verdict.
  // Levels: ok (deliverable) · warn (deliverable, unit issues) · blocked
  // (undeliverable — requires explicit acknowledgment to send) · error
  // (verification itself failed — fail OPEN, never blocking the send, since a
  // missing verification entitlement or a Lob hiccup shouldn't brick mailing).
  function verificationVerdict(data) {
    if (!data || data.error) {
      return { level: 'error', label: 'Couldn’t verify', note: (data && data.error && data.error.message) || 'Verification unavailable — you can still send.' };
    }
    switch (data.deliverability) {
      case 'deliverable':
        return { level: 'ok', label: 'Deliverable', note: '' };
      case 'deliverable_unnecessary_unit':
        return { level: 'warn', label: 'Deliverable · unit unnecessary', note: 'USPS says this address doesn’t need the unit/suite you provided.' };
      case 'deliverable_incorrect_unit':
        return { level: 'warn', label: 'Deliverable · unit looks wrong', note: 'The building exists but the unit/suite doesn’t match USPS records.' };
      case 'deliverable_missing_unit':
        return { level: 'warn', label: 'Deliverable · unit missing', note: 'This building needs a unit/suite number for reliable delivery.' };
      case 'undeliverable':
        return { level: 'blocked', label: 'Undeliverable', note: 'USPS has no deliverable match for this address.' };
      default:
        return { level: 'error', label: 'Couldn’t verify', note: 'Unrecognized verification result — you can still send.' };
    }
  }

export { normalizeAddressForHash, correctedAddress, verificationVerdict };
