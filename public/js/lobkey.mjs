'use strict';
// Client-side Lob key classifier: the ONE classifier on the browser side.
// Extracted verbatim from the former inline <script> in public/index.html so
// the browser app and the Node unit tests share ONE source of truth (the unit
// tests import this module directly instead of re-parsing the HTML).

  // Mirror of server.js lobKeyEnv, and the ONLY classifier on this side. It
  // must see the same trimmed value that authHeaders sends to Lob: classifying
  // the raw input while sending the trimmed key let " live_..." authenticate
  // as live while wearing the Test badge. Only test_ means Test; live_ and
  // unknown prefixes are Live, so an unrecognized key gets the live-mode
  // confirmation path instead of a reassuring Test badge.
  function lobKeyEnv(key) {
    const k = (key == null ? '' : String(key)).trim();
    if (!k) return null;
    return k.startsWith('test_') ? 'test' : 'live';
  }

export { lobKeyEnv };
