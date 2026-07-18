'use strict';
// Attribute-safe HTML escaping (pure).
// Extracted verbatim from the former inline <script> in public/index.html so
// the browser app and the Node unit tests share ONE source of truth (the unit
// tests import this module directly instead of re-parsing the HTML).

  // Attribute-safe HTML escaper: covers & < > " ' so values are safe in both
  // text content and double/single-quoted attribute contexts (data-*, value, href).
  const ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

  const esc = s => (s == null ? '' : String(s)).replace(/[&<>"']/g, c => ESC_MAP[c]);

export { ESC_MAP, esc };
