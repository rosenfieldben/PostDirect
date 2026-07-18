'use strict';
// multipart/form-data body builder for letter creation (pure).
// Extracted verbatim from the former inline <script> in public/index.html so
// the browser app and the Node unit tests share ONE source of truth (the unit
// tests import this module directly instead of re-parsing the HTML).

  // ═══ Multipart builder ═══
  // RFC 7578: strip CR/LF and replace " with %22 in any string written into a
  // multipart header (field name, filename, content-type) to prevent header /
  // part injection (e.g. a crafted filename forging extra form fields). Field
  // VALUES live in the body after the blank line and are left byte-for-byte intact.
  function mpHeaderSafe(s) {
    return String(s == null ? '' : s).replace(/[\r\n]/g, '').replace(/"/g, '%22');
  }

  function buildMultipart(fields, fileData, fileName, fileMimeType) {
    const boundary = '----PostDirect' + Math.random().toString(36).slice(2);
    const enc = new TextEncoder(), parts = [];
    for (const [k, val] of fields) parts.push(enc.encode('--' + boundary + '\r\nContent-Disposition: form-data; name="' + mpHeaderSafe(k) + '"\r\n\r\n' + val + '\r\n'));
    parts.push(enc.encode('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="' + mpHeaderSafe(fileName) + '"\r\nContent-Type: ' + mpHeaderSafe(fileMimeType) + '\r\n\r\n'));
    parts.push(new Uint8Array(fileData));
    parts.push(enc.encode('\r\n--' + boundary + '--\r\n'));
    const total = parts.reduce((s, p) => s + p.byteLength, 0), merged = new Uint8Array(total);
    let off = 0; for (const p of parts) { merged.set(p, off); off += p.byteLength; }
    return { body: merged.buffer, contentType: 'multipart/form-data; boundary=' + boundary };
  }

export { mpHeaderSafe, buildMultipart };
