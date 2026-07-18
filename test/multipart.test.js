'use strict';
const test = require('node:test');
const assert = require('node:assert');

// Import the REAL buildMultipart()/mpHeaderSafe() from the shipped ES module
// (js/multipart.mjs), so this suite tests the shipped code (TextEncoder is a
// Node global).
const { buildMultipart, mpHeaderSafe } = require('../public/js/multipart.mjs');

const decode = buf => Buffer.from(buf).toString('latin1'); // byte-exact for ASCII + binary

test('boundary, field headers/values, file part, and closing delimiter', () => {
  const fields = [['from[name]', 'Jane Smith'], ['to[address_city]', 'New York']];
  const fileBytes = new Uint8Array([0x25, 0x50, 0x44, 0x46]); // "%PDF"
  const { body, contentType } = buildMultipart(fields, fileBytes.buffer, 'letter.pdf', 'application/pdf');

  const m = contentType.match(/^multipart\/form-data; boundary=(.+)$/);
  assert.ok(m, 'contentType carries the boundary');
  const boundary = m[1];
  const text = decode(body);

  assert.ok(text.startsWith('--' + boundary + '\r\n'), 'opens with the boundary');
  assert.ok(text.endsWith('--' + boundary + '--\r\n'), 'closes with the terminating boundary');
  assert.ok(text.includes('Content-Disposition: form-data; name="from[name]"\r\n\r\nJane Smith\r\n'));
  assert.ok(text.includes('Content-Disposition: form-data; name="to[address_city]"\r\n\r\nNew York\r\n'));
  assert.ok(text.includes('name="file"; filename="letter.pdf"\r\nContent-Type: application/pdf\r\n\r\n'));
  assert.ok(text.includes('%PDF'), 'raw file bytes are present verbatim');
});

test('mpHeaderSafe strips CR/LF and percent-encodes double-quotes', () => {
  assert.strictEqual(mpHeaderSafe('a"b'), 'a%22b');
  assert.strictEqual(mpHeaderSafe('a\r\nb'), 'ab');
  assert.strictEqual(mpHeaderSafe('a\nb\rc'), 'abc');
  assert.strictEqual(mpHeaderSafe(null), '');
  assert.strictEqual(mpHeaderSafe('plain.pdf'), 'plain.pdf');
});

test('crafted filename cannot inject extra multipart headers/parts', () => {
  const evil = 'x.pdf"\r\nContent-Disposition: form-data; name="use_type"\r\n\r\nmarketing\r\n--';
  const { body } = buildMultipart([], new Uint8Array([1, 2, 3]).buffer, evil, 'application/pdf');
  const text = decode(body);
  assert.ok(!text.includes('\r\nContent-Disposition: form-data; name="use_type"'), 'no forged header line');
  assert.ok(text.includes('filename="x.pdf%22Content-Disposition: form-data; name=%22use_type%22marketing--"'),
    'CRLF stripped and quotes percent-encoded into one header line');
});

test('crafted field NAME cannot inject headers either', () => {
  const evilName = 'a"\r\nX-Injected: 1';
  const { body } = buildMultipart([[evilName, 'val']], new Uint8Array([0]).buffer, 'f.pdf', 'application/pdf');
  const text = decode(body);
  assert.ok(!text.includes('\r\nX-Injected: 1'), 'no injected header from the field name');
  assert.ok(text.includes('name="a%22X-Injected: 1"'), 'field name sanitized inline');
});

test('field VALUES (body) are left byte-for-byte intact (RFC 7578)', () => {
  const { body } = buildMultipart([['note', 'He said "hi"\nbye']], new Uint8Array([0]).buffer, 'f.pdf', 'application/pdf');
  const text = decode(body);
  assert.ok(text.includes('\r\n\r\nHe said "hi"\nbye\r\n'), 'value preserved verbatim, quotes and all');
});
