'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// Extract the REAL esc()/ESC_MAP source from public/index.html and evaluate it,
// so this suite tests the shipped code (not a copy). If the source shape changes
// incompatibly, extraction throws and the suite fails loudly.
const SRC = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
function line(re) { const m = re.exec(SRC); if (!m) throw new Error('not found in index.html: ' + re); return m[0]; }
const escMapSrc = line(/const ESC_MAP = \{[^}]*\};/);
const escSrc = line(/const esc = s => [^\n]*;/);
const { esc } = (new Function(escMapSrc + '\n' + escSrc + '\nreturn { esc };'))();

test('esc encodes &, <, >, " and \' (from index.html source)', () => {
  assert.strictEqual(esc('&'), '&amp;');
  assert.strictEqual(esc('<'), '&lt;');
  assert.strictEqual(esc('>'), '&gt;');
  assert.strictEqual(esc('"'), '&quot;');
  assert.strictEqual(esc("'"), '&#39;');
  assert.strictEqual(esc(null), '');
  assert.strictEqual(esc(undefined), '');
  assert.strictEqual(esc(0), '0');
});

test('attribute-injection payloads are neutralized', () => {
  const out = esc('" onmouseover="alert(1)');
  assert.ok(!out.includes('"'), 'no raw double-quote can terminate the attribute');
  assert.strictEqual(out, '&quot; onmouseover=&quot;alert(1)');
});

test('Bob\'s "Best" Plumbing round-trips to an attribute-safe encoding', () => {
  const out = esc('Bob\'s "Best" Plumbing');
  assert.strictEqual(out, 'Bob&#39;s &quot;Best&quot; Plumbing');
  assert.ok(!/["'<>]/.test(out), 'no raw quote/angle chars remain');
});
