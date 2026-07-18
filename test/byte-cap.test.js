'use strict';
// Item 7: byteCapTransform in isolation, the pure counting cap the streamed proxy
// passthrough uses. Kept in ITS OWN file: requiring lib/proxy here transitively
// loads lib/config (which snapshots LOB_UPSTREAM at load), and the proxy
// integration test in proxy-stream-cap.test.js must set PD_LOB_UPSTREAM BEFORE
// that snapshot. Mixing the two in one file loaded config too early and silently
// pointed the integration proxy at the real api.lob.com instead of its stub.
const test = require('node:test');
const assert = require('node:assert');
const { pipeline, Readable, Writable } = require('node:stream');
const { byteCapTransform } = require('../lib/proxy');

function runCap(chunks, cap) {
  return new Promise((resolve) => {
    let bytes = 0;
    const sink = new Writable({ write(c, e, cb) { bytes += c.length; cb(); } });
    pipeline(Readable.from(chunks), byteCapTransform(cap), sink, (err) => resolve({ err: err || null, bytes }));
  });
}

test('byteCapTransform forwards everything when under the cap', async () => {
  const { err, bytes } = await runCap([Buffer.alloc(1000), Buffer.alloc(1000)], 4096);
  assert.strictEqual(err, null, 'no error under the cap');
  assert.strictEqual(bytes, 2000, 'all bytes forwarded');
});

test('byteCapTransform errors (and tears down) once the running total exceeds the cap', async () => {
  const { err, bytes } = await runCap([Buffer.alloc(2000), Buffer.alloc(2000), Buffer.alloc(2000)], 4096);
  assert.ok(err instanceof Error, 'over-cap stream errors');
  assert.match(err.message, /exceeded 4096 bytes/);
  assert.ok(bytes < 6000, 'the over-cap chunk is not forwarded (got ' + bytes + ')');
});
