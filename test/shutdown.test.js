'use strict';
// Item 7: graceful shutdown. Boot server.js as a child process, wait until it is
// listening, send SIGTERM, and assert it drains and exits 0 (no in-flight
// requests, so the drain completes at once). The signal handlers are installed
// only in the require.main entrypoint, so this exercises the real shutdown path.
const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

function bootServer(port) {
  const child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env: Object.assign({}, process.env, {
      PORT: String(port),
      PD_USERNAME: 'shutdown-user',
      PD_PASSWORD: 'shutdown-pass-1234',
      PD_SECRET: 'shutdown-secret-fixed-0123456789abcd',
      PD_DATA_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'pd-shutdown-')),
      PD_LOB_UPSTREAM: '',
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  child.stdout.on('data', (c) => { out += c.toString(); });
  child.stderr.on('data', (c) => { out += c.toString(); });
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('server did not report ready:\n' + out)), 10000);
    child.stdout.on('data', () => { if (/PostDirect is running/.test(out)) { clearTimeout(timer); resolve(); } });
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error('server exited before ready (code ' + code + '):\n' + out)); });
  });
  return { child, ready, dump: () => out };
}

test('SIGTERM drains and exits 0', async () => {
  const port = await freePort();
  const srv = bootServer(port);
  await srv.ready;
  const exited = new Promise((resolve) => srv.child.on('exit', (code, signal) => resolve({ code, signal })));
  srv.child.kill('SIGTERM');
  const guard = setTimeout(() => srv.child.kill('SIGKILL'), 8000);
  const { code } = await exited;
  clearTimeout(guard);
  assert.strictEqual(code, 0, 'clean drain must exit 0. Output:\n' + srv.dump());
  assert.match(srv.dump(), /Drained cleanly/, 'logs the clean-drain line');
});

test('SIGINT also drains and exits 0', async () => {
  const port = await freePort();
  const srv = bootServer(port);
  await srv.ready;
  const exited = new Promise((resolve) => srv.child.on('exit', (code) => resolve(code)));
  srv.child.kill('SIGINT');
  const guard = setTimeout(() => srv.child.kill('SIGKILL'), 8000);
  const code = await exited;
  clearTimeout(guard);
  assert.strictEqual(code, 0, 'SIGINT clean drain must exit 0. Output:\n' + srv.dump());
});
