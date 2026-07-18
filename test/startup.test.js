'use strict';
process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value';

const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { validateStartupConfig } = require('../server.js');

const SERVER_JS = path.join(__dirname, '..', 'server.js');
// Credentials that satisfy startup validation, so the child-process tests
// below isolate the one variable each test is about (the port).
const GOOD_ENV = {
  PD_USERNAME: 'startup-itest-user',
  PD_PASSWORD: 'startup-itest-password',
  PD_SECRET: 'startup-itest-secret-0123456789abcdef',
};

// Run `node server.js` with the given env and resolve with its exit code and
// output. The child either exits on its own (fatal startup error) or reaches
// onListen output and is killed by the caller via the returned handle.
function spawnServer(env) {
  const child = spawn(process.execPath, [SERVER_JS], {
    env: { ...GOOD_ENV, PATH: process.env.PATH, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '';
  child.stdout.on('data', (d) => { stdout += d; });
  child.stderr.on('data', (d) => { stderr += d; });
  const exited = new Promise((resolve) => {
    child.on('close', (code) => resolve({ code, stdout: () => stdout, stderr: () => stderr }));
  });
  return { child, exited, stdout: () => stdout, stderr: () => stderr };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

test('validateStartupConfig accepts the default and explicit valid ports', () => {
  assert.strictEqual(validateStartupConfig({}).ok, true, 'unset PORT falls back to the default');
  assert.strictEqual(validateStartupConfig({ PORT: '' }).ok, true, 'empty PORT falls back to the default');
  assert.strictEqual(validateStartupConfig({ PORT: '8080' }).ok, true);
  assert.strictEqual(validateStartupConfig({ PORT: '1' }).ok, true);
  assert.strictEqual(validateStartupConfig({ PORT: '65535' }).ok, true);
});

test('validateStartupConfig rejects non-integer and out-of-range ports', () => {
  for (const bad of ['not-a-port', '0', '65536', '-1', '80abc', '80.5', 'NaN']) {
    const r = validateStartupConfig({ PORT: bad });
    assert.strictEqual(r.ok, false, 'PORT=' + JSON.stringify(bad) + ' must be rejected');
    assert.ok(r.errors.some((e) => e.includes('PORT')), 'error names PORT for ' + JSON.stringify(bad));
  }
});

test('PORT=not-a-port exits nonzero with a clear one-line error', async () => {
  const { exited } = spawnServer({ PORT: 'not-a-port' });
  const r = await exited;
  assert.notStrictEqual(r.code, 0, 'process must not exit 0');
  assert.match(r.stderr(), /FATAL: PORT must be an integer/);
});

test('binding an occupied port exits nonzero', async () => {
  // Hold a port open, then start the server on it: the EADDRINUSE listen
  // error must be fatal, not swallowed by the uncaughtException net.
  const holder = net.createServer();
  const port = await new Promise((resolve) => holder.listen(0, '127.0.0.1', () => resolve(holder.address().port)));
  try {
    const { exited } = spawnServer({ PORT: String(port) });
    const r = await exited;
    assert.notStrictEqual(r.code, 0, 'process must not exit 0');
    assert.match(r.stderr(), /FATAL: could not listen on port/);
    assert.match(r.stderr(), /EADDRINUSE/);
  } finally {
    await new Promise((resolve) => holder.close(resolve));
  }
});

test('valid config binds and serves exactly as before', async () => {
  const port = await freePort();
  const { child, exited, stdout } = spawnServer({ PORT: String(port) });
  try {
    // Wait for the startup banner (bounded; the test runner enforces overall time).
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('server did not start; stdout: ' + stdout())), 10000);
      const poll = setInterval(() => {
        if (stdout().includes('PostDirect is running')) { clearTimeout(t); clearInterval(poll); resolve(); }
      }, 50);
    });
    const status = await new Promise((resolve, reject) => {
      const req = require('node:http').get({ host: '127.0.0.1', port, path: '/login' }, (res) => {
        res.resume();
        resolve(res.statusCode);
      });
      req.on('error', reject);
    });
    assert.strictEqual(status, 200, 'login page served on the validated port');
  } finally {
    child.kill('SIGTERM');
    await exited;
  }
});
