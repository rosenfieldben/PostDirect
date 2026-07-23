'use strict';
process.env.PD_SECRET = process.env.PD_SECRET || 'test-secret-fixed-value';

const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { validateStartupConfig, ensureDataDir } = require('../server.js');

const SERVER_JS = path.join(__dirname, '..', 'server.js');
// Credentials that satisfy startup validation, so the child-process tests
// below isolate the one variable each test is about (the port).
const GOOD_ENV = {
  PD_USERNAME: 'startup-itest-user',
  PD_PASSWORD: 'startup-itest-password',
  PD_SECRET: 'startup-itest-secret-0123456789abcdef',
};

// Run `node server.js` with EXACTLY the given env (plus PATH) and resolve
// with its exit code and output. The env is not merged with GOOD_ENV so tests
// can boot with credentials genuinely unset. A fresh temp PD_DATA_DIR is
// injected by default (overridable) so a booting child never creates ./data in
// the repo; a caller can override PD_DATA_DIR to exercise the data-dir check.
function spawnServer(env) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-startup-'));
  const child = spawn(process.execPath, [SERVER_JS], {
    env: { PATH: process.env.PATH, PD_DATA_DIR: dataDir, ...env },
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
  assert.strictEqual(validateStartupConfig({ ...GOOD_ENV }).ok, true, 'unset PORT falls back to the default');
  assert.strictEqual(validateStartupConfig({ ...GOOD_ENV, PORT: '' }).ok, true, 'empty PORT falls back to the default');
  assert.strictEqual(validateStartupConfig({ ...GOOD_ENV, PORT: '8080' }).ok, true);
  assert.strictEqual(validateStartupConfig({ ...GOOD_ENV, PORT: '1' }).ok, true);
  assert.strictEqual(validateStartupConfig({ ...GOOD_ENV, PORT: '65535' }).ok, true);
});

test('validateStartupConfig rejects non-integer and out-of-range ports', () => {
  for (const bad of ['not-a-port', '0', '65536', '-1', '80abc', '80.5', 'NaN']) {
    const r = validateStartupConfig({ ...GOOD_ENV, PORT: bad });
    assert.strictEqual(r.ok, false, 'PORT=' + JSON.stringify(bad) + ' must be rejected');
    assert.ok(r.errors.some((e) => e.includes('PORT')), 'error names PORT for ' + JSON.stringify(bad));
  }
});

test('PORT=not-a-port exits nonzero with a clear one-line error', async () => {
  const r = await expectExit(spawnServer({ ...GOOD_ENV, PORT: 'not-a-port' }), 10000);
  assert.ok(r, 'server must exit, not boot');
  assert.notStrictEqual(r.code, 0, 'process must not exit 0');
  assert.match(r.stderr(), /FATAL: PORT must be an integer/);
});

test('binding an occupied port exits nonzero', async () => {
  // Hold a port open, then start the server on it: the EADDRINUSE listen
  // error must be fatal, not swallowed by the uncaughtException net.
  const holder = net.createServer();
  const port = await new Promise((resolve) => holder.listen(0, '127.0.0.1', () => resolve(holder.address().port)));
  try {
    const r = await expectExit(spawnServer({ ...GOOD_ENV, PORT: String(port) }), 10000);
    assert.ok(r, 'server must exit, not boot');
    assert.notStrictEqual(r.code, 0, 'process must not exit 0');
    assert.match(r.stderr(), /FATAL: could not listen on port/);
    assert.match(r.stderr(), /EADDRINUSE/);
  } finally {
    await new Promise((resolve) => holder.close(resolve));
  }
});

// Wait for the startup banner, bounded. Both timers are cleared on both
// paths: a timer leaked after rejection would keep this test process alive
// and hang the whole run instead of reporting the failure.
function waitForBanner(stdout) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      clearInterval(poll);
      reject(new Error('server did not start; stdout: ' + stdout()));
    }, 10000);
    const poll = setInterval(() => {
      if (stdout().includes('PostDirect is running')) { clearTimeout(t); clearInterval(poll); resolve(); }
    }, 50);
  });
}

// Bounded wait for a child that SHOULD exit on its own. If a regression made
// it boot instead, the exited promise would never settle and the suite would
// hang, so on overrun the child is killed and null is returned for the
// caller to assert on.
function expectExit(handle, ms) {
  return new Promise((resolve) => {
    const t = setTimeout(() => {
      handle.child.kill('SIGKILL');
      handle.exited.then(() => resolve(null));
    }, ms);
    handle.exited.then((r) => { clearTimeout(t); resolve(r); });
  });
}

function getStatus(host, port) {
  return new Promise((resolve, reject) => {
    const req = require('node:http').get({ host, port, path: '/login', timeout: 3000 }, (res) => {
      res.resume();
      resolve(res.statusCode);
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

test('valid config binds and serves exactly as before', async () => {
  const port = await freePort();
  const { child, exited, stdout } = spawnServer({ ...GOOD_ENV, PORT: String(port) });
  try {
    await waitForBanner(stdout);
    const status = await getStatus('127.0.0.1', port);
    assert.strictEqual(status, 200, 'login page served on the validated port');
  } finally {
    child.kill('SIGTERM');
    await exited;
  }
});

// ── Credential validation (item 4): applies under EVERY NODE_ENV value ──

test('validateStartupConfig refuses unset or default credentials under any NODE_ENV', () => {
  for (const nodeEnv of [undefined, 'production', 'development', 'prodcution']) {
    const env = nodeEnv === undefined ? {} : { NODE_ENV: nodeEnv };
    const r = validateStartupConfig(env);
    assert.strictEqual(r.ok, false, 'NODE_ENV=' + JSON.stringify(nodeEnv));
    for (const name of ['PD_USERNAME', 'PD_PASSWORD', 'PD_SECRET']) {
      assert.ok(r.errors.some((e) => e.includes(name)), name + ' named under NODE_ENV=' + JSON.stringify(nodeEnv));
    }
  }
});

test('validateStartupConfig refuses each weak or default credential individually', () => {
  const cases = [
    [{ ...GOOD_ENV, PD_USERNAME: 'admin' }, 'PD_USERNAME'],
    [{ ...GOOD_ENV, PD_PASSWORD: 'changeme' }, 'PD_PASSWORD'],
    [{ ...GOOD_ENV, PD_PASSWORD: 'elevenchars' }, 'at least 12'],
    [{ ...GOOD_ENV, PD_SECRET: '' }, 'PD_SECRET'],
    [{ ...GOOD_ENV, PD_SECRET: 'x'.repeat(31) }, 'at least 32'],
  ];
  for (const [env, needle] of cases) {
    const r = validateStartupConfig(env);
    assert.strictEqual(r.ok, false, JSON.stringify(env));
    assert.ok(r.errors.some((e) => e.includes(needle)), 'error mentions ' + JSON.stringify(needle));
  }
  // The floors, exactly: 12 and 32 characters pass.
  assert.strictEqual(validateStartupConfig({ ...GOOD_ENV, PD_PASSWORD: 'twelve-chars' }).ok, true);
  assert.strictEqual(validateStartupConfig({ ...GOOD_ENV, PD_SECRET: 'x'.repeat(32) }).ok, true);
});

test('validateStartupConfig treats a half-configured Access perimeter as fatal', () => {
  // Both set or both unset are fine; exactly one set is a boot error, because a
  // half-configured perimeter reads as protected while enforcing nothing.
  assert.strictEqual(validateStartupConfig({ ...GOOD_ENV }).ok, true, 'neither var: fine');
  assert.strictEqual(validateStartupConfig({ ...GOOD_ENV, PD_ACCESS_TEAM_DOMAIN: 'acme.cloudflareaccess.com', PD_ACCESS_AUD: 'a1' }).ok, true, 'both vars: fine');
  const onlyDomain = validateStartupConfig({ ...GOOD_ENV, PD_ACCESS_TEAM_DOMAIN: 'acme.cloudflareaccess.com' });
  assert.strictEqual(onlyDomain.ok, false);
  assert.ok(onlyDomain.errors.some((e) => /half-configured/.test(e)), 'error names the half-config');
  const onlyAud = validateStartupConfig({ ...GOOD_ENV, PD_ACCESS_AUD: 'a1' });
  assert.strictEqual(onlyAud.ok, false);
  assert.ok(onlyAud.errors.some((e) => /half-configured/.test(e)));
  // A bad team domain (both set) is also fatal.
  const badDomain = validateStartupConfig({ ...GOOD_ENV, PD_ACCESS_TEAM_DOMAIN: 'evil.example.com', PD_ACCESS_AUD: 'a1' });
  assert.strictEqual(badDomain.ok, false);
  assert.ok(badDomain.errors.some((e) => /team domain/.test(e)));
});

test('PD_INSECURE_LOCAL_DEMO=1 permits defaults but forces a loopback bind', () => {
  const demo = validateStartupConfig({ PD_INSECURE_LOCAL_DEMO: '1' });
  assert.strictEqual(demo.ok, true, 'defaults allowed under the demo flag');
  assert.strictEqual(demo.host, '127.0.0.1', 'demo mode binds loopback only');
  assert.strictEqual(demo.insecureDemo, true);
  // A bad PORT is still fatal even in demo mode.
  assert.strictEqual(validateStartupConfig({ PD_INSECURE_LOCAL_DEMO: '1', PORT: 'nope' }).ok, false);
  // A normal, strong config binds all interfaces as before.
  const normal = validateStartupConfig(GOOD_ENV);
  assert.strictEqual(normal.ok, true);
  assert.strictEqual(normal.host, undefined);
});

test('booting on defaults exits nonzero, with and without NODE_ENV=production', async () => {
  for (const extra of [{}, { NODE_ENV: 'production' }]) {
    const r = await expectExit(spawnServer(extra), 10000);
    assert.ok(r, 'server must exit, not boot (env: ' + JSON.stringify(extra) + ')');
    assert.notStrictEqual(r.code, 0, 'defaults must not boot (env: ' + JSON.stringify(extra) + ')');
    assert.match(r.stderr(), /FATAL: PD_PASSWORD/);
    assert.match(r.stderr(), /PD_INSECURE_LOCAL_DEMO/, 'the demo escape hatch is mentioned');
  }
});

test('a half-configured Access perimeter exits nonzero at boot', async () => {
  const r = await expectExit(spawnServer({ ...GOOD_ENV, PD_ACCESS_TEAM_DOMAIN: 'acme.cloudflareaccess.com' }), 10000);
  assert.ok(r, 'server must exit, not boot');
  assert.notStrictEqual(r.code, 0, 'a half-configured perimeter must not boot');
  assert.match(r.stderr(), /FATAL: .*half-configured/);
});

// ── Data directory validation (item 1): unwritable PD_DATA_DIR is fatal ──

test('ensureDataDir succeeds on a fresh dir and fails on an unusable one', () => {
  const ok = ensureDataDir(fs.mkdtempSync(path.join(os.tmpdir(), 'pd-dd-')));
  assert.strictEqual(ok.ok, true);
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-dd-'));
  const asFile = path.join(base, 'file');
  fs.writeFileSync(asFile, 'x');
  const bad = ensureDataDir(path.join(asFile, 'sub')); // parent is a file -> ENOTDIR, uid-independent
  assert.strictEqual(bad.ok, false);
  assert.match(bad.error, /not usable/);
});

test('an unwritable PD_DATA_DIR fails startup nonzero with a clear message', async () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-dd-'));
  const asFile = path.join(base, 'file');
  fs.writeFileSync(asFile, 'x');
  // PD_DATA_DIR whose parent is a regular file: mkdir throws ENOTDIR regardless
  // of uid (so the check is meaningful even when the test runs as root).
  const r = await expectExit(spawnServer({ ...GOOD_ENV, PD_DATA_DIR: path.join(asFile, 'data') }), 10000);
  assert.ok(r, 'server must exit, not boot');
  assert.notStrictEqual(r.code, 0, 'unwritable data dir must not boot');
  assert.match(r.stderr(), /FATAL: PD_DATA_DIR/);
});

test('demo flag boots on defaults, warns loudly, and serves on loopback only', async () => {
  const port = await freePort();
  const { child, exited, stdout } = spawnServer({ PD_INSECURE_LOCAL_DEMO: '1', PORT: String(port) });
  try {
    await waitForBanner(stdout);
    assert.match(stdout(), /WARNING: PD_INSECURE_LOCAL_DEMO=1/, 'loud startup warning');
    assert.match(stdout(), /127\.0\.0\.1 ONLY/, 'warning states the loopback bind');
    assert.strictEqual(await getStatus('127.0.0.1', port), 200, 'serves on loopback');
    // If this machine has a non-loopback address, the demo server must NOT be
    // reachable on it (loopback-only bind).
    const os = require('node:os');
    const external = Object.values(os.networkInterfaces()).flat()
      .find((i) => i && i.family === 'IPv4' && !i.internal);
    if (external) {
      await assert.rejects(getStatus(external.address, port),
        'demo server must not listen on ' + external.address);
    }
  } finally {
    child.kill('SIGTERM');
    await exited;
  }
});
