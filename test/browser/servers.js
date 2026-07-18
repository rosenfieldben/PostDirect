'use strict';
// Boots the real app (server.js as a child process) against a local stub Lob
// upstream, exactly like the unit integration tests but for the browser suite.
// No real network, no real Lob. Returns { appUrl, creds, dataDir, stop }.
const http = require('node:http');
const os = require('node:os');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const APP_ENTRY = path.join(__dirname, '..', '..', 'server.js');

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = http.createServer();
    srv.listen(0, '127.0.0.1', () => { const p = srv.address().port; srv.close(() => resolve(p)); });
    srv.on('error', reject);
  });
}

function tryGet(url) {
  return new Promise((resolve) => {
    const req = http.get(url, (res) => { res.resume(); resolve(res.statusCode); });
    req.on('error', () => resolve(0));
    req.setTimeout(1000, () => { req.destroy(); resolve(0); });
  });
}

// A stub Lob upstream: just enough of the API for the app's flows. Keeps the
// letters it creates in memory so the List and Get endpoints echo them back.
function startStub() {
  const letters = new Map();
  let counter = 0;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const p = new URL(req.url, 'http://stub').pathname;
      const json = (status, obj) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };

      // Rendered PDF asset (a letter's `url` points here; proof export fetches it).
      if (req.method === 'GET' && p.startsWith('/rendered/')) {
        res.writeHead(200, { 'Content-Type': 'application/pdf' });
        res.end(Buffer.from('%PDF-1.4 stub rendered letter\n%%EOF'));
        return;
      }
      // Create letter.
      if (req.method === 'POST' && p === '/v1/letters') {
        counter += 1;
        const id = 'ltr_stub' + String(counter).padStart(6, '0');
        const text = body.toString('latin1');
        const field = (name) => {
          const re = new RegExp('name="' + name.replace(/[[\]]/g, '\\$&') + '"\\r\\n\\r\\n([\\s\\S]*?)\\r\\n--');
          const m = re.exec(text);
          return m ? m[1] : '';
        };
        const letter = {
          id, object: 'letter',
          to: {
            name: field('to[name]'), company: field('to[company]'),
            address_line1: field('to[address_line1]'), address_line2: field('to[address_line2]'),
            address_city: field('to[address_city]'), address_state: field('to[address_state]'), address_zip: field('to[address_zip]'),
          },
          from: { name: field('from[name]') },
          mail_type: field('mail_type') || 'usps_first_class',
          extra_service: field('extra_service') || null,
          description: field('description') || '',
          date_created: new Date().toISOString(),
          send_date: null,
          // No tracking events and no past estimate, so deriveStatus renders the
          // honest "Created" label, never "Mailed"/"Delivered".
          expected_delivery_date: null,
          tracking_number: null,
          tracking_events: [],
          deleted: false,
          // Absolute URL; in stub mode proxyTargetFor routes it to the upstream
          // by PATH, so the host here is irrelevant.
          url: 'https://lob-assets.local/rendered/' + id + '.pdf',
        };
        letters.set(id, letter);
        json(200, letter);
        return;
      }
      // List letters (History).
      if (req.method === 'GET' && p === '/v1/letters') {
        json(200, { data: Array.from(letters.values()).reverse(), next_url: null });
        return;
      }
      // Get / cancel one letter.
      const m = /^\/v1\/letters\/(ltr_[A-Za-z0-9]+)$/.exec(p);
      if (m) {
        const letter = letters.get(m[1]);
        if (req.method === 'GET') { return letter ? json(200, letter) : json(404, { error: { message: 'not found' } }); }
        if (req.method === 'DELETE') { if (letter) letter.deleted = true; return json(200, { id: m[1], deleted: true }); }
      }
      // US verification: echo the typed address back so no correction prompt.
      if (req.method === 'POST' && p === '/v1/us_verifications') {
        let b = {};
        try { b = JSON.parse(body.toString('utf8')); } catch (e) { /* leave empty */ }
        json(200, {
          deliverability: 'deliverable',
          primary_line: b.primary_line || '', secondary_line: b.secondary_line || '',
          components: { city: b.city || '', state: b.state || '', zip_code: b.zip_code || '' },
        });
        return;
      }
      json(404, { error: { message: 'stub: unhandled ' + req.method + ' ' + p } });
    });
  });
  return server;
}

async function startServers() {
  const stub = startStub();
  const stubPort = await new Promise((r) => stub.listen(0, '127.0.0.1', () => r(stub.address().port)));
  const appPort = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-browser-'));
  const creds = { username: 'browser-user', password: 'browser-password-1' };
  const env = Object.assign({}, process.env, {
    PORT: String(appPort),
    PD_USERNAME: creds.username,
    PD_PASSWORD: creds.password,
    PD_SECRET: 'browser-secret-0123456789abcdef0123456789',
    PD_LOB_UPSTREAM: 'http://127.0.0.1:' + stubPort,
    PD_DATA_DIR: dataDir,
  });
  const child = spawn(process.execPath, [APP_ENTRY], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (d) => { out += d; });
  child.stderr.on('data', (d) => { out += d; });
  const appUrl = 'http://127.0.0.1:' + appPort;

  // Wait for the app to serve /login (bounded).
  const deadline = Date.now() + 12000;
  while (Date.now() < deadline) {
    if (await tryGet(appUrl + '/login') === 200) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  if (await tryGet(appUrl + '/login') !== 200) {
    child.kill('SIGKILL');
    await new Promise((r) => stub.close(r));
    throw new Error('app did not start; output:\n' + out);
  }

  return {
    appUrl, creds, dataDir,
    async stop() {
      child.kill('SIGKILL');
      await new Promise((r) => stub.close(() => r()));
    },
  };
}

module.exports = { startServers };
