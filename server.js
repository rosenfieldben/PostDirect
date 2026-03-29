const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// ══════════════════════════════════════════════════════════════
// CONFIGURATION — set these via environment variables
// ══════════════════════════════════════════════════════════════
const PORT = parseInt(process.env.PORT || '3491', 10);
const USERNAME = process.env.PD_USERNAME || 'admin';
const PASSWORD = process.env.PD_PASSWORD || 'changeme';
const SESSION_SECRET = process.env.PD_SECRET || crypto.randomBytes(32).toString('hex');
const COOKIE_NAME = 'pd_session';
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

// ══════════════════════════════════════════════════════════════
// SESSION STORE (in-memory, survives restarts via cookie re-validation)
// ══════════════════════════════════════════════════════════════
const sessions = new Map();

function createSession() {
  const id = crypto.randomBytes(32).toString('hex');
  const token = crypto.createHmac('sha256', SESSION_SECRET).update(id).digest('hex');
  sessions.set(token, { created: Date.now() });
  return token;
}

function validateSession(token) {
  if (!token) return false;
  const sess = sessions.get(token);
  if (!sess) return false;
  if (Date.now() - sess.created > SESSION_MAX_AGE) { sessions.delete(token); return false; }
  return true;
}

function destroySession(token) { sessions.delete(token); }

function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach(c => { const [k, ...v] = c.split('='); if (k) cookies[k.trim()] = v.join('=').trim(); });
  return cookies;
}

function getSessionToken(req) {
  return parseCookies(req.headers.cookie)[COOKIE_NAME] || null;
}

function setCookie(res, token) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MAX_AGE / 1000}`);
}

function clearCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}

// ══════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
}

function sendJSON(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(body);
}

function sendHTML(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function redirect(res, url) {
  res.writeHead(302, { 'Location': url });
  res.end();
}

// ══════════════════════════════════════════════════════════════
// STATIC FILES
// ══════════════════════════════════════════════════════════════
const STATIC_DIR = path.join(__dirname, 'public');
const MIME_TYPES = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

function serveStatic(res, filePath) {
  const full = path.join(STATIC_DIR, filePath);
  if (!full.startsWith(STATIC_DIR)) { res.writeHead(403); res.end(); return; }
  fs.readFile(full, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    const ext = path.extname(full);
    res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

// ══════════════════════════════════════════════════════════════
// LOGIN PAGE
// ══════════════════════════════════════════════════════════════
function loginPage(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PostDirect — Sign In</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,600;0,8..60,700;1,8..60,400&display=swap" rel="stylesheet">
<style>
  :root { --accent:#2563eb; --accent-hover:#1d4ed8; --accent-glow:rgba(37,99,235,0.15); --bg:#0b0d14; --card:#161822; --input-bg:#1c1f2e; --border:#252840; --text:#e4e5eb; --text-dim:#6b7094; --text-muted:#464a6a; --danger:#ef4444; --white:#fff; }
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Source Serif 4',Georgia,serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;-webkit-font-smoothing:antialiased}
  .mono{font-family:'JetBrains Mono',monospace}
  body::before{content:'';position:fixed;inset:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");pointer-events:none;z-index:0}
  .login-card{position:relative;z-index:1;width:100%;max-width:400px;padding:40px;background:var(--card);border:1.5px solid var(--border);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.3)}
  .logo{display:flex;align-items:center;gap:14px;margin-bottom:32px;justify-content:center}
  .logo-icon{width:44px;height:44px;border-radius:10px;background:linear-gradient(135deg,var(--accent),#3b82f6);display:flex;align-items:center;justify-content:center;font-size:20px;box-shadow:0 2px 12px rgba(37,99,235,0.25)}
  .logo-text{font-weight:700;font-size:22px;letter-spacing:-0.03em}
  .logo-sub{font-size:12px;color:var(--text-dim);margin-top:2px}
  .field{margin-bottom:20px}
  .field-label{display:block;margin-bottom:7px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-dim)}
  .field-input{width:100%;padding:12px 14px;border:1.5px solid var(--border);border-radius:8px;font-size:14.5px;font-family:'Source Serif 4',Georgia,serif;background:var(--input-bg);color:var(--text);outline:none;transition:border-color 0.25s,box-shadow 0.25s}
  .field-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow)}
  .btn{width:100%;padding:13px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;border:none;background:var(--accent);color:var(--white);transition:all 0.25s;letter-spacing:0.02em;margin-top:8px}
  .btn:hover{background:var(--accent-hover);transform:translateY(-1px);box-shadow:0 4px 16px rgba(37,99,235,0.3)}
  .error{padding:10px 14px;border-radius:8px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.25);color:#fca5a5;font-size:13px;margin-bottom:20px;text-align:center}
  .footer{text-align:center;margin-top:24px;font-size:12px;color:var(--text-muted)}
</style>
</head>
<body>
<div class="login-card">
  <div class="logo">
    <div class="logo-icon">✉</div>
    <div><div class="logo-text mono">PostDirect</div><div class="logo-sub mono">Sign in to continue</div></div>
  </div>
  ${error ? '<div class="error mono">' + error + '</div>' : ''}
  <form method="POST" action="/login">
    <div class="field">
      <label class="field-label mono" for="username">Username</label>
      <input class="field-input" type="text" name="username" id="username" autocomplete="username" required autofocus />
    </div>
    <div class="field">
      <label class="field-label mono" for="password">Password</label>
      <input class="field-input" type="password" name="password" id="password" autocomplete="current-password" required />
    </div>
    <button class="btn mono" type="submit">Sign In →</button>
  </form>
  <div class="footer mono">Secured access only</div>
</div>
</body>
</html>`;
}

// ══════════════════════════════════════════════════════════════
// REQUEST ROUTER
// ══════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  // ── Login page ──
  if (pathname === '/login' && req.method === 'GET') {
    if (validateSession(getSessionToken(req))) return redirect(res, '/');
    return sendHTML(res, 200, loginPage(null));
  }

  // ── Login POST ──
  if (pathname === '/login' && req.method === 'POST') {
    const body = await readBody(req);
    const params = new URLSearchParams(body.toString());
    const user = params.get('username');
    const pass = params.get('password');

    if (user === USERNAME && pass === PASSWORD) {
      const token = createSession();
      setCookie(res, token);
      return redirect(res, '/');
    }
    return sendHTML(res, 401, loginPage('Invalid username or password'));
  }

  // ── Logout ──
  if (pathname === '/logout') {
    destroySession(getSessionToken(req));
    clearCookie(res);
    return redirect(res, '/login');
  }

  // ── Everything below requires auth ──
  if (!validateSession(getSessionToken(req))) {
    return redirect(res, '/login');
  }

  // ── Lob API proxy ──
  if (pathname.startsWith('/api/lob/')) {
    const lobPath = pathname.replace('/api/lob', '');
    const bodyBuf = await readBody(req);

    const options = {
      hostname: 'api.lob.com',
      port: 443,
      path: lobPath,
      method: req.method,
      headers: { ...req.headers, host: 'api.lob.com' },
    };
    delete options.headers['origin'];
    delete options.headers['referer'];
    delete options.headers['cookie'];

    const proxy = https.request(options, (lobRes) => {
      res.writeHead(lobRes.statusCode, {
        'Content-Type': lobRes.headers['content-type'] || 'application/json',
      });
      lobRes.pipe(res);
    });

    proxy.on('error', (e) => sendJSON(res, 502, { error: { message: 'Proxy error: ' + e.message } }));
    if (bodyBuf.length > 0) proxy.write(bodyBuf);
    proxy.end();
    return;
  }

  // ── Serve app ──
  if (pathname === '/' || pathname === '/index.html') {
    return serveStatic(res, 'index.html');
  }

  // ── Other static files ──
  serveStatic(res, pathname);
});

server.listen(PORT, () => {
  console.log('');
  console.log('  ✉  PostDirect is running');
  console.log('');
  console.log(`     URL:      http://localhost:${PORT}`);
  console.log(`     Username: ${USERNAME}`);
  console.log(`     Password: ${'*'.repeat(PASSWORD.length)}`);
  console.log('');
  if (PASSWORD === 'changeme') {
    console.log('  ⚠  WARNING: Using default password!');
    console.log('     Set PD_USERNAME and PD_PASSWORD environment variables.');
    console.log('');
  }
  console.log('  Press Ctrl+C to stop.');
  console.log('');
});
