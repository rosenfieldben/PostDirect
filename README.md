# ✉ PostDirect — Web Edition

[![CI](https://github.com/rosenfieldben/postdirect/actions/workflows/ci.yml/badge.svg)](https://github.com/rosenfieldben/postdirect/actions/workflows/ci.yml)

Send physical USPS letters from any browser, secured with login authentication.

## Features

- **Password-protected** — only you can access it
- **All Lob mailing options** — First Class, Certified, Registered, return envelopes, scheduling, and more
- **Write or upload** — compose in-app or upload a PDF
- **Address verification** — every recipient is checked against USPS (Lob US Verifications) on the Review step, with one-click corrections; undeliverable addresses require an explicit acknowledgment before mailing
- **Zero dependencies** — runs on Node.js alone (no npm install needed)
- **Server-side API key (optional)** — set `PD_LOB_KEY` and your Lob key never touches the browser
- **Deploy anywhere** — Railway, Render, Fly.io, VPS, Docker, etc.

## Quick Deploy

### Option 1: Railway (easiest, free tier available)

1. Push this folder to a GitHub repo
2. Go to [railway.app](https://railway.app), create a new project → "Deploy from GitHub"
3. Add environment variables in the Railway dashboard:
   - `PD_USERNAME` = your chosen username
   - `PD_PASSWORD` = your chosen password
   - `PD_SECRET` = any long random string
   - `PD_LOB_KEY` = your Lob API key (optional — otherwise you paste it into the UI)
4. Railway auto-detects Node.js and deploys. You'll get a public URL like `postdirect-xxxx.up.railway.app`

### Option 2: Render (free tier available)

1. Push to GitHub
2. Go to [render.com](https://render.com), New → Web Service → connect your repo
3. Build command: (leave blank)
4. Start command: `node server.js`
5. Add the same environment variables as above — **including `NODE_ENV=production`** so the server refuses to boot on the default password (the guard only fires when `NODE_ENV=production`)
6. Deploy!

### Option 3: Any VPS (DigitalOcean, Linode, etc.)

```bash
# On your server:
git clone <your-repo-url> postdirect
cd postdirect

# Set your credentials
export PD_USERNAME="myusername"
export PD_PASSWORD="mysecretpassword"
export PD_SECRET="$(openssl rand -hex 32)"
export PORT=3491
# Recommended in production: makes the server refuse to boot on the default
# password (the fail-fast guard only fires when NODE_ENV=production).
export NODE_ENV=production

# Run it
node server.js

# Or use pm2 to keep it running:
# npm install -g pm2
# pm2 start server.js --name postdirect
```

Then set up a reverse proxy (nginx/Caddy) to point your domain to port 3491 with HTTPS.

### Option 4: Docker

```bash
docker build -t postdirect .
docker run -d -p 3491:3491 \
  -e PD_USERNAME=myusername \
  -e PD_PASSWORD=mysecretpassword \
  -e PD_SECRET=$(openssl rand -hex 32) \
  postdirect
```

The image runs as the non-root `node` user, sets `NODE_ENV=production` (so it will **refuse to boot without `PD_PASSWORD`**), and includes a `HEALTHCHECK` that probes `/login`.

## Local Development

```bash
# Set credentials
export PD_USERNAME="admin"
export PD_PASSWORD="mypassword"

# Start
node server.js

# Open http://localhost:3491
```

## Tests

Zero-dependency unit tests using Node's built-in runner (Node ≥ 18):

```bash
npm test     # = node --test
```

Covers session signing/validation (including tampered, malformed, and expired
tokens), constant-time credential comparison, the multipart builder's header
sanitization, the history status-derivation logic, and the address-verification
verdict/correction logic.

## Environment Variables

| Variable             | Required | Default    | Description                                                                                          |
|----------------------|----------|------------|------------------------------------------------------------------------------------------------------|
| `PD_USERNAME`        | Yes      | `admin`    | Login username                                                                                        |
| `PD_PASSWORD`        | Yes      | `changeme` | Login password                                                                                        |
| `PD_SECRET`          | Rec.     | (random)   | Secret key used to **sign** session cookies (HMAC-SHA256, nothing is encrypted). Must be a stable random string, or sessions are invalidated on every restart. The server warns at startup if it is shorter than 32 characters. |
| `PD_LOB_KEY`         | No       | —          | Lob API key held server-side. When set, the proxy injects it into Lob requests that don't carry their own key, so the key never reaches the browser. A key pasted into the UI still overrides it. The UI shows Test/Live based on the key's `test_`/`live_` prefix. |
| `PD_SECURE_COOKIES`  | No       | (auto)     | `1`/`0` to force the cookie `Secure` flag on/off. Default auto-detects HTTPS via `X-Forwarded-Proto`. |
| `PD_TRUST_PROXY`     | No       | `0`        | `1`/`true` to derive the client IP for login rate-limiting from the leftmost `X-Forwarded-For` entry. **Enable ONLY behind a trusted reverse proxy** (Railway/Render/nginx); otherwise clients can spoof `X-Forwarded-For` to evade the per-IP limit. |
| `NODE_ENV`           | No       | —          | When set to `production`, the server **refuses to start** if `PD_PASSWORD` is unset (no silent `changeme` fallback). The Docker image sets this automatically. |
| `PORT`               | No       | `3491`     | Server port                                                                                          |

## Security Notes

- Always change the default password before deploying
- Use HTTPS in production (most cloud hosts provide this automatically)
- Set a stable `PD_SECRET` in production — sessions are HMAC-signed with it, so a random per-process fallback logs everyone out on each restart (the server warns at startup if it is unset)
- Sessions are stateless signed cookies and expire after 7 days; logout clears the cookie (there is no server-side revocation)
- Login uses constant-time credential comparison plus rate limiting (5 failed attempts / 15 min) across **two** parallel buckets, per client IP **and** per username, so brute-force and random-username spray are both blunted, even when clients share a source IP behind a proxy (see `PD_TRUST_PROXY`). Credentials are checked **before** either bucket, so the buckets only throttle **failed** attempts and a correct password always logs in — even from an IP whose bucket is full. This matters behind a reverse proxy with `PD_TRUST_PROXY` off, where every client collapses to the proxy's socket IP: an attacker's failures can never lock the real owner (or anyone else with the right password) out. Bucket keys are capped at 256 characters and each bucket at 10,000 entries, bounding attacker-controlled memory between cleanup sweeps; IPv6 sources are keyed by /64 prefix so a single allocation can't mint unlimited buckets
- In production (`NODE_ENV=production`) the server refuses to start with the default/unset `PD_PASSWORD` — failing fast instead of silently running on `changeme`
- Every response carries hardening headers: a `Content-Security-Policy` (scripts/styles/connections locked to same-origin + Google Fonts, framing disabled), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`; HTTPS responses additionally carry `Strict-Transport-Security` (180 days)
- Frontend output is HTML-escaped including quotes (safe in attribute contexts), and the multipart builder sanitizes header fields (filename, field names) against CRLF/quote injection
- Request bodies are size-capped (16 KB for login, 52 MB for the Lob proxy) to prevent memory-exhaustion
- Every send carries a per-recipient Lob idempotency key that is reused on retry, so re-clicking Mail after a network failure cannot double-mail a letter
- The Lob API key is either held server-side (`PD_LOB_KEY` — the key is injected by the proxy and never sent to the browser; `/api/config` only reports that a key exists and whether it is test or live) or entered in-browser per session and proxied server-side (never stored)
- No request, recipient, or letter data and no credentials are logged or persisted on the server. (The startup banner prints the configured username and the password *length*; the proxy logs upstream *error* objects to stderr — neither is persisted)
- The request handler is wrapped so a malformed request (e.g. an invalid `Host` header) returns `400`/`500` instead of crashing the process, and server-level socket timeouts bound slow-body/slowloris connections
- The Lob proxy streams responses via `stream.pipeline` and tears down the upstream request if the client disconnects, so aborted transfers can't leak upstream sockets

## Files

```
PostDirect/
├── server.js         # Auth + proxy server (zero dependencies)
├── package.json      # Node.js manifest
├── Dockerfile        # Docker deployment (non-root user + healthcheck)
├── LICENSE           # MIT
├── .github/
│   └── workflows/
│       └── ci.yml    # GitHub Actions: npm test on Node 18/20/22
├── public/
│   └── index.html    # The PostDirect app
├── test/             # node:test unit tests (no deps) — run with `npm test`
└── README.md
```
