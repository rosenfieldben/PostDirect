# ✉ PostDirect — Web Edition

Send physical USPS letters from any browser, secured with login authentication.

## Features

- **Password-protected** — only you can access it
- **All Lob mailing options** — First Class, Certified, Registered, return envelopes, scheduling, and more
- **Write or upload** — compose in-app or upload a PDF
- **Zero dependencies** — runs on Node.js alone (no npm install needed)
- **Deploy anywhere** — Railway, Render, Fly.io, VPS, Docker, etc.

## Quick Deploy

### Option 1: Railway (easiest, free tier available)

1. Push this folder to a GitHub repo
2. Go to [railway.app](https://railway.app), create a new project → "Deploy from GitHub"
3. Add environment variables in the Railway dashboard:
   - `PD_USERNAME` = your chosen username
   - `PD_PASSWORD` = your chosen password
   - `PD_SECRET` = any long random string
4. Railway auto-detects Node.js and deploys. You'll get a public URL like `postdirect-xxxx.up.railway.app`

### Option 2: Render (free tier available)

1. Push to GitHub
2. Go to [render.com](https://render.com), New → Web Service → connect your repo
3. Build command: (leave blank)
4. Start command: `node server.js`
5. Add the same environment variables as above
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

## Local Development

```bash
# Set credentials
export PD_USERNAME="admin"
export PD_PASSWORD="mypassword"

# Start
node server.js

# Open http://localhost:3491
```

## Environment Variables

| Variable             | Required | Default    | Description                                                                                          |
|----------------------|----------|------------|------------------------------------------------------------------------------------------------------|
| `PD_USERNAME`        | Yes      | `admin`    | Login username                                                                                        |
| `PD_PASSWORD`        | Yes      | `changeme` | Login password                                                                                        |
| `PD_SECRET`          | Rec.     | (random)   | Secret key used to **sign** session cookies (HMAC-SHA256 — nothing is encrypted). Must be a stable random string, or sessions are invalidated on every restart. |
| `PD_SECURE_COOKIES`  | No       | (auto)     | `1`/`0` to force the cookie `Secure` flag on/off. Default auto-detects HTTPS via `X-Forwarded-Proto`. |
| `PORT`               | No       | `3491`     | Server port                                                                                          |

## Security Notes

- Always change the default password before deploying
- Use HTTPS in production (most cloud hosts provide this automatically)
- Set a stable `PD_SECRET` in production — sessions are HMAC-signed with it, so a random per-process fallback logs everyone out on each restart (the server warns at startup if it is unset)
- Sessions are stateless signed cookies and expire after 7 days; logout clears the cookie (there is no server-side revocation)
- Login uses constant-time credential comparison and per-IP rate limiting (5 attempts / 15 min) to blunt brute-force attempts
- Request bodies are size-capped (16 KB for login, 52 MB for the Lob proxy) to prevent memory-exhaustion
- The Lob API key is entered in-browser and proxied server-side (never stored)
- No data is logged or persisted on the server

## Files

```
PostDirect/
├── server.js         # Auth + proxy server (zero dependencies)
├── package.json      # Node.js manifest
├── Dockerfile        # Docker deployment
├── public/
│   └── index.html    # The PostDirect app
└── README.md
```
