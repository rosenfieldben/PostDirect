'use strict';
// Lob API proxy: the app's single controlled path to the Lob upstream. The
// browser talks to /api/lob/*, this forwards to exactly one operator-configured
// origin (config.LOB_UPSTREAM), and legally consequential calls are captured to
// the durable audit store on the way through. Nothing here runs at module load:
// requiring this module only wires functions (no bind, no I/O), so the
// inert-on-require property holds. readBody and sendJSON are injected into
// handleProxy rather than imported, so this module never depends back on
// server.js (the HTTP helpers live there), keeping the require graph acyclic.
const http = require('http');
const https = require('https');
const { pipeline, Transform } = require('stream');
const { URL } = require('url');
const { LOB_KEY, LOB_UPSTREAM, PROXY_BODY_LIMIT, PROXY_TIMEOUT_MS, PROXY_STREAM_MAX_BYTES } = require('./config');
const { proxyAuditType, captureProxyEvent, DATA_DIR } = require('./store');

// Counting pass-through that caps a STREAMED response. It forwards every chunk
// untouched (so backpressure from the client propagates straight through) while
// tallying bytes, and errors the moment the running total exceeds maxBytes. A
// pipeline() carrying this transform tears BOTH the upstream and the client
// response down on that error, so a compromised or runaway upstream cannot
// stream unbounded bytes into the browser. Pure factory: no I/O at construction.
function byteCapTransform(maxBytes) {
  let total = 0;
  return new Transform({
    transform(chunk, enc, cb) {
      total += chunk.length;
      if (total > maxBytes) { cb(new Error('proxied response exceeded ' + maxBytes + ' bytes')); return; }
      cb(null, chunk);
    },
  });
}

// Strict method+path allowlist: the browser can reach ONLY the exact Lob calls
// this app makes. Everything else is answered 404 locally and NEVER forwarded
// upstream, so the same-origin /api/lob endpoint cannot be used as an open proxy
// into the rest of the Lob API. This matters most for the money-moving and
// financial endpoints the app does not use: Lob's /v1/checks cuts a real check
// that draws funds from a linked bank account, and /v1/bank_accounts creates and
// exposes those linked accounts. A stolen session or an injected request must
// not be able to draw a check or read bank details through this proxy, so those
// paths (and every other Lob endpoint) are simply not on the list. The list is
// data: one {method, path-regex} rule per call, matched against the path with
// the query string removed.
const PROXY_ALLOWLIST = [
  { method: 'POST',   path: /^\/v1\/letters$/ },                   // create a letter
  { method: 'GET',    path: /^\/v1\/letters$/ },                   // list letters (pagination via ?limit/&after)
  { method: 'GET',    path: /^\/v1\/letters\/ltr_[A-Za-z0-9]+$/ }, // fetch one letter (status/tracking)
  { method: 'DELETE', path: /^\/v1\/letters\/ltr_[A-Za-z0-9]+$/ }, // cancel a letter
  { method: 'POST',   path: /^\/v1\/us_verifications$/ },          // verify a recipient address
];

// True iff (method, lobPath) is on the allowlist. The query string is ignored:
// only the method and path decide, so ?limit=... on the list call is fine while
// a disallowed path can never be smuggled in behind a '?'. (The proof export's
// letter/rendered-PDF fetch is a separate, server-initiated path that does not
// pass through here; it is host-restricted by proxyTargetFor, not by this list.)
function proxyRequestAllowed(method, lobPath) {
  const p = String(lobPath == null ? '' : lobPath).split('?')[0];
  return PROXY_ALLOWLIST.some((rule) => rule.method === method && rule.path.test(p));
}

// Authorization header the proxy sends upstream to Lob: the client's own
// header when present (a key pasted into the UI overrides the server key),
// else Basic auth minted from PD_LOB_KEY, else nothing (Lob replies 401).
function lobAuthorization(clientAuth) {
  if (clientAuth) return clientAuth;
  if (LOB_KEY) return 'Basic ' + Buffer.from(LOB_KEY + ':').toString('base64');
  return undefined;
}

// Resolve a rendered-PDF URL to a fetch target. In stub/test mode
// (PD_LOB_UPSTREAM set) the URL is routed to the configured upstream by PATH,
// preserving the single-origin property the proxy already guarantees. In
// production only Lob-owned asset hosts are allowed, so a tampered url can
// never make the server fetch an arbitrary host. Returns null if disallowed.
function proxyTargetFor(urlString) {
  let u;
  try { u = new URL(urlString); } catch (e) { return null; }
  if ((process.env.PD_LOB_UPSTREAM || '').trim()) {
    return { hostname: LOB_UPSTREAM.hostname, port: LOB_UPSTREAM.port, transport: LOB_UPSTREAM.transport, path: u.pathname + u.search, headers: { host: LOB_UPSTREAM.hostname } };
  }
  const host = u.hostname.toLowerCase();
  const ok = host === 'lob.com' || host.endsWith('.lob.com') || host === 'lob-assets.com' || host.endsWith('.lob-assets.com');
  if (!ok) return null;
  const isHttp = u.protocol === 'http:';
  return { hostname: u.hostname, port: u.port ? parseInt(u.port, 10) : (isHttp ? 80 : 443), transport: isHttp ? http : https, path: u.pathname + u.search, headers: { host: u.hostname } };
}

// The Lob API proxy handler (route already matched pathname.startsWith('/api/lob/')).
// pathname and search come from the parsed request URL; readBody and sendJSON are
// injected (they are server.js's HTTP helpers) so this module stays independent of
// the composition root. Behavior is identical to the pre-split inline handler.
async function handleProxy(req, res, pathname, search, deps) {
  const { readBody, sendJSON } = deps;
  const lobPath = pathname.replace('/api/lob', '') + search;
  // Allowlist gate: reject anything that is not one of the exact calls the app
  // makes, locally and BEFORE reading or forwarding a body, so a disallowed
  // request never reaches Lob. (Same as the other early rejections in route(),
  // the unread request body is left for Node to discard.)
  if (!proxyRequestAllowed(req.method, lobPath)) {
    return sendJSON(res, 404, { error: { message: 'Not found' } });
  }
  const bodyBuf = await readBody(req, res, PROXY_BODY_LIMIT);
  if (bodyBuf === null) return; // 413/400 already sent

  const options = {
    hostname: LOB_UPSTREAM.hostname,
    port: LOB_UPSTREAM.port,
    path: lobPath,
    method: req.method,
    headers: { ...req.headers, host: LOB_UPSTREAM.hostname },
  };
  delete options.headers['origin'];
  delete options.headers['referer'];
  delete options.headers['cookie'];
  delete options.headers['accept-encoding']; // prevent Lob from returning gzipped JSON we'd forward un-decoded
  // The proxy buffers the full body and writes it as one buffer, so Node
  // must compute framing from that buffer; forwarding the client's framing
  // headers can desynchronize them from the actual bytes written.
  delete options.headers['transfer-encoding'];
  delete options.headers['content-length'];
  // Inject the server-side Lob key (PD_LOB_KEY) unless the client sent its
  // own Authorization header (see lobAuthorization for the precedence).
  const lobAuth = lobAuthorization(options.headers['authorization']);
  if (lobAuth) options.headers['authorization'] = lobAuth;
  // Legally consequential calls are captured to the durable audit store. These
  // responses are small JSON, so for them we buffer the upstream response
  // fully (to record it and, for a create, the request bytes) before
  // answering the client. Everything else keeps streaming untouched.
  const auditType = proxyAuditType(req.method, lobPath);
  const upstreamAuth = options.headers['authorization'];

  const proxy = LOB_UPSTREAM.transport.request(options, (lobRes) => {
    // The client may have already disconnected while we waited on Lob; writing
    // to a destroyed response would throw from this async callback (outside the
    // route try/catch) and crash the process. Bail cleanly instead.
    if (res.destroyed) { lobRes.destroy(); return; }
    if (auditType) {
      // Buffer, capture (synchronously to disk), then forward the same bytes.
      // The buffer is BOUNDED at PROXY_STREAM_MAX_BYTES, the SAME ceiling the
      // streamed path enforces: an audited response (a letter/verification JSON)
      // that large is pathological (a runaway or compromised upstream), so we
      // fail safe with a 502 rather than buffer unbounded and OOM the
      // single-process server. The send may already exist at Lob, but Phase 1
      // idempotency makes a client retry safe, and a multi-megabyte "response"
      // is not a real Lob reply worth capturing. `done` guards the three lobRes
      // events so exactly one outcome (capture+forward, cap-502, or error-502)
      // runs; destroying lobRes on the cap path re-enters as an 'error' that the
      // guard drops.
      const parts = [];
      let total = 0;
      let done = false;
      lobRes.on('data', (c) => {
        if (done) return;
        total += c.length;
        if (total > PROXY_STREAM_MAX_BYTES) {
          done = true;
          console.error('Lob proxy audited response exceeded ' + PROXY_STREAM_MAX_BYTES + ' bytes for ' + auditType + '; refused, not captured.');
          try { lobRes.destroy(); } catch (_) { /* ignore */ }
          if (!res.headersSent && !res.destroyed) {
            try { sendJSON(res, 502, { error: { message: 'Upstream request failed' } }); } catch (_) { /* ignore */ }
          } else { try { res.destroy(); } catch (_) { /* ignore */ } }
          return;
        }
        parts.push(c);
      });
      lobRes.on('end', () => {
        if (done) return;
        done = true;
        const respBuf = Buffer.concat(parts);
        try {
          captureProxyEvent(DATA_DIR, auditType, lobPath, req.headers, upstreamAuth, bodyBuf, lobRes.statusCode, respBuf);
        } catch (e) {
          // A store failure must not sink a send that Lob already accepted, but
          // it is operationally serious, so log it loudly server-side.
          console.error('Audit capture failed for ' + auditType + ':', e && (e.code || e.message));
        }
        if (res.destroyed) return;
        res.writeHead(lobRes.statusCode, { 'Content-Type': lobRes.headers['content-type'] || 'application/json' });
        res.end(respBuf);
      });
      lobRes.on('error', (err) => {
        if (done) return;
        done = true;
        console.error('Lob proxy stream error:', err.code || err.message);
        if (!res.headersSent && !res.destroyed) {
          try { sendJSON(res, 502, { error: { message: 'Upstream request failed' } }); } catch (_) { /* ignore */ }
        } else { try { res.destroy(); } catch (_) { /* ignore */ } }
      });
      return;
    }
    res.writeHead(lobRes.statusCode, {
      'Content-Type': lobRes.headers['content-type'] || 'application/json',
    });
    // Stream the non-audited passthrough (the letter list/get GETs) with
    // backpressure and a byte cap. pipeline (not .pipe): an upstream mid-stream
    // reset, a client abort, or the cap tripping is delivered as a handled
    // callback error and tears ALL streams down (bidirectional cleanup), rather
    // than surfacing as an unhandled 'error' event that would crash the
    // single-process server. The byteCapTransform in the middle bounds a
    // compromised/runaway upstream; the response has already begun, so on a cap
    // trip we can only tear it down (the client sees a truncated, aborted body).
    pipeline(lobRes, byteCapTransform(PROXY_STREAM_MAX_BYTES), res, (err) => {
      if (err) console.error('Lob proxy stream error:', err.code || err.message);
    });
  });

  // If the client goes away BEFORE the response finished (a mid-stream abort),
  // tear down the upstream request now instead of leaking its socket until the
  // timeout. On a normal completion writableFinished is true, so we leave the
  // request alone (and its socket free for keep-alive reuse).
  res.on('close', () => { if (!res.writableFinished) proxy.destroy(); });
  proxy.setTimeout(PROXY_TIMEOUT_MS, () => proxy.destroy(new Error('Upstream request timed out')));
  proxy.on('error', (e) => {
    // Log the real error server-side only: upstream error strings can leak
    // internals (addresses, TLS details) and are useless to the browser.
    console.error('Lob proxy error:', e);
    if (!res.headersSent) {
      sendJSON(res, 502, { error: { message: 'Upstream request failed' } });
    } else {
      res.destroy(); // response already streaming, just tear it down
    }
  });
  if (bodyBuf.length > 0) proxy.write(bodyBuf);
  proxy.end();
}

module.exports = { PROXY_ALLOWLIST, proxyRequestAllowed, byteCapTransform, lobAuthorization, proxyTargetFor, handleProxy };
