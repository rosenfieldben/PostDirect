'use strict';
// PostDirect frontend entry module. Loaded with <script type="module">, so the
// page's CSP no longer needs script-src 'unsafe-inline'. The pure, unit-tested
// helpers were moved to the sibling js/*.mjs modules imported below; everything
// here is the DOM/wizard/rendering layer that drives them.

import { parseLobDate, formatShortDate, deriveStatus } from './dates.mjs';
import { esc } from './escape.mjs';
import { lobKeyEnv } from './lobkey.mjs';
import { buildMultipart } from './multipart.mjs';
import { normalizeAddressForHash, correctedAddress, verificationVerdict } from './address.mjs';
import { SEND_DATE_MAX_DAYS, replyMailFields, validateSendDate, isSharedOptionError, notAttemptedEntries } from './options.mjs';
import { sha256HexOf, computeFingerprint, getOrCreatePersistedKey, recordSentLetter } from './idempotency.mjs';
import { confirmDuplicateSends } from './duplicate.mjs';

(function() {
  const LOB_BASE = '/api/lob';
  const MAX_RECIPIENTS = 25;
  // History is sourced live from the Lob account (List Letters); no local persistence.
  const HISTORY_PAGE_LIMIT = 100;   // Lob's max page size for GET /v1/letters
  const HISTORY_MAX = 200;          // letters loaded per fetch ("Load older" pages beyond this)
  const TRACKED_SERVICES = ['certified', 'certified_return_receipt', 'registered'];
  // Single source of truth for the human labels — previously inlined in both
  // populateReview and renderHistory, where they had drifted (the same service
  // read "Certified + Return Receipt" on Review but "Certified + RR" in History).
  const MAIL_TYPE_LABELS = { usps_first_class: 'First Class', usps_standard: 'Standard' };
  const EXTRA_SERVICE_LABELS = { '': 'None', certified: 'Certified', certified_return_receipt: 'Certified + Return Receipt', registered: 'Registered' };

  // ── App state ──
  let currentStep = 0, sending = false;
  let contentMode = 'write', uploadedFile = null;
  let currentView = 'compose';
  let recipients = [];  // array of { id, name, company, line1, line2, city, state, zip }
  let nextRecipientId = 1;
  let lastSendResults = null;  // array of { recipient, success, id?, error? }
  let history = [];                 // current render model (account-sourced)
  let optimistic = [];              // letters sent this session, shown until the Lob list catches up
  let historyEnv = null;            // 'live' | 'test' of the currently loaded list
  let historyNextUrl = null;        // Lob next_url cursor for "Load older"
  let historyLoadedKey = null;      // the API key the list was last loaded for
  let historyLoading = false;
  let historyError = null;
  let keyDebounce = null;           // debounce auto-load when the key changes on the History view
  // ── Address verification (Review step) ──
  // verifyResults holds the verdict per recipient for the CURRENT review render;
  // verifyRun is a token that invalidates in-flight checks when the review
  // re-renders (back + edit + forward), so stale responses can't paint over a
  // newer render. verifyCache memoizes by normalized address so hopping between
  // steps doesn't re-bill verification lookups for unchanged addresses.
  let verifyResults = new Map();    // recipient id -> verdict (see verificationVerdict)
  let verifyRun = 0;
  let verifyDebounce = null;        // debounce re-verification when the key changes on Review
  const verifyCache = new Map();    // env + normalized address -> verdict

  const $ = id => document.getElementById(id);
  const v = id => $(id).value.trim();
  // ═══ API key resolution ═══
  // The key can come from two places: pasted into the UI, or held server-side
  // (PD_LOB_KEY, discovered via GET /api/config at init). A pasted key always
  // overrides the server key; with a server key and an empty input, requests
  // omit Authorization and the proxy injects the key — it never reaches the
  // browser.
  let serverKey = false, serverKeyEnv = null;   // set from /api/config
  const apiKey = () => $('api-key-input').value.trim();
  const usingServerKey = () => serverKey && !apiKey();
  const hasKey = () => usingServerKey() || !!apiKey();
  const isLive = () => usingServerKey() ? serverKeyEnv === 'live' : lobKeyEnv(apiKey()) === 'live';
  // Identity of the key History was last loaded with. A unique object
  // sentinel (compared by reference) keeps the server key distinguishable
  // from any pasteable string without embedding a control character in source.
  const SERVER_KEY_ID = { serverKey: true };
  const keyIdentity = () => usingServerKey() ? SERVER_KEY_ID : apiKey();

  // ═══ History engine (sourced from the Lob account via List Letters) ═══
  function updateHistoryCount() {
    $('history-count').textContent = history.length;
  }
  function authHeaders() {
    return usingServerKey() ? {} : { 'Authorization': 'Basic ' + btoa(apiKey() + ':') };
  }
  function isTrackedService(es) { return TRACKED_SERVICES.indexOf(es) !== -1; }
  function uspsTrackingUrl(num) {
    return 'https://tools.usps.com/go/TrackConfirmAction?tLabels=' + encodeURIComponent(num);
  }
  // Lob's next_url is an absolute api.lob.com URL — route it back through our same-origin proxy.
  function toProxyUrl(u) {
    try { const p = new URL(u, 'https://api.lob.com'); return LOB_BASE + p.pathname + p.search; }
    catch (e) { return LOB_BASE + (String(u).charAt(0) === '/' ? u : '/' + u); }
  }
  // Map a Lob letter object onto the existing history render shape.
  function mapLobLetter(L, envMode, fetchedAt) {
    const to = (L && typeof L.to === 'object' && L.to) ? L.to : {};
    const cityStateZip = [to.address_city, to.address_state, to.address_zip].filter(Boolean).join(', ');
    const addr = [to.address_line1, to.address_line2, cityStateZip].filter(Boolean).join(' · ');
    return {
      id: L.id,
      recipient_name: (typeof to.name === 'string' ? to.name : '') || '',
      recipient_company: to.company || '',
      recipient_address: addr,
      sender_name: (L.from && typeof L.from === 'object' && L.from.name) ? L.from.name : '',
      date_sent: L.date_created || null,             // Lob's date_created -> existing 'date_sent' field
      send_date: L.send_date || null,
      expected_delivery_date: L.expected_delivery_date || null,
      mail_type: L.mail_type || null,
      extra_service: L.extra_service || null,
      tracking_number: L.tracking_number || null,
      description: L.description || '',
      mode: envMode,
      last_refreshed: fetchedAt,
      tracking_events: Array.isArray(L.tracking_events) ? L.tracking_events : [],
      deleted: !!L.deleted,
      fetch_error: null,
      _lob: true,
    };
  }
  function setHistoryLoading(loading) {
    const btn = $('btn-refresh-all');
    if (btn) { btn.disabled = loading; btn.textContent = loading ? 'Loading…' : 'Refresh all'; }
  }
  // Fetch the account's letters through the proxy, paging via next_url up to a cap.
  async function loadAccountHistory(opts) {
    opts = opts || {};
    const reset = opts.reset !== false;
    if (!hasKey()) {
      history = []; historyEnv = null; historyNextUrl = null; historyLoadedKey = null; historyError = null;
      updateHistoryCount(); renderHistory(); return;
    }
    if (historyLoading) return;
    const env = isLive() ? 'live' : 'test';
    historyLoading = true; historyError = null;
    setHistoryLoading(true); renderHistory();
    const fetchedAt = new Date().toISOString();
    const seen = {};
    let collected = [];
    if (!reset) { collected = history.filter(h => h._lob && h.mode === env); collected.forEach(e => { seen[e.id] = true; }); }
    let url = reset ? ('/v1/letters?limit=' + HISTORY_PAGE_LIMIT) : historyNextUrl;
    const target = collected.length + HISTORY_MAX;
    let guard = 0;
    try {
      while (url && collected.length < target && guard < 60) {
        guard++;
        const resp = await fetch(toProxyUrl(url), { method: 'GET', headers: authHeaders() });
        let data;
        try { data = await resp.json(); } catch (e) { throw new Error('Unexpected response from Lob (HTTP ' + resp.status + ')'); }
        if (data && data.error) throw new Error((data.error && data.error.message) || 'Lob API error');
        const letters = Array.isArray(data.data) ? data.data : [];
        for (let k = 0; k < letters.length; k++) {
          const L = letters[k];
          if (!L || !L.id || seen[L.id]) continue;
          seen[L.id] = true;
          collected.push(mapLobLetter(L, env, fetchedAt));
        }
        url = data.next_url || null;
      }
      historyNextUrl = url;            // null when fully paged; otherwise the cursor for "Load older"
      historyEnv = env;
      historyLoadedKey = keyIdentity();
      const opt = optimistic.filter(o => o.mode === env && !seen[o.id]);  // keep just-sent letters not yet in the list
      history = opt.concat(collected);
    } catch (e) {
      historyError = e.message || 'Could not load mail history';
    } finally {
      historyLoading = false;
      setHistoryLoading(false);
      updateHistoryCount();
      renderHistory();
    }
  }
  // Copy-to-clipboard with a graceful, dependency-free fallback.
  function copyText(text, btn) {
    const flash = () => { if (btn) { const o = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = o; }, 1200); } };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(flash).catch(() => fallbackCopy(text, flash));
    } else { fallbackCopy(text, flash); }
  }
  function fallbackCopy(text, done) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', '');
      ta.style.position = 'fixed'; ta.style.top = '-1000px'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); document.body.removeChild(ta);
      if (done) done();
    } catch (e) { /* clipboard unavailable; no-op */ }
  }

  function verifyCacheKey(r) {
    // Prefixed with the key environment: test keys return fixture data, so a
    // verdict cached under a test key must not be reused once a live key is in.
    return (isLive() ? 'L' : 'T') + '|' + [r.line1, r.line2, r.city, r.state, r.zip].map(s => String(s == null ? '' : s).toUpperCase().replace(/\s+/g, ' ').trim()).join('|');
  }

  async function verifyOne(r) {
    const ck = verifyCacheKey(r);
    if (verifyCache.has(ck)) return verifyCache.get(ck);
    let result;
    try {
      const resp = await fetch(LOB_BASE + '/v1/us_verifications', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders()),
        body: JSON.stringify({ primary_line: r.line1, secondary_line: r.line2 || '', city: r.city, state: r.state, zip_code: r.zip }),
      });
      const data = await resp.json();
      const verdict = verificationVerdict(data);
      const cor = verdict.level === 'error' ? { corrected: null, differs: false } : correctedAddress(r, data);
      result = { level: verdict.level, label: verdict.label, note: verdict.note, corrected: cor.corrected, differs: cor.differs };
    } catch (e) {
      result = { level: 'error', label: 'Couldn’t verify', note: e.message || 'Network error — you can still send.', corrected: null, differs: false };
    }
    // Transient failures are not cached so a retry (re-entering Review) re-checks.
    if (result.level !== 'error') verifyCache.set(ck, result);
    return result;
  }

  // Send gate derived from the current verdicts. pending only counts when a
  // key exists (without one, verification can't run and the send button is
  // already disabled for the missing key — don't double-block).
  function verificationGate() {
    const rs = readAllRecipients();
    let pending = false, blocked = false;
    for (const r of rs) {
      const v = verifyResults.get(r.id);
      if (!v) pending = true;
      else if (v.level === 'blocked') blocked = true;
    }
    return { pending: pending && hasKey(), blocked };
  }

  function renderVerifyLine(id, result) {
    const el = document.getElementById('verify-r-' + id);
    if (!el) return;
    if (!result) {
      el.innerHTML = '<div class="verify-row"><span class="verify-spinner"></span><span class="verify-note">Verifying with USPS…</span></div>';
      return;
    }
    const variant = result.level === 'ok' ? 'success' : result.level === 'warn' ? 'progress' : result.level === 'blocked' ? 'error' : 'muted';
    let html = '<div class="verify-row"><span class="status-badge ' + variant + '">' + esc(result.label) + '</span></div>';
    if (result.note) html += '<div class="verify-note">' + esc(result.note) + '</div>';
    // Offer the standardized form only for sendable verdicts: for an
    // undeliverable address a "correction" to the same bad address is noise.
    if ((result.level === 'ok' || result.level === 'warn') && result.differs && result.corrected) {
      const c = result.corrected;
      const line = [c.line1, c.line2, [c.city, c.state].filter(Boolean).join(', ') + ' ' + c.zip].filter(Boolean).join(', ');
      html += '<div class="verify-suggest"><span>USPS standard: <strong>' + esc(line) + '</strong></span>' +
        '<button class="btn-mini" type="button" data-usecorrected="' + esc(id) + '">Use corrected</button></div>';
    }
    el.innerHTML = html;
    const btn = el.querySelector('[data-usecorrected]');
    if (btn) btn.addEventListener('click', () => applyCorrectedAddress(id));
  }

  function applyCorrectedAddress(id) {
    const v = verifyResults.get(id);
    if (!v || !v.corrected) return;
    // The step-1 inputs are the source of truth (readAllRecipients reads the
    // DOM), so write the correction into them; they exist even while hidden.
    const set = (key, val) => { const el = document.getElementById('r-' + id + '-' + key); if (el) el.value = val; };
    set('line1', v.corrected.line1); set('line2', v.corrected.line2);
    set('city', v.corrected.city); set('state', v.corrected.state); set('zip', v.corrected.zip);
    populateReview(); // re-render + re-verify; the standardized form hits the cache path cheaply
  }

  function updateVerifyAck() {
    const gate = verificationGate();
    $('verify-ack-wrap').classList.toggle('is-hidden', !gate.blocked);
    if (!gate.blocked) $('verify-ack').checked = false;
  }

  async function runReviewVerification(rs) {
    const run = ++verifyRun;
    verifyResults = new Map();
    updateVerifyAck();
    if (!hasKey()) {
      // No key, no verification. The send button is already disabled for the
      // missing key; show why the check didn't run instead of a stuck spinner.
      rs.forEach(r => renderVerifyLine(r.id, { level: 'error', label: 'Couldn’t verify', note: 'Enter an API key to verify addresses.', corrected: null, differs: false }));
      return;
    }
    rs.forEach(r => renderVerifyLine(r.id, null)); // pending spinners
    refreshNextBtn();
    await Promise.all(rs.map(async (r) => {
      const result = await verifyOne(r);
      if (run !== verifyRun) return; // review re-rendered since; drop stale paint
      verifyResults.set(r.id, result);
      renderVerifyLine(r.id, result);
    }));
    if (run !== verifyRun) return;
    updateVerifyAck();
    refreshNextBtn();
  }

  // ═══ Sender / Recipients data ═══
  function getFrom() {
    return { name: v('from-name'), company: v('from-company'), line1: v('from-line1'), line2: v('from-line2'), city: v('from-city'), state: v('from-state'), zip: v('from-zip') };
  }
  function readRecipientFromDOM(id) {
    const g = key => { const el = document.getElementById('r-' + id + '-' + key); return el ? el.value.trim() : ''; };
    return { id, name: g('name'), company: g('company'), line1: g('line1'), line2: g('line2'), city: g('city'), state: g('state'), zip: g('zip') };
  }
  function readAllRecipients() {
    return recipients.map(r => readRecipientFromDOM(r.id));
  }
  function recipientIsValid(r) {
    return !!(r.name && r.line1 && r.city && r.state && r.zip);
  }
  function allRecipientsValid() {
    const live = readAllRecipients();
    return live.length > 0 && live.every(recipientIsValid);
  }

  // ═══ Recipient card rendering ═══
  function recipientCardHTML(r, index, total) {
    const id = r.id;
    const showRemove = total > 1;
    return (
      '<div class="recipient-card" data-rid="' + esc(id) + '">' +
        '<div class="recipient-card-header">' +
          '<div class="recipient-number">Recipient ' + (index + 1) + '</div>' +
          (showRemove ? '<button type="button" class="btn-remove-recipient" data-remove="' + esc(id) + '">Remove</button>' : '') +
        '</div>' +
        '<div class="form-grid cols-2">' +
          '<div class="field"><label class="field-label" for="r-' + id + '-name">Full Name <span class="req">*</span></label><input class="field-input" id="r-' + id + '-name" data-rfield value="' + esc(r.name) + '" placeholder="John Doe" /></div>' +
          '<div class="field"><label class="field-label" for="r-' + id + '-company">Firm / Company</label><input class="field-input" id="r-' + id + '-company" data-rfield value="' + esc(r.company) + '" placeholder="Doe Industries" /></div>' +
        '</div>' +
        '<div class="field"><label class="field-label" for="r-' + id + '-line1">Address Line 1 <span class="req">*</span></label><input class="field-input" id="r-' + id + '-line1" data-rfield value="' + esc(r.line1) + '" placeholder="456 Oak Avenue" /></div>' +
        '<div class="field"><label class="field-label" for="r-' + id + '-line2">Address Line 2</label><input class="field-input" id="r-' + id + '-line2" data-rfield value="' + esc(r.line2) + '" placeholder="Floor 2" /></div>' +
        '<div class="form-grid cols-3">' +
          '<div class="field"><label class="field-label" for="r-' + id + '-city">City <span class="req">*</span></label><input class="field-input" id="r-' + id + '-city" data-rfield value="' + esc(r.city) + '" placeholder="Chicago" /></div>' +
          '<div class="field"><label class="field-label" for="r-' + id + '-state">State <span class="req">*</span></label><input class="field-input" id="r-' + id + '-state" data-rfield value="' + esc(r.state) + '" placeholder="IL" /></div>' +
          '<div class="field"><label class="field-label" for="r-' + id + '-zip">ZIP <span class="req">*</span></label><input class="field-input" id="r-' + id + '-zip" data-rfield value="' + esc(r.zip) + '" placeholder="60601" /></div>' +
        '</div>' +
      '</div>'
    );
  }
  function renderRecipients() {
    // Preserve current DOM values into state before re-rendering
    recipients = readAllRecipients();
    const list = $('recipients-list');
    list.innerHTML = recipients.map((r, i) => recipientCardHTML(r, i, recipients.length)).join('');
    $('recipient-counter').textContent = recipients.length >= MAX_RECIPIENTS ? 'Maximum of ' + MAX_RECIPIENTS + ' recipients reached.' : (recipients.length + ' recipient' + (recipients.length === 1 ? '' : 's'));
    $('btn-add-recipient').disabled = recipients.length >= MAX_RECIPIENTS;
    // Wire up remove buttons
    list.querySelectorAll('[data-remove]').forEach(btn => {
      btn.addEventListener('click', () => removeRecipient(parseInt(btn.getAttribute('data-remove'), 10)));
    });
    refreshNextBtn();
  }
  function addRecipient() {
    if (recipients.length >= MAX_RECIPIENTS) return;
    recipients = readAllRecipients();  // capture current values
    recipients.push({ id: nextRecipientId++, name: '', company: '', line1: '', line2: '', city: '', state: '', zip: '' });
    renderRecipients();
    // Focus the first field of the newly added card
    const newId = recipients[recipients.length - 1].id;
    const el = document.getElementById('r-' + newId + '-name');
    if (el) el.focus();
  }
  function removeRecipient(id) {
    if (recipients.length <= 1) return;
    recipients = readAllRecipients().filter(r => r.id !== id);
    // Idempotency keys are now persisted by content fingerprint, not by
    // recipient id, so changing the recipient set needs no key housekeeping: a
    // removed recipient simply is not sent, and its key harmlessly prunes at 24h.
    renderRecipients();
  }

  // ═══ Step navigation ═══
  const panels = [0,1,2,3,4].map(i => $('step-' + i));
  function canProceed() {
    if (currentStep === 0) { const f = getFrom(); return !!(f.name && f.line1 && f.city && f.state && f.zip); }
    if (currentStep === 1) { return allRecipientsValid(); }
    if (currentStep === 2) { return contentMode === 'write' ? v('letter-body').length > 0 : uploadedFile !== null; }
    return true;
  }
  function refreshNextBtn() {
    const btn = $('btn-next');
    if (currentStep < 3) { btn.disabled = !canProceed(); btn.textContent = 'Continue →'; btn.classList.remove('live'); }
    else if (currentStep === 3) {
      const gate = verificationGate();
      btn.disabled = sending || !hasKey() || gate.pending || (gate.blocked && !$('verify-ack').checked);
      const n = readAllRecipients().length;
      const label = n === 1 ? 'Letter' : (n + ' Letters');
      btn.textContent = sending ? 'Sending…'
        : gate.pending ? 'Verifying addresses…'
        : (isLive() ? ('Mail ' + label + ' (Live)') : ('Mail ' + label + ' (Test)'));
      btn.classList.toggle('live', isLive()); // Live mode wears the wax (styling class only)
    }
  }
  function goToStep(n, focus) {
    currentStep = n;
    panels.forEach((p, i) => p.classList.toggle('is-hidden', i !== n));
    for (let i = 0; i < 4; i++) {
      const l = $('sl-' + i);
      l.className = 'step-label' + (i < n ? ' done' : i === n ? ' active' : '');
      // Expose the active step to assistive tech (the visual state alone is silent).
      if (i === n) l.setAttribute('aria-current', 'step'); else l.removeAttribute('aria-current');
    }
    const pct = n === 0 ? 0 : n === 1 ? 33.33 : n === 2 ? 66.66 : 100;
    $('steps-fill').style.width = pct + '%';
    $('nav-bar').classList.toggle('is-hidden', n === 4);
    $('steps-bar').classList.toggle('is-hidden', n === 4);
    $('btn-back').disabled = n === 0;
    if (n === 3) populateReview();
    refreshNextBtn();
    const p = panels[n]; if (p) { p.classList.remove('animate-in'); void p.offsetWidth; p.classList.add('animate-in'); }
    // On a user-driven step change, land focus on the new step's heading so
    // keyboard/screen-reader users are told where they are (skipped on first
    // paint so the page doesn't steal focus on load).
    if (focus && p) {
      const heading = p.querySelector('.section-title, .success-title');
      if (heading) { heading.setAttribute('tabindex', '-1'); heading.focus(); }
    }
  }

  // ═══ Review ═══
  function formatAddrInline(d) {
    let h = '<strong>' + esc(d.name) + '</strong><br/>';
    if (d.company) h += esc(d.company) + '<br/>';
    h += esc(d.line1) + '<br/>';
    if (d.line2) h += esc(d.line2) + '<br/>';
    h += esc(d.city) + ', ' + esc(d.state) + ' ' + esc(d.zip);
    return h;
  }
  function populateReview() {
    $('review-from').innerHTML = formatAddrInline(getFrom());
    const rs = readAllRecipients();
    $('review-to-count').textContent = '(' + rs.length + ')';
    const list = $('review-recipients');
    list.className = 'review-recipients' + (rs.length > 1 ? ' cols-2' : '');
    list.innerHTML = rs.map((r, i) =>
      '<div class="addr-card">' +
        '<div class="addr-card-label"><span>To</span>' + (rs.length > 1 ? '<span class="recipient-idx">#' + (i + 1) + '</span>' : '') + '</div>' +
        '<div class="addr-card-body">' + formatAddrInline(r) + '</div>' +
        '<div class="verify-line" id="verify-r-' + esc(r.id) + '" role="status" aria-live="polite"></div>' +
      '</div>'
    ).join('');
    runReviewVerification(rs);

    if (contentMode === 'write') {
      const b = v('letter-body');
      $('review-body').innerHTML = b ? esc(b) : '<span class="empty">No content</span>';
    } else if (uploadedFile) {
      $('review-body').innerHTML = '<div style="display:flex;align-items:center;gap:14px;padding:8px 0"><div class="file-icon" style="width:40px;height:40px">' + esc(uploadedFile.type.toUpperCase()) + '</div><div><div style="font-weight:600;font-size:14px;color:#0f1419">' + esc(uploadedFile.name) + '</div><div style="font-size:12px;color:#9ca0a8">' + formatFileSize(uploadedFile.size) + '</div></div></div>';
    }
    const ml = MAIL_TYPE_LABELS;
    const el = EXTRA_SERVICE_LABELS;
    const tags = [];
    tags.push(rs.length + ' recipient' + (rs.length === 1 ? '' : 's'));
    tags.push(contentMode === 'upload' ? 'Uploaded PDF' : 'Written letter');
    tags.push(ml[$('opt-mail-type').value] || '');
    tags.push($('opt-color').checked ? 'Color' : 'Black & white');
    tags.push($('opt-double').checked ? 'Double-sided' : 'Single-sided');
    const es = $('opt-extra-service').value; if (es) tags.push(el[es]);
    tags.push($('opt-use-type').value === 'marketing' ? 'Marketing' : 'Operational');
    if ($('opt-address-placement').value === 'insert_blank_page') tags.push('Blank address page');
    if ($('opt-reply-envelope').checked) tags.push('Reply envelope (perforated pg 1)');
    const sd = $('opt-send-date').value; if (sd) tags.push('Send ' + sd);
    const desc = $('opt-description').value.trim(); if (desc) tags.push('“' + desc + '”');
    const modeTag = isLive() ? '<span class="mode-live">Live — real letters</span>' : '<span class="mode-test">Test mode</span>';
    const htmlTags = tags.filter(Boolean).map(esc);
    htmlTags.push(modeTag);
    $('review-meta').innerHTML = htmlTags.join('<span class="sep">·</span>');
  }

  function showError(m) { $('error-box').textContent = m; $('error-box').classList.remove('is-hidden'); }
  function hideError() { $('error-box').classList.add('is-hidden'); }
  function setProgress(text, show) {
    $('send-progress').classList.toggle('is-hidden', !show);
    $('send-progress-text').textContent = text || 'Sending…';
  }

  // ═══ File upload ═══
  function formatFileSize(b) { if (b < 1024) return b + ' B'; if (b < 1048576) return (b / 1024).toFixed(1) + ' KB'; return (b / 1048576).toFixed(1) + ' MB'; }
  const uploadZone = $('upload-zone'), fileInput = $('file-input'), fileInfo = $('file-info');
  function handleFile(file) {
    if (!file) return;
    const ext = file.name.split('.').pop().toLowerCase();
    if (ext !== 'pdf') { alert('Please upload a PDF. Word documents must be converted to PDF first.'); return; }
    if (file.size > 50*1024*1024) { alert('File too large. Maximum 50 MB.'); return; }
    const reader = new FileReader();
    reader.onload = function(e) {
      uploadedFile = { name: file.name, size: file.size, type: 'pdf', buffer: e.target.result };
      uploadZone.classList.add('is-hidden'); fileInfo.classList.remove('is-hidden');
      $('file-name').textContent = file.name; $('file-size').textContent = formatFileSize(file.size);
      $('file-icon').textContent = 'PDF';
      refreshNextBtn();
    };
    reader.readAsArrayBuffer(file);
  }
  function removeFile() { uploadedFile = null; fileInput.value = ''; uploadZone.classList.remove('is-hidden'); fileInfo.classList.add('is-hidden'); refreshNextBtn(); }
  uploadZone.addEventListener('click', () => fileInput.click());
  // Keyboard access: the drop zone is role="button" tabindex="0", so Enter/Space
  // must trigger the file picker just like a click would.
  uploadZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); fileInput.click(); }
  });
  fileInput.addEventListener('change', e => { if (e.target.files[0]) handleFile(e.target.files[0]); });
  uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('drag-over'); });
  uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag-over'));
  uploadZone.addEventListener('drop', e => { e.preventDefault(); uploadZone.classList.remove('drag-over'); if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]); });
  $('btn-remove').addEventListener('click', removeFile);

  // ═══ Mode tabs ═══
  function setMode(m) {
    contentMode = m;
    $('tab-write').classList.toggle('active', m === 'write');
    $('tab-upload').classList.toggle('active', m === 'upload');
    $('tab-write').setAttribute('aria-pressed', m === 'write' ? 'true' : 'false');
    $('tab-upload').setAttribute('aria-pressed', m === 'upload' ? 'true' : 'false');
    $('mode-write').classList.toggle('is-hidden', m !== 'write');
    $('mode-upload').classList.toggle('is-hidden', m !== 'upload');
    refreshNextBtn();
  }
  $('tab-write').addEventListener('click', () => setMode('write'));
  $('tab-upload').addEventListener('click', () => setMode('upload'));

  // ═══ Build letter file (HTML for written, PDF for upload) ═══
  function buildLetterPayload() {
    if (contentMode === 'write') {
      const body = $('letter-body').value;
      // Escape & before <: without the ampersand escape, literally typed
      // entities like &amp; collapse when the HTML renders, so the printed
      // letter would not match what the user typed. Order matters: escaping
      // & after < would double-escape the &lt; just produced.
      const lines = body.split('\n').map(l => l === '' ? '<br/>' : '<p style="margin:0 0 4px">' + l.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</p>').join('');
      const html = '<html><head><meta charset="UTF-8"><style>body{font-family:Georgia,serif;font-size:12pt;line-height:1.7;color:#1a1a1a;padding:0.75in 1in;}</style></head><body>' + lines + '</body></html>';
      return { buffer: new TextEncoder().encode(html).buffer, name: 'letter.html', mime: 'text/html' };
    }
    if (uploadedFile) {
      return { buffer: uploadedFile.buffer, name: uploadedFile.name, mime: 'application/pdf' };
    }
    return null;
  }

  // Local calendar date as YYYY-MM-DD (the date input's value format).
  function localDateStr(date) {
    const pad = (x) => String(x).padStart(2, '0');
    return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate());
  }

  // ═══ Common letter fields (independent of recipient) ═══
  function commonLetterFields() {
    const from = getFrom();
    const fields = [];
    fields.push(['from[name]', from.name]); if (from.company) fields.push(['from[company]', from.company]);
    fields.push(['from[address_line1]', from.line1]); if (from.line2) fields.push(['from[address_line2]', from.line2]);
    fields.push(['from[address_city]', from.city]); fields.push(['from[address_state]', from.state]); fields.push(['from[address_zip]', from.zip]);
    fields.push(['color', $('opt-color').checked.toString()]);
    fields.push(['double_sided', $('opt-double').checked.toString()]);
    fields.push(['mail_type', $('opt-mail-type').value]);
    fields.push(['use_type', $('opt-use-type').value]);
    fields.push(['address_placement', $('opt-address-placement').value]);
    const es = $('opt-extra-service').value; if (es) fields.push(['extra_service', es]);
    // Reply envelope + its required perforation, coupled so one can never be
    // sent without the other.
    replyMailFields($('opt-reply-envelope').checked).forEach((f) => fields.push(f));
    // Date-only YYYY-MM-DD (was a T12:00:00Z timestamp): pairs with parseLobDate
    // on display so the scheduled day is never off by one in a negative-UTC zone.
    const sd = $('opt-send-date').value; if (sd) fields.push(['send_date', sd]);
    const desc = $('opt-description').value.trim(); if (desc) fields.push(['description', desc]);
    return fields;
  }
  function recipientFields(to) {
    const f = [];
    f.push(['to[name]', to.name]); if (to.company) f.push(['to[company]', to.company]);
    f.push(['to[address_line1]', to.line1]); if (to.line2) f.push(['to[address_line2]', to.line2]);
    f.push(['to[address_city]', to.city]); f.push(['to[address_state]', to.state]); f.push(['to[address_zip]', to.zip]);
    return f;
  }

  async function computeRecipientHash(to) {
    return sha256HexOf(new TextEncoder().encode(normalizeAddressForHash(
      { line1: to.line1, line2: to.line2, city: to.city, state: to.state, zip: to.zip })));
  }

  // ═══ Unload guard while a send is in flight ═══
  // Leaving mid-batch can make the outcome ambiguous (Lob may have created a
  // letter whose response we never saw). Warn on navigation while sending; the
  // persisted key makes a reload-and-resubmit safe, but a warning is still owed.
  function unloadGuard(e) { e.preventDefault(); e.returnValue = ''; return ''; }
  function addUnloadGuard() { window.addEventListener('beforeunload', unloadGuard); }
  function removeUnloadGuard() { window.removeEventListener('beforeunload', unloadGuard); }

  // Send the given recipients and return a results array, or null if a
  // pre-flight check failed (in which case an error was surfaced). Callers own
  // presentation (showSuccessView) so a retry can merge with earlier results.
  async function sendToRecipients(rs, opts) {
    opts = opts || {};
    if (!hasKey()) { showError('Please enter your Lob API key above.'); return null; }
    if (!rs || rs.length === 0) { showError('Add at least one recipient.'); return null; }
    // Belt to the button's suspenders: the send button is disabled while these
    // hold, but re-check here so a stale enabled state can't slip a send through.
    const gate = verificationGate();
    if (gate.pending) { showError('Address verification is still running — one moment.'); return null; }
    if (gate.blocked && !$('verify-ack').checked) { showError('One or more addresses are undeliverable. Correct them, or check the acknowledgment above to mail anyway.'); return null; }
    const payload = buildLetterPayload();
    if (!payload) { showError('Letter content is missing.'); return null; }
    // Batch preflight: validate shared options ONCE, up front, before the first
    // letter fires, so a bad send date fails immediately instead of once per
    // recipient across a batch of up to 25.
    const sdCheck = validateSendDate($('opt-send-date').value, localDateStr(new Date()));
    if (!sdCheck.ok) { showError(sdCheck.error); return null; }

    sending = true; refreshNextBtn(); hideError();
    const results = [];

    try {
      // Setup inside the try so any throw here (a missing DOM node, or
      // crypto.subtle being unavailable in a non-secure context) is surfaced as
      // an error while the finally still clears the sending flag and the unload
      // guard, instead of rejecting silently and wedging the UI.
      addUnloadGuard();
      const common = commonLetterFields();
      const live = isLive();
      // One fingerprint + recipient-address hash per recipient; the uploaded-file
      // hash is shared, so it is computed once. Fingerprints drive the duplicate
      // warning and the persisted idempotency key; the recipient hash lets the
      // proof export correlate a verification to this letter.
      const fileHashHex = await sha256HexOf(payload.buffer);
      const fingerprints = [];
      const recipientHashes = [];
      for (const to of rs) {
        fingerprints.push(await computeFingerprint(to, common, fileHashHex));
        recipientHashes.push(await computeRecipientHash(to));
      }

      // Duplicate warning (warn, never block): only for a fresh batch, not a
      // deliberate "Retry failed". Consults the durable server record, so it
      // fires even after the 24h client window has pruned the local key.
      if (opts.warnDuplicates) {
        const proceed = await confirmDuplicateSends(rs, fingerprints);
        if (!proceed) return null; // operator cancelled; finally clears state
      }

      for (let i = 0; i < rs.length; i++) {
        const to = rs[i];
        const fingerprint = fingerprints[i];
        setProgress('Sending letter ' + (i + 1) + ' of ' + rs.length + ' — ' + (to.name || 'recipient'), true);
        // Reused across retries AND across reloads: the key is persisted by
        // fingerprint before the send fires, so an interrupted send is safe to
        // re-attempt and Lob de-dupes an identical resubmit within 24h.
        const idemKey = getOrCreatePersistedKey(window.localStorage, fingerprint, Date.now(), () => crypto.randomUUID()).idempotencyKey;
        try {
          // Build inside the try so a build-time throw is recorded as a per-recipient
          // failure rather than escaping the loop and wedging the UI (sending stuck true).
          const allFields = recipientFields(to).concat(common);
          const { body: mpBody, contentType } = buildMultipart(allFields, payload.buffer, payload.name, payload.mime);
          const resp = await fetch(LOB_BASE + '/v1/letters', {
            method: 'POST',
            headers: Object.assign({ 'Content-Type': contentType, 'Idempotency-Key': idemKey, 'X-PD-Fingerprint': fingerprint, 'X-PD-Recipient-Hash': recipientHashes[i] }, authHeaders()),
            body: mpBody
          });
          const data = await resp.json();
          if (data.error) throw new Error(data.error.message);
          // Note the letter id on the persisted record (kept, not deleted): an
          // identical resubmit within 24h reuses the key and Lob returns this
          // same letter. The durable server record surfaces the duplicate
          // warning for any resend after that.
          recordSentLetter(window.localStorage, fingerprint, data.id, Date.now());
          results.push({ recipient: to, success: true, data });
          // Optimistic entry so a freshly sent letter shows immediately. It de-dupes
          // against the Lob list by id the next time History loads (Lob's object wins).
          const entry = {
            id: data.id,
            recipient_name: to.name,
            recipient_company: to.company || '',
            recipient_address: [to.line1, to.line2, [to.city, to.state, to.zip].filter(Boolean).join(', ')].filter(Boolean).join(' · '),
            sender_name: getFrom().name,
            date_sent: data.date_created || new Date().toISOString(),
            send_date: data.send_date || null,
            expected_delivery_date: data.expected_delivery_date || null,
            mail_type: data.mail_type || $('opt-mail-type').value,
            extra_service: data.extra_service || ($('opt-extra-service').value || null),
            tracking_number: data.tracking_number || null,
            description: data.description || ($('opt-description').value.trim() || ''),
            mode: live ? 'live' : 'test',
            last_refreshed: new Date().toISOString(),
            tracking_events: Array.isArray(data.tracking_events) ? data.tracking_events : [],
            deleted: !!data.deleted,
            fetch_error: null,
            _lob: false,
          };
          optimistic.unshift(entry);
          history.unshift(entry);
          updateHistoryCount();
        } catch (e) {
          // The persisted key is intentionally kept on failure: a failed
          // (possibly ambiguous) send keeps its key so "Retry failed", or even a
          // reload-and-resubmit, reuses it and Lob returns the original letter
          // instead of printing a duplicate.
          const msg = e.message || 'Unknown error';
          results.push({ recipient: to, success: false, error: msg });
          // If a SHARED option was rejected, every remaining letter shares it and
          // would fail identically. Halt and mark the rest "not attempted" rather
          // than collect up to 25 duplicate failures (see notAttemptedEntries).
          if (isSharedOptionError(msg)) {
            notAttemptedEntries(rs, i).forEach((r) => results.push(r));
            break;
          }
        }
      }
    } catch (e) {
      // An unexpected failure BEFORE or AROUND the per-letter loop (the setup
      // above, the fingerprint/hash step, or a key mint) would otherwise reject
      // silently and no-op the send with no feedback. Surface it. Per-letter
      // send failures are still handled by the inner try/catch and do not reach
      // here.
      showError('Could not start the send: ' + (e && e.message ? e.message : 'unexpected error') + '. No letters were sent.');
      return null;
    } finally {
      setProgress('', false);
      sending = false;
      removeUnloadGuard();
      refreshNextBtn();
    }
    return results;
  }

  async function sendLetters() {
    const rs = readAllRecipients();
    const results = await sendToRecipients(rs, { warnDuplicates: true });
    if (!results) return; // pre-flight failed or cancelled; nothing to show
    lastSendResults = results;
    showSuccessView(results);
  }

  // Re-send ONLY the recipients that failed, reusing their persisted idempotency
  // keys so an ambiguous failure (Lob created the letter but the response was
  // lost) returns the original letter rather than mailing a duplicate. This is a
  // deliberate retry, so the duplicate warning is suppressed. Prior successes are
  // preserved and merged back so the view shows the full picture.
  async function retryFailed() {
    if (!lastSendResults) return;
    const failed = lastSendResults.filter(r => !r.success).map(r => r.recipient);
    if (failed.length === 0) return;
    const newResults = await sendToRecipients(failed, { warnDuplicates: false });
    if (!newResults) return;
    const byId = new Map(newResults.map(r => [r.recipient.id, r]));
    // Keep original ordering; replace each prior failure with its new outcome.
    lastSendResults = lastSendResults.map(r => r.success ? r : (byId.get(r.recipient.id) || r));
    showSuccessView(lastSendResults);
  }

  // ═══ Success view ═══
  function showSuccessView(results) {
    const ok = results.filter(r => r.success).length;
    const fail = results.length - ok;
    const live = isLive();

    const icon = $('success-icon');
    icon.classList.toggle('partial', fail > 0);

    if (fail === 0) {
      $('success-title').textContent = results.length === 1 ? 'Letter Queued' : (results.length + ' Letters Queued');
      $('success-desc').textContent = live ? 'Submitted to Lob and will be printed and mailed via USPS.' : 'Test mode — no real letters mailed. Switch to a live_ API key to send real mail.';
    } else if (ok === 0) {
      $('success-title').textContent = 'Send Failed';
      $('success-desc').textContent = 'None of the letters were submitted. See errors below.';
    } else {
      $('success-title').textContent = ok + ' of ' + results.length + ' Queued';
      $('success-desc').textContent = 'Some letters could not be submitted. See details below.';
    }

    $('success-results').innerHTML = results.map(r => {
      // "Queued", not "Mailed": a create response only means Lob accepted the
      // job, not that anything is in the mail yet. The honest label matches the
      // "Letter Queued" success title.
      // Three outcomes: Queued (accepted by Lob), Failed (Lob rejected this
      // letter), and Not sent (a shared option was rejected on an earlier letter
      // and the batch was halted, so this one was never attempted).
      const badge = r.success ? '<span class="status-badge success">Queued</span>'
        : (r.notAttempted ? '<span class="status-badge muted">Not sent</span>' : '<span class="status-badge error">Failed</span>');
      const sub = r.success ? '<div class="result-item-sub">' + esc(r.data.id) + '</div>' : '<div class="result-item-error">' + esc(r.error) + '</div>';
      let track = '';
      if (r.success && isTrackedService(r.data && r.data.extra_service)) {
        const tn = r.data && r.data.tracking_number;
        if (tn && live) {
          track = '<div class="result-item-track"><span class="key">Tracking</span> ' +
            '<a href="' + esc(uspsTrackingUrl(tn)) + '" target="_blank" rel="noopener">' + esc(tn) + '</a>' +
            '<button class="btn-mini" type="button" data-copy="' + esc(tn) + '">Copy</button></div>';
        } else if (live) {
          track = '<div class="result-item-note">Tracking number will appear in History once USPS assigns it (up to ~3 business days). Use “Refresh all” there to check.</div>';
        } else {
          track = '<div class="result-item-note">Test mode — test sends don’t get a real tracking number.</div>';
        }
      }
      return (
        '<div class="result-item">' +
          '<div class="result-item-left">' +
            '<div class="result-item-name">' + esc(r.recipient.name || '(unnamed)') + '</div>' +
            sub + track +
          '</div>' +
          badge +
        '</div>'
      );
    }).join('');
    $('success-results').querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => copyText(b.getAttribute('data-copy'), b)));
    // Offer an idempotency-preserving retry only when something failed.
    const retryBtn = $('btn-retry-failed');
    if (retryBtn) retryBtn.style.display = fail > 0 ? '' : 'none';
    goToStep(4, true);
  }

  // ═══ History view ═══
  function renderHistory() {
    const list = $('history-list');
    const empty = $('history-empty');
    const emptyTitle = empty.querySelector('.history-empty-title');
    const emptyDesc = empty.querySelector('.history-empty-desc');

    if (history.length === 0) {
      empty.classList.remove('is-hidden');
      list.innerHTML = '';
      if (historyLoading) {
        emptyTitle.textContent = 'Loading…';
        emptyDesc.textContent = 'Fetching your mail from Lob.';
      } else if (!hasKey()) {
        emptyTitle.textContent = 'API key required';
        emptyDesc.textContent = 'Enter your Lob API key above to load your mail history.';
      } else if (historyError) {
        emptyTitle.textContent = 'Couldn’t load history';
        emptyDesc.textContent = historyError;
      } else {
        emptyTitle.textContent = 'No letters found';
        emptyDesc.textContent = 'No ' + (historyEnv === 'live' ? 'live' : 'test') + ' letters on this Lob account for the API key above.';
      }
      $('history-last-refreshed').textContent = '';
      return;
    }
    empty.classList.add('is-hidden');

    const cards = history.map(h => {
      const status = deriveStatus(h);
      const badge = '<span class="status-badge ' + status.variant + '">' + esc(status.label) + '</span>';
      const metaBits = [];
      // True field names: date_sent is Lob's date_created (see mapLobLetter), so
      // it is labeled "Created", never "Sent". Send date and expected delivery
      // are shown under their own names when present.
      metaBits.push('<span><span class="key">Created</span> ' + esc(formatShortDate(h.date_sent)) + '</span>');
      if (h.send_date) metaBits.push('<span><span class="key">Send date</span> ' + esc(formatShortDate(h.send_date)) + '</span>');
      if (h.expected_delivery_date) metaBits.push('<span><span class="key">Expected delivery</span> ' + esc(formatShortDate(h.expected_delivery_date)) + '</span>');
      if (h.mail_type) {
        metaBits.push('<span>' + esc(MAIL_TYPE_LABELS[h.mail_type] || h.mail_type) + '</span>');
      }
      if (h.extra_service) {
        metaBits.push('<span>' + esc(EXTRA_SERVICE_LABELS[h.extra_service] || h.extra_service) + '</span>');
      }
      metaBits.push('<span><code>' + esc(h.id) + '</code></span>');
      if (h.mode === 'test') metaBits.push('<span style="color:var(--text-muted)">Test</span>');

      // Tracking number / pending state / return-receipt pointer
      const tracked = isTrackedService(h.extra_service);
      const liveEntry = h.mode === 'live';
      let trackHtml = '';
      if (h.tracking_number) {
        if (liveEntry) {
          const url = uspsTrackingUrl(h.tracking_number);
          trackHtml = '<div class="letter-card-tracking">' +
            '<div class="tracking-line"><span class="key">Tracking</span> ' +
              '<a class="tracking-link" href="' + esc(url) + '" target="_blank" rel="noopener">' + esc(h.tracking_number) + '</a>' +
              '<button class="btn-mini" type="button" data-copy="' + esc(h.tracking_number) + '">Copy</button>' +
            '</div>';
          if (h.extra_service === 'certified_return_receipt') {
            trackHtml += '<div class="tracking-hint"><a href="' + esc(url) + '" target="_blank" rel="noopener">Return receipt ↗</a> — the signed receipt isn’t exposed by Lob; open USPS tracking and choose “Return Receipt Email” to receive the signature PDF.</div>';
          }
          trackHtml += '</div>';
        } else {
          // Test mode: Lob returns a dummy number — show it, but not as a USPS link.
          trackHtml = '<div class="letter-card-tracking"><div class="tracking-line"><span class="key">Tracking</span> <code>' + esc(h.tracking_number) + '</code> <span class="tracking-hint" style="margin:0">test — not a real USPS number</span></div></div>';
        }
      } else if (tracked && liveEntry) {
        trackHtml = '<div class="letter-card-tracking">' +
          '<span class="tracking-pending">Tracking number pending</span>' +
          '<div class="tracking-hint">Certified &amp; registered numbers can take up to ~3 business days to appear. Use “Refresh all” to check again.</div>' +
        '</div>';
      }

      // Tracking events (if any)
      let eventsHtml = '';
      if (Array.isArray(h.tracking_events) && h.tracking_events.length > 0) {
        const sorted = h.tracking_events.slice().sort((a, b) => new Date(b.time || b.date_created || 0) - new Date(a.time || a.date_created || 0));
        eventsHtml = '<div class="tracking-events">' + sorted.slice(0, 4).map(e =>
          '<div class="tracking-event"><span>' + esc(e.name || e.type || 'Event') + (e.location ? ' · ' + esc(e.location) : '') + '</span><span class="tracking-event-date">' + esc(formatShortDate(e.time || e.date_created)) + '</span></div>'
        ).join('') + '</div>';
      }

      return (
        '<div class="letter-card" data-lid="' + esc(h.id) + '">' +
          '<div class="letter-card-top">' +
            '<div style="flex:1;min-width:0">' +
              '<div class="letter-card-name">' + esc(h.recipient_name || '(unnamed)') + (h.recipient_company ? ' <span style="font-weight:400;color:var(--text-dim);font-size:13px"> · ' + esc(h.recipient_company) + '</span>' : '') + '</div>' +
              '<div class="letter-card-addr">' + esc(h.recipient_address || '') + '</div>' +
            '</div>' +
            '<div class="letter-card-actions">' +
              badge +
              '<button class="btn-mini" type="button" data-refresh="' + esc(h.id) + '">Refresh</button>' +
              (LETTER_ID_RE.test(h.id) ? '<button class="btn-mini" type="button" data-proof="' + esc(h.id) + '" title="Download a self-contained evidence bundle (request bytes, Lob response, rendered PDF, tracking, verifications, audit log) as a ZIP.">Export proof</button>' : '') +
              '<button class="btn-mini danger" type="button" data-delete="' + esc(h.id) + '">Remove</button>' +
            '</div>' +
          '</div>' +
          '<div class="letter-card-meta">' + metaBits.join('<span class="sep">·</span>') + '</div>' +
          trackHtml +
          eventsHtml +
        '</div>'
      );
    }).join('');

    const moreHtml = historyNextUrl ? '<div class="history-more"><button class="btn btn-secondary" id="btn-load-more" type="button">Load older letters</button></div>' : '';
    list.innerHTML = cards + moreHtml;

    list.querySelectorAll('[data-refresh]').forEach(b => b.addEventListener('click', () => refreshOne(b.getAttribute('data-refresh'))));
    list.querySelectorAll('[data-delete]').forEach(b => b.addEventListener('click', () => removeFromHistory(b.getAttribute('data-delete'))));
    list.querySelectorAll('[data-proof]').forEach(b => b.addEventListener('click', () => exportProof(b.getAttribute('data-proof'), b)));
    list.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => copyText(b.getAttribute('data-copy'), b)));
    const moreBtn = $('btn-load-more');
    if (moreBtn) moreBtn.addEventListener('click', () => loadAccountHistory({ reset: false }));

    // Summary: count + environment of the loaded list
    if (historyError) {
      $('history-last-refreshed').textContent = historyError;
    } else {
      const envLabel = historyEnv === 'live' ? 'live' : 'test';
      const shown = history.length;
      $('history-last-refreshed').textContent = shown + (historyNextUrl ? '+' : '') + ' ' + envLabel + ' letter' + (shown === 1 ? '' : 's');
    }
  }

  // Download the server-assembled evidence bundle for a letter. The endpoint
  // validates the id server-side too; this guard just avoids offering the
  // action for a non-letter id (e.g. an optimistic entry mid-send). The proof
  // is built from the durable audit store, so it works even for a letter Lob
  // has since aged out of its 90-day window.
  const LETTER_ID_RE = /^ltr_[A-Za-z0-9]+$/;
  async function exportProof(id, btn) {
    if (!LETTER_ID_RE.test(id)) return;
    const original = btn ? btn.textContent : null;
    if (btn) { btn.disabled = true; btn.textContent = 'Exporting…'; }
    try {
      const resp = await fetch('/api/proof/' + encodeURIComponent(id), { method: 'GET' });
      if (!resp.ok) {
        let msg = 'Export failed (HTTP ' + resp.status + ')';
        try { const j = await resp.json(); if (j && j.error && j.error.message) msg = j.error.message; } catch (e) { /* not json */ }
        alert(msg);
        return;
      }
      // Completeness signals from the server (also in manifest.json), read
      // before saving so we can warn the operator that a bundle is partial.
      const complete = resp.headers.get('X-PD-Proof-Complete') === 'true';
      const hasLocalRecord = resp.headers.get('X-PD-Proof-Has-Local-Record') !== 'false';
      const missing = (resp.headers.get('X-PD-Proof-Missing') || '').split(',').filter(Boolean);
      const blob = await resp.blob();
      // Prefer the server's Content-Disposition filename; fall back to a sane default.
      let filename = 'proof-' + id + '.zip';
      const cd = resp.headers.get('Content-Disposition') || '';
      const m = /filename="([^"]+)"/.exec(cd);
      if (m) filename = m[1];
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      // The file still downloads; the warning just makes a partial proof
      // impossible to mistake for a complete evidentiary record.
      if (!complete) {
        const lead = hasLocalRecord
          ? 'This proof was downloaded, but it is INCOMPLETE.'
          : 'This proof was downloaded, but this letter has NO local record in this app (it was not sent through PostDirect), so the exact request bytes and Lob’s creation response are not included.';
        alert(lead + (missing.length ? '\n\nMissing: ' + missing.join(', ') + '.' : '') +
          '\n\nItems fetched live from Lob are unavailable after Lob’s 90-day window; export sooner to capture them.');
      }
    } catch (e) {
      alert('Export failed: ' + (e.message || 'network error'));
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = original; }
    }
  }

  function removeFromHistory(id) {
    if (!confirm('Hide this letter from the list? It remains on your Lob account and will reappear when you reload History.')) return;
    history = history.filter(h => h.id !== id);
    optimistic = optimistic.filter(h => h.id !== id);
    updateHistoryCount();
    renderHistory();
  }

  async function fetchStatusForLetter(h) {
    try {
      const resp = await fetch(LOB_BASE + '/v1/letters/' + encodeURIComponent(h.id), {
        method: 'GET',
        headers: authHeaders()
      });
      const data = await resp.json();
      if (data.error) { h.fetch_error = data.error.message || 'API error'; h.last_refreshed = new Date().toISOString(); return; }
      h.fetch_error = null;
      h.last_refreshed = new Date().toISOString();
      if (data.expected_delivery_date) h.expected_delivery_date = data.expected_delivery_date;
      if (data.send_date) h.send_date = data.send_date;
      if (data.tracking_number) h.tracking_number = data.tracking_number;
      if (Array.isArray(data.tracking_events)) h.tracking_events = data.tracking_events;
      if (typeof data.deleted === 'boolean') h.deleted = data.deleted;
      if (data.description) h.description = data.description;
    } catch (e) {
      h.fetch_error = e.message || 'Network error';
      h.last_refreshed = new Date().toISOString();
    }
  }

  async function refreshOne(id) {
    if (!hasKey()) { alert('Enter your Lob API key at the top of the page to refresh status.'); return; }
    const h = history.find(x => x.id === id);
    if (!h) return;
    const btn = document.querySelector('[data-refresh="' + id + '"]');
    if (btn) { btn.disabled = true; btn.textContent = '…'; }
    await fetchStatusForLetter(h);
    renderHistory();
  }

  async function refreshAll() {
    if (!hasKey()) { alert('Enter your Lob API key at the top of the page to load your mail history.'); return; }
    // Reloading the account list IS the tracking refresh: each letter returns its
    // current tracking_number and tracking_events.
    await loadAccountHistory({ reset: true });
  }

  // ═══ View switching ═══
  function setView(name) {
    currentView = name;
    const composeActive = name === 'compose';
    $('view-compose').classList.toggle('is-hidden', !composeActive);
    $('view-history').classList.toggle('is-hidden', composeActive);
    $('view-compose-tab').classList.toggle('active', composeActive);
    $('view-history-tab').classList.toggle('active', !composeActive);
    // Keep ARIA tab state + roving tabindex in sync with the visual state.
    $('view-compose-tab').setAttribute('aria-selected', composeActive ? 'true' : 'false');
    $('view-history-tab').setAttribute('aria-selected', composeActive ? 'false' : 'true');
    $('view-compose-tab').tabIndex = composeActive ? 0 : -1;
    $('view-history-tab').tabIndex = composeActive ? -1 : 0;
    if (name === 'history') {
      if (hasKey() && historyLoadedKey !== keyIdentity()) loadAccountHistory({ reset: true });
      else renderHistory();
    }
  }

  // ═══ Events ═══
  $('view-compose-tab').addEventListener('click', () => setView('compose'));
  $('view-history-tab').addEventListener('click', () => setView('history'));

  // Tablist keyboard navigation (WAI-ARIA APG): arrows move focus + activate,
  // Home/End jump to the first/last tab.
  (function () {
    const tabs = [$('view-compose-tab'), $('view-history-tab')];
    const views = ['compose', 'history'];
    function go(i) {
      const n = (i + tabs.length) % tabs.length;
      setView(views[n]);
      tabs[n].focus();
    }
    tabs.forEach((tab, i) => {
      tab.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') { e.preventDefault(); go(i + 1); }
        else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') { e.preventDefault(); go(i - 1); }
        else if (e.key === 'Home') { e.preventDefault(); go(0); }
        else if (e.key === 'End') { e.preventDefault(); go(tabs.length - 1); }
      });
    });
  })();

  function updateEnvBadge() {
    const l = isLive();
    $('env-dot').className = 'env-dot ' + (l ? 'live' : 'test');
    $('env-badge').classList.toggle('live', l); // Live mode wears the wax (styling class only)
    $('env-label').textContent = l ? 'Live' : 'Test';
  }
  $('api-key-input').addEventListener('input', function() {
    updateEnvBadge();
    historyLoadedKey = null;  // key changed — History reloads next time it opens
    if (currentView === 'history') {
      clearTimeout(keyDebounce);
      // hasKey, not apiKey: clearing a pasted override falls back to the
      // server key (reload), not to the "enter your key" empty state.
      if (hasKey()) keyDebounce = setTimeout(() => loadAccountHistory({ reset: true }), 600);
      else renderHistory();   // cleared key -> show the "enter your key" empty state
    }
    if (currentStep === 3) {
      // The key the review's verification ran with changed. Debounced like the
      // History reload so typing a key char-by-char doesn't fire a request per
      // keystroke; populateReview re-runs verification with the new key.
      refreshNextBtn();
      clearTimeout(verifyDebounce);
      verifyDebounce = setTimeout(() => { if (currentStep === 3) populateReview(); }, 600);
    }
  });

  // Refresh the next button when any recipient input changes (event delegation)
  $('recipients-list').addEventListener('input', refreshNextBtn);

  // Refresh the next button when any other compose input changes
  document.addEventListener('input', function(e) {
    if (e.target.closest && e.target.closest('#recipients-list')) return; // already handled
    if (e.target.classList && (e.target.classList.contains('field-input') || e.target.classList.contains('field-textarea'))) refreshNextBtn();
  });

  // Certified/Registered ride First Class: Lob rejects Standard plus an extra
  // service, and failing at review time after the whole wizard is hostile, so
  // the class is forced and locked the moment an extra service is chosen.
  function syncMailClassLock() {
    const locked = !!$('opt-extra-service').value;
    const mt = $('opt-mail-type');
    if (locked) mt.value = 'usps_first_class';
    mt.disabled = locked;
  }
  $('opt-extra-service').addEventListener('change', syncMailClassLock);
  // Checking/unchecking the undeliverable acknowledgment flips the send gate.
  $('verify-ack').addEventListener('change', refreshNextBtn);

  $('btn-add-recipient').addEventListener('click', addRecipient);
  $('btn-back').addEventListener('click', () => { if (currentStep > 0) goToStep(currentStep - 1, true); });
  $('btn-next').addEventListener('click', () => {
    if (currentStep < 3) { if (canProceed()) goToStep(currentStep + 1, true); }
    else if (currentStep === 3) sendLetters();
  });

  $('btn-reset').addEventListener('click', () => {
    recipients = [{ id: nextRecipientId++, name: '', company: '', line1: '', line2: '', city: '', state: '', zip: '' }];
    // No key housekeeping: persisted idempotency keys are content-addressed by
    // fingerprint, so a fresh compose that happens to reproduce an identical
    // letter correctly reuses its key (Lob de-dupes) until the 24h window prunes it.
    renderRecipients();
    $('letter-body').value = '';
    $('opt-color').checked = false; $('opt-double').checked = false; $('opt-reply-envelope').checked = false;
    $('opt-mail-type').value = 'usps_first_class'; $('opt-extra-service').value = ''; $('opt-use-type').value = 'operational';
    $('opt-address-placement').value = 'top_first_page'; $('opt-send-date').value = ''; $('opt-description').value = '';
    syncMailClassLock(); // values were reset programmatically (no change event), so re-derive the lock
    removeFile(); setMode('write'); hideError();
    goToStep(0, true);
  });
  $('btn-view-history').addEventListener('click', () => setView('history'));
  $('btn-retry-failed').addEventListener('click', retryFailed);
  $('btn-refresh-all').addEventListener('click', refreshAll);

  // ═══ Init ═══
  // Learn whether the server holds a Lob key (PD_LOB_KEY) and its test/live
  // mode. Async by nature; until it resolves the UI behaves exactly as before
  // (paste-in only), so nothing downstream waits on it.
  fetch('/api/config').then(r => r.json()).then(cfg => {
    serverKey = !!(cfg && cfg.server_key);
    serverKeyEnv = (cfg && cfg.env) || null;
    if (!serverKey) return;
    $('api-key-input').placeholder = 'Server key configured (' + serverKeyEnv + ') — paste a key to override';
    updateEnvBadge();
    refreshNextBtn();
    // If History was opened before this resolved, it showed "API key required";
    // now that a key exists, load it.
    if (currentView === 'history' && historyLoadedKey !== keyIdentity()) loadAccountHistory({ reset: true });
  }).catch(() => { /* config unavailable — paste-in only, as before */ });
  updateHistoryCount();
  syncMailClassLock(); // in case the browser restored a stale extra-service selection
  // Constrain the Send Date picker to the same window validateSendDate enforces:
  // minimum tomorrow (Lob rejects a same-day or past date), maximum 180 days out.
  // Bounding the picker avoids the late-failure pattern the mail-class lock also
  // avoids; validateSendDate is the authoritative backstop at send time.
  (function () {
    const sd = $('opt-send-date');
    const today = new Date();
    const tomorrow = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);
    const max = new Date(today.getFullYear(), today.getMonth(), today.getDate() + SEND_DATE_MAX_DAYS);
    sd.min = localDateStr(tomorrow);
    sd.max = localDateStr(max);
  })();
  // Start with one empty recipient card
  recipients = [{ id: nextRecipientId++, name: '', company: '', line1: '', line2: '', city: '', state: '', zip: '' }];
  renderRecipients();
  goToStep(0);
})();
