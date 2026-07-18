'use strict';
// Shared option validation and coupling: send-date, reply mail, batch-halt (pure).
// Extracted verbatim from the former inline <script> in public/index.html so
// the browser app and the Node unit tests share ONE source of truth (the unit
// tests import this module directly instead of re-parsing the HTML).

import { parseLobDate } from './dates.mjs';

  // ═══ Shared option validation and coupling (item 5) ═══
  const SEND_DATE_MAX_DAYS = 180;

  // Reply mail couples two Lob fields: a return envelope requires a perforated
  // first page (so the recipient can tear off and return a reply). Emitting
  // them from ONE control makes it structurally impossible to send a return
  // envelope without the perforation. Pure and named for unit testing.
  function replyMailFields(replyEnvelope) {
    return replyEnvelope ? [['return_envelope', 'true'], ['perforated_page', '1']] : [];
  }

  // Validate the scheduled send date against Lob's real constraints: empty means
  // send immediately; otherwise it must be a calendar date from tomorrow up to
  // SEND_DATE_MAX_DAYS out (Lob rejects same-day once its cutoff passes, and has
  // no use for a date far in the future). Pure: today is injected as YYYY-MM-DD.
  function validateSendDate(value, todayStr) {
    if (!value) return { ok: true };
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return { ok: false, error: 'Send date must be a calendar date (YYYY-MM-DD).' };
    const v = parseLobDate(value);
    if (isNaN(v.getTime())) return { ok: false, error: 'Send date is not a valid date.' };
    const today = parseLobDate(todayStr);
    const tomorrow = new Date(today.getFullYear(), today.getMonth(), today.getDate() + 1);
    const max = new Date(today.getFullYear(), today.getMonth(), today.getDate() + SEND_DATE_MAX_DAYS);
    if (v.getTime() < tomorrow.getTime()) return { ok: false, error: 'Send date must be tomorrow or later (Lob rejects a same-day or past date).' };
    if (v.getTime() > max.getTime()) return { ok: false, error: 'Send date must be within ' + SEND_DATE_MAX_DAYS + ' days.' };
    return { ok: true };
  }

  // Heuristic: does a Lob 422 message point at a SHARED option (so every letter
  // in the batch would fail identically) rather than one recipient's address?
  // Shared options are batch-wide; a recipient error names the recipient ("to")
  // or their address and is per-letter. Used to halt a batch once instead of
  // collecting 25 identical failures.
  function isSharedOptionError(message) {
    const m = String(message == null ? '' : message).toLowerCase();
    const sharedField = /(send_date|send date|mail_type|mail type|extra_service|extra service|use_type|use type|perforated|return_envelope|return envelope|address_placement|address placement|double_sided|double-sided|\bcolor\b)/.test(m);
    if (!sharedField) return false;
    // Only a recipient FIELD PATH (to[...] / to....) makes it per-letter. The
    // bare word "recipient" is NOT enough: Lob may name the recipient in a
    // shared-option message ("send_date is invalid for recipient X"), and
    // treating that as per-letter would defeat the halt and collect up to 25
    // identical failures, the exact case this guards against.
    const recipientField = /\bto\[|\bto\./.test(m);
    return !recipientField;
  }

  // Result entries for the recipients AFTER a halt: the shared option they share
  // was rejected on letter (failedIndex+1), so they were never sent. Named +
  // pure so the halt semantics (which letters were rejected vs never attempted)
  // are unit-testable without the browser send loop.
  function notAttemptedEntries(rs, failedIndex) {
    const out = [];
    for (let j = failedIndex + 1; j < rs.length; j++) {
      out.push({
        recipient: rs[j], success: false, notAttempted: true,
        error: 'Not attempted: a shared option was rejected on letter ' + (failedIndex + 1) +
          ', so letters ' + (failedIndex + 2) + ' through ' + rs.length + ' were not sent.',
      });
    }
    return out;
  }

export { SEND_DATE_MAX_DAYS, replyMailFields, validateSendDate, isSharedOptionError, notAttemptedEntries };
