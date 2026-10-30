// Cost guards: switches and hard caps for everything that spends real money
// per use. AXESS isn't charging members yet, so anything metered is either off
// by default or capped. All limits are env-tunable; the counters are in-memory
// per UTC day (single Render instance), so a restart resets them early, never
// late. Every refusal is logged and returned to the caller, never swallowed.

'use strict';

const ON_RE = /^(on|1|true|yes)$/i;
const num = (v, d) => { const n = Number(v); return isFinite(n) && n >= 0 && String(v).trim() !== '' ? n : d; };

// ── paid AI (document reading, description drafting, intro drafting) ────────
// Off unless AI_FEATURES=on. Checked before quota and before any provider call.
function aiEnabled() { return ON_RE.test(String(process.env.AI_FEATURES || '').trim()); }
const AI_PAUSED_MESSAGE = 'AI features are paused for now. Fill this in by hand. Everything else works as usual.';

// ── daily counters ──────────────────────────────────────────────────────────
function today(nowMs) { return new Date(nowMs || Date.now()).toISOString().slice(0, 10); }
const state = { day: '', emails: 0, uploadsBy: {}, uploadBytesTotal: 0 };
function roll(nowMs) {
  const d = today(nowMs);
  if (state.day !== d) { state.day = d; state.emails = 0; state.uploadsBy = {}; state.uploadBytesTotal = 0; }
}
function reset() { state.day = ''; roll(); }

// ── email (Resend) ──────────────────────────────────────────────────────────
// Hard cap on non-essential email per UTC day (alerts, digests, notices).
// Sign-in links are "essential" and never capped, so sign-in and sign-up work
// exactly as before.
function emailDailyCap() { return num(process.env.EMAIL_DAILY_CAP, 300); }
function emailTake(nowMs) {
  roll(nowMs);
  if (state.emails >= emailDailyCap()) return false;
  state.emails++;
  return true;
}

// ── uploads (Cloudflare R2, or inline in Postgres when R2 is off) ───────────
function uploadLimits() {
  return {
    filesPerMember: num(process.env.UPLOAD_DAILY_FILES_PER_MEMBER, 150),
    mbPerMember: num(process.env.UPLOAD_DAILY_MB_PER_MEMBER, 750),
    mbTotal: num(process.env.UPLOAD_DAILY_MB_TOTAL, 5000)
  };
}
// Reserve one upload of `bytes` for `email`. Returns { ok } or { ok:false, scope }.
function uploadTake(email, bytes, nowMs) {
  roll(nowMs);
  const L = uploadLimits(), MB = 1024 * 1024;
  const k = String(email || '').toLowerCase();
  const u = state.uploadsBy[k] || { files: 0, bytes: 0 };
  if (state.uploadBytesTotal + bytes > L.mbTotal * MB) return { ok: false, scope: 'network' };
  if (u.files + 1 > L.filesPerMember || u.bytes + bytes > L.mbPerMember * MB) return { ok: false, scope: 'member' };
  u.files++; u.bytes += bytes; state.uploadsBy[k] = u; state.uploadBytesTotal += bytes;
  return { ok: true };
}
// Give the reservation back when the store itself failed.
function uploadRefund(email, bytes) {
  const u = state.uploadsBy[String(email || '').toLowerCase()];
  if (u) { u.files = Math.max(0, u.files - 1); u.bytes = Math.max(0, u.bytes - bytes); }
  state.uploadBytesTotal = Math.max(0, state.uploadBytesTotal - bytes);
}

module.exports = { aiEnabled, AI_PAUSED_MESSAGE, emailDailyCap, emailTake, uploadLimits, uploadTake, uploadRefund, reset, _state: state };
