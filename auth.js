// ── ACCESS auth — email magic-link ──────────────────────────────────────────
// A product sold to agents at any brokerage can't lean on one company's Google
// login. So sign-in is a magic link: enter your email, get a one-tap link, and
// you're in. The member record is `pm_profiles` (same shape the hub used):
// email, name, license, brokerage, status (pending/approved), socials, referral
// fields. Admin is whoever's email is set in ACCESS_ADMIN.
//
// Email delivery is pluggable: set RESEND_API_KEY for real send (one HTTPS call,
// no dependency). With no key set, the link is logged to the server console so
// the flow still works in dev/staging.

const crypto = require('crypto');
const { pmLoad, pmSave } = require('./db');

// ACCESS_ADMIN may hold one email or several (comma-separated) — every listed
// address is a full owner. ADMIN is the primary (first), used as the "to" for
// admin notification emails.
const ADMINS = String(process.env.ACCESS_ADMIN || '').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
const ADMIN = ADMINS[0] || '';
const FROM = process.env.ACCESS_FROM || 'AXESS <login@access.example>';
// Replies to our transactional mail (the From is a no-reply sending subdomain)
// are routed here so a member who hits "reply" reaches a real inbox.
const REPLY_TO = process.env.ACCESS_REPLY_TO || 'info@axessre.com';
const TOKEN_TTL_MS = 30 * 60 * 1000; // 30 min

const lc = s => String(s || '').toLowerCase().trim();

// Short-lived login tokens. Persisted in Postgres (pm_store key pm_authtokens)
// so a pending link SURVIVES a server restart / free-tier spin-down — otherwise
// an in-memory map would silently invalidate every outstanding link on restart.
// Falls back to an in-memory map only when there's no database (local dev).
const TOKKEY = 'pm_authtokens';
const memTokens = new Map(); // token -> { email, exp } (no-DB fallback)

async function putToken(token, email) {
  const exp = Date.now() + TOKEN_TTL_MS;
  try {
    const now = Date.now();
    const list = (await pmLoad(TOKKEY)) || [];
    const pruned = list.filter(t => t && t.exp > now); // drop expired
    pruned.push({ token, email, exp });
    await pmSave(TOKKEY, pruned.length > 1000 ? pruned.slice(-1000) : pruned);
  } catch (e) { memTokens.set(token, { email, exp }); }
}
// Consume a token: return { email, exp } if valid, else null. Single-use.
async function takeToken(token) {
  if (memTokens.has(token)) {
    const r = memTokens.get(token); memTokens.delete(token);
    return (r && r.exp > Date.now()) ? r : null;
  }
  try {
    const now = Date.now();
    const list = (await pmLoad(TOKKEY)) || [];
    const rec = list.find(t => t && t.token === token) || null;
    const remaining = list.filter(t => t && t.token !== token && t.exp > now);
    if (list.length !== remaining.length) await pmSave(TOKKEY, remaining);
    return (rec && rec.exp > now) ? rec : null;
  } catch (e) { return null; }
}

async function sendEmail(to, subject, html) {
  const key = process.env.RESEND_API_KEY;
  if (!key) { console.log('[ACCESS email — no RESEND_API_KEY, logging]\nTo:', to, '\nSubject:', subject, '\n', html); return true; }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: FROM, to: [to], subject, html, reply_to: REPLY_TO })
    });
    return r.ok;
  } catch (e) { console.error('email send failed', e); return false; }
}

async function profileFor(email) {
  const profs = await pmLoad('pm_profiles');
  return profs.find(p => p && lc(p.email) === lc(email)) || null;
}

// Turn a session email into the request-scoped user the routes expect.
async function userFor(email) {
  const e = lc(email);
  if (!e) return null;
  const p = await profileFor(e);
  const role = ADMINS.includes(e) ? 'owner' : 'member';
  // Deactivated members keep every record but lose access — the gate reads this flag.
  const deactivated = role !== 'owner' && !!(p && p.deactivated);
  const status = role === 'owner' ? 'approved' : (deactivated ? 'deactivated' : (p && p.status) || 'none');
  return { email: e, name: (p && p.name) || '', brokerage: (p && p.brokerage) || '', status, role, deactivated };
}

// Create a login token and email the one-tap sign-in link. Used by the signup
// flow so a new pending member gets their magic link immediately.
async function sendMagicLink(email, baseUrl) {
  const e = lc(email);
  if (!e || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)) return false;
  const token = crypto.randomBytes(24).toString('hex');
  await putToken(token, e);
  const link = (baseUrl || 'https://access-network.onrender.com') + '/auth/verify?token=' + token;
  const sent = await sendEmail(e, 'Your AXESS sign-in link',
    `<p>Welcome to AXESS — tap to sign in:</p><p><a href="${link}">Sign in</a></p><p>This link expires in 30 minutes.</p>`);
  if (!sent) console.error('[ACCESS] signup sign-in email FAILED for', e);
  return sent !== false;
}

function mount(app, baseUrl) {
  // Request a login link. Sent to any well-formed address; whether the session
  // can actually reach the app is decided at the gate (approved member / admin).
  app.post('/auth/request', async (req, res) => {
    const email = lc((req.body || {}).email);
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ ok: false, error: 'bad_email' });
    const token = crypto.randomBytes(24).toString('hex');
    await putToken(token, email);
    const link = (baseUrl || ('https://' + (req.headers.host || ''))) + '/auth/verify?token=' + token;
    const sent = await sendEmail(email, 'Your AXESS sign-in link',
      `<p>Tap to sign in to AXESS:</p><p><a href="${link}">Sign in</a></p><p>This link expires in 30 minutes.</p>`);
    // Don't leak whether an address exists, but DO record a real send failure so
    // a silent delivery problem is diagnosable instead of looking like success.
    if (!sent) console.error('[ACCESS] sign-in email send FAILED for', email, '(check RESEND_API_KEY / verified domain / rate limits)');
    res.json({ ok: true, sent: sent !== false });
  });

  // Consume a login link → set the session.
  app.get('/auth/verify', async (req, res) => {
    const token = String((req.query || {}).token || '');
    const rec = await takeToken(token);
    if (!rec) return res.status(401).send('Link expired — request a new one.');
    req.session.email = rec.email;
    res.redirect('/app.html');
  });

  app.get('/auth/logout', (req, res) => { req.session = null; res.redirect('/'); });
  // Alias: the app's "Sign out" link points here — clear the session and go home.
  app.get('/logout', (req, res) => { req.session = null; res.redirect('/'); });

  app.get('/api/me', async (req, res) => {
    const u = req.user;
    res.json(u ? { ok: true, email: u.email, name: u.name, role: u.role, status: u.status, brokerage: u.brokerage } : { ok: false });
  });
}

// Attach req.user from the session on every request (null when signed out).
function attachUser() {
  return async (req, res, next) => {
    try { req.user = req.session && req.session.email ? await userFor(req.session.email) : null; }
    catch (e) { req.user = null; }
    next();
  };
}

// Require a signed-in session (any status).
function ensureAuth(req, res, next) {
  if (req.user && req.user.email) return next();
  if (req.accepts('html')) return res.redirect('/');
  return res.status(401).json({ ok: false, error: 'auth' });
}

module.exports = { mount, attachUser, ensureAuth, userFor, profileFor, sendEmail, sendMagicLink, ADMIN, ADMINS, lc };
