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
const { pmLoad } = require('./db');

const ADMIN = String(process.env.ACCESS_ADMIN || '').toLowerCase().trim();
const FROM = process.env.ACCESS_FROM || 'ACCESS <login@access.example>';
const TOKEN_TTL_MS = 30 * 60 * 1000; // 30 min

const lc = s => String(s || '').toLowerCase().trim();

// Short-lived login tokens (a restart just means request a fresh link).
const TOKENS = new Map(); // token -> { email, exp }

async function sendEmail(to, subject, html) {
  const key = process.env.RESEND_API_KEY;
  if (!key) { console.log('[ACCESS email — no RESEND_API_KEY, logging]\nTo:', to, '\nSubject:', subject, '\n', html); return true; }
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: FROM, to: [to], subject, html })
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
  const role = (e === ADMIN) ? 'owner' : 'member';
  const status = role === 'owner' ? 'approved' : (p && p.status) || 'none';
  return { email: e, name: (p && p.name) || '', brokerage: (p && p.brokerage) || '', status, role };
}

function mount(app, baseUrl) {
  // Request a login link. Sent to any well-formed address; whether the session
  // can actually reach the app is decided at the gate (approved member / admin).
  app.post('/auth/request', async (req, res) => {
    const email = lc((req.body || {}).email);
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ ok: false, error: 'bad_email' });
    const token = crypto.randomBytes(24).toString('hex');
    TOKENS.set(token, { email, exp: Date.now() + TOKEN_TTL_MS });
    const link = (baseUrl || ('https://' + (req.headers.host || ''))) + '/auth/verify?token=' + token;
    await sendEmail(email, 'Your ACCESS sign-in link',
      `<p>Tap to sign in to ACCESS:</p><p><a href="${link}">Sign in</a></p><p>This link expires in 30 minutes.</p>`);
    res.json({ ok: true });
  });

  // Consume a login link → set the session.
  app.get('/auth/verify', (req, res) => {
    const token = String((req.query || {}).token || '');
    const rec = TOKENS.get(token);
    if (!rec || rec.exp < Date.now()) { TOKENS.delete(token); return res.status(401).send('Link expired — request a new one.'); }
    TOKENS.delete(token);
    req.session.email = rec.email;
    res.redirect('/app.html');
  });

  app.get('/auth/logout', (req, res) => { req.session = null; res.redirect('/'); });

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

module.exports = { mount, attachUser, ensureAuth, userFor, profileFor, sendEmail, ADMIN, lc };
