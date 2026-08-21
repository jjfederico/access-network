// ── AXESS — standalone server ──────────────────────────────────────────────
// Invite-only, agent-to-agent, off-market investment deal network.
// Own repo · own Render service · own Postgres. Data layer: db.js
// (pmLoad/pmSave over Postgres). Auth: auth.js (email magic-link).
// The full /api/pm/* marketplace, ported from the Grove hub onto Postgres.

const express = require('express');
const cookieSession = require('cookie-session');
const path = require('path');
const fs = require('fs');
const https = require('https');
const db = require('./db');
const authMod = require('./auth');
const { pmLoad, pmSave } = db;

// Tiny HTTPS GET → JSON (used to verify Google sign-in tokens; no extra deps).
function httpsGetJson(url) {
  return new Promise((resolve, reject) => {
    https.get(url, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => { try { resolve(JSON.parse(d)); } catch (e) { reject(e); } }); }).on('error', reject);
  });
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieSession({
  name: 'access_sess',
  keys: [process.env.SESSION_SECRET || 'dev-change-me'],
  maxAge: 90 * 24 * 3600 * 1000,
  httpOnly: true, sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production'
}));

const BASE_URL = (process.env.BASE_URL || '').replace(/\/$/, '');
const PM_BASE = BASE_URL || 'http://localhost:' + (process.env.PORT || 3000);

app.use(authMod.attachUser());
const ensureAuth = authMod.ensureAuth;
const ADMIN = authMod.ADMIN;
const ADMINS = authMod.ADMINS || (ADMIN ? [ADMIN] : []);

// ── Cloudflare Turnstile (captcha on the public join form) ──────────────────
const TURNSTILE_SITE = process.env.TURNSTILE_SITE_KEY || '';
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || '';
async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET) return true; // not configured yet → don't block
  if (!token) return false;
  try {
    const body = new URLSearchParams({ secret: TURNSTILE_SECRET, response: String(token) });
    if (ip) body.append('remoteip', String(ip));
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body });
    const j = await r.json();
    return !!(j && j.success);
  } catch (e) { return false; }
}

// ── shared helpers (ported, now sheet-free) ─────────────────────────────────
const _lc = s => String(s || '').toLowerCase().trim();
const lc = _lc;
const pmEmail = u => _lc((u && u.email) || '');
function pmId(p) { return p + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }
const PM_KEYS = { listings: 'pm_listings', intros: 'pm_intros', buyboxes: 'pm_buyboxes' };

// Canonical licensure attestation — the exact text a member must accept at signup.
// Stored verbatim on their profile with a timestamp + IP so acceptance is provable.
const ATTEST_TEXT = "I certify that I am a currently licensed real estate agent in good standing, that my name, license number, brokerage, and all information I've provided are true and accurate, and that I am not misrepresenting my identity or licensure. I understand AXESS verifies licenses and that any false statement is grounds for immediate termination without refund.";

// ── give-to-get reciprocity ─────────────────────────────────────────────────
// The network only works if members contribute. A member keeps FULL access
// (seeing addresses + contacting posters) while they have a live deal OR a live
// client need in the last GG_DAYS. New members get a GG_GRACE-day grace window
// to explore first. Owner is always exempt; a profile flag exemptGiveGet/founder
// exempts specific members. Set GIVE_GET_OFF=1 to disable enforcement (demo).
const GG_DAYS = parseInt(process.env.GIVE_GET_DAYS || '', 10) || 60;
const GG_GRACE = parseInt(process.env.GIVE_GET_GRACE || '', 10) || 21;
const GG_ENFORCE = !process.env.GIVE_GET_OFF;
function _daysSince(iso) { if (!iso) return Infinity; const t = new Date(iso).getTime(); return isNaN(t) ? Infinity : (Date.now() - t) / 86400000; }
function pmReciprocity(email, listings, boxes, profs) {
  const e = _lc(email);
  const prof = (profs || []).find(p => p && _lc(p.email) === e) || {};
  if (prof.exemptGiveGet || prof.founder) return { active: true, exempt: true, enforce: GG_ENFORCE, hasDeal: true, hasNeed: false, inGrace: false, graceDaysLeft: 0, lastDealDays: 0, lastNeedDays: null, windowDays: GG_DAYS };
  let lastDeal = Infinity, lastNeed = Infinity;
  (listings || []).forEach(l => { if (l && _lc(l.owner) === e && (l.status || 'active') !== 'off') { const d = _daysSince(l.updatedAt || l.createdAt); if (d < lastDeal) lastDeal = d; } });
  (boxes || []).forEach(b => { if (b && _lc(b.owner) === e) { const d = _daysSince(b.updatedAt || b.createdAt); if (d < lastNeed) lastNeed = d; } });
  const hasDeal = lastDeal <= GG_DAYS, hasNeed = lastNeed <= GG_DAYS;
  const graceUsed = _daysSince(prof.approvedAt || prof.createdAt);
  const inGrace = graceUsed <= GG_GRACE;
  const active = !GG_ENFORCE || hasDeal || hasNeed || inGrace;
  return {
    active, exempt: false, enforce: GG_ENFORCE, hasDeal, hasNeed, inGrace,
    graceDaysLeft: inGrace ? Math.max(0, Math.ceil(GG_GRACE - graceUsed)) : 0,
    lastDealDays: isFinite(lastDeal) ? Math.floor(lastDeal) : null,
    lastNeedDays: isFinite(lastNeed) ? Math.floor(lastNeed) : null,
    windowDays: GG_DAYS
  };
}

// Gate: signed in AND (admin OR approved member). Invite-only — a pending or
// unknown session gets nothing from the API.
// Signed-in gate. Owner + approved + PENDING members all pass (pending can browse
// a limited feed and set up their profile). Write/contact actions separately
// require pmApproved (verified), so pending can look but not post or contact.
async function pmGate(req, res, next) {
  if (!req.user || !req.user.email) return res.status(403).json({ ok: false, error: 'forbidden' });
  if (req.user.deactivated && req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'deactivated' });
  if (req.user.role === 'owner' || req.user.status === 'approved' || req.user.status === 'pending') return next();
  return res.status(403).json({ ok: false, error: 'not_approved' });
}
async function pmApproved(user) {
  if (!user) return false;
  if (user.role === 'owner') return true;
  return user.status === 'approved';
}
function pmEntitled(listing, u, intros) {
  if (!listing) return false;
  if (u.role === 'owner') return true;
  if (_lc(listing.owner) === pmEmail(u)) return true;
  const email = pmEmail(u);
  return (intros || []).some(i => i && i.listingId === listing.id && _lc(i.buyer) === email && i.status === 'approved');
}
function pmPublicView(l, full, gated) {
  if (!l) return null;
  const zip = String(l.zip || '');
  const showAddr = full || (!l.hideAddress && !gated);
  const expired = l.expiresAt ? (new Date(l.expiresAt) < new Date()) : false;
  const out = {
    id: l.id, owner: l.owner, ownerName: l.ownerName || '',
    createdAt: l.createdAt || '', updatedAt: l.updatedAt || '', expiresAt: l.expiresAt || '', expired,
    status: l.status || 'active', mlsAt: l.mlsAt || '', featured: !!l.featured,
    city: l.city || '', area: l.area || '', state: l.state || '',
    zipPrefix: zip ? zip.slice(0, 3) : '',
    propType: l.propType || '', dist: l.dist || 'broad',
    units: l.units || '', sqft: l.sqft || '',
    beds: l.beds || '', baths: l.baths || '', yearBuilt: l.yearBuilt || '',
    price: l.price || '', noi: l.noi || '', capRate: l.capRate || '',
    grossIncome: l.grossIncome || '', expenses: l.expenses || '',
    commissionPct: l.commissionPct || '', commissionNotes: l.commissionNotes || '',
    notes: l.notes || '', docCount: Array.isArray(l.docs) ? l.docs.length : 0, views: l.views || 0,
    photoCount: Array.isArray(l.photos) ? l.photos.length : 0,
    hideAddress: !!l.hideAddress, addressHidden: !showAddr,
    closedAt: l.closedAt || '', closePrice: l.closePrice || ''
  };
  if (showAddr) {
    out.address = l.address || ''; out.zip = zip;
    out.photos = Array.isArray(l.photos) ? l.photos : [];
    // Documents (OMs, financials) contain the address & full details — only entitled viewers get them.
    out.docs = Array.isArray(l.docs) ? l.docs : [];
    if (l.lat && l.lng) { out.lat = l.lat; out.lng = l.lng; } // exact pin only for entitled viewers
  }
  return out;
}
const pmSendEmail = (to, subject, body) =>
  authMod.sendEmail(to, subject, `<pre style="font:inherit;white-space:pre-wrap">${String(body || '')}</pre>`);
function pmNum(v) { const n = parseFloat(String(v == null ? '' : v).replace(/[^0-9.]/g, '')); return isFinite(n) ? n : 0; }
const pmFocus = v => (['residential', 'commercial', 'both'].indexOf(String(v || '').toLowerCase().trim()) >= 0 ? String(v).toLowerCase().trim() : '');
// Category grouping (mirrors the app). Crossover types (2–4 unit, land, multifamily)
// count as BOTH so a commercial agent still hears about small multifamily & land,
// but never single-family / condo / townhouse.
const RESI_TYPES = ['Single-family', 'Condo / Conversion', 'Townhouse', 'Multifamily', 'Land'];
const COMM_TYPES = ['Multifamily', 'Mixed-use', 'Retail / Commercial', 'Industrial', 'Development site', 'Land'];
function pmFocusAllows(focus, propType) {
  focus = String(focus || '').toLowerCase();
  if (focus !== 'residential' && focus !== 'commercial') return true; // both / unset → everything
  const inR = RESI_TYPES.indexOf(propType) >= 0, inC = COMM_TYPES.indexOf(propType) >= 0;
  if (!inR && !inC) return true; // unclassified type → don't suppress
  return focus === 'commercial' ? inC : inR;
}
// Does this member want a deal-match alert for this listing? Member notification
// settings win; if they've never set them, fall back to their focus (sensible default).
function pmWantsDealAlert(prof, deal) {
  const p = prof && prof.notifPrefs;
  if (!p) return pmFocusAllows(prof && prof.focus, deal.propType); // legacy default
  if (p.deals === 'off') return false;
  if (p.deals === 'types') {
    const list = Array.isArray(p.dealTypes) ? p.dealTypes : [];
    if (list.length && list.indexOf(deal.propType) < 0) return false;
  }
  if (Array.isArray(p.dealMarkets) && p.dealMarkets.length) {
    const loc = String(deal.area || deal.city || '').toLowerCase();
    const hit = p.dealMarkets.some(m => { m = String(m).toLowerCase().trim(); return m && loc.indexOf(m) >= 0; });
    if (!hit) return false;
  }
  return true;
}
function pmWantsEmail(prof, kind) { // kind: 'deals' | 'intros'
  const p = prof && prof.notifPrefs;
  if (!p) return true; // legacy → email on
  if (kind === 'intros') return p.intros !== false;
  return p.email !== false;
}
function pmMoneyShort(v) { const n = Math.round(pmNum(v)); if (!n) return ''; if (n >= 1e6) return '$' + (n / 1e6).toFixed(n % 1e6 ? 1 : 0) + 'M'; if (n >= 1e3) return '$' + Math.round(n / 1e3) + 'K'; return '$' + n; }
// Public-safe proof-of-funds view: status + amount only (never the uploaded doc).
function pmPofPublic(prof) {
  const p = prof && prof.pof;
  if (!p || !p.status || p.status === 'none') return { status: 'none', amount: '' };
  return { status: p.status, amount: p.status === 'verified' ? (p.amount || '') : '' };
}
// One-line credibility summary for emails.
function pmCredLine(prof) {
  const bits = [];
  if (prof && prof.verified) bits.push('license-verified');
  const pof = pmPofPublic(prof);
  if (pof.status === 'verified') bits.push('proof-of-funds verified' + (pof.amount ? (' up to ' + pof.amount) : ''));
  return bits.length ? ('Buyer: ' + bits.join(' · ')) : '';
}
function pmMatch(l, box) {
  if (!l || !box) return false;
  const price = pmNum(l.price), minP = pmNum(box.minPrice), maxP = pmNum(box.maxPrice);
  if (minP && price && price < minP) return false;
  if (maxP && price && price > maxP) return false;
  const units = pmNum(l.units), minU = pmNum(box.minUnits), maxU = pmNum(box.maxUnits);
  if (minU && units && units < minU) return false;
  if (maxU && units && units > maxU) return false;
  const cap = pmNum(l.capRate), minC = pmNum(box.minCap);
  if (minC && cap && cap < minC) return false;
  const bm = String(box.markets || '').toLowerCase().trim();
  if (bm) { const loc = (String(l.area || '') + ' ' + String(l.city || '') + ' ' + String(l.state || '')).toLowerCase(); let any = false; bm.split(/[,;/]+/).forEach(m => { m = m.trim(); if (m && loc.indexOf(m) >= 0) any = true; }); if (!any) return false; }
  const bt = String(box.propType || '').toLowerCase().trim();
  if (bt) { const lt = String(l.propType || '').toLowerCase(); if (lt) { let any2 = false; bt.split(/[,;/ ]+/).forEach(w => { if (w && w.length > 2 && lt.indexOf(w) >= 0) any2 = true; }); if (!any2) return false; } }
  return true;
}
function pmSocial(kind, v) {
  v = String(v == null ? '' : v).trim().slice(0, 200);
  if (!v) return '';
  if (/^https?:\/\//i.test(v)) return /^https?:\/\/[^\s"'<>`]+$/i.test(v) ? v : '';
  const handle = v.replace(/^@+/, '').replace(/[^A-Za-z0-9_.\/-]/g, '');
  if (!handle) return '';
  if (kind === 'website') return 'https://' + handle;
  const base = { linkedin: 'https://www.linkedin.com/in/', instagram: 'https://instagram.com/', facebook: 'https://facebook.com/', x: 'https://x.com/' }[kind];
  return base ? base + handle : '';
}
function pmRefCode(email) {
  const s = _lc(email); let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h.toString(36).toUpperCase().replace(/[^A-Z0-9]/g, '').padStart(6, 'X').slice(0, 6);
}
function pmThreadKey(a, b, listingId) {
  const p = [_lc(a), _lc(b)].sort();
  return p[0] + '|' + p[1] + (listingId ? ('|' + listingId) : '');
}
function pmIsAdmin(req) { return req.user && req.user.role === 'owner'; }

// ── auth routes + health + import ───────────────────────────────────────────
authMod.mount(app, BASE_URL);
app.get('/api/health', async (req, res) => res.json(await db.health()));
app.post('/api/pm/import', ensureAuth, async (req, res) => {
  if (req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  try { res.json(await db.importAll(req.body || {})); }
  catch (e) { res.status(500).json({ ok: false, error: String(e && e.message || e) }); }
});

// ── feed / listings ─────────────────────────────────────────────────────────
app.get('/api/pm/feed', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, intros, profs, boxes] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.intros), pmLoad('pm_profiles'), pmLoad(PM_KEYS.buyboxes)]);
    const meEmail = pmEmail(req.user);
    const meProf = profs.find(p => p && _lc(p.email) === meEmail) || {};
    const isOwner = req.user.role === 'owner';
    const mine = l => _lc(l.owner) === meEmail;
    const recip = pmReciprocity(meEmail, listings, boxes, profs);
    const gated = !isOwner && !recip.active;   // throttle non-contributors
    const isExpired = l => l.expiresAt && (new Date(l.expiresAt) < new Date());
    const profBy = {}; profs.forEach(p => { if (p && p.email) profBy[_lc(p.email)] = p; });
    const attachOwner = r => { const p = profBy[_lc(r.owner)]; r.ownerVerified = !!(p && p.verified); r.ownerProducer = !!(p && p.producer); const pof = pmPofPublic(p || {}); r.ownerPof = pof.status === 'verified' ? { amount: pof.amount } : null; return r; };
    const rows = listings
      .filter(l => l && (((l.status || 'active') !== 'off' && (l.status || 'active') !== 'mls' && (l.status || 'active') !== 'closed') || mine(l) || isOwner))
      .filter(l => !isExpired(l) || mine(l) || isOwner)
      .map(l => attachOwner(pmPublicView(l, mine(l) || isOwner, gated && !mine(l))))
      .sort((a, b) => (b.featured - a.featured) || String(b.createdAt).localeCompare(String(a.createdAt)));
    res.json({ ok: true, listings: rows, me: { email: req.user.email, role: req.user.role, focus: meProf.focus || '', reciprocity: recip } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.get('/api/pm/listing/:id', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, intros, boxes, profs] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.intros), pmLoad(PM_KEYS.buyboxes), pmLoad('pm_profiles')]);
    const l = listings.find(x => x && x.id === String(req.params.id));
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    const full = _lc(l.owner) === pmEmail(req.user) || req.user.role === 'owner';
    const recip = pmReciprocity(pmEmail(req.user), listings, boxes, profs);
    const gated = !full && !recip.active;
    const oProf = profs.find(p => p && _lc(p.email) === _lc(l.owner)) || {};
    const view = pmPublicView(l, full, gated);
    view.ownerVerified = !!oProf.verified;
    view.ownerProducer = !!oProf.producer;
    const oPof = pmPofPublic(oProf); view.ownerPof = oPof.status === 'verified' ? { amount: oPof.amount } : null;
    res.json({ ok: true, listing: view, reciprocity: recip });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.post('/api/pm/listing', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const S = (v, n) => String(v == null ? '' : v).slice(0, n || 120);
  try {
    if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_approved' });
    const listings = await pmLoad(PM_KEYS.listings);
    const id = S(b.id, 40);
    const now = new Date().toISOString();
    const docsIn = Array.isArray(b.docs) ? b.docs.slice(0, 20).map(d => ({ name: S(d && d.name, 160), url: S(d && d.url, 900) })).filter(d => d.url) : [];
    const photosIn = Array.isArray(b.photos) ? b.photos.slice(0, 24).map(p => ({ name: String((p && p.name) || '').slice(0, 120), url: String((p && p.url) || '') })).filter(p => p.url && p.url.length < 6000000) : [];
    const fields = {
      ownerName: S(b.ownerName, 80),
      status: (b.status === 'off' ? 'off' : b.status === 'mls' ? 'mls' : 'active'),
      address: S(b.address, 200), city: S(b.city, 80), area: S(b.area, 80),
      state: S(b.state, 40), zip: S(b.zip, 20), hideAddress: !!b.hideAddress,
      propType: S(b.propType, 60),
      dist: (['broad', 'private', 'pocket'].indexOf(b.dist) >= 0 ? b.dist : 'broad'),
      units: S(b.units, 20), sqft: S(b.sqft, 20),
      beds: S(b.beds, 20), baths: S(b.baths, 20), yearBuilt: S(b.yearBuilt, 12),
      price: S(b.price, 24), noi: S(b.noi, 24), capRate: S(b.capRate, 16),
      lat: S(b.lat, 24), lng: S(b.lng, 24),
      grossIncome: S(b.grossIncome, 24), expenses: S(b.expenses, 24),
      commissionPct: S(b.commissionPct, 16), commissionNotes: S(b.commissionNotes, 300),
      notes: S(b.notes, 3000), docs: docsIn, photos: photosIn
    };
    const in30 = new Date(Date.now() + 30 * 864e5).toISOString();
    let rec, isNew = false;
    if (id) {
      const idx = listings.findIndex(x => x && x.id === id);
      if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
      const cur = listings[idx];
      if (req.user.role !== 'owner' && _lc(cur.owner) !== pmEmail(req.user))
        return res.status(403).json({ ok: false, error: 'not_your_listing' });
      rec = Object.assign({}, cur, fields, { updatedAt: now });
      // Preserve existing media when the request doesn't include it (e.g. status toggles).
      if (!Array.isArray(b.docs)) rec.docs = Array.isArray(cur.docs) ? cur.docs : [];
      if (!Array.isArray(b.photos)) rec.photos = Array.isArray(cur.photos) ? cur.photos : [];
      listings[idx] = rec;
    } else {
      rec = Object.assign({ id: pmId('L'), owner: req.user.email, createdAt: now, updatedAt: now, expiresAt: in30, views: 0, featured: false }, fields);
      listings.push(rec); isNew = true;
    }
    await pmSave(PM_KEYS.listings, listings);
    if (isNew && rec.status !== 'off') {
      try {
        const boxes = await pmLoad(PM_KEYS.buyboxes), ns = await pmLoad('pm_notifs'), profs = await pmLoad('pm_profiles');
        const profOf = {}; profs.forEach(p => { if (p && p.email) profOf[_lc(p.email)] = p; });
        const hits = [];
        boxes.forEach(bx => {
          if (!bx || _lc(bx.owner) === pmEmail(req.user) || !pmMatch(rec, bx)) return;
          const prof = profOf[_lc(bx.owner)] || {};
          // Member's own notification settings decide this (default = their focus).
          if (!pmWantsDealAlert(prof, rec)) return;
          const txt = 'New match — ' + (rec.propType || 'deal') + ' in ' + (rec.area || rec.city || 'your market') + (rec.price ? (' · ' + pmMoneyShort(rec.price)) : '');
          ns.push({ id: pmId('N'), to: _lc(bx.owner), type: 'match', text: txt, listingId: rec.id, at: now, read: false });
          if (pmWantsEmail(prof, 'deals')) hits.push({ to: _lc(bx.owner), txt });
        });
        await pmSave('pm_notifs', ns.length > 2000 ? ns.slice(-2000) : ns);
        for (const h of hits) await pmSendEmail(h.to, 'AXESS · new deal matches your buy box', h.txt + '\n\nOpen AXESS to view the deal and message the listing agent.');
      } catch (e) { /* best-effort */ }
    }
    res.json({ ok: true, listing: pmPublicView(rec, req.user.role === 'owner' || _lc(rec.owner) === pmEmail(req.user)), id: rec.id });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.post('/api/pm/listing/delete', ensureAuth, pmGate, async (req, res) => {
  const id = String((req.body || {}).id || '');
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const l = listings.find(x => x && x.id === id);
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (req.user.role !== 'owner' && _lc(l.owner) !== pmEmail(req.user)) return res.status(403).json({ ok: false, error: 'not_your_listing' });
    await pmSave(PM_KEYS.listings, listings.filter(x => x && x.id !== id));
    const intros = await pmLoad(PM_KEYS.intros);
    if (intros.some(i => i && i.listingId === id)) await pmSave(PM_KEYS.intros, intros.filter(i => i && i.listingId !== id));
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.post('/api/pm/listing/mls', ensureAuth, pmGate, async (req, res) => {
  const id = String((req.body || {}).id || '');
  const on = (req.body || {}).on !== false;
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const l = listings.find(x => x && x.id === id);
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (req.user.role !== 'owner' && _lc(l.owner) !== pmEmail(req.user)) return res.status(403).json({ ok: false, error: 'not_your_listing' });
    if (on) { l.status = 'mls'; l.mlsAt = new Date().toISOString(); } else { l.status = 'active'; delete l.mlsAt; }
    await pmSave(PM_KEYS.listings, listings);
    res.json({ ok: true, status: l.status });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// Mark a deal closed through AXESS (social proof). Owner of the deal or admin.
// closePrice is optional; showClose controls whether it appears in public proof.
app.post('/api/pm/listing/close', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const id = String(b.id || '');
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const l = listings.find(x => x && x.id === id);
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (req.user.role !== 'owner' && _lc(l.owner) !== pmEmail(req.user)) return res.status(403).json({ ok: false, error: 'not_your_listing' });
    if (b.on === false) { // undo
      l.status = 'active'; delete l.closedAt; delete l.closePrice;
    } else {
      l.status = 'closed'; l.closedAt = new Date().toISOString();
      l.closePrice = String(b.closePrice != null ? b.closePrice : (l.price || '')).replace(/[^0-9.]/g, '').slice(0, 24);
      l.showClose = b.show !== false;
    }
    await pmSave(PM_KEYS.listings, listings);
    res.json({ ok: true, status: l.status });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Closed-deal proof: aggregate totals, recent public closings, and a leaderboard.
app.get('/api/pm/closings', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, profs] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad('pm_profiles')]);
    const nameBy = {}; profs.forEach(p => { if (p && p.email) nameBy[_lc(p.email)] = p.name || ''; });
    const closed = listings.filter(l => l && (l.status || '') === 'closed');
    const totalCount = closed.length;
    const totalVolume = closed.reduce((a, l) => a + pmNum(l.closePrice || l.price), 0);
    const recent = closed.slice().sort((a, b) => String(b.closedAt).localeCompare(String(a.closedAt))).slice(0, 12).map(l => ({
      area: l.area || l.city || '', propType: l.propType || '', state: l.state || '',
      price: l.showClose === false ? '' : (l.closePrice || l.price || ''),
      ownerName: l.ownerName || nameBy[_lc(l.owner)] || '', closedAt: l.closedAt || ''
    }));
    const board = {}; closed.forEach(l => { const k = _lc(l.owner); if (!board[k]) board[k] = { email: l.owner, ownerName: l.ownerName || nameBy[k] || l.owner, count: 0, volume: 0 }; board[k].count++; board[k].volume += pmNum(l.closePrice || l.price); });
    const leaderboard = Object.values(board).sort((a, b) => (b.count - a.count) || (b.volume - a.volume)).slice(0, 15);
    res.json({ ok: true, totalCount, totalVolume, recent, leaderboard });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── intros ──────────────────────────────────────────────────────────────────
app.post('/api/pm/intro', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const listingId = String(b.listingId || '');
  if (!listingId) return res.status(400).json({ ok: false, error: 'no_listing' });
  if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_verified', message: 'Contacting members unlocks once your license is verified.' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const l = listings.find(x => x && x.id === listingId);
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (_lc(l.owner) === pmEmail(req.user)) return res.status(400).json({ ok: false, error: 'own_listing' });
    if (req.user.role !== 'owner') {
      const [gboxes, gprofs] = await Promise.all([pmLoad(PM_KEYS.buyboxes), pmLoad('pm_profiles')]);
      if (!pmReciprocity(pmEmail(req.user), listings, gboxes, gprofs).active)
        return res.status(403).json({ ok: false, error: 'contribute_required', message: 'Post a deal or a live client need to contact members.' });
    }
    const intros = await pmLoad(PM_KEYS.intros);
    const email = pmEmail(req.user);
    const live = intros.find(i => i && i.listingId === listingId && _lc(i.buyer) === email && i.status !== 'declined');
    if (live) return res.json({ ok: true, intro: live, already: true });
    const allProfs = await pmLoad('pm_profiles');
    const buyerProf = allProfs.find(p => p && _lc(p.email) === email) || {};
    const buyerPof = pmPofPublic(buyerProf); // snapshot buyer's credibility onto the intro
    const rec = { id: pmId('I'), listingId, seller: l.owner, buyer: req.user.email,
      buyerName: String(b.buyerName || req.user.name || '').slice(0, 80), message: String(b.message || '').slice(0, 1000),
      buyerVerified: !!buyerProf.verified, buyerProducer: !!buyerProf.producer, buyerPof,
      status: 'pending', createdAt: new Date().toISOString(), decidedAt: '' };
    intros.push(rec);
    await pmSave(PM_KEYS.intros, intros);
    try {
      const sProf = allProfs.find(p => p && _lc(p.email) === _lc(l.owner)) || {};
      const cred = pmCredLine(buyerProf);
      if (pmWantsEmail(sProf, 'intros')) await pmSendEmail(l.owner, 'AXESS · new intro request', (rec.buyerName || rec.buyer) + ' requested an intro on your ' + (l.area || l.city || 'deal') + ' listing.' + (cred ? ('\n\n' + cred) : '') + '\n\nOpen AXESS to approve or decline.');
    } catch (e) {}
    res.json({ ok: true, intro: rec });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.get('/api/pm/intros', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, intros] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.intros)]);
    const email = pmEmail(req.user);
    const byId = {}; listings.forEach(l => { if (l && l.id) byId[l.id] = l; });
    const asBuyer = [], asSeller = [];
    intros.forEach(i => {
      if (!i) return;
      const l = byId[i.listingId];
      const summary = l ? pmPublicView(l, i.status === 'approved' || req.user.role === 'owner') : null;
      if (_lc(i.buyer) === email) asBuyer.push({ id: i.id, listingId: i.listingId, status: i.status, message: i.message, createdAt: i.createdAt, decidedAt: i.decidedAt, listing: summary });
      if (_lc(i.seller) === email || req.user.role === 'owner') asSeller.push({ id: i.id, listingId: i.listingId, status: i.status, message: i.message, createdAt: i.createdAt, decidedAt: i.decidedAt, buyer: i.buyer, buyerName: i.buyerName, buyerVerified: !!i.buyerVerified, buyerProducer: !!i.buyerProducer, buyerPof: i.buyerPof || { status: 'none', amount: '' }, listing: summary });
    });
    res.json({ ok: true, asBuyer, asSeller });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.post('/api/pm/intro/decide', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const introId = String(b.introId || '');
  const decision = b.decision === 'approved' ? 'approved' : b.decision === 'declined' ? 'declined' : '';
  if (!introId || !decision) return res.status(400).json({ ok: false, error: 'bad_request' });
  try {
    const intros = await pmLoad(PM_KEYS.intros);
    const idx = intros.findIndex(i => i && i.id === introId);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    const it = intros[idx];
    if (req.user.role !== 'owner' && _lc(it.seller) !== pmEmail(req.user)) return res.status(403).json({ ok: false, error: 'not_your_listing' });
    it.status = decision; it.decidedAt = new Date().toISOString();
    intros[idx] = it;
    await pmSave(PM_KEYS.intros, intros);
    try { await pmSendEmail(it.buyer, 'AXESS · your intro was ' + decision, decision === 'approved' ? 'The listing agent approved your intro. Open AXESS to see the address and message them.' : 'The listing agent declined your intro this time.'); } catch (e) {}
    res.json({ ok: true, intro: it });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.get('/api/pm/reveal/:id', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, intros] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.intros)]);
    const l = listings.find(x => x && x.id === String(req.params.id));
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (!pmEntitled(l, req.user, intros)) return res.status(403).json({ ok: false, error: 'not_approved' });
    res.json({ ok: true, id: l.id, address: l.address || '', city: l.city || '', state: l.state || '', zip: l.zip || '' });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── buy boxes ─────────────────────────────────────────────────────────────
app.get('/api/pm/buybox', ensureAuth, pmGate, async (req, res) => {
  try {
    const [boxes, listings] = await Promise.all([pmLoad(PM_KEYS.buyboxes), pmLoad(PM_KEYS.listings)]);
    const email = pmEmail(req.user);
    const mine = boxes.find(x => x && _lc(x.owner) === email) || null;
    let matches = [];
    if (mine) {
      const isExpired = l => l.expiresAt && (new Date(l.expiresAt) < new Date());
      matches = listings.filter(l => l && (l.status || 'active') !== 'off' && (l.status || 'active') !== 'mls' && (l.status || 'active') !== 'closed' && !isExpired(l) && _lc(l.owner) !== email && pmMatch(l, mine))
        .map(l => pmPublicView(l, false))
        .sort((a, b) => (b.featured - a.featured) || String(b.createdAt).localeCompare(String(a.createdAt)));
    }
    res.json({ ok: true, buybox: mine, matches });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.post('/api/pm/buybox', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const S = (v, n) => String(v == null ? '' : v).slice(0, n || 120);
  try {
    if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_verified', message: 'Posting unlocks once your license is verified.' });
    const boxes = await pmLoad(PM_KEYS.buyboxes);
    const email = pmEmail(req.user);
    const now = new Date().toISOString();
    const fields = { markets: S(b.markets, 200), propType: S(b.propType, 80), minUnits: S(b.minUnits, 12), maxUnits: S(b.maxUnits, 12), minPrice: S(b.minPrice, 24), maxPrice: S(b.maxPrice, 24), minCap: S(b.minCap, 12), notes: S(b.notes, 1500), contact: S(b.contact || req.user.email, 120) };
    const idx = boxes.findIndex(x => x && _lc(x.owner) === email);
    let rec, isNew = false;
    if (idx >= 0) { rec = Object.assign({}, boxes[idx], fields, { updatedAt: now }); boxes[idx] = rec; }
    else { rec = Object.assign({ owner: req.user.email, ownerName: String(req.user.name || '').slice(0, 80), createdAt: now, updatedAt: now }, fields); boxes.push(rec); isNew = true; }
    await pmSave(PM_KEYS.buyboxes, boxes);
    if (isNew) {
      try {
        const listings = await pmLoad(PM_KEYS.listings), ns = await pmLoad('pm_notifs');
        const isExpired = l => l.expiresAt && (new Date(l.expiresAt) < new Date());
        const sellers = {};
        listings.forEach(l => {
          if (l && (l.status || 'active') !== 'off' && (l.status || 'active') !== 'mls' && (l.status || 'active') !== 'closed' && !isExpired(l) && _lc(l.owner) !== email && pmMatch(l, rec)) {
            const s = _lc(l.owner); (sellers[s] = sellers[s] || []).push(l);
            ns.push({ id: pmId('N'), to: s, type: 'buyer', text: 'New buyer for your ' + (l.area || l.city || 'deal') + ' listing — their buy box matches', listingId: l.id, at: now, read: false });
          }
        });
        await pmSave('pm_notifs', ns.length > 2000 ? ns.slice(-2000) : ns);
        for (const s of Object.keys(sellers)) await pmSendEmail(s, 'AXESS · a buyer is hunting deals like yours', 'A new buyer just posted a buy box that matches ' + sellers[s].length + ' of your live deal(s).\n\nOpen AXESS to see the buyer and start a conversation.');
      } catch (e) { /* best-effort */ }
    }
    res.json({ ok: true, buybox: rec });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.get('/api/pm/activity', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, intros] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.intros)]);
    const email = pmEmail(req.user);
    const myListings = listings.filter(l => l && _lc(l.owner) === email);
    const myListingIds = new Set(myListings.map(l => l.id));
    res.json({ ok: true, activity: {
      listings: myListings.length,
      active: myListings.filter(l => (l.status || 'active') !== 'off').length,
      sentPending: intros.filter(i => i && _lc(i.buyer) === email && i.status === 'pending').length,
      sentApproved: intros.filter(i => i && _lc(i.buyer) === email && i.status === 'approved').length,
      inboundPending: intros.filter(i => i && myListingIds.has(i.listingId) && i.status === 'pending').length
    } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── messaging ────────────────────────────────────────────────────────────
app.post('/api/pm/message', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const to = _lc(b.to), body = String(b.body || '').slice(0, 4000).trim(), listingId = String(b.listingId || '');
  const att = (b.docUrl) ? { url: String(b.docUrl).slice(0, 6000000), name: String(b.docName || 'file').slice(0, 160) } : null;
  if (!to || (!body && !att)) return res.status(400).json({ ok: false, error: 'bad_request' });
  if (to === pmEmail(req.user)) return res.status(400).json({ ok: false, error: 'cannot_message_self' });
  try {
    if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_approved' });
    const msgs = await pmLoad('pm_messages');
    const rec = { id: pmId('M'), key: pmThreadKey(req.user.email, to, listingId), from: req.user.email, fromName: String(req.user.name || '').slice(0, 80), to, listingId, body, att, at: new Date().toISOString(), readBy: [pmEmail(req.user)] };
    msgs.push(rec);
    await pmSave('pm_messages', msgs);
    res.json({ ok: true, message: rec });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.get('/api/pm/threads', ensureAuth, pmGate, async (req, res) => {
  try {
    const [msgs, listings] = await Promise.all([pmLoad('pm_messages'), pmLoad(PM_KEYS.listings)]);
    const email = pmEmail(req.user), byId = {}; listings.forEach(l => { if (l && l.id) byId[l.id] = l; });
    const mine = msgs.filter(m => m && (_lc(m.from) === email || _lc(m.to) === email));
    const threads = {};
    mine.forEach(m => {
      const t = threads[m.key] || (threads[m.key] = { key: m.key, other: '', otherName: '', listingId: m.listingId || '', last: '', at: '', unread: 0 });
      const otherIsFrom = _lc(m.from) !== email;
      if (otherIsFrom && m.fromName) t.otherName = m.fromName;
      if (!t.at || String(m.at) > t.at) { t.at = m.at; t.last = m.body; t.other = otherIsFrom ? m.from : m.to; }
      if (_lc(m.to) === email && !(m.readBy || []).map(_lc).includes(email)) t.unread++;
    });
    const list = Object.values(threads).map(t => { const l = t.listingId ? byId[t.listingId] : null; t.listing = l ? { id: l.id, area: l.area || l.city || '', price: l.price || '' } : null; return t; }).sort((a, b) => String(b.at).localeCompare(String(a.at)));
    res.json({ ok: true, threads: list, me: { email: req.user.email, name: req.user.name } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

app.get('/api/pm/thread', ensureAuth, pmGate, async (req, res) => {
  const other = _lc(req.query.with), listingId = String(req.query.listingId || '');
  if (!other) return res.status(400).json({ ok: false, error: 'no_party' });
  try {
    const [msgs, listings] = await Promise.all([pmLoad('pm_messages'), pmLoad(PM_KEYS.listings)]);
    const key = pmThreadKey(req.user.email, other, listingId), email = pmEmail(req.user);
    let changed = false;
    const thread = msgs.filter(m => m && m.key === key).sort((a, b) => String(a.at).localeCompare(String(b.at)));
    thread.forEach(m => { if (_lc(m.to) === email) { m.readBy = m.readBy || []; if (!m.readBy.map(_lc).includes(email)) { m.readBy.push(req.user.email); changed = true; } } });
    if (changed) { try { await pmSave('pm_messages', msgs); } catch (e) {} }
    const l = listingId ? listings.find(x => x && x.id === listingId) : null;
    const listing = l ? { id: l.id, area: l.area || l.city || '', price: l.price || '', propType: l.propType || '' } : null;
    res.json({ ok: true, messages: thread.map(m => ({ id: m.id, from: m.from, fromName: m.fromName, mine: _lc(m.from) === email, body: m.body, att: m.att || null, at: m.at })), listing, me: { email: req.user.email } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── notifs / matches / market / broadcasts ──────────────────────────────────
app.get('/api/pm/notifs', ensureAuth, pmGate, async (req, res) => {
  try {
    const ns = await pmLoad('pm_notifs'), email = pmEmail(req.user);
    const mine = ns.filter(n => n && _lc(n.to) === email).sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 50);
    res.json({ ok: true, notifs: mine, unread: mine.filter(n => !n.read).length });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/notifs/read', ensureAuth, pmGate, async (req, res) => {
  try {
    const ns = await pmLoad('pm_notifs'), email = pmEmail(req.user); let ch = false;
    ns.forEach(n => { if (n && _lc(n.to) === email && !n.read) { n.read = true; ch = true; } });
    if (ch) await pmSave('pm_notifs', ns);
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/pm/matches/:listingId', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, boxes] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes)]);
    const l = listings.find(x => x && x.id === String(req.params.listingId));
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    const owner = _lc(l.owner) === pmEmail(req.user) || req.user.role === 'owner';
    const matches = boxes.filter(b => b && pmMatch(l, b));
    res.json({ ok: true, count: matches.length, buyers: owner ? matches.map(b => ({ owner: b.owner, ownerName: b.ownerName || '', markets: b.markets || '', propType: b.propType || '', contact: b.contact || b.owner })) : [] });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/pm/market', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, boxes] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes)]);
    const live = listings.filter(l => l && (l.status || 'active') !== 'off');
    const off = listings.filter(l => l && (l.status || 'active') === 'off');
    const val = live.reduce((a, l) => a + pmNum(l.price), 0);
    const comms = live.map(l => pmNum(l.commissionPct)).filter(x => x > 0);
    const caps = live.map(l => pmNum(l.capRate)).filter(x => x > 0);
    const areas = {}; live.forEach(l => { const a = l.area || l.city || '—'; areas[a] = (areas[a] || 0) + 1; });
    const recent = live.slice().sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))).slice(0, 6).map(l => ({ id: l.id, area: l.area || l.city || '', propType: l.propType || '', price: l.price || '', createdAt: l.createdAt || '' }));
    res.json({ ok: true, market: { liveDeals: live.length, offMarket: off.length, totalValue: val, buyboxes: boxes.length, avgCommission: comms.length ? (comms.reduce((a, b) => a + b, 0) / comms.length) : 0, avgCap: caps.length ? (caps.reduce((a, b) => a + b, 0) / caps.length) : 0, byArea: areas, recent } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/pm/broadcasts', ensureAuth, pmGate, async (req, res) => {
  try { let bs = await pmLoad('pm_broadcasts'); bs = bs.filter(Boolean).sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 60); res.json({ ok: true, broadcasts: bs }); }
  catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/broadcast', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const title = String(b.title || '').slice(0, 160).trim(), body = String(b.body || '').slice(0, 4000).trim(), category = String(b.category || 'Misc').slice(0, 40);
  if (!title && !body) return res.status(400).json({ ok: false, error: 'empty' });
  if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_verified', message: 'Posting unlocks once your license is verified.' });
  try {
    const bs = await pmLoad('pm_broadcasts');
    const rec = { id: pmId('B'), from: req.user.email, fromName: String(req.user.name || '').slice(0, 80), category, title, body, at: new Date().toISOString() };
    bs.push(rec); await pmSave('pm_broadcasts', bs);
    res.json({ ok: true, broadcast: rec });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── views / analytics / renew ───────────────────────────────────────────────
app.post('/api/pm/view/:id', ensureAuth, pmGate, async (req, res) => {
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const idx = listings.findIndex(x => x && x.id === String(req.params.id));
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    if (_lc(listings[idx].owner) !== pmEmail(req.user)) {
      listings[idx].views = (Number(listings[idx].views) || 0) + 1;
      const vb = listings[idx].viewers = Array.isArray(listings[idx].viewers) ? listings[idx].viewers : [];
      const me = pmEmail(req.user); if (!vb.includes(me)) vb.push(me);
      await pmSave(PM_KEYS.listings, listings);
    }
    res.json({ ok: true, views: listings[idx].views || 0 });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/pm/analytics/:id', ensureAuth, pmGate, async (req, res) => {
  try {
    const [listings, boxes, msgs] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes), pmLoad('pm_messages')]);
    const l = listings.find(x => x && x.id === String(req.params.id));
    if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
    if (_lc(l.owner) !== pmEmail(req.user) && req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'not_your_listing' });
    const matches = boxes.filter(b => b && pmMatch(l, b));
    const threadKeys = new Set(msgs.filter(m => m && m.listingId === l.id).map(m => m.key));
    const daysLeft = l.expiresAt ? Math.max(0, Math.ceil((new Date(l.expiresAt) - new Date()) / 864e5)) : null;
    res.json({ ok: true, analytics: { id: l.id, views: Number(l.views) || 0, uniqueViewers: Array.isArray(l.viewers) ? l.viewers.length : 0, matches: matches.length, messageThreads: threadKeys.size, messages: msgs.filter(m => m && m.listingId === l.id).length, expiresAt: l.expiresAt || '', daysLeft, featured: !!l.featured, expired: l.expiresAt ? (new Date(l.expiresAt) < new Date()) : false } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
const PM_PAID_RENEW = process.env.PM_PAID_RENEW === '1';
app.post('/api/pm/renew', ensureAuth, pmGate, async (req, res) => {
  const id = String((req.body || {}).id || '');
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const idx = listings.findIndex(x => x && x.id === id);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    const l = listings[idx];
    if (_lc(l.owner) !== pmEmail(req.user) && req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'not_your_listing' });
    if (PM_PAID_RENEW && !(req.body && req.body.paid) && req.user.role !== 'owner') return res.status(402).json({ ok: false, error: 'payment_required', message: 'Renewing a deal is $1.' });
    const base = l.expiresAt && new Date(l.expiresAt) > new Date() ? new Date(l.expiresAt) : new Date();
    l.expiresAt = new Date(base.getTime() + 30 * 864e5).toISOString();
    l.renewedAt = new Date().toISOString(); l.renew5Sent = false; l.renew1Sent = false;
    if ((l.status || 'active') === 'off') l.status = 'active';
    await pmSave(PM_KEYS.listings, listings);
    res.json({ ok: true, expiresAt: l.expiresAt });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── profiles / directory ────────────────────────────────────────────────────
app.get('/api/pm/profile', ensureAuth, pmGate, async (req, res) => {
  try {
    const profs = await pmLoad('pm_profiles');
    const me = profs.find(p => p && _lc(p.email) === pmEmail(req.user)) || null;
    res.json({ ok: true, profile: me, approved: await pmApproved(req.user), role: req.user.role });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/profile', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const S = (v, n) => String(v == null ? '' : v).slice(0, n || 120).trim();
  try {
    const profs = await pmLoad('pm_profiles');
    const email = pmEmail(req.user);
    const now = new Date().toISOString();
    const fields = { name: S(b.name || req.user.name, 100), license: S(b.license, 60), brokerage: S(b.brokerage, 120), phone: S(b.phone, 40), markets: S(b.markets, 200), bio: S(b.bio, 1200), linkedin: pmSocial('linkedin', b.linkedin), instagram: pmSocial('instagram', b.instagram), facebook: pmSocial('facebook', b.facebook), x: pmSocial('x', b.x), website: pmSocial('website', b.website) };
    if (b.focus !== undefined) fields.focus = pmFocus(b.focus);
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    let rec, isNew = false;
    if (idx >= 0) { rec = Object.assign({}, profs[idx], fields, { updatedAt: now }); profs[idx] = rec; }
    else { const status = req.user.role === 'owner' ? 'approved' : 'pending'; rec = Object.assign({ email: req.user.email, status, createdAt: now, updatedAt: now }, fields); profs.push(rec); isNew = true; }
    await pmSave('pm_profiles', profs);
    if (isNew && rec.status === 'pending' && ADMIN) { try { await pmSendEmail(ADMIN, 'AXESS · new member awaiting approval', (rec.name || rec.email) + ' signed up.\nLicense: ' + (rec.license || '—') + '\nBrokerage: ' + (rec.brokerage || '—') + '\n\nApprove them in the AXESS admin panel.'); } catch (e) {} }
    res.json({ ok: true, profile: rec, approved: await pmApproved(req.user) });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/notifprefs', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  try {
    const profs = await pmLoad('pm_profiles');
    const email = pmEmail(req.user);
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'no_profile', message: 'Save your profile first.' });
    const deals = ['all', 'types', 'off'].indexOf(b.deals) >= 0 ? b.deals : 'all';
    const dealTypes = Array.isArray(b.dealTypes) ? b.dealTypes.slice(0, 20).map(t => String(t).slice(0, 60)) : [];
    const dealMarkets = Array.isArray(b.dealMarkets) ? b.dealMarkets.slice(0, 40).map(m => String(m).slice(0, 60)).filter(Boolean) : [];
    profs[idx].notifPrefs = { deals, dealTypes, dealMarkets, email: b.email !== false, intros: b.intros !== false };
    await pmSave('pm_profiles', profs);
    res.json({ ok: true, notifPrefs: profs[idx].notifPrefs });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// ── smart-match digest ───────────────────────────────────────────────────────
// The anti-noise engine. Instead of blasting every deal to everyone, we email
// each member ONLY the new deals that match their buy box (or their saved deal
// alert prefs), since the digest last ran for them. Trigger on a schedule by
// POSTing /api/pm/digest/run?key=DIGEST_KEY, or from the admin panel. ?dry=1
// previews counts without sending.
function pmDigestLine(l) {
  const bits = [l.propType || 'Deal'];
  const loc = l.area || l.city || l.state; if (loc) bits.push('in ' + loc);
  const facts = [];
  if (pmNum(l.price)) facts.push(pmMoneyShort(l.price));
  if (pmNum(l.capRate)) facts.push(pmNum(l.capRate).toFixed(1) + '% cap');
  else if (pmNum(l.units)) facts.push(pmNum(l.units) + ' units');
  if (pmNum(l.commissionPct)) facts.push(pmNum(l.commissionPct).toFixed(1) + '% BBC');
  return '• ' + bits.join(' ') + (facts.length ? ' — ' + facts.join(', ') : '');
}
function pmDigestFor(prof, listings, boxes, sinceMs) {
  const email = _lc(prof.email);
  const box = boxes.find(b => b && _lc(b.owner) === email) || null;
  const np = prof.notifPrefs;
  const hasPrefs = np && np.deals !== 'off' && ((Array.isArray(np.dealTypes) && np.dealTypes.length) || (Array.isArray(np.dealMarkets) && np.dealMarkets.length));
  if (!box && !hasPrefs) return [];   // nothing to match on → no digest (never spam)
  return listings.filter(l => {
    if (!l || _lc(l.owner) === email) return false;
    const st = l.status || 'active'; if (st === 'off' || st === 'mls' || st === 'closed') return false;
    if (l.expiresAt && new Date(l.expiresAt) < new Date()) return false;
    const created = l.createdAt ? new Date(l.createdAt).getTime() : 0;
    if (!(created > sinceMs)) return false;
    if (box && !pmMatch(l, box)) return false;
    if (!pmWantsDealAlert(prof, l)) return false; // respects their type/market notif prefs + focus
    return true;
  }).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}
app.post('/api/pm/digest/run', async (req, res) => {
  const q = req.query || {}, b = req.body || {};
  const key = String(q.key || b.key || '');
  const admin = req.user && req.user.role === 'owner';
  const DKEY = process.env.DIGEST_KEY || '';
  if (!admin && !(DKEY && key === DKEY)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const dry = String(q.dry || b.dry || '') === '1';
  const days = Math.min(60, Math.max(1, parseInt(q.days || b.days || '7', 10) || 7));
  try {
    const [listings, boxes, profs, ns] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes), pmLoad('pm_profiles'), pmLoad('pm_notifs')]);
    const now = new Date().toISOString(), fallback = Date.now() - days * 86400000;
    const results = []; let sent = 0, notifs = 0;
    for (const prof of profs) {
      if (!prof || prof.status !== 'approved') continue;
      const sinceMs = prof.lastDigestAt ? new Date(prof.lastDigestAt).getTime() : fallback;
      const matches = pmDigestFor(prof, listings, boxes, sinceMs);
      if (!matches.length) { if (!dry) prof.lastDigestAt = now; continue; }
      const top = matches.slice(0, 10);
      results.push({ email: prof.email, name: prof.name || '', count: matches.length });
      if (!dry) {
        ns.push({ id: pmId('N'), to: _lc(prof.email), type: 'digest', text: matches.length + ' new deal' + (matches.length === 1 ? '' : 's') + ' match your criteria', at: now, read: false });
        notifs++;
        if (pmWantsEmail(prof, 'deals')) {
          const body = matches.length + ' new off-market deal' + (matches.length === 1 ? '' : 's') + ' match your criteria on AXESS:\n\n' +
            top.map(pmDigestLine).join('\n') + (matches.length > top.length ? ('\n…and ' + (matches.length - top.length) + ' more') : '') +
            '\n\nSee them and request intros: ' + PM_BASE + '/app.html\n\nToo many or too few? Tune your buy box and alert settings in AXESS → Notifications.';
          try { await pmSendEmail(prof.email, 'AXESS · ' + matches.length + ' new deal' + (matches.length === 1 ? '' : 's') + ' match you', body); sent++; } catch (e) {}
        }
        prof.lastDigestAt = now;
      }
    }
    if (!dry) { await pmSave('pm_profiles', profs); await pmSave('pm_notifs', ns.length > 2000 ? ns.slice(-2000) : ns); }
    res.json({ ok: true, dry, days, recipients: results.length, emailsSent: sent, notifsCreated: notifs, breakdown: results.slice(0, 100) });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Member requests a Proof-of-Funds badge (buy-side credibility). Stores amount +
// optional doc; goes to 'pending' for admin review. Doc is never exposed publicly.
app.post('/api/pm/pof/request', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  try {
    if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_approved' });
    const profs = await pmLoad('pm_profiles');
    const email = pmEmail(req.user);
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'no_profile', message: 'Save your profile first.' });
    const amount = String(b.amount || '').slice(0, 40);
    const doc = String(b.doc || '').slice(0, 900);
    profs[idx].pof = { status: 'pending', amount, doc, requestedAt: new Date().toISOString() };
    await pmSave('pm_profiles', profs);
    if (ADMIN) { try { await pmSendEmail(ADMIN, 'AXESS · proof-of-funds review', (profs[idx].name || email) + ' requested a Proof-of-Funds badge' + (amount ? (' (' + amount + ')') : '') + '.\n\nReview it in the AXESS admin panel.'); } catch (e) {} }
    res.json({ ok: true, pof: pmPofPublic(profs[idx]) });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Admin decides a POF request.
app.post('/api/pm/admin/pof', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const email = _lc(b.email);
  const decision = b.decision === 'verified' ? 'verified' : b.decision === 'rejected' ? 'rejected' : b.decision === 'none' ? 'none' : '';
  if (!email || !decision) return res.status(400).json({ ok: false, error: 'bad_request' });
  try {
    const profs = await pmLoad('pm_profiles');
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    const cur = profs[idx].pof || {};
    if (decision === 'none') profs[idx].pof = { status: 'none', amount: '', doc: '' };
    else profs[idx].pof = { status: decision, amount: (b.amount != null ? String(b.amount).slice(0, 40) : (cur.amount || '')), doc: cur.doc || '', requestedAt: cur.requestedAt || '', verifiedAt: decision === 'verified' ? new Date().toISOString() : '' };
    await pmSave('pm_profiles', profs);
    try { await pmSendEmail(email, 'AXESS · proof-of-funds ' + decision, decision === 'verified' ? ('Your Proof-of-Funds badge is verified' + (profs[idx].pof.amount ? (' (up to ' + profs[idx].pof.amount + ')') : '') + '. Sellers will now see you as a credible buyer.') : 'Your Proof-of-Funds request was not approved this time.'); } catch (e) {}
    res.json({ ok: true, email, pof: pmPofPublic(profs[idx]) });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Admin grants/removes the curated "Producer" credibility badge. This is an
// editorial curation signal (admin's judgment) — NOT an automated claim about a
// member's sales volume, which keeps it free of misrepresentation risk.
app.post('/api/pm/admin/producer', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const email = _lc(b.email);
  if (!email) return res.status(400).json({ ok: false, error: 'no_email' });
  try {
    const profs = await pmLoad('pm_profiles');
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    profs[idx].producer = !!b.producer;
    profs[idx].producerAt = b.producer ? new Date().toISOString() : '';
    await pmSave('pm_profiles', profs);
    res.json({ ok: true, email, producer: !!profs[idx].producer });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/pm/profile/:email', ensureAuth, pmGate, async (req, res) => {
  try {
    const profs = await pmLoad('pm_profiles');
    const p = profs.find(x => x && _lc(x.email) === _lc(req.params.email));
    if (!p) return res.json({ ok: true, profile: null });
    // Pending (unverified) viewers can see who an agent is, but not their contact details.
    const canContact = req.user.role === 'owner' || req.user.status === 'approved';
    res.json({ ok: true, profile: { email: canContact ? p.email : '', name: p.name || '', brokerage: p.brokerage || '', license: p.license || '', markets: p.markets || '', bio: p.bio || '', phone: canContact ? (p.phone || '') : '', linkedin: canContact ? (p.linkedin || '') : '', instagram: canContact ? (p.instagram || '') : '', facebook: canContact ? (p.facebook || '') : '', x: canContact ? (p.x || '') : '', website: canContact ? (p.website || '') : '', verified: !!p.verified, producer: !!p.producer, pof: pmPofPublic(p), status: p.status || 'pending' } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/pm/directory', ensureAuth, pmGate, async (req, res) => {
  try {
    if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_approved' });
    const isOwner = req.user.role === 'owner';
    const [profs, listings] = await Promise.all([pmLoad('pm_profiles'), pmLoad(PM_KEYS.listings)]);
    const counts = {}; listings.forEach(l => { if (l) counts[_lc(l.owner)] = (counts[_lc(l.owner)] || 0) + 1; });
    const members = profs.filter(p => p && p.status === 'approved').map(p => ({ email: p.email, name: p.name || '', brokerage: p.brokerage || '', markets: p.markets || '', bio: p.bio || '', phone: p.phone || '', license: isOwner ? (p.license || '') : '', linkedin: p.linkedin || '', instagram: p.instagram || '', facebook: p.facebook || '', x: p.x || '', website: p.website || '', verified: !!p.verified, producer: !!p.producer, pof: pmPofPublic(p), deals: counts[_lc(p.email)] || 0, joined: p.createdAt || '' })).sort((a, b) => (b.deals - a.deals) || String(a.name || a.email).localeCompare(String(b.name || b.email)));
    res.json({ ok: true, members, count: members.length, me: { email: req.user.email, role: req.user.role } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── admin: members / approvals / featuring ──────────────────────────────────
app.get('/api/pm/admin/members', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const [profs, listings] = await Promise.all([pmLoad('pm_profiles'), pmLoad(PM_KEYS.listings)]);
    const counts = {}; listings.forEach(l => { if (l) counts[_lc(l.owner)] = (counts[_lc(l.owner)] || 0) + 1; });
    const members = profs.filter(Boolean).map(p => ({ email: p.email, name: p.name || '', license: p.license || '', brokerage: p.brokerage || '', phone: p.phone || '', markets: p.markets || '', state: p.state || 'MA', status: p.status || 'pending', verified: !!p.verified, producer: !!p.producer, pof: (p.pof && p.pof.status) || 'none', pofAmount: (p.pof && p.pof.amount) || '', pofDoc: (p.pof && p.pof.doc) || '', attested: !!(p.attestation && p.attestation.accepted), attestedAt: (p.attestation && p.attestation.at) || '', deactivated: !!p.deactivated, deactivatedAt: p.deactivatedAt || '', createdAt: p.createdAt || '', deals: counts[_lc(p.email)] || 0 })).sort((a, b) => (a.deactivated ? 1 : 0) - (b.deactivated ? 1 : 0) || (a.status === 'pending' ? -1 : 1) - (b.status === 'pending' ? -1 : 1) || String(b.createdAt).localeCompare(String(a.createdAt)));
    res.json({ ok: true, members, pending: members.filter(m => m.status === 'pending').length, pofPending: members.filter(m => m.pof === 'pending').length });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/admin/approve', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const email = _lc(b.email), decision = b.status === 'rejected' ? 'rejected' : 'approved';
  if (!email) return res.status(400).json({ ok: false, error: 'no_email' });
  try {
    const profs = await pmLoad('pm_profiles');
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    profs[idx].status = decision; profs[idx].decidedAt = new Date().toISOString();
    if (decision === 'approved') {
      if (!profs[idx].approvedAt) profs[idx].approvedAt = profs[idx].decidedAt; // start give-to-get grace clock
      profs[idx].verified = true; profs[idx].verifiedAt = profs[idx].verifiedAt || profs[idx].decidedAt; // license checked → Verified badge
    }
    await pmSave('pm_profiles', profs);
    try { await pmSendEmail(email, 'AXESS · your membership was ' + decision, decision === 'approved' ? 'You\'re verified and in. Sign in to AXESS to post deals, request intros, and message members.' : 'Your AXESS application was not approved at this time.'); } catch (e) {}
    res.json({ ok: true, email, status: decision });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Deactivate / reactivate a member. Soft-only: flips a flag, never touches the
// member's records (profile, listings, payout info, history all preserved). A
// deactivated member fails pmGate and can no longer reach the app. Reversible.
app.post('/api/pm/admin/deactivate', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const email = _lc(b.email);
  const on = b.deactivated !== false; // default = deactivate
  if (!email) return res.status(400).json({ ok: false, error: 'no_email' });
  if (ADMINS.includes(email)) return res.status(400).json({ ok: false, error: 'cant_deactivate_owner' });
  try {
    const profs = await pmLoad('pm_profiles');
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    profs[idx].deactivated = on;
    profs[idx].deactivatedAt = on ? new Date().toISOString() : '';
    await pmSave('pm_profiles', profs);
    res.json({ ok: true, email, deactivated: on });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// ── Self-serve: a member cancels their own account. Access ends immediately,
//    but every record is kept (payout/referral history, past deals). The owner
//    can restore access later from the admin panel. ──────────────────────────
app.post('/api/pm/cancel', ensureAuth, pmGate, async (req, res) => {
  // Owner can't self-cancel — that would lock the whole network's admin out.
  if (req.user.role === 'owner') return res.status(400).json({ ok: false, error: 'owner_cant_cancel', message: 'The owner account cannot be cancelled here.' });
  const email = pmEmail(req.user);
  try {
    const profs = await pmLoad('pm_profiles');
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    const now = new Date().toISOString();
    if (idx >= 0) {
      profs[idx].deactivated = true;
      profs[idx].deactivatedAt = now;
      profs[idx].cancelledAt = now;
      profs[idx].cancelledSelf = true;
      await pmSave('pm_profiles', profs);
    }
    // Confirm to the member, and let the owner know someone left.
    try { await pmSendEmail(email, 'AXESS · your account is cancelled', 'Your AXESS account has been cancelled and your access has ended. We\'ve kept your records on file. If you\'d like to come back, just reply to this email or request access again at ' + PM_BASE + ' and we\'ll reactivate you.\n\nThanks for being part of AXESS.'); } catch (e) {}
    if (ADMIN) { try { await pmSendEmail(ADMIN, 'AXESS · a member cancelled', (req.user.name || email) + ' cancelled their AXESS account.\n\nEmail: ' + email + '\n\nTheir records are retained. You can restore access from the Members tab if they return.'); } catch (e) {} }
    // End their session so access stops right away.
    req.session = null;
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/admin/verify', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const email = _lc(b.email);
  if (!email) return res.status(400).json({ ok: false, error: 'no_email' });
  try {
    const profs = await pmLoad('pm_profiles');
    const idx = profs.findIndex(p => p && _lc(p.email) === email);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    profs[idx].verified = !!b.verified;
    profs[idx].verifiedAt = b.verified ? new Date().toISOString() : '';
    await pmSave('pm_profiles', profs);
    res.json({ ok: true, email, verified: profs[idx].verified });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/admin/feature', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const id = String(b.id || '');
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const idx = listings.findIndex(x => x && x.id === id);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    listings[idx].featured = !!b.featured;
    await pmSave(PM_KEYS.listings, listings);
    res.json({ ok: true, id, featured: listings[idx].featured });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── public join requests (no auth) ──────────────────────────────────────────
app.post('/api/pm/request', async (req, res) => {
  const b = req.body || {};
  const S = (v, n) => String(v == null ? '' : v).slice(0, n || 120).trim();
  const email = S(b.email, 120).toLowerCase(), name = S(b.name, 100);
  const phone = S(b.phone, 40), license = S(b.license, 60), brokerage = S(b.brokerage, 120);
  if (!name || !email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ ok: false, error: 'bad_request', message: 'Name and a valid email are required.' });
  if (!phone || !license || !brokerage) return res.status(400).json({ ok: false, error: 'bad_request', message: 'Phone, license number, and brokerage are all required.' });
  if (b.attest !== true) return res.status(400).json({ ok: false, error: 'attest_required', message: 'You must accept the licensure certification to join.' });
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip;
  if (!(await verifyTurnstile(b.captcha, ip))) return res.status(400).json({ ok: false, error: 'captcha_failed', message: 'Please complete the verification and try again.' });
  try {
    const now = new Date().toISOString();
    const attestation = { text: ATTEST_TEXT, accepted: true, at: now, ip };
    const refCode = S(b.ref, 12).toUpperCase().replace(/[^A-Z0-9]/g, '') || '';
    // 1) Create/refresh the PROFILE — auto-approved on licensure attestation so the
    //    member gets full access right away. The owner can remove anyone at any time
    //    from the Members tab (and reserves that right in the Terms).
    const profs = await pmLoad('pm_profiles');
    const pIdx = profs.findIndex(p => p && _lc(p.email) === email);
    // Founding-member lock-in: the first PM_FOUNDING_CAP (100) approved members
    // are stamped foundingRate=true — they'll get the $25/mo lifetime rate when
    // billing is switched on. Everyone after pays the standard rate. memberNo is
    // their join order. (Separate from the give-get `founder` exemption flag.)
    const foundingCap = Number(process.env.PM_FOUNDING_CAP || 100);
    const priorMembers = profs.filter(p => p && !p.sample && _lc(p.email) !== email).length;
    const isFounder = priorMembers < foundingCap;
    if (pIdx >= 0) {
      const cur = profs[pIdx];
      profs[pIdx] = Object.assign({}, cur, { name: name || cur.name, phone: phone || cur.phone, license: license || cur.license, brokerage: brokerage || cur.brokerage, markets: S(b.markets, 200) || cur.markets, focus: pmFocus(b.focus) || cur.focus, state: cur.state || 'MA', attestation, updatedAt: now, status: 'approved', deactivated: false });
    } else {
      profs.push({ email, name, phone, license, brokerage, markets: S(b.markets, 200), focus: pmFocus(b.focus), state: 'MA', status: 'approved', attestation, foundingRate: isFounder, memberNo: priorMembers + 1, createdAt: now, updatedAt: now });
    }
    // Credit the referrer (if any), now that the member is in.
    try {
      if (refCode) {
        const ref = profs.find(x => x && x.email && pmRefCode(x.email) === refCode);
        if (ref) {
          ref.referredEmails = Array.isArray(ref.referredEmails) ? ref.referredEmails : [];
          if (!ref.referredEmails.some(e => _lc(e) === email)) {
            ref.referredEmails.push(email); ref.referrals = (ref.referrals || 0) + 1; ref.referralCredits = (ref.referralCredits || 0) + 1;
            try { await pmSendEmail(ref.email, 'AXESS · your referral joined', (name || email) + ' just joined AXESS through your invite. You\'ve earned 1 free month, credited when membership billing begins. That\'s ' + ref.referralCredits + ' free month(s) so far — thanks for growing the network.'); } catch (e) {}
          }
        }
      }
    } catch (e) {}
    await pmSave('pm_profiles', profs);
    // 2) Keep a request record for the audit log (already auto-approved).
    const reqs = await pmLoad('pm_requests');
    if (!reqs.some(r => r && _lc(r.email) === email && r.status !== 'denied')) {
      reqs.push({ id: pmId('R'), email, name, license, brokerage, phone, markets: S(b.markets, 200), focus: pmFocus(b.focus), note: S(b.note, 1000), referredBy: refCode, status: 'approved', auto: true, at: now, decidedAt: now });
      await pmSave('pm_requests', reqs.length > 2000 ? reqs.slice(-2000) : reqs);
    }
    // 3) Send the sign-in link now so they can log in right away.
    let linkSent = false;
    try { linkSent = await authMod.sendMagicLink(email, BASE_URL || ('https://' + (req.headers.host || ''))); } catch (e) {}
    if (ADMIN) { try { await pmSendEmail(ADMIN, 'AXESS · new member joined', name + ' joined AXESS (auto-approved on licensure attestation).\n\nEmail: ' + email + '\nLicense: ' + (license || '—') + '\nBrokerage: ' + (brokerage || '—') + '\nPhone: ' + (phone || '—') + '\n\nManage members — including removing anyone — in the AXESS admin panel (Members tab).'); } catch (e) {} }
    res.json({ ok: true, linkSent });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// ── Contact / support: anyone (member or not) can send a question or issue. ──
app.post('/api/pm/contact', async (req, res) => {
  const b = req.body || {};
  const S = (v, n) => String(v == null ? '' : v).slice(0, n || 120).trim();
  const name = S(b.name, 100), email = S(b.email, 120).toLowerCase();
  const subject = S(b.subject, 120) || 'General question';
  const message = S(b.message, 4000);
  if (!name || !email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ ok: false, error: 'bad_request', message: 'Name and a valid email are required.' });
  if (!message || message.length < 3) return res.status(400).json({ ok: false, error: 'bad_request', message: 'Please add a short message.' });
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip;
  try {
    const now = new Date().toISOString();
    const list = await pmLoad('pm_contacts');
    list.push({ id: pmId('C'), name, email, subject, message, ip, at: now, status: 'new' });
    await pmSave('pm_contacts', list.length > 3000 ? list.slice(-3000) : list);
    if (ADMIN) { try { await pmSendEmail(ADMIN, 'AXESS · contact form: ' + subject, 'New message from the AXESS contact form.\n\nName: ' + name + '\nEmail: ' + email + '\nSubject: ' + subject + '\n\n' + message + '\n\nReply directly to ' + email + '.'); } catch (e) {} }
    try { await pmSendEmail(email, 'AXESS · we got your message', 'Hi ' + name + ',\n\nThanks for reaching out to AXESS — we\'ve received your message and will get back to you shortly.\n\nYour message:\n"' + message + '"\n\n— The AXESS team'); } catch (e) {}
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// ── Owner: invite a member by email only. Sends them a one-click link to the
//    signup form with their email prefilled — owner never types anyone's info. ──
app.post('/api/pm/admin/invite', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const email = String((req.body || {}).email || '').toLowerCase().trim();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ ok: false, error: 'bad_email', message: 'Enter a valid email address.' });
  try {
    const base = BASE_URL || ('https://' + (req.headers.host || ''));
    const link = base + '/?join=1&inv=1&email=' + encodeURIComponent(email);
    const now = new Date().toISOString();
    // Log the invite (for a simple record / de-dupe view later).
    try { const invs = await pmLoad('pm_invites'); invs.push({ email, by: pmEmail(req.user), at: now }); await pmSave('pm_invites', invs.length > 3000 ? invs.slice(-3000) : invs); } catch (e) {}
    const html = '<div style="font-family:Inter,Arial,sans-serif;max-width:480px">'
      + '<p style="font-size:16px">You\'re invited to <b>AXESS</b> — a private, invite-only network where licensed agents move off-market real estate deals agent-to-agent.</p>'
      + '<p><a href="' + link + '" style="display:inline-block;background:#0064E5;color:#fff;font-weight:700;text-decoration:none;padding:12px 22px;border-radius:8px">Accept your invite &amp; sign up →</a></p>'
      + '<p style="color:#5B6472;font-size:13px">Founding members join free. You\'ll just confirm your license — takes about a minute. If the button doesn\'t work, paste this link:<br>' + link + '</p></div>';
    const sent = await authMod.sendEmail(email, 'Your invite to AXESS', html);
    if (sent === false) return res.status(502).json({ ok: false, error: 'send_failed', message: 'Could not send the email — check email settings.' });
    res.json({ ok: true });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
// Owner: list invites sent, with whether each person has signed up yet.
app.get('/api/pm/admin/invites', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const [invs, profs] = await Promise.all([pmLoad('pm_invites'), pmLoad('pm_profiles')]);
    const profBy = {}; (profs || []).forEach(p => { if (p && p.email) profBy[_lc(p.email)] = p; });
    // De-dupe by email, keep the most recent invite; attach signup status.
    const byEmail = {};
    (invs || []).filter(Boolean).forEach(v => {
      const e = _lc(v.email); if (!e) return;
      if (!byEmail[e] || String(v.at) > String(byEmail[e].at)) byEmail[e] = v;
    });
    const list = Object.keys(byEmail).map(e => {
      const v = byEmail[e], p = profBy[e];
      let status = 'invited';
      if (p) status = (p.status === 'approved' || p.verified) ? 'verified' : 'signed_up';
      return { email: v.email, at: v.at, by: v.by || '', status, name: (p && p.name) || '' };
    }).sort((a, b) => String(b.at).localeCompare(String(a.at)));
    res.json({ ok: true, invites: list, pending: list.filter(i => i.status === 'invited').length });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.get('/api/pm/admin/requests', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  try {
    const reqs = await pmLoad('pm_requests');
    res.json({ ok: true, requests: reqs.filter(Boolean).sort((a, b) => (a.status === 'pending' ? 0 : 1) - (b.status === 'pending' ? 0 : 1) || String(b.at).localeCompare(String(a.at))), pending: reqs.filter(r => r && r.status === 'pending').length });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
app.post('/api/pm/admin/request/decide', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const b = req.body || {};
  const id = String(b.id || ''), decision = b.decision === 'denied' ? 'denied' : 'approved';
  if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
  try {
    const reqs = await pmLoad('pm_requests');
    const idx = reqs.findIndex(r => r && r.id === id);
    if (idx < 0) return res.status(404).json({ ok: false, error: 'not_found' });
    reqs[idx].status = decision; reqs[idx].decidedAt = new Date().toISOString();
    await pmSave('pm_requests', reqs);
    const r = reqs[idx];
    if (decision === 'approved') {
      try {
        const profs = await pmLoad('pm_profiles');
        const p = profs.find(x => x && _lc(x.email) === _lc(r.email));
        if (p) { p.status = 'approved'; if (!p.focus && r.focus) p.focus = r.focus; }
        else profs.push({ email: r.email, name: r.name || '', license: r.license || '', brokerage: r.brokerage || '', phone: r.phone || '', markets: r.markets || '', focus: r.focus || '', status: 'approved', createdAt: new Date().toISOString() });
        if (r.referredBy) {
          const ref = profs.find(x => x && x.email && pmRefCode(x.email) === r.referredBy);
          if (ref) {
            ref.referredEmails = Array.isArray(ref.referredEmails) ? ref.referredEmails : [];
            if (!ref.referredEmails.some(e => _lc(e) === _lc(r.email))) {
              ref.referredEmails.push(r.email); ref.referrals = (ref.referrals || 0) + 1; ref.referralCredits = (ref.referralCredits || 0) + 1;
              try { await pmSendEmail(ref.email, 'AXESS · your referral was approved', (r.name || r.email) + ' just joined AXESS through your invite. You\'ve earned 1 free month, credited when membership billing begins. That\'s ' + ref.referralCredits + ' free month(s) so far — thanks for growing the network.'); } catch (e) {}
            }
          }
        }
        await pmSave('pm_profiles', profs);
      } catch (e) {}
      try { await pmSendEmail(r.email, 'AXESS · you\'re approved to join', 'Good news — you\'re approved as a founding member of AXESS.\n\nYour access is free while we build out the network. Membership will be $50/month afterward, and we\'ll always give you notice before anything is ever charged.\n\nSign in at ' + PM_BASE + '/app.html to start posting deals and connecting with members.'); } catch (e) {}
    } else {
      try { await pmSendEmail(r.email, 'AXESS · membership request', 'Thanks for your interest in AXESS. We\'re not able to approve your request at this time.'); } catch (e) {}
    }
    res.json({ ok: true, id, status: decision });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── referral link ───────────────────────────────────────────────────────────
app.get('/api/pm/referral', ensureAuth, pmGate, async (req, res) => {
  try {
    const email = pmEmail(req.user), code = pmRefCode(email);
    const origin = BASE_URL || ((req.headers.origin && /^https?:\/\//.test(req.headers.origin)) ? req.headers.origin : ('https://' + (req.headers.host || '')));
    const link = origin + '/?ref=' + code;
    const [profs, reqs] = await Promise.all([pmLoad('pm_profiles'), pmLoad('pm_requests')]);
    const me = profs.find(p => p && _lc(p.email) === email) || {};
    const referred = Array.isArray(me.referredEmails) ? me.referredEmails : [];
    const pending = reqs.filter(r => r && r.referredBy === code && r.status === 'pending').length;
    res.json({ ok: true, code, link, approved: referred.length, pending, credits: me.referralCredits || referred.length, referred });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── public marketing stats (no auth) ────────────────────────────────────────
app.get('/api/pm/stats', async (req, res) => {
  try {
    const [listings, boxes, profs] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes), pmLoad('pm_profiles')]);
    const now = new Date();
    const active = listings.filter(l => l && (l.status || 'active') !== 'off' && (l.status || 'active') !== 'mls' && (l.status || 'active') !== 'closed' && !(l.expiresAt && new Date(l.expiresAt) < now));
    const volume = active.reduce((a, l) => a + pmNum(l.price), 0);
    const commission = active.reduce((a, l) => a + pmNum(l.price) * pmNum(l.commissionPct) / 100, 0);
    const members = profs.filter(p => p && p.status === 'approved').length;
    const foundingCap = Number(process.env.PM_FOUNDING_CAP || 100);
    res.json({ ok: true, stats: { liveDeals: active.length, volume: Math.round(volume), commission: Math.round(commission), members, clientNeeds: boxes.filter(Boolean).length, dealsPosted: listings.length, foundingCap, foundingLeft: Math.max(0, foundingCap - members), foundingFull: members >= foundingCap } });
  } catch (e) { res.json({ ok: false }); }
});

// ── public teaser cards for the landing page (no auth) ───────────────────────
// Returns ONLY safe basics — asset type, general submarket/town, rounded price,
// and buyer-broker commission — pulled from real, actively-listed, BROADLY
// distributed deals. Never exposes address, owner, docs, photos, exact geo, or
// notes. Pocket/private-distribution listings are excluded. Shuffled per request
// so the cards rotate.
app.get('/api/pm/teaser', async (req, res) => {
  try {
    const listings = await pmLoad(PM_KEYS.listings);
    const now = new Date();
    const items = listings
      // Active, non-expired deals. Show the owner's own inventory as marketing teasers
      // regardless of in-network distribution; from other members, only broadly-
      // distributed deals (never expose a member's private/pocket deal publicly).
      .filter(l => l && (l.status || 'active') === 'active' && !(l.expiresAt && new Date(l.expiresAt) < now) && ((l.dist || 'broad') === 'broad' || ADMINS.includes(_lc(l.owner))))
      .map(l => ({
        type: l.propType || '',
        area: l.area || l.city || '',
        price: pmNum(l.price) ? pmMoneyShort(l.price) : '',
        commission: pmNum(l.commissionPct) ? (Number(pmNum(l.commissionPct).toFixed(1)) + '% BBC') : ''
      }))
      .filter(x => x.type && x.area && x.price);
    for (let i = items.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); const t = items[i]; items[i] = items[j]; items[j] = t; }
    res.json({ ok: true, deals: items.slice(0, 6) });
  } catch (e) { res.json({ ok: true, deals: [] }); }
});

// ── document upload (small files stored inline until object storage is added) ─
const PM_UPLOAD_MAX = Number(process.env.PM_UPLOAD_MAX || 3 * 1024 * 1024); // 3MB inline cap
app.post('/api/pm/upload', ensureAuth, pmGate, async (req, res) => {
  const b = req.body || {};
  const data = String(b.data || '');
  if (!data) return res.status(400).json({ ok: false, error: 'no_file' });
  try {
    if (!(await pmApproved(req.user))) return res.status(403).json({ ok: false, error: 'not_approved' });
    const approxBytes = Math.floor(data.length * 0.75);
    if (approxBytes > PM_UPLOAD_MAX) return res.status(413).json({ ok: false, error: 'too_big', message: 'File too large — max ' + Math.round(PM_UPLOAD_MAX / 1e6) + 'MB for now (object storage coming).' });
    const mime = String(b.mime || 'application/octet-stream').slice(0, 120);
    const name = String(b.name || 'file').slice(0, 200);
    // Inline data URL — same-origin, no external service. Swap for S3/R2 later.
    const url = 'data:' + mime + ';base64,' + data;
    res.json({ ok: true, url, name });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── Stripe: renew ($10), feature ($25), membership (subscription) ────────────
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  try { const Stripe = require('stripe'); stripe = new Stripe(process.env.STRIPE_SECRET_KEY); }
  catch (e) { console.log('[stripe] load failed — payments disabled:', e && e.message); }
}
const PM_PRICE = { renew: Number(process.env.PM_PRICE_RENEW || 1000), feature: Number(process.env.PM_PRICE_FEATURE || 2500) };
// Membership pricing. Founding members (first 100) pay the founding rate for life;
// everyone after pays the standard rate. Set the two Stripe recurring Price IDs
// (STRIPE_PRICE_FOUNDING / STRIPE_PRICE_STANDARD) when you're ready to charge.
// STRIPE_PRICE_MEMBERSHIP is a legacy single-price fallback.
const STRIPE_PRICE_MEMBERSHIP = process.env.STRIPE_PRICE_MEMBERSHIP || '';
const STRIPE_PRICE_FOUNDING = process.env.STRIPE_PRICE_FOUNDING || '';
const STRIPE_PRICE_STANDARD = process.env.STRIPE_PRICE_STANDARD || '';
const MEMBERSHIP_FOUNDING = Number(process.env.PM_PRICE_FOUNDING || 25); // dollars/mo
const MEMBERSHIP_STANDARD = Number(process.env.PM_PRICE_STANDARD || 50); // dollars/mo
// Billing is OFF until the owner switches it on — nobody is charged during the
// free launch period. The flag lives in pm_settings so the owner can toggle it
// from the admin panel without a redeploy.
async function pmSettings() { const l = await pmLoad('pm_settings'); return (l && l[0]) || {}; }
async function pmSaveSettings(s) { await pmSave('pm_settings', [s]); }
function priceIdForMember(me) { return (me && me.foundingRate ? STRIPE_PRICE_FOUNDING : STRIPE_PRICE_STANDARD) || STRIPE_PRICE_MEMBERSHIP; }
app.get('/api/pm/pay/status', ensureAuth, pmGate, async (req, res) => {
  try {
    const settings = await pmSettings();
    const profs = await pmLoad('pm_profiles');
    const me = profs.find(p => p && _lc(p.email) === pmEmail(req.user)) || {};
    const founder = !!me.foundingRate;
    const monthly = founder ? MEMBERSHIP_FOUNDING : MEMBERSHIP_STANDARD;
    const membershipConfigured = !!(stripe && priceIdForMember(me));
    res.json({ ok: true, enabled: !!stripe, membership: membershipConfigured, billingOn: !!settings.billingOn, founder, monthly, memberNo: me.memberNo || null, paid: !!me.paid, prices: { renew: PM_PRICE.renew / 100, feature: PM_PRICE.feature / 100, founding: MEMBERSHIP_FOUNDING, standard: MEMBERSHIP_STANDARD } });
  } catch (e) { res.status(502).json({ ok: false, error: String((e && e.message) || e).slice(0, 200) }); }
});
// Owner: switch membership billing on/off. Off = nobody charged (free launch).
app.post('/api/pm/admin/billing', ensureAuth, pmGate, async (req, res) => {
  if (!pmIsAdmin(req)) return res.status(403).json({ ok: false, error: 'forbidden' });
  const on = (req.body || {}).on === true;
  try {
    const s = await pmSettings();
    s.billingOn = on; s.billingUpdatedAt = new Date().toISOString();
    await pmSaveSettings(s);
    res.json({ ok: true, billingOn: on });
  } catch (e) { res.status(502).json({ ok: false, error: String((e && e.message) || e).slice(0, 200) }); }
});
app.post('/api/pm/checkout', ensureAuth, pmGate, async (req, res) => {
  if (!stripe) return res.status(503).json({ ok: false, error: 'not_configured' });
  const b = req.body || {}, kind = String(b.kind || '');
  try {
    if (kind === 'renew' || kind === 'feature') {
      const id = String(b.listingId || ''); if (!id) return res.status(400).json({ ok: false, error: 'no_id' });
      const listings = await pmLoad(PM_KEYS.listings); const l = listings.find(x => x && x.id === id);
      if (!l) return res.status(404).json({ ok: false, error: 'not_found' });
      if (_lc(l.owner) !== pmEmail(req.user) && req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'not_your_listing' });
      const amount = PM_PRICE[kind];
      const label = kind === 'renew' ? 'AXESS — renew deal (30 days)' : 'AXESS — feature deal';
      const session = await stripe.checkout.sessions.create({ mode: 'payment', payment_method_types: ['card'], line_items: [{ price_data: { currency: 'usd', unit_amount: amount, product_data: { name: label } }, quantity: 1 }], metadata: { kind, listingId: id, email: pmEmail(req.user) }, success_url: PM_BASE + '/app.html?paid={CHECKOUT_SESSION_ID}', cancel_url: PM_BASE + '/app.html' });
      return res.json({ ok: true, url: session.url });
    }
    if (kind === 'membership') {
      // Free launch period: no charging until the owner switches billing on.
      const settings = await pmSettings();
      if (!settings.billingOn) return res.status(409).json({ ok: false, error: 'billing_off', message: 'Membership is free during our launch — billing hasn\'t started yet.' });
      const profs = await pmLoad('pm_profiles');
      const me = profs.find(p => p && _lc(p.email) === pmEmail(req.user)) || {};
      const priceId = priceIdForMember(me);
      if (!priceId) return res.status(503).json({ ok: false, error: 'no_membership_price' });
      const tier = me.foundingRate ? 'founding' : 'standard';
      const session = await stripe.checkout.sessions.create({ mode: 'subscription', payment_method_types: ['card'], line_items: [{ price: priceId, quantity: 1 }], customer_email: pmEmail(req.user), metadata: { kind: 'membership', email: pmEmail(req.user), tier }, success_url: PM_BASE + '/app.html?paid={CHECKOUT_SESSION_ID}', cancel_url: PM_BASE + '/app.html' });
      return res.json({ ok: true, url: session.url });
    }
    res.status(400).json({ ok: false, error: 'bad_kind' });
  } catch (e) { res.status(502).json({ ok: false, error: String((e && e.message) || e).slice(0, 200) }); }
});
app.get('/api/pm/pay/confirm', ensureAuth, pmGate, async (req, res) => {
  if (!stripe) return res.status(503).json({ ok: false, error: 'not_configured' });
  const sid = String(req.query.session_id || ''); if (!sid) return res.status(400).json({ ok: false, error: 'no_session' });
  try {
    const s = await stripe.checkout.sessions.retrieve(sid);
    if (!s || (s.payment_status !== 'paid' && s.status !== 'complete')) return res.json({ ok: false, error: 'unpaid' });
    const m = s.metadata || {}, kind = m.kind;
    const pays = await pmLoad('pm_pays');
    if (pays.some(p => p && p.sid === sid)) return res.json({ ok: true, already: true, kind });
    if (kind === 'renew' || kind === 'feature') {
      const listings = await pmLoad(PM_KEYS.listings); const idx = listings.findIndex(x => x && x.id === m.listingId);
      if (idx >= 0) {
        if (kind === 'renew') { const l = listings[idx]; const base = l.expiresAt && new Date(l.expiresAt) > new Date() ? new Date(l.expiresAt) : new Date(); l.expiresAt = new Date(base.getTime() + 30 * 864e5).toISOString(); l.renew5Sent = false; l.renew1Sent = false; if ((l.status || 'active') === 'off') l.status = 'active'; }
        else { listings[idx].featured = true; }
        await pmSave(PM_KEYS.listings, listings);
      }
    } else if (kind === 'membership') {
      const profs = await pmLoad('pm_profiles'); const p = profs.find(x => x && _lc(x.email) === _lc(m.email || pmEmail(req.user)));
      if (p) { p.status = 'approved'; p.paid = true; p.paidAt = new Date().toISOString(); await pmSave('pm_profiles', profs); }
    }
    pays.push({ sid, kind, email: m.email || pmEmail(req.user), at: new Date().toISOString() });
    await pmSave('pm_pays', pays.length > 5000 ? pays.slice(-5000) : pays);
    res.json({ ok: true, kind });
  } catch (e) { res.status(502).json({ ok: false, error: String((e && e.message) || e).slice(0, 200) }); }
});

// ── sample data (admin) ──────────────────────────────────────────────────────
app.all('/api/pm/seed', ensureAuth, pmGate, async (req, res) => {
  if (!req.user || req.user.role !== 'owner') return res.status(403).json({ ok: false, error: 'forbidden' });
  const mode = String((req.query && req.query.mode) || (req.body && req.body.mode) || 'load').toLowerCase();
  try {
    let [listings, boxes, profs] = await Promise.all([pmLoad(PM_KEYS.listings), pmLoad(PM_KEYS.buyboxes), pmLoad('pm_profiles')]);
    listings = listings.filter(x => !(x && x.sample));
    boxes = boxes.filter(x => !(x && x.sample));
    profs = profs.filter(x => !(x && x.sample));
    if (mode === 'clear') { await Promise.all([pmSave(PM_KEYS.listings, listings), pmSave(PM_KEYS.buyboxes, boxes), pmSave('pm_profiles', profs)]); return res.json({ ok: true, cleared: true }); }
    const now = Date.now(), D = 864e5, iso = ms => new Date(ms).toISOString();
    const PEOPLE = [
      { email: 'marcus.reilly@reillyre.com', name: 'Marcus Reilly', brokerage: 'Reilly Investment Real Estate', license: '9812345', markets: 'South Boston, Dorchester, South End', phone: '(617) 555-0142', bio: 'Multifamily investment sales, 11 years. Southie & Dorchester specialist.', linkedin: 'https://www.linkedin.com/in/marcusreilly', instagram: 'https://instagram.com/reilly.re', verified: true },
      { email: 'priya.shah@coastalcre.com', name: 'Priya Shah', brokerage: 'Coastal Commercial RE', license: '9823456', markets: 'Cambridge, Somerville, Medford', phone: '(617) 555-0173', bio: 'Mixed-use and multifamily across Cambridge/Somerville.', linkedin: 'https://www.linkedin.com/in/priyashah', website: 'https://coastalcre.com', verified: true },
      { email: 'danny.fournier@fournierco.com', name: 'Danny Fournier', brokerage: 'Fournier & Co', license: '9834567', markets: 'Quincy, Weymouth, Braintree', phone: '(617) 555-0119', bio: 'South Shore investment specialist.', facebook: 'https://facebook.com/fournierco' },
      { email: 'alyssa.nguyen@northshorecap.com', name: 'Alyssa Nguyen', brokerage: 'North Shore Capital RE', license: '9845678', markets: 'Lynn, Salem, Peabody', phone: '(781) 555-0188', bio: 'Value-add multifamily on the North Shore.', linkedin: 'https://www.linkedin.com/in/alyssanguyen', instagram: 'https://instagram.com/northshore.deals', verified: true },
      { email: 'tom.bradley@bradleymf.com', name: 'Tom Bradley', brokerage: 'Bradley Multifamily', license: '9856789', markets: 'Worcester, Shrewsbury', phone: '(508) 555-0155', bio: 'Larger multifamily and portfolios in Central MA.', website: 'https://bradleymultifamily.com' },
      { email: 'sofia.marchetti@baystateig.com', name: 'Sofia Marchetti', brokerage: 'Bay State Investment Group', license: '9867890', markets: 'Malden, Medford, Everett', phone: '(617) 555-0166', bio: 'Investment sales north of Boston.', linkedin: 'https://www.linkedin.com/in/sofiamarchetti', instagram: 'https://instagram.com/sofia.cre' },
      { email: 'kevin.odonnell@odra.com', name: "Kevin O'Donnell", brokerage: "O'Donnell Realty Advisors", license: '9878901', markets: 'Brockton, Stoughton', phone: '(508) 555-0177', bio: 'Mixed-use and retail south of Boston.', facebook: 'https://facebook.com/odonnellrealty', website: 'https://odonnelladvisors.com' },
      { email: 'rachel.kim@kimcre.com', name: 'Rachel Kim', brokerage: 'Kim Commercial Partners', license: '9889012', markets: 'Lowell, Lawrence, Haverhill', phone: '(978) 555-0121', bio: 'Merrimack Valley commercial & multifamily.', linkedin: 'https://www.linkedin.com/in/rachelkimcre', verified: true },
      { email: 'andre.dubois@duboispg.com', name: 'Andre Dubois', brokerage: 'Dubois Property Group', license: '9890123', markets: 'Revere, Chelsea, East Boston', phone: '(617) 555-0134', bio: 'Off-market deals in Revere/Chelsea/Eastie.', instagram: 'https://instagram.com/dubois.deals' },
      { email: 'jenna.walsh@walshassoc.com', name: 'Jenna Walsh', brokerage: 'Walsh & Associates', license: '9801234', markets: 'Framingham, Natick, MetroWest', phone: '(508) 555-0198', bio: 'MetroWest investment and development sites.', linkedin: 'https://www.linkedin.com/in/jennawalsh', website: 'https://walshassociates.com' }
    ];
    PEOPLE.forEach(p => profs.push(Object.assign({ status: 'approved', createdAt: iso(now - 20 * D), sample: true }, p)));
    const DEALS = [
      { o: 0, L: { propType: 'Multifamily', area: 'South Boston', city: 'Boston', zip: '02127', address: '42 Telegraph St', price: 1850000, commissionPct: 2.5, units: 6, capRate: 5.2, noi: 96200, sqft: 5400, yearBuilt: 1905, notes: 'Turn-key 6-unit, all 2-beds, separate utilities. Upside on 2 units at lease turn.', featured: true } },
      { o: 0, L: { propType: 'Multifamily', area: 'Dorchester', city: 'Boston', zip: '02122', address: '18 Melville Ave', price: 2950000, commissionPct: 2.0, units: 12, capRate: 5.8, noi: 171100, sqft: 10200, yearBuilt: 1920, notes: '12-unit brick, mostly renovated. Value-add on 4 legacy tenants.' } },
      { o: 1, L: { propType: 'Mixed-use', area: 'Cambridge', city: 'Cambridge', zip: '02139', address: '605 Massachusetts Ave', price: 3400000, commissionPct: 3.0, units: 8, capRate: 4.9, noi: 166600, sqft: 8900, notes: 'Retail + 6 apartments on Mass Ave. Below-market retail lease rolls next year.', featured: true } },
      { o: 1, L: { propType: 'Development', area: 'Somerville', city: 'Somerville', zip: '02143', price: 1200000, commissionPct: 2.5, sqft: 9000, notes: 'Permitted for 14 units near Union Sq. Full plans available.', dist: 'private', hideAddress: true, address: '0 Prospect St (assemblage)' } },
      { o: 2, L: { propType: 'Retail', area: 'Quincy', city: 'Quincy', zip: '02169', address: '380 Hancock St', price: 2100000, commissionPct: 2.5, capRate: 6.1, noi: 128100, sqft: 7200, notes: 'Single-tenant retail, corporate guarantee, 7 years remaining.' } },
      { o: 4, L: { propType: 'Multifamily', area: 'Worcester', city: 'Worcester', zip: '01610', address: '22 Kingsbury St', price: 3600000, commissionPct: 2.0, units: 24, capRate: 6.5, noi: 234000, sqft: 19800, notes: '24-unit garden style. Assumable financing at 4.1%.' } },
      { o: 3, L: { propType: 'Condo', area: 'Lynn', city: 'Lynn', zip: '01902', address: '55 Broad St', price: 1450000, commissionPct: 2.5, units: 5, sqft: 6100, notes: '5 condo-able units, master deed started. Conversion play.' } },
      { o: 5, L: { propType: 'Industrial', area: 'Malden', city: 'Malden', zip: '02148', address: '120 Commercial St', price: 4200000, commissionPct: 2.0, capRate: 6.0, noi: 252000, sqft: 31000, notes: '31k SF flex/industrial, fully leased to 3 tenants.', featured: true } },
      { o: 6, L: { propType: 'Single-family', area: 'Brockton', city: 'Brockton', zip: '02301', address: 'Scattered-site portfolio (7 homes)', price: 1100000, commissionPct: 2.5, units: 7, notes: '7-home SFR rental portfolio, all leased. Clean management.' } },
      { o: 7, L: { propType: 'Mixed-use', area: 'Lowell', city: 'Lowell', zip: '01852', address: '145 Merrimack St', price: 2750000, commissionPct: 2.5, units: 10, capRate: 5.5, noi: 151300, sqft: 12400, notes: 'Downtown mixed-use, 2 retail + 8 residential.' } },
      { o: 8, L: { propType: 'Multifamily', area: 'Revere', city: 'Revere', zip: '02151', price: 2400000, commissionPct: 2.5, units: 9, capRate: 5.6, noi: 134400, sqft: 8600, notes: '9-unit near the beach. Seller wants a quiet sale.', hideAddress: true, address: '(on file — hidden)' } },
      { o: 8, L: { propType: 'Land', area: 'Framingham', city: 'Framingham', zip: '01702', address: '0 Waverley St', price: 900000, commissionPct: 3.0, sqft: 43560, notes: '1 acre, commercial zoning, curb cut in place.' } },
      { o: 5, L: { propType: 'Multifamily', area: 'Medford', city: 'Medford', zip: '02155', address: '31 Salem St', price: 2650000, commissionPct: 2.25, units: 8, capRate: 5.4, noi: 143100, sqft: 7800, notes: '8-unit near Tufts. Consistent student demand.' } },
      { o: 3, L: { propType: 'Retail', area: 'Salem', city: 'Salem', zip: '01970', address: '210 Essex St', price: 1950000, commissionPct: 2.5, capRate: 6.2, noi: 120900, sqft: 5600, notes: 'Downtown Salem retail, strong foot traffic.' } }
    ];
    DEALS.forEach((d, i) => { const p = PEOPLE[d.o]; listings.push(Object.assign({ id: 'SAMPLE-' + (i + 1), owner: p.email, ownerName: p.name, status: 'active', dist: 'broad', state: 'MA', docs: [], views: (7 * i) % 40, createdAt: iso(now - (i + 1) * 2 * D), updatedAt: iso(now - i * D), expiresAt: iso(now + (26 - (i % 12)) * D), sample: true }, d.L)); });
    const BOXES = [
      { o: 1, B: { markets: 'Cambridge, Somerville, Medford', propType: 'Multifamily', minUnits: '8', maxUnits: '30', minPrice: '2000000', maxPrice: '5000000', minCap: '5', notes: '1031 buyer, needs to close in 60 days. Value-add ok.' } },
      { o: 6, B: { markets: 'Brockton, Quincy, Stoughton', propType: 'Mixed-use', minUnits: '', maxUnits: '', minPrice: '1000000', maxPrice: '3000000', minCap: '6', notes: 'Retail + resi, stabilized preferred.' } },
      { o: 4, B: { markets: 'Worcester, Central MA', propType: 'Multifamily', minUnits: '20', maxUnits: '', minPrice: '3000000', maxPrice: '8000000', minCap: '6', notes: 'Institutional buyer seeking 20+ unit assets.' } },
      { o: 3, B: { markets: 'Lynn, Salem, Peabody', propType: 'Multifamily', minUnits: '4', maxUnits: '20', minPrice: '1000000', maxPrice: '3000000', minCap: '5.5', notes: 'Value-add North Shore, cash buyer.' } },
      { o: 8, B: { markets: 'Revere, Chelsea, East Boston', propType: 'Retail', minUnits: '', maxUnits: '', minPrice: '1000000', maxPrice: '2500000', minCap: '6', notes: 'Looking for retail/mixed near transit.' } }
    ];
    BOXES.forEach((bx, i) => { const p = PEOPLE[bx.o]; boxes.push(Object.assign({ owner: p.email, ownerName: p.name, contact: p.email, createdAt: iso(now - (i + 3) * D), updatedAt: iso(now), sample: true }, bx.B)); });
    await Promise.all([pmSave(PM_KEYS.listings, listings), pmSave(PM_KEYS.buyboxes, boxes), pmSave('pm_profiles', profs)]);
    res.json({ ok: true, loaded: { listings: DEALS.length, members: PEOPLE.length, clientNeeds: BOXES.length } });
  } catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});

// ── renewal reminder sweep (self-scheduled) ──────────────────────────────────
const PM_CRON_TOKEN = process.env.PM_CRON_TOKEN || '';
async function pmRunRenewals() {
  const listings = await pmLoad(PM_KEYS.listings);
  const now = new Date(); let changed = false; const sent = { r5: 0, r1: 0, expired: 0 };
  for (const l of listings) {
    if (!l || !l.expiresAt || (l.status || 'active') === 'off') continue;
    const days = (new Date(l.expiresAt) - now) / 864e5;
    const link = 'Open AXESS and hit Renew to extend this deal another 30 days.';
    const label = (l.area || l.city || 'your deal') + (l.price ? (' · ' + pmMoneyShort(l.price)) : '');
    if (days <= 0) { l.status = 'off'; l.expiredAt = now.toISOString(); changed = true; sent.expired++; continue; }
    if (days <= 5 && days > 1 && !l.renew5Sent) { await pmSendEmail(l.owner, 'AXESS · your deal expires in 5 days', label + ' expires in 5 days.\n\n' + link); l.renew5Sent = true; changed = true; sent.r5++; }
    if (days <= 1 && !l.renew1Sent) { await pmSendEmail(l.owner, 'AXESS · your deal expires tomorrow', label + ' expires in 1 day.\n\n' + link); l.renew1Sent = true; changed = true; sent.r1++; }
  }
  if (changed) await pmSave(PM_KEYS.listings, listings);
  return sent;
}
app.all('/api/pm/cron', async (req, res) => {
  const tok = String((req.query && req.query.token) || (req.body && req.body.token) || '');
  const authed = (PM_CRON_TOKEN && tok === PM_CRON_TOKEN) || (req.user && req.user.role === 'owner');
  if (!authed) return res.status(403).json({ ok: false, error: 'forbidden' });
  try { res.json({ ok: true, sent: await pmRunRenewals() }); }
  catch (e) { res.status(502).json({ ok: false, error: String(e).slice(0, 200) }); }
});
setTimeout(() => { pmRunRenewals().catch(() => {}); }, 30000);
setInterval(() => { pmRunRenewals().catch(() => {}); }, 12 * 3600 * 1000);

// ── pages ─────────────────────────────────────────────────────────────────
// The members app needs the signed-in identity the old hub used to inject.
function serveWithIdentity(res, file, user) {
  let html = fs.readFileSync(path.join(__dirname, 'public', file), 'utf8');
  const mapsKey = process.env.GOOGLE_MAPS_KEY || process.env.MAPS_API_KEY || '';
  const inject = `<script>window.__ROLE__=${JSON.stringify(user.role)};window.__USER__=${JSON.stringify(user.name || '')};window.__EMAIL__=${JSON.stringify(user.email)};window.__ACCT__="access";window.__STATUS__=${JSON.stringify(user.status)};window.__MAPS_KEY__=${JSON.stringify(mapsKey)};window.__GOOGLE_CLIENT_ID__=${JSON.stringify(process.env.GOOGLE_CLIENT_ID || '')};</script>`;
  html = html.includes('</head>') ? html.replace('</head>', inject + '</head>') : inject + html;
  res.type('html').send(html);
}
// Members app: approved members + admin only. Pending/unknown bounced to landing.
app.get('/app.html', ensureAuth, (req, res) => {
  if (req.user.role !== 'owner' && req.user.status !== 'approved') return res.redirect('/?pending=1');
  serveWithIdentity(res, 'app.html', req.user);
});
// Legacy demo URL. A stale premarket-hub.html still lives in public/ from an
// earlier build; this route shadows it (registered before express.static) so
// the old link always serves the CURRENT app instead of the frozen copy.
app.get('/premarket-hub.html', ensureAuth, (req, res) => {
  if (req.user.role !== 'owner' && req.user.status !== 'approved') return res.redirect('/?pending=1');
  serveWithIdentity(res, 'app.html', req.user);
});
// Landing: inject the Turnstile site key (captcha) before static serving.
function serveLanding(req, res) {
  try {
    let html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
    const inject = `<script>window.__TURNSTILE_SITE__=${JSON.stringify(TURNSTILE_SITE)};window.__GOOGLE_CLIENT_ID__=${JSON.stringify(process.env.GOOGLE_CLIENT_ID || '')};</script>`;
    html = html.includes('</head>') ? html.replace('</head>', inject + '</head>') : inject + html;
    res.type('html').send(html);
  } catch (e) { res.sendFile(path.join(__dirname, 'public', 'index.html')); }
}
app.get(['/', '/index.html'], serveLanding);

// Google Sign-In: the client sends the Google ID token (JWT). We verify it with
// Google's tokeninfo endpoint, confirm the audience is our OAuth client and the
// email is verified, then start the same session the magic link would. Existing
// members sign in instantly; anyone without a profile still passes the gate as a
// signed-in guest and is routed to Request access. No password stored, ever.
app.post('/auth/google', async (req, res) => {
  const cred = String((req.body || {}).credential || '');
  const CID = process.env.GOOGLE_CLIENT_ID || '';
  if (!cred) return res.status(400).json({ ok: false, error: 'no_credential' });
  if (!CID) return res.status(500).json({ ok: false, error: 'not_configured' });
  try {
    const info = await httpsGetJson('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(cred));
    if (!info || info.aud !== CID) return res.status(401).json({ ok: false, error: 'bad_audience' });
    if (String(info.email_verified) !== 'true' || !info.email) return res.status(401).json({ ok: false, error: 'unverified' });
    req.session.email = String(info.email).toLowerCase().trim();
    res.json({ ok: true, email: req.session.email });
  } catch (e) { res.status(502).json({ ok: false, error: 'verify_failed' }); }
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const PORT = process.env.PORT || 3000;
db.ensureSchema()
  .then(ok => console.log(ok ? 'Postgres ready' : 'No DATABASE_URL — set it in Render to enable storage'))
  .catch(e => console.error('schema init failed', e))
  .finally(() => app.listen(PORT, () => console.log('AXESS listening on ' + PORT)));
