// Demo mode — an isolated test workspace for auditing the real member app.
//
// Isolation model: every request that belongs to a demo session runs inside an
// AsyncLocalStorage context. While that context is active, db.js reads and
// writes `demo:<key>` instead of `<key>`, so demo profiles, listings, needs,
// intros, messages and notifications live in their own partition and real
// data is never visible to (or writable from) demo mode. auth.js skips real
// email sends inside the context, and billing routes refuse it.
//
// Gates: demo mode exists only when DEMO_MODE is not "off" AND the visitor is
// either a signed-in admin or presents DEMO_ACCESS_CODE. The demo session is a
// separate signed cookie (axess_demo), so the real session cookie is untouched.

'use strict';

const crypto = require('crypto');
const { AsyncLocalStorage } = require('async_hooks');

const als = new AsyncLocalStorage();
const PREFIX = 'demo:';
const COOKIE = 'axess_demo';
const MAX_AGE_S = 7 * 24 * 3600;

// Single off switch: DEMO_MODE=off (or 0/false) disables demo mode entirely.
function enabled() {
  return !/^(off|0|false|no)$/i.test(String(process.env.DEMO_MODE || '').trim());
}
function accessCode() { return String(process.env.DEMO_ACCESS_CODE || '').trim(); }
function codeOk(code) {
  const want = accessCode(), got = String(code || '');
  if (!want || got.length !== want.length) return false;
  return crypto.timingSafeEqual(Buffer.from(got), Buffer.from(want));
}

function active() { const s = als.getStore(); return !!(s && s.demo); }
function run(fn) { return als.run({ demo: true }, fn); }
function scopedKey(key) { return active() ? PREFIX + String(key) : String(key); }

// ── signed demo cookie ──────────────────────────────────────────────────────
function secret() { return (process.env.SESSION_SECRET || 'dev-change-me') + ':axess-demo'; }
function sign(v) { return crypto.createHmac('sha256', secret()).update(v).digest('base64url'); }
function readCookie(req) {
  const raw = String((req.headers && req.headers.cookie) || '');
  const m = raw.split(/;\s*/).find(c => c.indexOf(COOKIE + '=') === 0);
  if (!m) return null;
  const val = decodeURIComponent(m.slice(COOKIE.length + 1));
  const dot = val.lastIndexOf('.');
  if (dot < 0) return null;
  const body = val.slice(0, dot), mac = val.slice(dot + 1);
  const good = sign(body);
  if (mac.length !== good.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(good))) return null;
  try {
    const o = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!o || !o.ok || !o.exp || o.exp < Date.now()) return null;
    return o;
  } catch (e) { return null; }
}
function cookieAttrs(secure) { return '; Path=/; HttpOnly; SameSite=Lax' + (secure ? '; Secure' : ''); }
function writeCookie(res, obj, secure) {
  const body = Buffer.from(JSON.stringify(Object.assign({}, obj, { ok: true, exp: Date.now() + MAX_AGE_S * 1000 }))).toString('base64url');
  res.append('Set-Cookie', COOKIE + '=' + encodeURIComponent(body + '.' + sign(body)) + '; Max-Age=' + MAX_AGE_S + cookieAttrs(secure));
}
function clearCookie(res, secure) { res.append('Set-Cookie', COOKIE + '=; Max-Age=0' + cookieAttrs(secure)); }

// Paths that run inside the demo partition for a demo session. Everything else
// (homepage, public counters/teaser, real sign-up, real sign-in, legal pages,
// cron, Stripe webhook) always runs against real data.
const PUBLIC_API = ['/api/pm/stats', '/api/pm/teaser', '/api/pm/request', '/api/pm/contact', '/api/pm/unsub', '/api/pm/digest/run', '/api/pm/cron', '/api/pm/stripe/webhook', '/api/pm/import', '/api/pm/seed'];
function pathInDemo(p) {
  if (p === '/app.html' || p === '/premarket-hub.html' || p === '/api/me') return true;
  if (p.indexOf('/api/demo/') === 0) return true;
  if (p.indexOf('/api/pm/') === 0) return PUBLIC_API.indexOf(p) < 0;
  return false;
}

// ── seed accounts & content (all clearly fake, all flagged is_demo) ─────────
const DOMAIN = 'demo.axess.invalid';
const ACCOUNTS = [
  { n: 1, market: 'South Boston', focus: 'residential' },
  { n: 2, market: 'Quincy', focus: 'commercial' },
  { n: 3, market: 'Cambridge', focus: 'both' },
  { n: 4, market: 'Dorchester', focus: 'residential' },
  { n: 5, market: 'West Roxbury', focus: 'commercial' }
].map(a => Object.assign(a, { email: 'demo-agent-' + a.n + '@' + DOMAIN, name: 'Demo Agent ' + a.n, brokerage: 'Demo Brokerage ' + a.n }));
const FOCUS_LABEL = { residential: 'Residential', commercial: 'Commercial & investment', both: 'Both' };
function isDemoEmail(e) { return String(e || '').toLowerCase().endsWith('@' + DOMAIN); }
function accountByN(n) { return ACCOUNTS.find(a => a.n === Number(n)) || null; }

// A tiny valid PDF used as the seller-authorization placeholder.
const PLACEHOLDER_PDF = 'data:application/pdf;base64,' + Buffer.from(
  '%PDF-1.1\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 120]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n4 0 obj<</Length 63>>stream\nBT /F1 14 Tf 20 60 Td (DEMO seller authorization - not real) Tj ET\nendstream endobj\n5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n'
).toString('base64');
const PLACEHOLDER_FORM = { name: 'DEMO-seller-authorization.pdf', url: PLACEHOLDER_PDF };

function seedData(nowMs) {
  const now = nowMs || Date.now();
  const iso = d => new Date(now + d * 864e5).toISOString();
  const profiles = ACCOUNTS.map(a => ({
    email: a.email, name: a.name, brokerage: a.brokerage, license: 'DEMO-' + a.n, phone: '(000) 000-000' + a.n,
    markets: a.market, focus: a.focus, state: 'MA', status: 'approved', is_demo: true, verified: false,
    bio: 'DEMO account — not a real agent.', approvedAt: iso(-1), createdAt: iso(-1), updatedAt: iso(-1),
    attestation: { text: 'DEMO account — no attestation; license verification bypassed because is_demo=true.', accepted: true, at: iso(-1), ip: '' },
    memberNo: a.n, foundingRate: true, marketingOptIn: false, exemptGiveGet: true,
    notifPrefs: { deals: 'all', dealTypes: [], dealMarkets: [], email: false, intros: false }
  }));
  const L = (n, owner, o) => Object.assign({
    id: 'DEMO-L' + n, owner: ACCOUNTS[owner].email, ownerName: ACCOUNTS[owner].name, brokerage: ACCOUNTS[owner].brokerage,
    status: 'active', state: 'MA', dist: 'broad', hideAddress: false, docs: [], photos: [], views: 0, featured: false,
    sellerForm: Object.assign({ uploadedAt: iso(-1) }, PLACEHOLDER_FORM), is_demo: true,
    createdAt: iso(-n * 0.25), updatedAt: iso(-n * 0.25), expiresAt: iso(30)
  }, o);
  const listings = [
    L(1, 0, { city: 'Boston', area: 'DEMO · South Boston', zip: '02127', propType: 'Condo / Conversion', price: '895000', beds: '2', baths: '2', sqft: '1150', address: 'DEMO — 1 Example St, South Boston (not a real address)', notes: 'DEMO LISTING — not a real property. Two-bed condo used for testing the member app.' }),
    L(2, 1, { city: 'Quincy', area: 'DEMO · Quincy', zip: '02169', propType: 'Retail / Commercial', price: '1450000', capRate: '6.2', noi: '89900', sqft: '6200', address: 'DEMO — 2 Example Ave, Quincy (not a real address)', notes: 'DEMO LISTING — not a real property. Single-tenant retail for testing.' }),
    L(3, 2, { city: 'Cambridge', area: 'DEMO · Cambridge', zip: '02139', propType: 'Multifamily', price: '2650000', units: '6', capRate: '5.1', noi: '135150', sqft: '6400', address: 'DEMO — 3 Example Rd, Cambridge (not a real address)', notes: 'DEMO LISTING — not a real property. Six-unit for testing intros.', dist: 'private', hideAddress: true }),
    L(4, 3, { city: 'Boston', area: 'DEMO · Dorchester', zip: '02122', propType: 'Multifamily', price: '1325000', units: '3', sqft: '3900', beds: '9', baths: '3', address: 'DEMO — 4 Example Pl, Dorchester (not a real address)', notes: 'DEMO LISTING — not a real property. Triple-decker for testing.', hideAddress: true }),
    L(5, 4, { city: 'Boston', area: 'DEMO · West Roxbury', zip: '02132', propType: 'Mixed-use', price: '1980000', units: '4', capRate: '5.6', noi: '110880', sqft: '5200', address: 'DEMO — 5 Example Way, West Roxbury (not a real address)', notes: 'DEMO LISTING — not a real property. Mixed-use for testing.' }),
    L(6, 2, { city: 'Cambridge', area: 'DEMO · Cambridge', zip: '02140', propType: 'Single-family', price: '1750000', beds: '4', baths: '2.5', sqft: '2600', address: 'DEMO — 6 Example Ct, Cambridge (not a real address)', notes: 'DEMO LISTING — not a real property. Single-family for testing filters.', comingSoon: true })
  ];
  const B = (owner, o) => Object.assign({ owner: ACCOUNTS[owner].email, ownerName: ACCOUNTS[owner].name, is_demo: true, createdAt: iso(-0.5), updatedAt: iso(-0.5) }, o);
  const buyboxes = [
    B(0, { markets: 'Cambridge', propType: 'Multifamily', priceBand: '2m_5m', minPrice: '2000000', maxPrice: '5000000', timeline: '90_days', notes: 'DEMO CLIENT NEED — not a real client. Investor wants 4–8 units.' }),
    B(1, { markets: 'Dorchester', propType: 'Multifamily', priceBand: '1m_2m', minPrice: '1000000', maxPrice: '2000000', timeline: '60_days', notes: 'DEMO CLIENT NEED — not a real client. Owner-occupant triple-decker.' }),
    B(3, { markets: 'South Boston', propType: 'Condo', priceBand: '500k_1m', minPrice: '500000', maxPrice: '1000000', beds: '2', timeline: '30_days', notes: 'DEMO CLIENT NEED — not a real client. First-time buyer, 2 beds.' })
  ];
  return { pm_profiles: profiles, pm_listings: listings, pm_buyboxes: buyboxes };
}
// Every list the member app reads or writes; reset clears all of them.
const DEMO_KEYS = ['pm_profiles', 'pm_listings', 'pm_buyboxes', 'pm_intros', 'pm_messages', 'pm_notifs', 'pm_broadcasts', 'pm_requests', 'pm_admissions', 'pm_settings', 'pm_pays', 'pm_contacts', 'pm_invites', 'pm_ai_usage'];

module.exports = {
  als, run, active, scopedKey, enabled, accessCode, codeOk,
  readCookie, writeCookie, clearCookie, pathInDemo,
  ACCOUNTS, FOCUS_LABEL, isDemoEmail, accountByN, PLACEHOLDER_FORM, seedData, DEMO_KEYS, PREFIX
};
