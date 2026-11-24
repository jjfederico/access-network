'use strict';
// Seller consent recorded in AXESS: owner path, emailed seller link, material
// change, revocation, admin log, the upload path alongside, and demo mode.
// Runs the stubbed server (server-harness.js): in-memory store, no network.
const assert = require('assert');
process.env.DEMO_MODE = 'on';
const { store, sent, call, demo } = require('./server-harness');
const c = require('../lib/compliance');

const PDF = 'data:application/pdf;base64,' + Buffer.from('%PDF-1.4 seller-signed authorization ' + 'x'.repeat(4000)).toString('base64');
const poster = { email: 'poster@example.com', role: 'member', status: 'approved' };
const other = { email: 'other@example.com', role: 'member', status: 'approved' };
const admin = { email: 'owner@example.com', role: 'owner', status: 'approved' };
const now = new Date().toISOString();
const prof = (email, name) => ({ email, name, brokerage: 'Example Realty', license: '654321', status: 'approved', state: 'MA', approvedAt: now, createdAt: now, exemptGiveGet: true });
store.pm_profiles = [prof(poster.email, 'Pat Poster'), prof(other.email, 'Olive Other'), prof(admin.email, 'Owner')];
const base = { city: 'Worcester', area: 'Main South', address: '12 Example St, Worcester, MA', price: '750000', propType: 'Multifamily', notes: 'Six units.' };
const feedIds = async u => ((await call('get', '/api/pm/feed', {}, u)).body.listings || []).map(l => l.id);
const L = id => store.pm_listings.find(l => l.id === id);
const linkFrom = (html, key) => { const m = String(html).match(new RegExp('/consent\\?' + key + '=([A-Za-z0-9_%]+)')); return m ? decodeURIComponent(m[1]) : ''; };
const lastTo = to => sent.filter(e => e.to === to).slice(-1)[0];

(async () => {
  // ── pure: coverage + material change ──────────────────────────────────────
  const cons = { path: 'owner_in_app', name: 'Pat', at: now, address: '12 Example St', price: '750000' };
  assert.ok(c.listingAuthorized({ address: '12 example st.', price: '750,000', consent: cons }), 'consent covers same address/price (normalized)');
  assert.ok(!c.listingAuthorized({ address: '12 Example St', price: '760000', consent: cons }), 'price change → not covered');
  assert.ok(!c.listingAuthorized({ address: '14 Example St', price: '750000', consent: cons }), 'address change → not covered');
  assert.ok(c.consentLapsed({ address: '14 Example St', price: '750000', consent: cons }));
  assert.ok(!c.listingAuthorized({ address: '12 Example St', price: '750000', consent: Object.assign({}, cons, { revokedAt: now }) }), 'revoked → not covered');
  assert.ok(!c.listingAuthorized({ address: '12 Example St', price: '750000', consent: Object.assign({}, cons, { path: 'uploaded_form' }) }), 'a consent snapshot never stands in for a form');
  assert.ok(!c.listingAuthorized({ sellerRevokedAt: now, sellerForm: { name: 'f.pdf', url: PDF } }), 'seller revocation takes down even an uploaded form');
  assert.ok(c.CONSENT_TEXT.join(' ').match(/AXESS RE LLC/) && /not a real estate broker/.test(c.CONSENT_TEXT.join(' ')) && /revoke/.test(c.CONSENT_TEXT.join(' ')));

  // ── no authorization at all → refused, as before ─────────────────────────
  let r = await call('post', '/api/pm/listing', base, poster);
  assert.strictEqual(r.body.error, 'seller_form_required');
  assert.ok(/signed .*form.*or record the seller’s consent/i.test(r.body.message), r.body.message);

  // ── 1. owner path ────────────────────────────────────────────────────────
  r = await call('post', '/api/pm/listing', Object.assign({}, base, { consent: { mode: 'owner', agree: false, name: 'Pat Poster' } }), poster);
  assert.strictEqual(r.body.error, 'consent_agree_required');
  r = await call('post', '/api/pm/listing', Object.assign({}, base, { consent: { mode: 'owner', agree: true, name: ' ' } }), poster);
  assert.strictEqual(r.body.error, 'consent_name_required');
  r = await call('post', '/api/pm/listing', Object.assign({}, base, { address: '', consent: { mode: 'owner', agree: true, name: 'Pat Poster' } }), poster);
  assert.strictEqual(r.body.error, 'consent_address_required');
  assert.ok(!(store.pm_listings || []).length && !(store.pm_consents || []).length, 'refused attempts store nothing');
  r = await call('post', '/api/pm/listing', Object.assign({}, base, { consent: { mode: 'owner', agree: true, name: 'Pat Poster' } }), poster);
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  const ownerId = r.body.id;
  assert.strictEqual(L(ownerId).status, 'active', 'owner consent → live immediately');
  let rec = store.pm_consents.find(x => x.listingId === ownerId);
  assert.ok(rec && rec.path === 'owner_in_app' && rec.name === 'Pat Poster' && rec.account === poster.email && rec.textVersion === c.CONSENT_TEXT_VERSION && rec.address === base.address && rec.price === base.price && rec.at && 'ip' in rec && 'ua' in rec, 'full consent record');
  assert.ok((await feedIds(other)).includes(ownerId), 'live for other members');
  const ownerMail = lastTo(poster.email);
  assert.ok(ownerMail && /consent is recorded/.test(ownerMail.subject) && linkFrom(ownerMail.html, 'r'), 'owner gets a confirmation with a revoke link');
  const mine = (await call('get', '/api/pm/feed', {}, poster)).body.listings.find(l => l.id === ownerId);
  assert.ok(mine.hasConsent && mine.authz && mine.authz.consent.path === 'owner_in_app', 'poster sees how it is authorized');
  const theirs = (await call('get', '/api/pm/feed', {}, other)).body.listings.find(l => l.id === ownerId);
  assert.ok(!theirs.authz, 'other members never see consent details');

  // ── material change: price edit drops it back to awaiting ────────────────
  r = await call('post', '/api/pm/listing', Object.assign({}, base, { id: ownerId, price: '799000' }), poster);
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.awaiting && r.body.lapsed, 'response says it needs consent again');
  assert.strictEqual(L(ownerId).status, 'awaiting_consent');
  assert.ok(!(await feedIds(other)).includes(ownerId), 'hidden from others while awaiting');
  assert.ok(store.pm_consents.find(x => x.id === rec.id).lapsedAt, 'old consent marked as no longer covering');
  // Editing other fields while awaiting keeps it awaiting.
  r = await call('post', '/api/pm/listing', Object.assign({}, base, { id: ownerId, price: '799000', notes: 'Six units, updated.' }), poster);
  assert.strictEqual(L(ownerId).status, 'awaiting_consent');
  // Re-consent at the new price → live again.
  r = await call('post', '/api/pm/listing', Object.assign({}, base, { id: ownerId, price: '799000', consent: { mode: 'owner', agree: true, name: 'Pat Poster' } }), poster);
  assert.strictEqual(L(ownerId).status, 'active');
  assert.strictEqual(L(ownerId).consent.price, '799000');
  assert.ok((await feedIds(other)).includes(ownerId));

  // ── 2. seller link path ──────────────────────────────────────────────────
  const b2 = Object.assign({}, base, { address: '40 Sample Ave, Worcester, MA', price: '1200000' });
  r = await call('post', '/api/pm/listing', Object.assign({}, b2, { consent: { mode: 'seller_link', sellerName: 'Sam Seller', sellerEmail: 'bad' } }), poster);
  assert.strictEqual(r.body.error, 'seller_email_required');
  r = await call('post', '/api/pm/listing', Object.assign({}, b2, { consent: { mode: 'seller_link', sellerName: 'Sam Seller', sellerEmail: poster.email } }), poster);
  assert.strictEqual(r.body.error, 'seller_email_is_you');
  r = await call('post', '/api/pm/listing', Object.assign({}, b2, { consent: { mode: 'seller_link', sellerName: 'Sam Seller', sellerEmail: 'sam@seller.test' } }), poster);
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  const linkId = r.body.id;
  assert.ok(r.body.awaiting && r.body.consentSentTo === 'sam@seller.test' && !r.body.demoLink, 'real mode never hands the link to the poster');
  assert.strictEqual(L(linkId).status, 'awaiting_consent');
  assert.ok(!(await feedIds(other)).includes(linkId), 'not in the feed while awaiting');
  const teaser = (await call('get', '/api/pm/teaser', {}, null)).body;
  assert.ok(!JSON.stringify(teaser).includes('1200000'), 'not in the public teaser');
  const lk = store.pm_consent_links.find(k => k.listingId === linkId);
  assert.ok(lk && lk.th && !lk.token && JSON.stringify(lk).indexOf('t=') < 0, 'only a hash of the token is stored');
  const sellerMail = lastTo('sam@seller.test');
  const tok = linkFrom(sellerMail.html, 't');
  assert.ok(tok && !/^demo_/.test(tok), 'seller emailed a link');
  r = await call('get', '/api/consent/info', {}, null, { query: { t: tok } });
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.address === b2.address && r.body.priceText === '$1,200,000' && r.body.agentName === 'Pat Poster' && r.body.brokerage === 'Example Realty' && r.body.text.length === 4);
  r = await call('get', '/api/consent/info', {}, null, { query: { t: 'x'.repeat(30) } });
  assert.strictEqual(r.status, 404);
  r = await call('post', '/api/consent/accept', { t: tok, agree: true, name: 'Sam Seller', address: b2.address, price: '1100000' });
  assert.strictEqual(r.status, 409, 'stale details refused');
  r = await call('post', '/api/consent/accept', { t: tok, agree: false, name: 'Sam Seller', address: b2.address, price: b2.price });
  assert.strictEqual(r.body.error, 'agree_required');
  r = await call('post', '/api/consent/accept', { t: tok, agree: true, name: '', address: b2.address, price: b2.price });
  assert.strictEqual(r.body.error, 'name_required');
  assert.strictEqual(L(linkId).status, 'awaiting_consent');
  r = await call('post', '/api/consent/accept', { t: tok, agree: true, name: 'Sam Seller', address: b2.address, price: b2.price });
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.live, 'goes live automatically');
  assert.strictEqual(L(linkId).status, 'active');
  assert.ok((await feedIds(other)).includes(linkId));
  rec = store.pm_consents.find(x => x.listingId === linkId && x.path === 'seller_link');
  assert.ok(rec && rec.name === 'Sam Seller' && rec.email === 'sam@seller.test' && rec.linkId === lk.id && rec.ip && rec.textVersion);
  assert.ok((store.pm_notifs || []).some(n => n.to === poster.email && n.type === 'consent' && n.listingId === linkId), 'poster notified in app');
  assert.ok(sent.some(e => e.to === poster.email && /seller consent recorded/.test(e.subject)), 'poster emailed');
  const confirm = lastTo('sam@seller.test');
  assert.ok(/consent is recorded/.test(confirm.subject));
  const rtok = linkFrom(confirm.html, 'r');
  assert.ok(rtok, 'seller confirmation carries a revoke link');
  r = await call('post', '/api/consent/accept', { t: tok, agree: true, name: 'Sam Seller', address: b2.address, price: b2.price });
  assert.strictEqual(r.status, 410, 'single use');
  assert.strictEqual(r.body.error, 'used');

  // ── expiry + resend ──────────────────────────────────────────────────────
  const b3 = Object.assign({}, base, { address: '7 Third St, Worcester, MA', price: '450000' });
  r = await call('post', '/api/pm/listing', Object.assign({}, b3, { consent: { mode: 'seller_link', sellerName: 'Tia Seller', sellerEmail: 'tia@seller.test' } }), poster);
  const expId = r.body.id;
  const tok3 = linkFrom(lastTo('tia@seller.test').html, 't');
  store.pm_consent_links.find(k => k.listingId === expId).expiresAt = new Date(Date.now() - 1000).toISOString();
  r = await call('get', '/api/consent/info', {}, null, { query: { t: tok3 } });
  assert.strictEqual(r.body.error, 'expired');
  r = await call('post', '/api/pm/listing/consent/resend', { id: expId }, other);
  assert.strictEqual(r.status, 403, 'only the poster/admin can resend');
  r = await call('post', '/api/pm/listing/consent/resend', { id: expId }, poster);
  assert.ok(r.body.ok && r.body.sentTo === 'tia@seller.test', JSON.stringify(r.body));
  const tok3b = linkFrom(lastTo('tia@seller.test').html, 't');
  assert.ok(tok3b && tok3b !== tok3);
  r = await call('get', '/api/consent/info', {}, null, { query: { t: tok3 } });
  assert.ok(['expired', 'superseded'].includes(r.body.error));
  r = await call('get', '/api/consent/info', {}, null, { query: { t: tok3b } });
  assert.ok(r.body.ok);
  r = await call('post', '/api/pm/listing/consent/resend', { id: linkId }, poster);
  assert.strictEqual(r.body.error, 'not_awaiting', 'no resend once live');

  // ── revocation by the seller's link ──────────────────────────────────────
  r = await call('get', '/api/consent/revoke-info', {}, null, { query: { r: rtok } });
  assert.ok(r.body.ok && !r.body.revokedAt && r.body.name === 'Sam Seller');
  r = await call('post', '/api/consent/revoke', { r: rtok });
  assert.ok(r.body.ok);
  assert.strictEqual(L(linkId).status, 'off');
  assert.ok(L(linkId).sellerRevokedAt);
  assert.ok(!(await feedIds(other)).includes(linkId), 'taken down');
  assert.ok(store.pm_consents.find(x => x.id === rec.id).revokedAt, 'revocation logged on the record');
  assert.ok(sent.some(e => e.to === poster.email && /revoked/.test(e.subject)));
  r = await call('post', '/api/pm/listing', Object.assign({}, b2, { id: linkId, status: 'active' }), poster);
  assert.strictEqual(r.body.error, 'seller_form_required', 'cannot relist without a new authorization');
  r = await call('post', '/api/pm/renew', { id: linkId }, poster);
  assert.strictEqual(r.body.error, 'seller_form_required');

  // ── 3. upload path still works and is recorded ───────────────────────────
  const b4 = Object.assign({}, base, { address: '9 Form Rd, Worcester, MA', price: '640000' });
  r = await call('post', '/api/pm/listing', Object.assign({}, b4, { sellerForm: { name: 'signed.pdf', url: PDF } }), poster);
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  const formId = r.body.id;
  assert.strictEqual(L(formId).status, 'active');
  assert.ok(store.pm_consents.some(x => x.listingId === formId && x.path === 'uploaded_form' && x.file === 'signed.pdf' && x.account === poster.email));
  // A price change on a form-authorized listing keeps it live (the form isn't a per-price consent).
  r = await call('post', '/api/pm/listing', Object.assign({}, b4, { id: formId, price: '650000' }), poster);
  assert.strictEqual(L(formId).status, 'active');

  // ── admin: log + revoke on the seller's request ──────────────────────────
  r = await call('get', '/api/pm/admin/consents', {}, other);
  assert.strictEqual(r.status, 403);
  r = await call('get', '/api/pm/admin/consents', {}, admin);
  assert.ok(r.body.ok && r.body.records.length >= 4 && r.body.links.length >= 3);
  assert.ok(!JSON.stringify(r.body).match(/"rth"|"th"/), 'token hashes never leave the server');
  assert.ok(new Set(r.body.records.map(x => x.path)).size === 3, 'all three paths in the log');
  r = await call('post', '/api/pm/admin/consent/revoke', { listingId: ownerId, note: 'Seller called 11/24' }, admin);
  assert.ok(r.body.ok, JSON.stringify(r.body));
  assert.strictEqual(L(ownerId).status, 'off');
  const rv = store.pm_consents.filter(x => x.listingId === ownerId && x.revokedAt);
  assert.ok(rv.length && rv[0].revokeVia === 'contacted_axess' && rv[0].revokeNote === 'Seller called 11/24' && rv[0].revokedBy === admin.email);
  const adminFeed = (await call('get', '/api/pm/feed', {}, admin)).body.listings.find(l => l.id === ownerId);
  assert.ok(adminFeed.authz && adminFeed.authz.revokedAt, 'admin deal view shows the revocation');

  // ── demo mode: owner consent + simulated seller link, isolated ───────────
  const seed = demo.seedData();
  store['demo:pm_profiles'] = seed.pm_profiles;
  const D2 = { email: demo.ACCOUNTS[1].email, role: 'member', status: 'approved' };
  const DC = { ok: true, as: D2.email };
  const realListings = store.pm_listings.length, realConsents = store.pm_consents.length;
  r = await call('post', '/api/pm/listing', Object.assign({}, base, { address: 'DEMO — 99 Example St (not real)', consent: { mode: 'owner', agree: true, name: 'Demo Agent 2' } }), D2, { demo: DC });
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  assert.strictEqual(store['demo:pm_listings'].find(l => l.id === r.body.id).status, 'active');
  r = await call('post', '/api/pm/listing', Object.assign({}, base, { address: 'DEMO — 98 Example St (not real)', consent: { mode: 'seller_link', sellerName: 'Demo Seller', sellerEmail: 'demo-seller@demo.axess.invalid' } }), D2, { demo: DC });
  assert.ok(r.body.awaiting && /^\/consent\?t=demo_/.test(r.body.demoLink), 'demo hands the poster the simulated seller link');
  const demoId = r.body.id, dtok = decodeURIComponent(r.body.demoLink.split('t=')[1]);
  assert.ok(sent.filter(e => e.to === 'demo-seller@demo.axess.invalid').every(e => e.demo), 'no real email in demo');
  // The seller page has no demo cookie: the token prefix alone routes it to the demo partition.
  r = await call('get', '/api/consent/info', {}, null, { query: { t: dtok } });
  assert.ok(r.body.ok && r.body.demo === true, JSON.stringify(r.body));
  r = await call('post', '/api/consent/accept', { t: dtok, agree: true, name: 'Demo Seller', address: 'DEMO — 98 Example St (not real)', price: base.price });
  assert.ok(r.body.ok && r.body.live, JSON.stringify(r.body));
  assert.strictEqual(store['demo:pm_listings'].find(l => l.id === demoId).status, 'active');
  assert.ok(store['demo:pm_consents'].length === 2, 'demo consents stay in the demo partition');
  assert.strictEqual(store.pm_listings.length, realListings, 'real listings untouched');
  assert.strictEqual(store.pm_consents.length, realConsents, 'real consent log untouched');
  // The demo placeholder form still works.
  r = await call('post', '/api/pm/listing', Object.assign({}, base, { address: 'DEMO — 97 Example St', sellerForm: demo.PLACEHOLDER_FORM }), D2, { demo: DC });
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  // Demo tokens are dead when demo mode is off.
  process.env.DEMO_MODE = 'off';
  r = await call('get', '/api/consent/info', {}, null, { query: { t: dtok } });
  assert.strictEqual(r.status, 404);
  process.env.DEMO_MODE = 'on';

  console.log('consent tests ok');
})().catch(e => { console.error(e); process.exit(1); });
