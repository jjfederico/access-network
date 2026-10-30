'use strict';
// Demo mode: gates, seed fixtures, partition isolation, no email, no Stripe.
// Runs the stubbed server (server-harness.js): in-memory store, no network,
// no database, no email. Seed data only ever lands in `demo:` keys here.
const assert = require('assert');
process.env.DEMO_MODE = 'on';
process.env.DEMO_ACCESS_CODE = 'test-demo-code-0001';
const { store, sent, outbound, call, demo } = require('./server-harness');
const c = require('../lib/compliance');

// ── seed fixtures (pure) ────────────────────────────────────────────────────
const seed = demo.seedData(Date.UTC(2026, 9, 30));
assert.strictEqual(seed.pm_profiles.length, 5);
seed.pm_profiles.forEach((p, i) => {
  assert.strictEqual(p.name, 'Demo Agent ' + (i + 1));
  assert.strictEqual(p.brokerage, 'Demo Brokerage ' + (i + 1));
  assert.strictEqual(p.is_demo, true);
  assert.ok(demo.isDemoEmail(p.email) && /\.invalid$/.test(p.email), 'undeliverable demo email');
  assert.strictEqual(p.marketingOptIn, false);
});
assert.strictEqual(new Set(seed.pm_profiles.map(p => p.markets)).size, 5, 'each account has its own market');
assert.deepStrictEqual([...new Set(seed.pm_profiles.map(p => p.focus))].sort(), ['both', 'commercial', 'residential']);
assert.strictEqual(seed.pm_listings.length, 6);
assert.strictEqual(new Set(seed.pm_listings.map(l => l.owner)).size, 5, 'listings spread across all five accounts');
seed.pm_listings.forEach(l => {
  assert.strictEqual(l.is_demo, true);
  assert.ok(/^DEMO/.test(l.id) && /DEMO/.test(l.area) && /DEMO/.test(l.notes) && /DEMO/.test(l.address), 'listing labeled DEMO: ' + l.id);
  assert.ok(c.listingAuthorized(l) && c.cleanSellerForm(l.sellerForm), 'demo placeholder seller form is valid');
});
assert.strictEqual(seed.pm_buyboxes.length, 3);
seed.pm_buyboxes.forEach(b => assert.ok(b.is_demo === true && /DEMO CLIENT NEED/.test(b.notes)));

// ── gating / routing (pure) ─────────────────────────────────────────────────
for (const p of ['/', '/index.html', '/membership', '/terms', '/privacy', '/demo.html', '/api/pm/stats', '/api/pm/teaser', '/api/pm/request', '/api/pm/stripe/webhook', '/api/pm/cron', '/api/pm/digest/run', '/auth/email', '/login'])
  assert.strictEqual(demo.pathInDemo(p), false, p + ' must always run on real data');
for (const p of ['/app.html', '/api/me', '/api/pm/feed', '/api/pm/listing', '/api/demo/reset']) assert.strictEqual(demo.pathInDemo(p), true, p);
assert.strictEqual(demo.scopedKey('pm_listings'), 'pm_listings');
demo.run(() => assert.strictEqual(demo.scopedKey('pm_listings'), 'demo:pm_listings'));
assert.ok(demo.codeOk('test-demo-code-0001') && !demo.codeOk('test-demo-code-0002') && !demo.codeOk(''));
{ const save = process.env.DEMO_ACCESS_CODE; process.env.DEMO_ACCESS_CODE = ''; assert.ok(!demo.codeOk(''), 'no code configured → code gate closed'); process.env.DEMO_ACCESS_CODE = save; }
for (const v of ['off', 'OFF', '0', 'false', 'no']) { process.env.DEMO_MODE = v; assert.strictEqual(demo.enabled(), false, v); }
process.env.DEMO_MODE = 'on';
// Signed cookie: round-trips, rejects tampering.
{
  const res = { h: [], append(k, v) { this.h.push(v); } };
  demo.writeCookie(res, { admin: false, as: 'demo-agent-2@demo.axess.invalid' }, false);
  const cookie = res.h[0].split(';')[0];
  assert.strictEqual(demo.readCookie({ headers: { cookie } }).as, 'demo-agent-2@demo.axess.invalid');
  const val = decodeURIComponent(cookie.split('=')[1]); const body = val.slice(0, val.lastIndexOf('.'));
  const forged = Buffer.from(JSON.stringify({ ok: true, admin: true, as: '', exp: Date.now() + 1e7 })).toString('base64url') + val.slice(val.lastIndexOf('.'));
  assert.ok(body.length > 0);
  assert.strictEqual(demo.readCookie({ headers: { cookie: 'axess_demo=' + encodeURIComponent(forged) } }), null, 'forged demo cookie rejected');
}

const D = n => ({ email: 'demo-agent-' + n + '@demo.axess.invalid', role: 'member', status: 'approved' });
const DC = (n, admin) => ({ ok: true, admin: !!admin, as: n ? D(n).email : '' });
const ADMIN_USER = { email: 'owner@example.com', role: 'owner', status: 'approved' };
const notFound = p => p.then(r => assert.fail('expected the route to fall through (404), got ' + r.status), e => assert.ok(/ended without a response/.test(e.message), e.message));

(async () => {
  // Real data that must never show up in demo, and vice versa.
  const PDF = 'data:application/pdf;base64,' + Buffer.from('%PDF-1.4 real').toString('base64');
  store.pm_profiles = [
    { email: 'real1@example.com', name: 'Real One', brokerage: 'Real Realty', license: '111111', status: 'approved', foundingRate: true },
    { email: 'real2@example.com', name: 'Real Two', brokerage: 'Real Realty', license: '222222', status: 'approved', foundingRate: true }
  ];
  store.pm_listings = [{ id: 'Lreal', owner: 'real1@example.com', status: 'active', city: 'Worcester', area: 'Main South', propType: 'Multifamily', price: '900000', dist: 'broad', sellerForm: { name: 'f.pdf', url: PDF }, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 864e6).toISOString() }];
  store.pm_buyboxes = [{ id: 'Breal', owner: 'real2@example.com', markets: 'Worcester', propType: 'Multifamily', priceBand: '500k_1m', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }];
  const realBefore = JSON.stringify({ p: store.pm_profiles, l: store.pm_listings });

  // ── gate: no admin, no code → demo mode does not exist ───────────────────
  await notFound(call('get', '/demo-mode', {}, null));
  await notFound(call('get', '/demo-mode', {}, { email: 'real1@example.com', role: 'member', status: 'approved' }));
  await notFound(call('get', '/demo-mode', {}, null, { query: { code: 'wrong' } }));
  let r = await call('post', '/api/demo/signin', { n: 1 }, null);
  assert.strictEqual(r.status, 404, '/api/demo/* is 404 without a demo session');
  process.env.DEMO_MODE = 'off';
  await notFound(call('get', '/demo-mode', {}, ADMIN_USER));
  await notFound(call('get', '/demo-mode', {}, null, { query: { code: 'test-demo-code-0001' } }));
  process.env.DEMO_MODE = 'on';
  assert.ok(!Object.keys(store).some(k => k.indexOf('demo:') === 0), 'nothing seeded before the gate opens');

  // Code gate → sets the demo cookie and redirects to strip the code from the URL.
  r = await call('get', '/demo-mode', {}, null, { query: { code: 'test-demo-code-0001' } });
  assert.strictEqual(r.status, 302);
  // Admin gate → picker with Reset; seeds the demo partition only.
  r = await call('get', '/demo-mode', {}, ADMIN_USER);
  assert.strictEqual(r.status, 200);
  assert.ok(/Reset demo data/.test(r.body) && /noindex/.test(r.body) && /Demo Agent 5/.test(r.body));
  assert.strictEqual(store['demo:pm_profiles'].length, 5);
  assert.strictEqual(store['demo:pm_listings'].length, 6);
  assert.strictEqual(store['demo:pm_buyboxes'].length, 3);
  assert.strictEqual(JSON.stringify({ p: store.pm_profiles, l: store.pm_listings }), realBefore, 'real data untouched by seeding');
  // Code (non-admin) users get no Reset button.
  r = await call('get', '/demo-mode', {}, null, { demo: DC(0, false) });
  assert.ok(!/Reset demo data/.test(r.body));

  // ── isolation: demo feed shows only demo; real feed shows no demo ─────────
  r = await call('get', '/api/pm/feed', {}, D(1), { demo: DC(1) });
  assert.strictEqual(r.status, 200);
  let ids = r.body.listings.map(l => l.id);
  assert.ok(ids.length >= 5 && ids.every(id => /^DEMO-/.test(id)), 'demo feed is demo-only: ' + ids);
  r = await call('get', '/api/pm/feed', {}, { email: 'real2@example.com', role: 'member', status: 'approved' });
  ids = r.body.listings.map(l => l.id);
  assert.deepStrictEqual(ids, ['Lreal'], 'real feed has no demo listings');

  // ── full flow inside demo: post with placeholder form, need, intro, unlock, message
  const sentBefore = sent.length;
  r = await call('post', '/api/pm/listing', { city: 'Quincy', area: 'DEMO · Wollaston', price: '650000', propType: 'Condo', notes: 'DEMO test post', sellerForm: demo.PLACEHOLDER_FORM }, D(2), { demo: DC(2) });
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  assert.strictEqual(store['demo:pm_listings'].length, 7);
  assert.strictEqual(store.pm_listings.length, 1, 'demo post did not reach real listings');
  r = await call('post', '/api/pm/buybox', { markets: 'Cambridge', propType: 'Multifamily', priceBand: '2m_5m', notes: 'DEMO need' }, D(5), { demo: DC(5) });
  assert.ok(r.body.ok, JSON.stringify(r.body));
  assert.deepStrictEqual(store.pm_buyboxes.map(b => b.id), ['Breal'], 'demo need did not reach real needs');

  // Agent 1 requests an intro to Agent 3's private (address-hidden) listing.
  r = await call('get', '/api/pm/reveal/DEMO-L3', {}, D(1), { demo: DC(1) });
  assert.strictEqual(r.status, 403, 'address locked before approval');
  r = await call('post', '/api/pm/intro', { listingId: 'DEMO-L3', confidential: true, message: 'DEMO intro' }, D(1), { demo: DC(1) });
  assert.ok(r.body.ok, JSON.stringify(r.body));
  const intro = store['demo:pm_intros'].find(i => i.listingId === 'DEMO-L3');
  r = await call('post', '/api/pm/intro/decide', { introId: intro.id, decision: 'approved' }, D(3), { demo: DC(3) });
  assert.ok(r.body.ok, JSON.stringify(r.body));
  r = await call('get', '/api/pm/reveal/DEMO-L3', {}, D(1), { demo: DC(1) });
  assert.strictEqual(r.status, 200);
  assert.ok(/DEMO/.test(r.body.address), 'address unlocks after approval');
  r = await call('post', '/api/pm/message', { to: D(3).email, body: 'DEMO hello', listingId: 'DEMO-L3' }, D(1), { demo: DC(1) });
  assert.ok(r.body.ok, JSON.stringify(r.body));
  assert.ok(store['demo:pm_messages'].length >= 1 && !(store.pm_messages || []).length);
  // Every email attempted during the demo flow happened inside the demo context
  // (auth.sendEmail suppresses those; see the auth test below).
  assert.ok(sent.slice(sentBefore).every(m => m.demo === true), 'no email attempted outside the demo context');
  // A real member can't see any of it.
  r = await call('get', '/api/pm/listing/DEMO-L3', {}, { email: 'real2@example.com', role: 'member', status: 'approved' });
  assert.strictEqual(r.status, 404);

  // ── public counters / teaser never include demo ──────────────────────────
  r = await call('get', '/api/pm/stats', {}, null);
  assert.strictEqual(r.body.stats.members, 2, 'members = real approved only');
  assert.strictEqual(r.body.stats.liveDeals, 1);
  assert.strictEqual(r.body.stats.volume, 900000);
  assert.strictEqual(r.body.stats.foundingLeft, c.FOUNDING_CAP - 2, 'spots left moves with real founding members only');
  r = await call('get', '/api/pm/teaser', {}, null);
  assert.strictEqual(r.body.total, 1);
  assert.ok(r.body.deals.every(d => !/DEMO/.test(d.area)));

  // ── billing: refused in demo, no Stripe call ─────────────────────────────
  const outBefore = outbound.length;
  for (const [m, p] of [['post', '/api/pm/checkout'], ['post', '/api/pm/billing/portal'], ['post', '/api/pm/billing/resume'], ['get', '/api/pm/pay/confirm']]) {
    r = await call(m, p, {}, D(1), { demo: DC(1), query: { session_id: 'cs_test_x' } });
    assert.strictEqual(r.status, 403, p + ' refused in demo');
    assert.strictEqual(r.body.error, 'demo', p);
  }
  assert.strictEqual(outbound.length, outBefore, 'no outbound call from billing in demo');

  // ── switch / sign out / reset ─────────────────────────────────────────────
  r = await call('post', '/api/demo/signin', { n: 4 }, null, { demo: DC(1) });
  assert.ok(r.body.ok);
  const asCookie = demo.readCookie({ headers: { cookie: r.headers['Set-Cookie'][0].split(';')[0] } });
  assert.strictEqual(asCookie.as, D(4).email, 'account switch sets the demo session to the chosen account');
  r = await call('post', '/api/demo/signout', {}, null, { demo: DC(4) });
  assert.strictEqual(demo.readCookie({ headers: { cookie: r.headers['Set-Cookie'][0].split(';')[0] } }).as, '', 'demo sign-out returns to the picker');
  r = await call('get', '/api/pm/feed', {}, D(4), { demo: DC(4) });
  assert.ok(r.body.listings.some(l => /Wollaston/.test(l.submarket || l.area || '')) || store['demo:pm_listings'].length === 7, 'demo data persists across sign-out/in');
  r = await call('post', '/api/demo/reset', {}, D(1), { demo: DC(1, false) });
  assert.strictEqual(r.status, 403, 'reset is admin-only');
  r = await call('post', '/api/demo/reset', {}, D(1), { demo: DC(1, true) });
  assert.ok(r.body.ok);
  assert.strictEqual(store['demo:pm_listings'].length, 6, 'reset restores the seed');
  assert.ok(!store['demo:pm_intros'].length && !store['demo:pm_messages'].length);
  assert.strictEqual(JSON.stringify({ p: store.pm_profiles, l: store.pm_listings }), realBefore, 'real data untouched by reset');

  // ── the real email sender sends nothing in demo ──────────────────────────
  {
    process.env.RESEND_API_KEY = 'test-not-a-key';
    const realAuth = require('../auth');
    const _log = console.log, _err2 = console.error; console.log = () => {}; console.error = () => {};
    const n0 = outbound.length;
    await demo.run(() => realAuth.sendEmail('demo-agent-1@demo.axess.invalid', 'x', '<p>x</p>'));
    assert.strictEqual(outbound.length, n0, 'no email provider call in demo');
    await realAuth.sendEmail('real1@example.com', 'x', '<p>x</p>');
    assert.ok(outbound.length === n0 + 1 && /resend/.test(outbound[n0]), 'control: outside demo the provider is called');
    console.log = _log; console.error = _err2; delete process.env.RESEND_API_KEY;
  }

  // ── counters fail loudly, not as a silent "ok" ────────────────────────────
  const _err = console.error; console.error = () => {};
  Object.defineProperty(store, 'pm_listings', { configurable: true, get() { throw new Error('db down'); } });
  r = await call('get', '/api/pm/stats', {}, null);
  assert.ok(r.status === 503 && r.body.ok === false, 'stats error is reported');
  r = await call('get', '/api/pm/teaser', {}, null);
  assert.ok(r.status === 503 && r.body.ok === false, 'teaser error is reported (homepage keeps its labeled sample cards)');
  console.error = _err;

  console.log('demo tests ok');
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
