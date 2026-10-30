'use strict';
// Cost guards: paid AI is off unless AI_FEATURES=on and is refused before any
// provider call; email and uploads have hard daily caps. Runs the stubbed
// server (server-harness.js): no network, no database, no email.
const assert = require('assert');
delete process.env.AI_FEATURES;
const { store, outbound, call, demo } = require('./server-harness');
process.env.ANTHROPIC_API_KEY = 'test-not-a-key'; // present, so only the switch can stop the call
const costguard = require('../lib/costguard');

const member = { email: 'agent@example.com', role: 'member', status: 'approved', name: 'Pat' };
const quiet = async fn => { const l = console.log, e = console.error; console.log = () => {}; console.error = () => {}; try { return await fn(); } finally { console.log = l; console.error = e; } };
const AI_CALLS = [
  ['/api/pm/extract', { data: Buffer.from('Unit,Rent\n1,2000').toString('base64'), mime: 'text/csv' }],
  ['/api/pm/ai/describe', { propType: 'Multifamily', area: 'Worcester', price: '900000' }],
  ['/api/pm/ai/intro', { listingId: 'L1' }]
];

(async () => {
  store.pm_profiles = [{ email: member.email, name: 'Pat', brokerage: 'Example Realty', license: '123456', status: 'approved' }];
  store.pm_listings = [{ id: 'L1', owner: 'other@example.com', status: 'active', propType: 'Multifamily', area: 'Worcester', price: '900000', sellerForm: { name: 'f.pdf', url: 'data:application/pdf;base64,JVBERg==' } }];

  // ── switch helper ─────────────────────────────────────────────────────────
  for (const v of [undefined, '', 'off', '0', 'false', 'maybe']) { if (v === undefined) delete process.env.AI_FEATURES; else process.env.AI_FEATURES = v; assert.strictEqual(costguard.aiEnabled(), false, String(v)); }
  for (const v of ['on', 'ON', '1', 'true', 'yes']) { process.env.AI_FEATURES = v; assert.strictEqual(costguard.aiEnabled(), true, v); }
  delete process.env.AI_FEATURES;

  // ── AI off by default: refused before quota or provider ──────────────────
  for (const ctx of [null, { ok: true, admin: false, as: member.email }]) {
    for (const [p, body] of AI_CALLS) {
      const n0 = outbound.length;
      const r = await call('post', p, body, member, ctx ? { demo: ctx } : {});
      assert.strictEqual(r.status, 503, p);
      assert.strictEqual(r.body.error, 'ai_paused', p);
      assert.ok(/paused/i.test(r.body.message), p);
      assert.strictEqual(outbound.length, n0, p + ' made no provider call' + (ctx ? ' (demo)' : ''));
    }
  }
  assert.ok(!(store.pm_ai_usage || []).length && !(store['demo:pm_ai_usage'] || []).length, 'no AI quota consumed while paused');

  // The member app is told AI is off, so it can show the Paused state.
  let r = await call('get', '/premarket-hub.html', {}, member);
  assert.ok(/window\.__AI__=false/.test(r.body), 'app gets __AI__=false');
  assert.ok(/AI · Paused/.test(r.body) && /function applyAIPaused/.test(r.body), 'app has the Paused UI');

  // ── switching it on restores the calls ───────────────────────────────────
  process.env.AI_FEATURES = 'on';
  for (const [p, body] of AI_CALLS) {
    const n0 = outbound.length;
    r = await quiet(() => call('post', p, body, member));
    assert.notStrictEqual(r.body.error, 'ai_paused', p);
    assert.strictEqual(outbound.length, n0 + 1, p + ' reaches the provider when on');
    assert.ok(/api\.anthropic\.com/.test(outbound[n0]), p);
  }
  r = await call('get', '/premarket-hub.html', {}, member);
  assert.ok(/window\.__AI__=true/.test(r.body));
  // A failed provider call refunds the quota unit.
  const u = (store.pm_ai_usage || [])[0] || {};
  assert.strictEqual(u.total || 0, 0, 'quota refunded on provider failure');
  delete process.env.AI_FEATURES;

  // ── email: hard daily cap; sign-in links exempt ──────────────────────────
  process.env.EMAIL_DAILY_CAP = '2';
  process.env.RESEND_API_KEY = 'test-not-a-key';
  costguard.reset();
  const auth = require('../auth');
  const n0 = outbound.length;
  await quiet(async () => {
    await auth.sendEmail('a@example.com', 'alert 1', '<p>x</p>');
    await auth.sendEmail('a@example.com', 'alert 2', '<p>x</p>');
  });
  assert.strictEqual(outbound.length, n0 + 2);
  const capped = await quiet(() => auth.sendEmail('a@example.com', 'alert 3', '<p>x</p>'));
  assert.strictEqual(capped, false, 'over the cap → not sent, reported as false');
  assert.strictEqual(outbound.length, n0 + 2, 'no provider call over the cap');
  await quiet(() => auth.sendEmail('a@example.com', 'Your AXESS sign-in link', '<p>x</p>', { essential: true }));
  assert.strictEqual(outbound.length, n0 + 3, 'sign-in links are never capped');
  await quiet(() => auth.sendMagicLink('new@example.com', 'https://example.test'));
  assert.strictEqual(outbound.length, n0 + 4, 'sign-up magic link still sends at the cap');
  assert.ok(costguard.emailTake(Date.parse('2026-11-02T00:00:01Z')), 'cap resets on a new UTC day');
  delete process.env.EMAIL_DAILY_CAP; delete process.env.RESEND_API_KEY;

  // ── uploads: hard daily caps ─────────────────────────────────────────────
  costguard.reset();
  process.env.UPLOAD_DAILY_FILES_PER_MEMBER = '2';
  const img = { data: Buffer.from('fake-png-bytes').toString('base64'), mime: 'image/png', name: 'p.png' };
  for (let i = 0; i < 2; i++) { r = await call('post', '/api/pm/upload', img, member); assert.ok(r.body.ok, JSON.stringify(r.body)); }
  r = await quiet(() => call('post', '/api/pm/upload', img, member));
  assert.strictEqual(r.status, 429);
  assert.strictEqual(r.body.error, 'upload_cap');
  r = await call('post', '/api/pm/upload', img, { email: 'second@example.com', role: 'member', status: 'approved' });
  assert.ok(r.body.ok, 'cap is per member');
  delete process.env.UPLOAD_DAILY_FILES_PER_MEMBER;
  process.env.UPLOAD_DAILY_MB_TOTAL = '0';
  costguard.reset();
  r = await quiet(() => call('post', '/api/pm/upload', img, member));
  assert.strictEqual(r.body.error, 'upload_cap', 'network-wide byte cap');
  delete process.env.UPLOAD_DAILY_MB_TOTAL;
  costguard.reset();
  assert.deepStrictEqual(costguard.uploadLimits(), { filesPerMember: 150, mbPerMember: 750, mbTotal: 5000 });
  assert.strictEqual(costguard.emailDailyCap(), 300);
  assert.ok(demo);

  console.log('cost tests ok');
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
