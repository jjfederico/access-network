'use strict';
// Listing reports, the daily license-check list, and the public sitemap.
const assert = require('assert');
const { store, call, sent } = require('./server-harness');

const PDF = 'data:application/pdf;base64,' + Buffer.from('%PDF-1.4 seller ' + 'x'.repeat(4000)).toString('base64');
const lister = { email: 'lister@x.co', role: 'member', status: 'approved' };
const member = { email: 'member@x.co', role: 'member', status: 'approved' };
const owner = { email: 'owner@x.co', role: 'owner', status: 'approved' };

(async () => {
  store.pm_profiles = [{ email: lister.email, status: 'approved', brokerage: 'B', verified: true }, { email: member.email, status: 'approved', name: 'Pat', license: '9012345', brokerage: 'Acme', approvedAt: '2026-11-10T00:00:00Z' }];
  store.pm_listings = [{ id: 'L1', owner: lister.email, status: 'active', dist: 'broad', city: 'Boston', area: 'Southie', propType: 'Condo', price: '900000', expiresAt: new Date(Date.now() + 9e9).toISOString(), sellerForm: { name: 'f.pdf', url: PDF } }];

  // ── reports ──
  let r = await call('post', '/api/pm/listing/report', { id: 'L1', reason: 'bogus' }, member);
  assert.strictEqual(r.body.error, 'bad_reason');
  r = await call('post', '/api/pm/listing/report', { id: 'L1', reason: 'stale' }, lister);
  assert.strictEqual(r.body.error, 'own_listing', 'cannot report your own listing');
  r = await call('post', '/api/pm/listing/report', { id: 'L1', reason: 'stale', note: 'Closed last week' }, member);
  assert.deepStrictEqual(r.body, { ok: true, already: false });
  r = await call('post', '/api/pm/listing/report', { id: 'L1', reason: 'stale' }, member);
  assert.strictEqual(r.body.already, true, 'duplicate open report is not stored twice');
  assert.strictEqual(store.pm_reports.length, 1);
  assert.strictEqual((await call('get', '/api/pm/admin/reports', {}, member)).status, 403, 'members cannot see the queue');
  const q = (await call('get', '/api/pm/admin/reports', {}, owner)).body;
  assert.strictEqual(q.open, 1);
  assert.strictEqual(q.reports[0].reasonLabel, 'Already sold, on the MLS, or no longer available');

  r = await call('post', '/api/pm/admin/report/resolve', { id: q.reports[0].id, action: 'withdraw', note: 'Confirmed closed' }, owner);
  assert.ok(r.body.ok);
  assert.strictEqual(store.pm_listings[0].status, 'off', 'listing withdrawn (not deleted)');
  assert.strictEqual(store.pm_reports[0].status, 'withdrawn');
  assert.ok(store.pm_notifs.some(n => n.to === lister.email && n.type === 'withdrawn'), 'lister notified in-app');
  assert.ok(sent.some(m => m.to === lister.email && /taken off the feed/.test(m.subject)), 'lister emailed');

  // ── license-check list: members endpoint reports unchecked count ──
  const m = (await call('get', '/api/pm/admin/members', {}, owner)).body;
  assert.strictEqual(m.unchecked, 1, 'one member (Pat) still needs a registry check');

  // ── sitemap / robots ──
  r = await call('get', '/sitemap.xml', {}, null);
  assert.ok(/<loc>[^<]*\/membership<\/loc>/.test(r.body) && !/app\.html/.test(r.body), 'sitemap lists public pages only');
  r = await call('get', '/robots.txt', {}, null);
  assert.ok(/Disallow: \/app\.html/.test(r.body) && /Sitemap: /.test(r.body));

  console.log('moderation tests ok');
})().catch(e => { console.error(e); process.exit(1); });
