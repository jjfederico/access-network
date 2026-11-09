'use strict';
// New members browse the full feed during their first 21 days; after that,
// members who have never posted a listing or client need see totals only.
const assert = require('assert');
const { store, call } = require('./server-harness');

const PDF = 'data:application/pdf;base64,' + Buffer.from('%PDF-1.4 seller-signed authorization ' + 'x'.repeat(4000)).toString('base64');
const day = 864e5, iso = ms => new Date(ms).toISOString();
const user = email => ({ email, role: 'member', status: 'approved' });

(async () => {
  store.pm_profiles = [
    { email: 'lister@example.com', status: 'approved', approvedAt: iso(Date.now() - 90 * day) },
    { email: 'new@example.com', status: 'approved', approvedAt: iso(Date.now() - 2 * day) },
    { email: 'old@example.com', status: 'approved', approvedAt: iso(Date.now() - 30 * day) },
    { email: 'poster@example.com', status: 'approved', approvedAt: iso(Date.now() - 30 * day) }
  ];
  store.pm_listings = [
    { id: 'L1', owner: 'lister@example.com', status: 'active', dist: 'broad', city: 'Boston', price: '900000', createdAt: iso(Date.now() - day), updatedAt: iso(Date.now() - day), expiresAt: iso(Date.now() + 60 * day), sellerForm: { name: 'f.pdf', url: PDF } },
    { id: 'L2', owner: 'poster@example.com', status: 'active', dist: 'broad', city: 'Quincy', price: '700000', createdAt: iso(Date.now() - day), updatedAt: iso(Date.now() - day), expiresAt: iso(Date.now() + 60 * day), sellerForm: { name: 'f.pdf', url: PDF } }
  ];

  let r = await call('get', '/api/pm/feed', {}, user('new@example.com'));
  assert.strictEqual(r.body.gated, undefined, 'a member in their first 21 days is not gated');
  assert.strictEqual(r.body.listings.length, 2, 'and sees the full feed');
  assert.strictEqual(r.body.me.reciprocity.inGrace, true);

  r = await call('get', '/api/pm/feed', {}, user('old@example.com'));
  assert.strictEqual(r.body.gated, true, 'past 21 days without posting → totals only');
  assert.strictEqual(r.body.listings.length, 0);
  assert.strictEqual(r.body.gatedCount, 2);

  r = await call('get', '/api/pm/feed', {}, user('poster@example.com'));
  assert.ok(!r.body.gated && r.body.listings.length === 2, 'a member who has posted is unaffected');

  console.log('grace tests ok');
})().catch(e => { console.error(e); process.exit(1); });
