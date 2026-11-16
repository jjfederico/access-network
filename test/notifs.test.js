'use strict';
// Notifications are capped per member, not site-wide.
const assert = require('assert');
const { store, call } = require('./server-harness');

(async () => {
  const at = i => new Date(Date.UTC(2026, 10, 1) + i * 1000).toISOString();
  // A busy member with 500 alerts, a quiet member with 3 older ones.
  store.pm_notifs = [{ id: 'q1', to: 'quiet@x.co', text: 'q1', at: at(0), read: false }, { id: 'q2', to: 'quiet@x.co', text: 'q2', at: at(1), read: false }, { id: 'q3', to: 'quiet@x.co', text: 'q3', at: at(2), read: false }]
    .concat(Array.from({ length: 2500 }, (_, i) => ({ id: 'b' + i, to: 'busy@x.co', text: 'b' + i, at: at(10 + i), read: false })));
  store.pm_profiles = [{ email: 'lister@x.co', status: 'approved', brokerage: 'B', approvedAt: at(0) }, { email: 'quiet@x.co', status: 'approved', approvedAt: new Date().toISOString() }];
  store.pm_listings = [{ id: 'L1', owner: 'lister@x.co', status: 'active', dist: 'broad', city: 'Boston', area: 'Southie', price: '1', createdAt: at(0), expiresAt: new Date(Date.now() + 9e9).toISOString(), sellerForm: { name: 'f.pdf', url: 'data:application/pdf;base64,' + Buffer.from('%PDF-1.4 ' + 'x'.repeat(4000)).toString('base64') } }];
  // Any write path that appends a notification (an intro request) triggers the cap.
  const r = await call('post', '/api/pm/intro', { listingId: 'L1', confidential: true, buyerName: 'Quiet' }, { email: 'quiet@x.co', role: 'member', status: 'approved' });
  assert.ok(r.body.ok, 'intro sent');
  const ns = store.pm_notifs;
  assert.strictEqual(ns.filter(n => n.to === 'quiet@x.co').length, 3, 'quiet member keeps all 3 old alerts');
  assert.strictEqual(ns.filter(n => n.to === 'busy@x.co').length, 100, 'busy member capped at newest 100');
  assert.ok(ns.some(n => n.id === 'b2499') && !ns.some(n => n.id === 'b0'), 'newest kept, oldest dropped');
  assert.strictEqual(ns.filter(n => n.to === 'lister@x.co').length, 1, 'new alert delivered');
  console.log('notification tests ok');
})().catch(e => { console.error(e); process.exit(1); });
