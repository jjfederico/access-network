'use strict';
// Nov 15 / Nov 22 audit fixes: one member definition everywhere, sample data
// never live, calculator computes on load, region counts add up, one posting time.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { store, call } = require('./server-harness');
const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.html'), 'utf8');
const idx = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

(async () => {
  // 2. Counter, founding spots, directory agree; test/removed/sample accounts don't count.
  store.pm_profiles = [
    { email: 'a@x.co', status: 'approved', foundingRate: true },
    { email: 'b@x.co', status: 'approved', foundingRate: true },
    { email: 'test@x.co', status: 'approved', foundingRate: true, testAccount: true },
    { email: 'gone@x.co', status: 'approved', deactivated: true },
    { email: 'sample@x.co', status: 'approved', sample: true },
    { email: 'pending@x.co', status: 'pending' }
  ];
  const stats = (await call('get', '/api/pm/stats', {}, null)).body.stats;
  assert.strictEqual(stats.members, 2, 'homepage counts only real members');
  assert.strictEqual(stats.foundingLeft, 98);
  const dir = (await call('get', '/api/pm/directory', {}, { email: 'owner@x.co', role: 'owner', status: 'approved' })).body;
  assert.strictEqual(dir.count, stats.members, 'directory agrees with the homepage counter');
  let r = await call('post', '/api/pm/admin/test-account', { email: 'b@x.co', on: true }, { email: 'owner@x.co', role: 'owner', status: 'approved' });
  assert.ok(r.body.ok);
  assert.strictEqual((await call('get', '/api/pm/stats', {}, null)).body.stats.members, 1, 'marking a test account removes it from the count');
  assert.strictEqual((await call('post', '/api/pm/admin/test-account', { email: 'b@x.co' }, { email: 'm@x.co', role: 'member', status: 'approved' })).status, 403);

  // 1. Sample listings carry a flag and never count as live in the app.
  store.pm_listings = [{ id: 'S1', sample: true, owner: 'a@x.co', status: 'active', dist: 'broad', city: 'Boston', price: '9000000' }];
  const feed = (await call('get', '/api/pm/feed', {}, { email: 'owner@x.co', role: 'owner', status: 'approved' })).body;
  assert.strictEqual(feed.listings[0].sample, true, 'feed rows say which listings are sample data');
  assert.ok(/function isLiveDeal\(d\)\{return !!d&&!d\.sample/.test(app), 'isLiveDeal excludes sample data');
  assert.ok(/var live=LISTINGS\.filter\(isLiveDeal\)/.test(app), 'header totals use isLiveDeal');
  assert.ok(/feedVisible\(d\)&&isLiveDeal\(d\)/.test(app), 'Market Pulse charts use isLiveDeal');

  // 3. Calculator has a real starting value and computes on load.
  assert.ok(/id="mcPrice"[^>]*value="1,000,000"/.test(app));
  assert.ok(/DOMContentLoaded',function\(\)\{try\{mcCalc\(\);/.test(app));

  // 7. Cambridge has a region; a catch-all keeps region counts summing to the total.
  assert.ok(/name:'Cambridge & Inner Core',cities:\['cambridge'/.test(app));
  assert.ok(/\{k:'other',name:'Other MA',cities:null,other:true\}/.test(app));

  // 6. One posting time everywhere.
  for (const t of [app, idx]) assert.ok(!/30[ -]seconds?/.test(t), 'no "30 seconds" posting claim');

  // 8. Map uses the Maps Embed API when a key is set.
  assert.ok(/maps\/embed\/v1\/place\?key=/.test(app));

  console.log('audit nov22 tests ok');
})().catch(e => { console.error(e); process.exit(1); });
