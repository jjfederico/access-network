'use strict';
// Walk-through findings (Nov 8): client needs can be deleted, and the app has
// no native confirm()/prompt() dialogs (they fail on phones and in automation).
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { store, call } = require('./server-harness');

const me = { email: 'agent@example.com', role: 'member', status: 'approved' };
const other = { email: 'other@example.com', role: 'member', status: 'approved' };

(async () => {
  store.pm_profiles = [{ email: me.email, status: 'approved', approvedAt: new Date().toISOString() }, { email: other.email, status: 'approved' }];
  let r = await call('post', '/api/pm/buybox', { markets: 'Quincy', propType: 'Multifamily', priceBand: '1m_2m', notes: 'Investor, 4-8 units' }, me);
  assert.ok(r.body.ok, 'need posted');
  r = await call('post', '/api/pm/buybox', { markets: 'Boston', priceBand: '500k_1m' }, other);
  assert.ok(r.body.ok);
  assert.strictEqual((await call('get', '/api/pm/needs', {}, other)).body.needs.length, 2);

  r = await call('post', '/api/pm/buybox/delete', {}, me);
  assert.deepStrictEqual(r.body, { ok: true, removed: 1 });
  assert.strictEqual((await call('get', '/api/pm/buybox', {}, me)).body.buybox, null, 'my need is gone');
  const board = (await call('get', '/api/pm/needs', {}, other)).body.needs;
  assert.strictEqual(board.length, 1, 'removed from the needs board; others untouched');
  assert.ok(store.pm_buyboxes.every(b => b.owner !== me.email), 'nothing left to match or alert on');
  assert.strictEqual((await call('post', '/api/pm/buybox/delete', {}, me)).body.removed, 0, 'deleting again is harmless');

  const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.html'), 'utf8');
  assert.ok(!/(^|[^.\w])(alert|confirm|prompt)\(/.test(app), 'no native alert()/confirm()/prompt() in the members app');

  console.log('walkthrough tests ok');
})().catch(e => { console.error(e); process.exit(1); });
