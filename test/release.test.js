'use strict';
// Pre-release hardening: fair-housing language is refused on listings and
// client needs; sign-up form fields have labels for screen readers.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { store, call } = require('./server-harness');

const PDF = 'data:application/pdf;base64,' + Buffer.from('%PDF-1.4 seller-signed authorization ' + 'x'.repeat(4000)).toString('base64');
const me = { email: 'agent@example.com', role: 'member', status: 'approved' };

(async () => {
  store.pm_profiles = [{ email: me.email, status: 'approved', brokerage: 'Example Realty', approvedAt: new Date().toISOString() }];
  const listing = notes => ({ city: 'Boston', area: 'South Boston', propType: 'Multifamily', price: '1000000', state: 'MA', dist: 'broad', notes, sellerForm: { name: 'f.pdf', url: PDF } });

  let r = await call('post', '/api/pm/listing', listing('Three-family, no Section 8, great for a young couple.'), me);
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.body.error, 'fair_housing_language');
  assert.ok(/protected class/.test(r.body.message) && /no Section 8/i.test(r.body.message), 'message names the phrase');
  assert.ok(!(store.pm_listings || []).length, 'nothing saved');

  r = await call('post', '/api/pm/listing', listing('Three-family near the Red Line, Section 8 tenant in place.'), me);
  assert.ok(r.body.ok, 'ordinary description posts');

  r = await call('post', '/api/pm/buybox', { markets: 'Quincy', priceBand: '1m_2m', notes: 'Buyer wants adults only building' }, me);
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.body.error, 'fair_housing_language');
  r = await call('post', '/api/pm/buybox', { markets: 'Quincy', priceBand: '1m_2m', notes: 'Investor, 4-8 units' }, me);
  assert.ok(r.body.ok);

  const idx = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  for (const id of ['qName', 'qEmail', 'qPhone', 'qLicense', 'qBrokerage', 'qMarkets', 'qFocus'])
    assert.ok(idx.indexOf('<label for="' + id + '"') >= 0, 'sign-up field has a label: ' + id);

  const srv = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');
  assert.ok(!/error: String\(e/.test(srv), 'no raw error text is sent to the browser');

  console.log('release tests ok');
})().catch(e => { console.error(e); process.exit(1); });
