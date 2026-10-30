'use strict';
// Route-level regression tests for sign-up admission logging and seller
// authorization, run against the stubbed server (see server-harness.js).
const assert = require('assert');
const { store, call } = require('./server-harness');

const PDF = 'data:application/pdf;base64,' + Buffer.from('%PDF-1.4 seller-signed authorization ' + 'x'.repeat(4000)).toString('base64');
const member = { email: 'agent@example.com', role: 'member', status: 'approved' };

(async () => {
  // ── sign-up: every application is logged, incomplete is not a denial ──────
  const base = { name: 'Pat Agent', email: 'pat@example.com', phone: '555-0100', brokerage: 'Example Realty' };

  let r = await call('post', '/api/pm/request', Object.assign({}, base, { license: 'n/a-xx', attest: true }));
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.body.error, 'bad_license');
  let log = store.pm_admissions || [];
  assert.strictEqual(log.length, 1, 'a bad-license application is recorded');
  assert.strictEqual(log[0].decision, 'incomplete');
  assert.strictEqual(log[0].cause, '', 'incomplete is not a denial and carries no cause');
  assert.strictEqual(log[0].criteria.maLicense, false);
  assert.strictEqual(log[0].licenseVerification.result, 'format_invalid');
  assert.strictEqual(log[0].applicant.email, 'pat@example.com');
  assert.ok(log[0].at && log[0].missing.length === 1);
  assert.ok(!(store.pm_profiles || []).length, 'no profile is created for an incomplete application');

  r = await call('post', '/api/pm/request', Object.assign({}, base, { license: '123456', attest: false }));
  assert.strictEqual(r.status, 400);
  assert.strictEqual(r.body.error, 'attest_required');
  log = store.pm_admissions;
  assert.strictEqual(log.length, 2);
  assert.strictEqual(log[1].decision, 'incomplete');
  assert.strictEqual(log[1].criteria.termsAccepted, false);

  r = await call('post', '/api/pm/request', Object.assign({}, base, { license: '123456', attest: true }));
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  log = store.pm_admissions;
  assert.strictEqual(log.length, 3);
  assert.strictEqual(log[2].decision, 'admit', 'a complete application meeting the criteria is admitted');
  assert.strictEqual(log[2].decidedBy, 'automatic');
  assert.strictEqual(store.pm_profiles[0].status, 'approved');

  // ── seller authorization on the listing write path ───────────────────────
  store.pm_profiles.push({ email: member.email, name: 'Lee', brokerage: 'Example Realty', license: '654321', status: 'approved' });
  const listing = { city: 'Worcester', area: 'Main South', price: '750000', propType: 'Multifamily', notes: 'Six units.' };

  r = await call('post', '/api/pm/listing', listing, member);
  assert.strictEqual(r.body.error, 'seller_form_required', 'no form → cannot go live');
  assert.ok(!(store.pm_listings || []).length);

  for (const bad of [
    { name: 'form.pdf', url: 'https://example.com/anything.pdf' },  // arbitrary link, not an upload
    { name: 'form.pdf', key: '!!!' },                                // sanitizes to nothing
    { name: 'form.pdf', key: '../../etc/passwd' },                   // not an upload key
    { name: '', url: PDF },                                          // no file name
    { name: 'form.pdf', url: 'javascript:alert(1)' }
  ]) {
    r = await call('post', '/api/pm/listing', Object.assign({}, listing, { sellerForm: bad }), member);
    assert.strictEqual(r.status, 400, 'bad form must be refused: ' + JSON.stringify(bad).slice(0, 80));
    assert.strictEqual(r.body.error, 'seller_form_invalid');
    assert.ok(!(store.pm_listings || []).length, 'nothing is saved with an unusable form');
  }

  r = await call('post', '/api/pm/listing', Object.assign({}, listing, { sellerForm: { name: 'signed.pdf', url: PDF } }), member);
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  assert.strictEqual(store.pm_listings.length, 1);
  assert.strictEqual(store.pm_listings[0].sellerForm.url, PDF, 'inline form is stored whole, not truncated');
  assert.ok(PDF.length > 900);

  r = await call('post', '/api/pm/listing', Object.assign({}, listing, { status: 'off', sellerForm: { name: 'signed.pdf', key: 'u/0123456789/lzx9abc.pdf' } }), member);
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  const offId = r.body.id;
  const off = store.pm_listings.find(l => l.id === offId);
  assert.strictEqual(off.status, 'off');
  assert.strictEqual(off.sellerForm.key, 'u/0123456789/lzx9abc.pdf', 'a form uploaded with an off-market draft is kept');

  // Editing a live listing without sending a form keeps the form on file.
  const liveId = store.pm_listings[0].id;
  r = await call('post', '/api/pm/listing', Object.assign({}, listing, { id: liveId, notes: 'Six units, updated.' }), member);
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  assert.strictEqual(store.pm_listings.find(l => l.id === liveId).sellerForm.url, PDF);

  // A legacy listing without a form cannot be switched live by an edit.
  store.pm_listings.push({ id: 'Llegacy', owner: member.email, status: 'off', city: 'Lowell', price: '500000', brokerage: 'Example Realty' });
  r = await call('post', '/api/pm/listing', Object.assign({}, listing, { id: 'Llegacy', status: 'active' }), member);
  assert.strictEqual(r.body.error, 'seller_form_required');
  assert.strictEqual(store.pm_listings.find(l => l.id === 'Llegacy').status, 'off');

  // The feed shows only authorized listings to other members.
  r = await call('get', '/api/pm/feed', {}, { email: 'other@example.com', role: 'member', status: 'approved' });
  assert.strictEqual(r.status, 200, JSON.stringify(r.body).slice(0, 200));
  const ids = (r.body.listings || []).map(l => l.id);
  assert.ok(ids.indexOf('Llegacy') < 0, 'unauthorized listing is not in the feed');

  console.log('route tests ok');
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
