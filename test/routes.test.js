'use strict';
// Route-level regression tests for sign-up admission logging and seller
// authorization. server.js is loaded with express, cookie-session, the
// database and auth/email replaced by in-memory stubs: no network, no
// database, no email. Nothing here touches stored data anywhere.
const assert = require('assert');
const path = require('path');
const Module = require('module');

for (const k of ['DATABASE_URL', 'BASE_URL', 'TURNSTILE_SECRET', 'R2_ACCOUNT_ID', 'R2_BUCKET', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'STRIPE_SECRET_KEY', 'RESEND_API_KEY', 'ANTHROPIC_API_KEY']) delete process.env[k];
process.env.NODE_ENV = 'test';
process.env.DEMO_MODE = 'off';

// ── stubs ──────────────────────────────────────────────────────────────────
const routes = [];
const mw = () => (req, res, next) => next && next();
function expressStub() {
  const app = {};
  ['get', 'post', 'put', 'delete', 'patch', 'all'].forEach(m => {
    app[m] = (p, ...h) => { if (typeof p === 'string' && h.length) routes.push({ m, p, h }); return app; };
  });
  app.use = () => app; app.set = () => app; app.enable = () => app; app.disable = () => app;
  app.listen = () => ({ close() {} });
  return app;
}
expressStub.json = mw; expressStub.urlencoded = mw; expressStub.static = mw; expressStub.raw = mw; expressStub.text = mw;
expressStub.Router = () => expressStub();

const store = {};
const clone = v => JSON.parse(JSON.stringify(v));
const dbStub = {
  pool: null, hasDb: true,
  ensureSchema: async () => true,
  pmLoad: async k => clone(store[k] || []),
  pmSave: async (k, v) => { store[k] = clone(v); return true; },
  pmMutate: async (k, fn) => { const cur = clone(store[k] || []); const out = (await fn(cur)) || {}; store[k] = clone(out.save !== undefined ? out.save : cur); return out.result; },
  importAll: async () => { throw new Error('import must not run in tests'); },
  health: async () => ({ ok: true })
};
const sent = [];
const authStub = {
  mount() {}, attachUser: mw, ensureAuth: (req, res, next) => next(),
  userFor: async () => null, profileFor: async () => null,
  sendEmail: async (to, subject) => { sent.push({ to, subject }); return true; },
  sendMagicLink: async () => true,
  emailShell: h => h, emailBtn: () => '', ADMIN: '', ADMINS: [], lc: s => String(s || '').toLowerCase()
};
const root = path.join(__dirname, '..');
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'express') return expressStub;
  if (request === 'cookie-session') return mw;
  if (parent && parent.filename === path.join(root, 'server.js')) {
    if (request === './db') return dbStub;
    if (request === './auth') return authStub;
  }
  return origLoad.apply(this, arguments);
};
// Keep server timers from holding the process open.
const _si = global.setInterval, _st = global.setTimeout;
global.setInterval = (...a) => { const t = _si(...a); if (t.unref) t.unref(); return t; };
global.setTimeout = (...a) => { const t = _st(...a); if (t.unref) t.unref(); return t; };
require(path.join(root, 'server.js'));
global.setInterval = _si; global.setTimeout = _st;

function call(method, p, body, user) {
  const r = routes.find(x => x.m === method && x.p === p);
  assert.ok(r, 'route not registered: ' + method + ' ' + p);
  return new Promise((resolve, reject) => {
    const req = { method: method.toUpperCase(), path: p, body: body || {}, query: {}, headers: {}, ip: '10.0.0.' + Math.floor(Math.random() * 250), user: user || null, session: {} };
    const res = {
      statusCode: 200, headers: {},
      status(c) { this.statusCode = c; return this; },
      setHeader(k, v) { this.headers[k] = v; },
      json(o) { resolve({ status: this.statusCode, body: o }); return this; },
      send(o) { resolve({ status: this.statusCode, body: o }); return this; },
      redirect(c, u) { resolve({ status: typeof c === 'number' ? c : 302, body: u || c }); }
    };
    let i = 0;
    const next = err => {
      if (err) return reject(err);
      const h = r.h[i++];
      if (!h) return reject(new Error('handler chain ended without a response'));
      Promise.resolve(h(req, res, next)).catch(reject);
    };
    next();
  });
}

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
