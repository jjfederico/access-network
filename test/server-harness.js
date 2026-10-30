'use strict';
// Shared test harness: loads server.js with express, cookie-session, the
// database and auth/email replaced by in-memory stubs. No network, no
// database, no email; nothing here touches stored data anywhere. The stub
// store scopes keys with lib/demo exactly as db.js does, so demo-partition
// isolation is exercised for real.
const assert = require('assert');
const demo = require('../lib/demo');
const path = require('path');
const Module = require('module');

for (const k of ['DATABASE_URL', 'BASE_URL', 'TURNSTILE_SECRET', 'R2_ACCOUNT_ID', 'R2_BUCKET', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'STRIPE_SECRET_KEY', 'RESEND_API_KEY', 'ANTHROPIC_API_KEY']) delete process.env[k];
process.env.NODE_ENV = 'test';
if (!process.env.DEMO_MODE) process.env.DEMO_MODE = 'off';

// ── stubs ──────────────────────────────────────────────────────────────────
const routes = [];
const scoped = []; // app.use('/prefix', fn) guards
const mw = () => (req, res, next) => next && next();
function expressStub() {
  const app = {};
  ['get', 'post', 'put', 'delete', 'patch', 'all'].forEach(m => {
    app[m] = (p, ...h) => { if (typeof p === 'string' && h.length) routes.push({ m, p, h }); return app; };
  });
  app.use = (p, ...h) => { if (typeof p === 'string' && h.length) scoped.push({ p, h }); return app; }; app.set = () => app; app.enable = () => app; app.disable = () => app;
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
  pmLoad: async k => clone(store[demo.scopedKey(k)] || []),
  pmSave: async (k, v) => { store[demo.scopedKey(k)] = clone(v); return true; },
  pmMutate: async (k, fn) => { k = demo.scopedKey(k); const cur = clone(store[k] || []); const out = (await fn(cur)) || {}; store[k] = clone(out.save !== undefined ? out.save : cur); return out.result; },
  importAll: async () => { throw new Error('import must not run in tests'); },
  health: async () => ({ ok: true })
};
const sent = [];
const outbound = [];
const authStub = {
  mount() {}, attachUser: mw, ensureAuth: (req, res, next) => next(),
  userFor: async () => null, profileFor: async () => null,
  sendEmail: async (to, subject) => { sent.push({ to, subject, demo: demo.active() }); return true; },
  sendMagicLink: async () => true,
  emailShell: h => h, emailBtn: () => '', ADMIN: '', ADMINS: [], lc: s => String(s || '').toLowerCase()
};
const root = path.join(__dirname, '..');
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'express') return expressStub;
  if (request === 'cookie-session') return mw;
  if (parent && parent.filename === path.join(root, 'auth.js') && request === './db') return dbStub;
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

// opts.demo: run the handler inside the demo partition, as server.js does for a
// demo session (req.demo is the signed demo cookie payload).
function call(method, p, body, user, opts) {
  opts = opts || {};
  const reOf = pat => new RegExp('^' + pat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\?:([A-Za-z_]+)/g, '(?<$1>[^/]+)') + '$');
  const r = routes.find(x => x.m === method && reOf(x.p).test(p));
  assert.ok(r, 'route not registered: ' + method + ' ' + p);
  const params = (reOf(r.p).exec(p).groups) || {};
  const chain = [].concat(...scoped.filter(u => p === u.p || p.indexOf(u.p + '/') === 0).map(u => u.h), r.h);
  return new Promise((resolve, reject) => {
    const req = { method: method.toUpperCase(), path: p, body: body || {}, query: opts.query || {}, params, headers: {}, ip: '10.0.0.' + Math.floor(Math.random() * 250), user: user || null, session: {}, demo: opts.demo || null };
    const res = {
      statusCode: 200, headers: {},
      status(c) { this.statusCode = c; return this; },
      setHeader(k, v) { this.headers[k] = v; },
      json(o) { resolve({ status: this.statusCode, body: o, headers: this.headers }); return this; },
      send(o) { resolve({ status: this.statusCode, body: o, headers: this.headers }); return this; },
      redirect(c, u) { resolve({ status: typeof c === 'number' ? c : 302, body: u || c, headers: this.headers }); },
      type() { return this; }, append(k, v) { (this.headers[k] = this.headers[k] || []).push(v); }, sendFile(f) { resolve({ status: this.statusCode, body: f }); }
    };
    let i = 0;
    const next = err => {
      if (err) return reject(err);
      const h = chain[i++];
      if (!h) return reject(new Error('handler chain ended without a response'));
      Promise.resolve(h(req, res, next)).catch(reject);
    };
    if (opts.demo) demo.run(() => next()); else next();
  });
}
// Real Stripe/AI/Turnstile calls would go through global fetch: record any.
global.fetch = async (u) => { outbound.push(String(u)); throw new Error('network disabled in tests'); };

module.exports = { routes, store, sent, outbound, call, demo };

