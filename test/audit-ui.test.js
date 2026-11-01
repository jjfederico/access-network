'use strict';
// Regression tests for the Nov 1 weekly audit fixes: demo banner link, modal
// field sizing, marketing opt-in default, "Browse the feed" target, sample
// labels on /demo.html, and the demo filter count line / empty state.
// Pure checks plus the stubbed server (server-harness.js): no browser, no
// network, no database, no email.
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const pub = f => fs.readFileSync(path.join(__dirname, '..', 'public', f), 'utf8');
const index = pub('index.html');
const demoHtml = pub('demo.html');

// 1. Demo banner "Create account" points at the working join flow.
const bannerCta = demoHtml.match(/<a class="cta" href="([^"]+)"/);
assert.ok(bannerCta, 'demo banner CTA exists');
assert.strictEqual(bannerCta[1], '/?join=1', 'demo banner CTA goes to the join flow');
assert.ok(!/#contact-req/.test(demoHtml) && !/#contact-req/.test(index), 'no dead #contact-req links remain');
assert.ok(/\[\?&\]join=1/.test(index), 'homepage still opens the join modal on ?join=1');

// 2. Modal fields are constrained to the modal (grid tracks can shrink, fields fill).
assert.ok(/\.rgrid\{display:grid;grid-template-columns:minmax\(0,1fr\) minmax\(0,1fr\)/.test(index), 'modal grid tracks use minmax(0,1fr)');
assert.ok(/\.rf\{[^}]*min-width:0/.test(index), '.rf may shrink');
assert.ok(/\.rf input,\.rf textarea,\.rf select\{width:100%;max-width:100%;min-width:0\}/.test(index), 'modal fields fill and never exceed their cell');
assert.ok(/id="cEmail"/.test(index) && /id="qEmail"/.test(index), 'contact and join email fields still present');

// 3. Marketing opt-in is unchecked by default; the legal attestation stays unchecked too.
const mk = index.match(/<input[^>]*id="qMarketing"[^>]*>/);
assert.ok(mk, 'marketing opt-in checkbox still present');
assert.ok(!/\bchecked\b/.test(mk[0]), 'marketing opt-in is not pre-checked');
assert.ok(!/\bchecked\b/.test(index.match(/<input[^>]*id="qAttest"[^>]*>/)[0]));

// 4. "Browse the feed" goes somewhere a visitor can browse listings.
const browse = index.match(/<a[^>]*id="browseFeedCta"[^>]*>Browse the feed<\/a>/);
assert.ok(browse && /href="\/demo\.html"/.test(browse[0]), '"Browse the feed" links to /demo.html');
assert.ok(/<section id="feed">/.test(index), 'homepage feed teaser section is kept');

// 5. Demo counters and heading are labeled as sample data.
assert.ok(/<h1[^>]*>Sample pre-market deals<\/h1>/.test(demoHtml), 'demo heading says Sample');
assert.ok(!/>Live pre-market deals</.test(demoHtml));
const keys = [...demoHtml.matchAll(/<div class="k">([^<]+)<\/div><\/div>/g)].map(m => m[1]);
assert.deepStrictEqual(keys, ['Sample deals', 'Sample volume', 'Sample MA areas', 'Sample members']);

// 6. Filter count line: names the region, singular/plural, empty state.
function loadDemo() {
  const els = {};
  const el = id => els[id] || (els[id] = { id, textContent: '', innerHTML: '', style: {}, classList: { add() {}, remove() {}, toggle() {}, contains: () => false }, getAttribute: () => null, scrollIntoView() {}, getBoundingClientRect: () => ({}) });
  const segButtons = ['all', 'residential', 'commercial'].map(c => ({ dataset: { cat: c }, getAttribute: () => c, classList: { on: c === 'all', add() { this.on = true; }, remove() { this.on = false; }, toggle(_, v) { this.on = !!v; } } }));
  const ctx = {
    document: { getElementById: el, querySelectorAll: s => (s === '.seg button' ? segButtons : []), querySelector: () => segButtons[0], body: { style: {} } },
    location: { search: '?notour=1', href: '' }, window: { innerWidth: 1280, innerHeight: 800 },
    setTimeout: () => 0, clearTimeout() {}
  };
  const script = demoHtml.slice(demoHtml.lastIndexOf('<script>') + 8, demoHtml.lastIndexOf('</script>'));
  vm.createContext(ctx);
  vm.runInContext(script, ctx);
  const line = () => [el('cnt').textContent, el('cntNoun').textContent, 'in', el('cntRegion').textContent].join(' ');
  return { ctx, el, line, segButtons };
}
{
  const { ctx, el, line, segButtons } = loadDemo();
  assert.strictEqual(el('stDeals').textContent, 6);
  assert.strictEqual(el('stVol').textContent, '$14.8M');
  assert.strictEqual(el('stAreas').textContent, 6);
  assert.strictEqual(line(), '6 sample deals in Massachusetts');
  assert.ok(!/emptyState/.test(el('grid').innerHTML));
  ctx.setMk('Worcester');
  assert.strictEqual(line(), '1 sample deal in Worcester', 'singular for one result, region named');
  assert.strictEqual((el('grid').innerHTML.match(/class="deal"/g) || []).length, 1);
  ctx.setCat('residential', segButtons[1]);
  assert.strictEqual(line(), '0 sample residential deals in Worcester');
  assert.ok(/id="emptyState"/.test(el('grid').innerHTML) && /No sample residential deals in Worcester/.test(el('grid').innerHTML), 'empty state shown');
  assert.ok(/All types in Worcester/.test(el('grid').innerHTML) && /clearFilters\(\)/.test(el('grid').innerHTML), 'empty state offers a way out');
  ctx.setMk('Boston');
  assert.strictEqual(line(), '2 sample residential deals in Boston');
  ctx.setCat('commercial', segButtons[2]);
  assert.strictEqual(line(), '1 sample commercial deal in Boston');
  ctx.setCat('all', segButtons[0]);
  ctx.setMk('Western MA');
  assert.strictEqual(line(), '0 sample deals in Western MA');
  assert.ok(/No sample deals in Western MA/.test(el('grid').innerHTML) && !/All types in/.test(el('grid').innerHTML));
  ctx.clearFilters();
  assert.strictEqual(line(), '6 sample deals in Massachusetts');
  assert.ok(segButtons[0].classList.on && !segButtons[1].classList.on, 'clear resets the type toggle');
}

// Server side of finding 3: an opt-out sign-up records no marketing consent.
const { store, call } = require('./server-harness');
(async () => {
  const base = { name: 'Pat Agent', phone: '555-0100', brokerage: 'Example Realty', license: '123456', attest: true };
  let r = await call('post', '/api/pm/request', Object.assign({}, base, { email: 'optout@example.com', marketingOptIn: false }));
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  let p = store.pm_profiles.find(x => x.email === 'optout@example.com');
  assert.strictEqual(p.marketingOptIn, false);
  assert.strictEqual(p.marketingConsentAt, '', 'no consent timestamp when the box is left unchecked');
  r = await call('post', '/api/pm/request', Object.assign({}, base, { email: 'optin@example.com', marketingOptIn: true }));
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  p = store.pm_profiles.find(x => x.email === 'optin@example.com');
  assert.strictEqual(p.marketingOptIn, true);
  assert.ok(p.marketingConsentAt, 'opt-in records when consent was given');
  console.log('audit ui tests ok');
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
