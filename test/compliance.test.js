'use strict';
const assert = require('assert');
const c = require('../lib/compliance');

assert.ok(c.compensationHit('2.5% BBC to buyer agent'));
assert.ok(c.compensationHit('Buyer-broker commission 2.5%'));
assert.ok(c.compensationHit('referral fee paid at closing'));
assert.ok(c.compensationHit("finder's fee"));
assert.ok(c.compensationHit('3% commission to buyer broker'));
assert.strictEqual(c.compensationHit('Six-unit brick, all 2-beds, below-market rents.'), null);
assert.strictEqual(c.compensationHit(''), null);

assert.ok(c.motivatedHit('Highly motivated seller'));
assert.strictEqual(c.motivatedHit('Buyer looking in Worcester'), null);

assert.strictEqual(c.mlsZoneFor('Falmouth', '', ''), 'cape_islands');
assert.strictEqual(c.mlsZoneFor('Nantucket', '', ''), 'cape_islands');
assert.strictEqual(c.mlsZoneFor('Pittsfield', '', ''), 'berkshire');
assert.strictEqual(c.mlsZoneFor('Lenox', 'Berkshires', ''), 'berkshire');
assert.strictEqual(c.mlsZoneFor('Worcester', '', ''), '');
assert.strictEqual(c.mlsZoneFor('Boston', 'South Boston', ''), '');
assert.ok(/confirm with your broker/i.test(c.MLS_ZONE_WARNING));
assert.ok(!/one business day/i.test(c.MLS_ZONE_WARNING));

assert.ok(c.isMassachusettsState('MA'));
assert.ok(c.isMassachusettsState('Massachusetts'));
assert.ok(c.isMassachusettsState(''));
assert.ok(!c.isMassachusettsState('NH'));
assert.ok(!c.isMassachusettsState('NY'));

assert.strictEqual(c.normalizePriceBand('1m_2m'), '1m_2m');
assert.strictEqual(c.normalizePriceBand('not-a-band'), '');
assert.strictEqual(c.priceBandById('5m_plus').min, 5000000);
assert.strictEqual(c.normalizeTimeline('60_days'), '60_days');
assert.strictEqual(c.normalizeTimeline('whenever'), '');

const first = c.foundingForJoinOrder(0);
assert.strictEqual(first.founder, true);
assert.strictEqual(first.memberNo, 1);
assert.strictEqual(first.monthly, 25);
const lastFounder = c.foundingForJoinOrder(99);
assert.strictEqual(lastFounder.founder, true);
const after = c.foundingForJoinOrder(100);
assert.strictEqual(after.founder, false);
assert.strictEqual(after.monthly, 50);
assert.strictEqual(after.memberNo, 101);

assert.ok(c.validTerminationCause('license_lapse'));
assert.ok(c.validTerminationCause('non_payment'));
assert.ok(c.validTerminationCause('material_breach'));
assert.ok(!c.validTerminationCause('competitive_pricing'));
assert.ok(!c.validTerminationCause(''));

assert.ok(c.sellerFormOk({ name: 'seller-consent.pdf', key: 'u/abc/form.pdf' }));
assert.ok(c.sellerFormOk({ name: 'form.pdf', url: 'https://example.com/f.pdf' }));
assert.ok(!c.sellerFormOk(null));
assert.ok(!c.sellerFormOk({ name: 'form.pdf' }));
assert.ok(!c.sellerFormOk({ key: 'u/x' }));

assert.ok(c.listingAuthorized({ sellerForm: { name: 'f.pdf', key: 'u/f.pdf' } }));
assert.ok(c.listingAuthorized({ sample: true }));
assert.ok(!c.listingAuthorized({ status: 'active' }));
assert.ok(!c.listingAuthorized({ sellerForm: { name: 'f.pdf' } }));
assert.ok(!c.listingAuthorized(null));

assert.ok(c.licenseFormatOk('9012345'));
assert.ok(!c.licenseFormatOk('n/a'));
assert.ok(!c.licenseFormatOk('12'));

const ok = c.admissionCriteria({ license: '9012345', brokerage: 'Acme Realty', state: 'MA', attest: true });
assert.strictEqual(ok.met, true);
assert.strictEqual(ok.checks.subscription, 'free_trial_then_published_rate');

assert.strictEqual(c.TRIAL_DAYS, 14);
assert.strictEqual(c.trialEndsAt('2026-10-01T00:00:00Z', ''), '');
assert.strictEqual(c.trialEndsAt('2026-10-01T00:00:00Z', '2026-11-01T00:00:00Z'), '2026-11-15T00:00:00.000Z');
assert.strictEqual(c.trialEndsAt('2026-11-10T00:00:00Z', '2026-11-01T00:00:00Z'), '2026-11-24T00:00:00.000Z');
assert.strictEqual(c.admissionCriteria({ license: '9012345', brokerage: 'Acme', state: 'NH', attest: true }).met, false);
assert.strictEqual(c.admissionCriteria({ license: '9012345', brokerage: '', state: 'MA', attest: true }).met, false);
assert.strictEqual(c.admissionCriteria({ license: '9012345', brokerage: 'Acme', state: 'MA', attest: false }).met, false);
assert.deepStrictEqual(Object.keys(c.CAUSE_LABELS).sort(), c.TERMINATION_CAUSES.slice().sort());

// Seller-signed form: only a real upload counts; validated after sanitizing.
const pdfUrl = 'data:application/pdf;base64,' + Buffer.from('%PDF-1.4 ' + 'y'.repeat(3000)).toString('base64');
assert.ok(c.cleanSellerForm({ name: 'signed.pdf', key: 'u/0123456789/lzx9abc.pdf' }));
assert.strictEqual(c.cleanSellerForm({ name: 'signed.pdf', url: pdfUrl }).url, pdfUrl);
assert.strictEqual(c.cleanSellerForm({ name: 'signed.pdf', url: 'https://example.com/x.pdf' }), null);
assert.strictEqual(c.cleanSellerForm({ name: 'signed.pdf', key: '!!!' }), null);
assert.strictEqual(c.cleanSellerForm({ name: 'signed.pdf', key: '../x' }), null);
assert.strictEqual(c.cleanSellerForm({ name: '  ', url: pdfUrl }), null);
assert.strictEqual(c.cleanSellerForm({ name: 'x.html', url: 'data:text/html;base64,PGI+' }), null);
assert.strictEqual(c.cleanSellerForm(null), null);
// The demo placeholder form must still be accepted.
assert.ok(c.cleanSellerForm(require('../lib/demo').PLACEHOLDER_FORM));
// Legacy forms already on file keep counting (no data is re-evaluated or hidden).
assert.ok(c.listingAuthorized({ sellerForm: { name: 'old.pdf', url: 'https://example.com/old.pdf' } }));

// Sign-up shortfalls are named for the admissions log.
assert.deepStrictEqual(c.admissionShortfalls(c.admissionCriteria({ license: '9012345', brokerage: 'Acme', state: 'MA', attest: true }).checks), []);
assert.strictEqual(c.admissionShortfalls(c.admissionCriteria({ license: 'n/a', brokerage: 'Acme', state: 'MA', attest: false }).checks).length, 2);

// Copy audit: no invite-only / exclusivity / around-public-marketing language
// anywhere served or emailed, and the legal pages agree with each other.
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..');
const pub = fs.readdirSync(path.join(root, 'public')).filter(f => /\.(html|js|webmanifest|txt)$/.test(f)).map(f => 'public/' + f);
const srcs = pub.concat(['server.js', 'auth.js', 'lib/demo.js', 'lib/demo-bar.js', 'README.md']);
const BANNED = [/invite[- ]only/i, /invitation[- ]only/i, /by invitation/i, /pocket listing/i, /before it (hits|lists)/i, /off[- ]market network/i, /exclusive (network|access|club|membership|members)/i, /members[- ]only deals/i, /private network/i, /closed network/i, /hand-picked members/i, /curated (network|membership|members)/i];
const strip = s => s.replace(/<style[\s\S]*?<\/style>/gi, '').replace(/not by invitation|is not by invitation|membership is not by invitation|free access based on brokerage, invitation/gi, '');
for (const f of srcs) {
  const t = strip(fs.readFileSync(path.join(root, f), 'utf8'));
  for (const re of BANNED) assert.ok(!re.test(t), f + ' contains banned copy ' + re + ': ' + (t.match(re) || [''])[0]);
}
const txt = f => fs.readFileSync(path.join(root, 'public', f), 'utf8').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
const terms = txt('terms.html'), privacy = txt('privacy.html'), membership = txt('membership.html'), landing = txt('index.html');
assert.ok(/be affiliated with a licensed Massachusetts brokerage/.test(terms), 'Terms eligibility list includes brokerage affiliation');
assert.ok(!/immediate suspension or termination/i.test(terms), 'Terms §4 must not override the stated-cause notice-and-cure rule');
assert.ok(/Stripe/.test(privacy) && /subscription billing/.test(terms), 'Terms vendor list matches Privacy');
assert.ok(/\$0 during your 14-day free trial/.test(membership), 'membership page states the $0 trial period');
for (const [n, t] of [['terms', terms], ['membership', membership], ['landing', landing]]) {
  assert.ok(/every applicant who meets/i.test(t) || /granted to every applicant who meets/i.test(t), n + ' states every qualified applicant is admitted');
}
{ const idx = fs.readFileSync(path.join(root, 'public/index.html'), 'utf8'); const j = idx.indexOf('<h3>Join AXESS</h3>'); assert.ok(j > 0 && /href="\/membership"/.test(idx.slice(j, j + 1500)), 'the sign-up form links the criteria page'); }
for (const t of [terms, membership, landing]) assert.ok(/\$25/.test(t) && /\$50/.test(t) && /14-day/.test(t), 'pricing unchanged and consistent');

console.log('compliance tests ok');
