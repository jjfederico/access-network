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

console.log('compliance tests ok');
