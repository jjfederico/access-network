'use strict';
// Lost-update protection: concurrent load → modify → save must not erase each
// other's records. Simulates the store the way db.js uses lib/store-merge.
const assert = require('assert');
const sm = require('../lib/store-merge');

const db = {};
const clone = v => JSON.parse(JSON.stringify(v));
const load = k => sm.track(k, clone(db[k] || []));
const save = (k, v) => { db[k] = clone(sm.merge(k, v, db[k] || [])); };
const ids = k => db[k].map(x => x.id).join(',');

// 1. The AXESS incident: a slow job loads, a new listing is posted, the job saves.
db.L = [{ id: 'A', status: 'active' }, { id: 'B', status: 'active' }];
let job = load('L');
let post = load('L'); post.push({ id: 'C', status: 'active' }); save('L', post);
job[0].status = 'off'; save('L', job);
assert.strictEqual(ids('L'), 'A,B,C');
assert.strictEqual(db.L[0].status, 'off');

// 2. Two requests change different records: both changes survive.
let r1 = load('L'), r2 = load('L');
r1[1] = Object.assign({}, r1[1], { price: '1' }); r2[2].price = '2';
save('L', r1); save('L', r2);
assert.strictEqual(db.L[1].price, '1');
assert.strictEqual(db.L[2].price, '2');

// 3. A delete races an insert: the delete sticks, the insert survives.
r1 = load('L'); r2 = load('L');
r2.push({ id: 'D' }); save('L', r2);
save('L', r1.filter(x => x.id !== 'B'));
assert.strictEqual(ids('L'), 'A,C,D');

// 4. Someone else deleted a record this request didn't touch: it stays deleted.
r1 = load('L'); r2 = load('L');
save('L', r2.filter(x => x.id !== 'D'));
r1[0].views = 5; save('L', r1);
assert.strictEqual(ids('L'), 'A,C');
assert.strictEqual(db.L[0].views, 5);

// 5. Same record changed by both: the later save wins for that record only.
r1 = load('L'); r2 = load('L');
r1[1].status = 'mls'; save('L', r1);
r2[1].status = 'closed'; save('L', r2);
assert.strictEqual(db.L[1].status, 'closed');

// 6. Capped lists (slice) drop old records on purpose.
db.N = [{ id: 1 }, { id: 2 }, { id: 3 }];
let n = load('N'); n.push({ id: 4 }); save('N', n.slice(-3));
assert.strictEqual(ids('N'), '2,3,4');

// 7. A list built from scratch (e.g. demo reset) replaces everything, as before.
save('N', [{ id: 9 }]);
assert.strictEqual(ids('N'), '9');

// 8. Profiles keyed by email; concurrent sign-up survives a paid-flag update.
db.P = [{ email: 'a@x.co', paid: false }];
r1 = load('P'); r2 = load('P');
r2.push({ email: 'b@x.co' }); save('P', r2);
r1[0].paid = true; save('P', r1);
assert.deepStrictEqual(db.P.map(p => p.email + ':' + !!p.paid), ['a@x.co:true', 'b@x.co:false']);

// 9. Lists without identities (settings) save exactly as given.
db.S = [{ billingOn: false }];
const s = load('S'); s[0].billingOn = true; save('S', s);
assert.strictEqual(db.S[0].billingOn, true);

// 10. Keys don't cross: an array loaded for one key saved to another is a plain save.
db.X = [{ id: 'x1' }];
const fromL = load('L'); save('X', fromL);
assert.strictEqual(ids('X'), ids('L'));

console.log('store merge tests ok');
