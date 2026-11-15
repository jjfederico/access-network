'use strict';
// Nightly backup file: what goes in, round-trip, schedule, retention.
const assert = require('assert');
const b = require('../lib/backup');

const rows = [
  { k: 'pm_listings', v: [{ id: 'L1' }, { id: 'L2' }] },
  { k: 'pm_profiles', v: [{ email: 'a@x.co' }] },
  { k: 'pm_settings', v: [{ billingOn: false }] },
  { k: 'pm_authtokens', v: [{ token: 'secret' }] },
  { k: 'demo:pm_listings', v: [{ id: 'DEMO-L1' }] }
];
const now = Date.UTC(2026, 10, 15, 7, 0, 0);
const out = b.build(rows, now);
assert.strictEqual(out.key, 'backups/axess-2026-11-15.json.gz');
assert.deepStrictEqual(out.counts, { pm_listings: 2, pm_profiles: 1, pm_settings: 1 });
const doc = b.read(out.buffer);
assert.deepStrictEqual(doc.data.pm_listings, rows[0].v, 'round-trips exactly');
assert.ok(!('pm_authtokens' in doc.data), 'sign-in tokens are never backed up');
assert.ok(!Object.keys(doc.data).some(k => k.startsWith('demo:')), 'demo data is not backed up');
assert.throws(() => b.read(require('zlib').gzipSync(Buffer.from('{"x":1}'))), /not an AXESS backup/);

assert.ok(b.isDue('', now));
assert.ok(!b.isDue(new Date(now - 3 * 3600e3).toISOString(), now), 'not twice in a day');
assert.ok(b.isDue(new Date(now - 21 * 3600e3).toISOString(), now));
assert.strictEqual(b.expiredKey(now), 'backups/axess-2026-10-16.json.gz', 'the file 30 days back is removed');

console.log('backup tests ok');
