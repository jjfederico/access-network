// Nightly backups: every stored list (pm_store row) as one gzipped JSON file in
// object storage (R2), one per day, kept for RETAIN_DAYS. Sign-in tokens and
// the demo partition are left out. Restore with scripts/restore-backup.js.

'use strict';

const zlib = require('zlib');

const RETAIN_DAYS = Number(process.env.BACKUP_RETAIN_DAYS || 30);
const PREFIX = 'backups/';
const SKIP = k => k === 'pm_authtokens' || String(k).indexOf('demo:') === 0;

const day = d => new Date(d).toISOString().slice(0, 10);
const keyFor = d => PREFIX + 'axess-' + day(d) + '.json.gz';

// rows: [{ k, v, updated_at }] → { key, buffer, counts }
function build(rows, now) {
  now = now || Date.now();
  const data = {};
  const counts = {};
  for (const r of rows || []) {
    if (!r || SKIP(r.k)) continue;
    data[r.k] = r.v;
    counts[r.k] = Array.isArray(r.v) ? r.v.length : 1;
  }
  const doc = { app: 'AXESS', format: 1, createdAt: new Date(now).toISOString(), counts, data };
  return { key: keyFor(now), buffer: zlib.gzipSync(Buffer.from(JSON.stringify(doc))), counts };
}

function read(buffer) {
  const doc = JSON.parse(zlib.gunzipSync(buffer).toString('utf8'));
  if (!doc || doc.app !== 'AXESS' || !doc.data) throw new Error('not an AXESS backup');
  return doc;
}

// Due when the last successful backup is ~a day old (or there is none).
function isDue(lastIso, now) {
  if (!lastIso) return true;
  return (now || Date.now()) - new Date(lastIso).getTime() >= 20 * 3600 * 1000;
}

// The file that falls out of the retention window today.
function expiredKey(now) { return keyFor((now || Date.now()) - RETAIN_DAYS * 864e5); }

module.exports = { build, read, isDue, expiredKey, keyFor, RETAIN_DAYS, PREFIX };
