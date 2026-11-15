#!/usr/bin/env node
// Restore lists from an AXESS backup file into the database at DATABASE_URL.
//
//   node scripts/restore-backup.js axess-2026-11-15.json.gz                 # dry run: show what's inside
//   node scripts/restore-backup.js FILE --keys pm_listings,pm_profiles --confirm
//
// Only the lists named in --keys are replaced; everything else is untouched.
// Without --confirm nothing is written. Take a fresh backup first.
'use strict';
const fs = require('fs');
const backup = require('../lib/backup');

const args = process.argv.slice(2);
const file = args.find(a => !a.startsWith('--') && args[args.indexOf(a) - 1] !== '--keys');
const ki = args.findIndex(a => a === '--keys' || a.startsWith('--keys='));
const keys = (ki < 0 ? '' : (args[ki].includes('=') ? args[ki].split('=')[1] : args[ki + 1] || '')).split(',').map(s => s.trim()).filter(Boolean);
const confirm = args.includes('--confirm');

(async () => {
  if (!file) { console.error('usage: restore-backup.js FILE [--keys a,b] [--confirm]'); process.exit(2); }
  const doc = backup.read(fs.readFileSync(file));
  console.log('Backup from', doc.createdAt);
  Object.keys(doc.counts).sort().forEach(k => console.log('  ' + k.padEnd(18) + doc.counts[k]));
  if (!keys.length) { console.log('\nDry run. Pass --keys list1,list2 --confirm to restore those lists.'); return; }
  const missing = keys.filter(k => !(k in doc.data));
  if (missing.length) { console.error('Not in this backup:', missing.join(', ')); process.exit(1); }
  if (!confirm) { console.log('\nWould replace:', keys.join(', '), '\nAdd --confirm to write.'); return; }
  if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set.'); process.exit(1); }
  const db = require('../db');
  await db.importAll(Object.fromEntries(keys.map(k => [k, doc.data[k]])));
  console.log('Restored:', keys.join(', '));
  await db.pool.end();
})().catch(e => { console.error('Restore failed:', e.message); process.exit(1); });
