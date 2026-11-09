// Lost-update protection for pmLoad → modify → pmSave.
//
// Most routes load a whole list, change it, and save the whole list back. Two
// requests doing that at the same time used to clobber each other: the later
// save erased records the other request had just added or changed. db.js now
// tracks what each pmLoad returned and, under a row lock, merges the list being
// saved with what is in the database at that moment:
//   - records this request didn't touch take the database's current version;
//   - records this request added, changed, or removed are applied as-is;
//   - records someone else added since this request loaded are kept;
//   - records someone else deleted, and this request didn't touch, stay deleted.
// Lists whose provenance is unknown (built from scratch, e.g. a demo reset) or
// whose records have no stable identity are saved exactly as given, as before.

'use strict';

const LOADS = new WeakMap(); // loaded array → load record
const ELEMS = new WeakMap(); // loaded element → { load, json }

function identity(x) {
  if (!x || typeof x !== 'object') return null;
  if (x.id) return 'id:' + x.id;
  if (x.sid) return 'sid:' + x.sid;
  if (x.token) return 'tok:' + x.token;
  if (x.email) return 'em:' + String(x.email).toLowerCase() + (x.at ? '|' + x.at : '');
  if (x.owner) return 'ow:' + String(x.owner).toLowerCase();
  return null;
}

// Remember what was loaded for `key` (call on every array pmLoad returns).
function track(key, arr) {
  if (!Array.isArray(arr)) return arr;
  const load = { key, ids: new Set() };
  for (const el of arr) {
    const id = identity(el);
    if (id == null) continue;
    load.ids.add(id);
    ELEMS.set(el, { load, json: JSON.stringify(el) });
  }
  LOADS.set(arr, load);
  return arr;
}

function findLoad(key, saving) {
  const direct = LOADS.get(saving);
  if (direct && direct.key === key) return direct;
  for (const el of saving) {
    const m = el && typeof el === 'object' ? ELEMS.get(el) : null;
    if (m && m.load.key === key) return m.load;
  }
  return null;
}

// Returns the list to write, given the list being saved and the list currently
// stored (read under lock).
function merge(key, saving, current) {
  if (!Array.isArray(saving)) return saving;
  const load = findLoad(key, saving);
  if (!load) return saving;
  const cur = new Map();
  for (const c of (Array.isArray(current) ? current : [])) {
    const id = identity(c);
    if (id == null) continue;
    if (cur.has(id)) return saving; // ambiguous identities → plain save
    cur.set(id, c);
  }
  const seen = new Set();
  const out = [];
  for (const el of saving) {
    const id = identity(el);
    if (id == null) { out.push(el); continue; }
    if (seen.has(id)) return saving;
    seen.add(id);
    const m = ELEMS.get(el);
    const untouched = m && m.load === load && JSON.stringify(el) === m.json;
    if (untouched) {
      if (cur.has(id)) out.push(cur.get(id)); // latest version wins
      // else: deleted by someone else meanwhile → stays deleted
      continue;
    }
    out.push(el); // added or changed by this request
  }
  // Records someone else added after this request loaded.
  for (const [id, c] of cur) if (!load.ids.has(id) && !seen.has(id)) out.push(c);
  return out;
}

module.exports = { track, merge, identity };
