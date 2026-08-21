// ── ACCESS data layer — Postgres ────────────────────────────────────────────
// Everything ACCESS stores is a named list (listings, intros, buyboxes,
// members, messages, notifs, profiles…). The old app kept each list as one
// JSON blob in a Google Sheet cell via pmLoad(key)/pmSave(key,arr). We keep
// that exact contract, so every route ports over unchanged — but the store is
// now a real database: writes either commit or throw, no silent "unsaved".
//
//   pm_store(k TEXT PRIMARY KEY, v JSONB, updated_at TIMESTAMPTZ)
//
// One row per list. Reads are a point lookup; writes are a single upsert in a
// transaction. Postgres gives us atomicity and durability the sheet never had.

const { Pool } = require('pg');

const URL = process.env.DATABASE_URL || '';
// Render's managed Postgres needs SSL; local dev usually doesn't. Enable SSL
// whenever a full URL is present (Render), skip it for bare localhost.
const ssl = URL && !/localhost|127\.0\.0\.1/.test(URL) ? { rejectUnauthorized: false } : false;

const pool = URL ? new Pool({ connectionString: URL, ssl, max: 8, idleTimeoutMillis: 30000 }) : null;

let ready = false;
async function ensureSchema() {
  if (!pool) return false;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS pm_store (
      k TEXT PRIMARY KEY,
      v JSONB NOT NULL DEFAULT '[]'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  ready = true;
  return true;
}

// Load a named list. Always resolves to an array (never throws to the caller),
// so a cold cache or a missing key behaves like the old empty-sheet case.
async function pmLoad(key) {
  if (!pool) return [];
  try {
    const r = await pool.query('SELECT v FROM pm_store WHERE k=$1', [String(key)]);
    if (!r.rows.length) return [];
    const v = r.rows[0].v;
    return Array.isArray(v) ? v : [];
  } catch (e) { throw e; } // never swallow a read error as [] — the caller would then overwrite the whole table with a truncated array
}

// Save a named list. Throws on failure ON PURPOSE — the route should report a
// real error to the user instead of pretending it saved. Callers already
// await this; unhandled rejection => the route's try/catch returns 5xx.
async function pmSave(key, arr) {
  if (!pool) throw new Error('no_database');
  const v = JSON.stringify(Array.isArray(arr) ? arr : []);
  await pool.query(
    `INSERT INTO pm_store (k, v, updated_at) VALUES ($1, $2::jsonb, now())
     ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, updated_at = now()`,
    [String(key), v]
  );
  return { ok: true };
}

// Atomic read-modify-write on one named list. Serializes concurrent writers to the
// same key with a row lock, so two requests can't clobber each other's changes
// (the load-mutate-save race). fn(arr) receives the current array (locked), may
// mutate it or return a replacement, and returns { save?, result? } — `save`
// defaults to the (mutated) array, and `result` is returned to the caller.
async function pmMutate(key, fn) {
  if (!pool) throw new Error('no_database');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`INSERT INTO pm_store (k, v) VALUES ($1, '[]'::jsonb) ON CONFLICT (k) DO NOTHING`, [String(key)]);
    const r = await client.query('SELECT v FROM pm_store WHERE k=$1 FOR UPDATE', [String(key)]);
    const cur = Array.isArray(r.rows[0] && r.rows[0].v) ? r.rows[0].v : [];
    const out = (await fn(cur)) || {};
    const save = out.save !== undefined ? out.save : cur;
    await client.query('UPDATE pm_store SET v=$2::jsonb, updated_at=now() WHERE k=$1', [String(key), JSON.stringify(Array.isArray(save) ? save : [])]);
    await client.query('COMMIT');
    return out.result;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    throw e;
  } finally {
    client.release();
  }
}

// One-time importer: hand it a { key: array } map (pulled from the old sheet)
// and it writes every list into Postgres in a single transaction.
async function importAll(map) {
  if (!pool) throw new Error('no_database');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let n = 0;
    for (const k of Object.keys(map || {})) {
      const v = JSON.stringify(Array.isArray(map[k]) ? map[k] : (map[k] || []));
      await client.query(
        `INSERT INTO pm_store (k, v, updated_at) VALUES ($1, $2::jsonb, now())
         ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, updated_at = now()`,
        [String(k), v]
      );
      n++;
    }
    await client.query('COMMIT');
    return { ok: true, imported: n };
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

async function health() {
  if (!pool) return { ok: false, error: 'no DATABASE_URL' };
  try { await pool.query('SELECT 1'); return { ok: true, ready }; }
  catch (e) { return { ok: false, error: String(e && e.message || e) }; }
}

module.exports = { pool, ensureSchema, pmLoad, pmSave, pmMutate, importAll, health, hasDb: !!pool };
