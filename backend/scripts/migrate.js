#!/usr/bin/env node
/**
 * ══════════════════════════════════════════════════════════════════
 *  Wadjet-Eye AI — Database Migration Runner
 *  backend/scripts/migrate.js
 *
 *  Runs all pending SQL migrations in order against Supabase/Postgres.
 *  Tracks applied migrations in a schema_migrations table.
 *
 *  Usage:
 *    node scripts/migrate.js            — apply all pending migrations
 *    node scripts/migrate.js --dry-run  — show pending without applying
 *    node scripts/migrate.js --rollback — rollback last migration
 * ══════════════════════════════════════════════════════════════════
 */
'use strict';

require('dotenv').config();

const fs   = require('fs');
const path = require('path');
const { Client } = require('pg');

const MIGRATIONS_DIR = path.join(__dirname, '../db/migrations');
const DRY_RUN        = process.argv.includes('--dry-run');
const ROLLBACK       = process.argv.includes('--rollback');

const DB_URL = process.env.DATABASE_URL || process.env.SUPABASE_DB_URL;

if (!DB_URL) {
  console.error('[migrate] ❌  DATABASE_URL or SUPABASE_DB_URL env var is required');
  process.exit(1);
}

// ── Bootstrap schema_migrations table ────────────────────────────
const BOOTSTRAP_SQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  id          SERIAL PRIMARY KEY,
  filename    TEXT        NOT NULL UNIQUE,
  applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  checksum    TEXT        NOT NULL,
  duration_ms INTEGER
);
`;

// ── Simple SHA-256 checksum of file content ───────────────────────
const crypto = require('crypto');
function checksum(content) {
  return crypto.createHash('sha256').update(content).digest('hex');
}

// ── Get sorted list of migration files ───────────────────────────
function getMigrationFiles() {
  return fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort(); // lexicographic — 001_, 002_, 003_ …
}

async function run() {
  const client = new Client({ connectionString: DB_URL, ssl: { rejectUnauthorized: false } });

  try {
    await client.connect();
    console.log('[migrate] ✓  Connected to database');

    // Create tracking table
    await client.query(BOOTSTRAP_SQL);

    // Load applied migrations
    const { rows: applied } = await client.query(
      'SELECT filename, checksum FROM schema_migrations ORDER BY id'
    );
    const appliedMap = new Map(applied.map(r => [r.filename, r.checksum]));

    const files = getMigrationFiles();

    if (ROLLBACK) {
      // Rollback: show last applied migration (manual SQL required for true rollback)
      const last = applied[applied.length - 1];
      if (!last) { console.log('[migrate] Nothing to rollback'); return; }
      console.log(`[migrate] ⚠  Last applied migration: ${last.filename}`);
      console.log('[migrate]    To rollback, manually run the inverse SQL and then:');
      console.log(`[migrate]    DELETE FROM schema_migrations WHERE filename = '${last.filename}';`);
      return;
    }

    // Determine pending
    const pending = files.filter(f => !appliedMap.has(f));

    if (pending.length === 0) {
      console.log('[migrate] ✓  All migrations are up to date');
      return;
    }

    console.log(`[migrate] Found ${pending.length} pending migration(s):`);
    pending.forEach(f => console.log(`  • ${f}`));

    if (DRY_RUN) {
      console.log('[migrate] DRY RUN — no changes applied');
      return;
    }

    // Apply pending migrations in order
    for (const filename of pending) {
      const filePath = path.join(MIGRATIONS_DIR, filename);
      const content  = fs.readFileSync(filePath, 'utf8');
      const cs       = checksum(content);

      console.log(`[migrate] Applying: ${filename} …`);
      const t0 = Date.now();

      try {
        await client.query('BEGIN');
        await client.query(content);
        await client.query(
          'INSERT INTO schema_migrations (filename, checksum, duration_ms) VALUES ($1, $2, $3)',
          [filename, cs, Date.now() - t0]
        );
        await client.query('COMMIT');
        console.log(`[migrate] ✓  ${filename} applied in ${Date.now() - t0} ms`);
      } catch (err) {
        await client.query('ROLLBACK');
        console.error(`[migrate] ❌  ${filename} FAILED: ${err.message}`);
        process.exit(1);
      }
    }

    console.log(`[migrate] ✅  ${pending.length} migration(s) applied successfully`);

  } finally {
    await client.end();
  }
}

run().catch(err => {
  console.error('[migrate] Fatal:', err.message);
  process.exit(1);
});
