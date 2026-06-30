// Unit tests for filesystem-touching util helpers (no IDA required).
//
// Run: npm test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { backupLargeIdb, IDB_BACKUP_THRESHOLD_BYTES } from '../src/util.ts';

test('backupLargeIdb: a sub-threshold file is left in place (overwrite is cheap)', () => {
  const dir = mkdtempSync(join(tmpdir(), 're-bak-'));
  try {
    const f = join(dir, 'binary.i64');
    writeFileSync(f, 'x'.repeat(100));
    assert.equal(backupLargeIdb(f, 1000), null);  // 100 <= 1000 → no backup
    assert.ok(existsSync(f), 'original untouched');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('backupLargeIdb: an over-threshold file is renamed to <path>.<unix-ts>.bak', () => {
  const dir = mkdtempSync(join(tmpdir(), 're-bak-'));
  try {
    const f = join(dir, 'binary.i64');
    writeFileSync(f, 'x'.repeat(100));
    const bak = backupLargeIdb(f, 10);  // 100 > 10 → back up
    assert.ok(bak, 'returned a backup path');
    assert.match(bak!, /\/binary\.i64\.\d+\.bak$/);
    assert.ok(!existsSync(f), 'original moved away (so the fresh -c writes a clean binary.i64)');
    assert.ok(existsSync(bak!), 'backup preserved');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('backupLargeIdb: missing file → null (nothing to back up)', () => {
  const dir = mkdtempSync(join(tmpdir(), 're-bak-'));
  try {
    assert.equal(backupLargeIdb(join(dir, 'nope.i64'), 10), null);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('IDB_BACKUP_THRESHOLD_BYTES is 2 GB', () => {
  assert.equal(IDB_BACKUP_THRESHOLD_BYTES, 2 * 1024 ** 3);
});
