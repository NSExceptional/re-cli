// Unit tests for filesystem-touching util helpers (no IDA required).
//
// Run: npm test

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { backupLargeIdb, IDB_BACKUP_THRESHOLD_BYTES } from '../src/util.ts';
import { writeIdbMeta, readIdbMeta, purgeUnpackedIdb, type IdbMeta } from '../src/cache.ts';

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

test('writeIdbMeta/readIdbMeta: round-trips identifying metadata to idb/<hash>/meta.json', () => {
  const cacheDir = mkdtempSync(join(tmpdir(), 're-meta-'));
  try {
    const meta: IdbMeta = {
      name: 'MusicallyCore', path: '/x/MusicallyCore', arch: 'arm64', backend: 'ida',
      backendVersion: '8.3', binHash: 'abc123', analyzedAt: '2026-07-01T00:00:00.000Z',
      mtimeMs: 123, size: 456,
    };
    writeIdbMeta(cacheDir, 'abc123', undefined, meta);
    assert.ok(existsSync(join(cacheDir, 'idb', 'abc123', 'meta.json')), 'written under idb/<hash>/');
    const r = readIdbMeta(cacheDir, 'abc123');
    assert.equal(r?.name, 'MusicallyCore');
    assert.equal(r?.arch, 'arm64');
    assert.equal(r?.binHash, 'abc123');
    assert.equal(r?.path, '/x/MusicallyCore');
    assert.equal(readIdbMeta(cacheDir, 'missing'), null);
  } finally { rmSync(cacheDir, { recursive: true, force: true }); }
});

test('purgeUnpackedIdb: deletes the .id*/.nam/.til scratch, keeps binary.i64 and unrelated files', () => {
  const dir = mkdtempSync(join(tmpdir(), 're-purge-'));
  try {
    for (const f of ['binary.i64', 'binary.id0', 'binary.id1', 'binary.id2', 'binary.nam', 'binary.til', 'meta.json'])
      writeFileSync(join(dir, f), 'x'.repeat(10));
    const freed = purgeUnpackedIdb(dir);
    assert.equal(freed, 50, '5 components × 10 bytes reclaimed');
    assert.ok(existsSync(join(dir, 'binary.i64')), 'packed .i64 kept');
    assert.ok(existsSync(join(dir, 'meta.json')), 'unrelated files kept');
    for (const c of ['id0', 'id1', 'id2', 'nam', 'til'])
      assert.ok(!existsSync(join(dir, `binary.${c}`)), `binary.${c} removed`);
    assert.equal(purgeUnpackedIdb(dir), 0, 'idempotent — nothing left to purge');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
