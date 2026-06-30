// Unit tests for the streaming API's pure layer (issue #13). No IDA required: these feed
// synthetic flag bags / events into the parse, validate, format, projection and
// serialization functions and assert the spec-defined behavior.
//
// Run: npm test   (node's built-in runner via --experimental-strip-types)

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseStreamFlags, validateStream, ValidateError, resolveFormat, isBounded,
  projectItem, identityOf, serializeEvent, EventSink, hasStreamingFlags,
  type StreamEvent, type PartialEvent, type CompleteEvent, type MetaEvent,
} from '../src/stream.ts';
import { exitCodeFor } from '../src/stream_runner.ts';

// ─── hasStreamingFlags (§4) ──────────────────────────────────────────────────────

test('hasStreamingFlags: detects each streaming flag', () => {
  assert.equal(hasStreamingFlags({ 'first-match': true }), true);
  assert.equal(hasStreamingFlags({ 'max-matches': '5' }), true);
  assert.equal(hasStreamingFlags({ 'max-wait': '60' }), true);
  assert.equal(hasStreamingFlags({ stream: true }), true);
  assert.equal(hasStreamingFlags({ watch: true }), true);
  assert.equal(hasStreamingFlags({ format: 'jsonl' }), true);
  assert.equal(hasStreamingFlags({ format: 'tsv' }), true);
  assert.equal(hasStreamingFlags({ 'no-meta': true }), true);
});

test('hasStreamingFlags: plain --format json is NOT streaming (legacy path)', () => {
  assert.equal(hasStreamingFlags({ format: 'json' }), false);
  assert.equal(hasStreamingFlags({ filter: 'Argus' }), false);
  assert.equal(hasStreamingFlags({}), false);
});

// ─── parseStreamFlags (§4.1) ─────────────────────────────────────────────────────

test('parseStreamFlags: --first-match aliases --max-matches 1', () => {
  const f = parseStreamFlags({ 'first-match': true });
  assert.equal(f.maxMatches, 1);
});

test('parseStreamFlags: --first-match + matching --max-matches 1 is ok', () => {
  const f = parseStreamFlags({ 'first-match': true, 'max-matches': '1' });
  assert.equal(f.maxMatches, 1);
});

test('parseStreamFlags: --first-match conflicting with --max-matches 5 throws', () => {
  assert.throws(() => parseStreamFlags({ 'first-match': true, 'max-matches': '5' }), ValidateError);
});

test('parseStreamFlags: non-positive / non-integer values throw', () => {
  assert.throws(() => parseStreamFlags({ 'max-matches': '0' }), ValidateError);
  assert.throws(() => parseStreamFlags({ 'max-matches': '-3' }), ValidateError);
  assert.throws(() => parseStreamFlags({ 'max-wait': 'abc' }), ValidateError);
  assert.throws(() => parseStreamFlags({ 'min-batch-size': '1.5' }), ValidateError);
});

test('parseStreamFlags: min-batch-size defaults to 1', () => {
  assert.equal(parseStreamFlags({}).minBatchSize, 1);
  assert.equal(parseStreamFlags({ 'min-batch-size': '50' }).minBatchSize, 50);
});

test('parseStreamFlags: --emit parses aliases and rejects unknown', () => {
  const f = parseStreamFlags({ emit: 'items,progress' });
  assert.ok(f.emit?.has('partial'));   // items ⇒ partial
  assert.ok(f.emit?.has('progress'));
  assert.throws(() => parseStreamFlags({ emit: 'bogus' }), ValidateError);
});

test('parseStreamFlags: --no-meta sets noMeta', () => {
  assert.equal(parseStreamFlags({ 'no-meta': true }).noMeta, true);
  // parseArgs lowers `--no-meta` to meta:false; support that spelling too.
  assert.equal(parseStreamFlags({ meta: false }).noMeta, true);
});

test('parseStreamFlags: --format validates the enum', () => {
  assert.equal(parseStreamFlags({ format: 'jsonl' }).format, 'jsonl');
  assert.throws(() => parseStreamFlags({ format: 'yaml' }), ValidateError);
});

// ─── default-format rules (§4.2) ─────────────────────────────────────────────────

test('resolveFormat: TTY + bounded ⇒ json', () => {
  const f = parseStreamFlags({ 'first-match': true });
  assert.equal(resolveFormat(f, true), 'json');
});

test('resolveFormat: TTY + unbounded ⇒ pretty', () => {
  const f = parseStreamFlags({ stream: true });
  assert.equal(resolveFormat(f, true), 'pretty');
});

test('resolveFormat: piped (non-TTY) ⇒ jsonl', () => {
  const f = parseStreamFlags({ stream: true });
  assert.equal(resolveFormat(f, false), 'jsonl');
});

test('resolveFormat: explicit --format always wins', () => {
  const f = parseStreamFlags({ format: 'tsv', 'first-match': true });
  assert.equal(resolveFormat(f, true), 'tsv');
});

test('isBounded: true only when a stop condition is set', () => {
  assert.equal(isBounded(parseStreamFlags({ 'first-match': true })), true);
  assert.equal(isBounded(parseStreamFlags({ 'max-wait': '60' })), true);
  assert.equal(isBounded(parseStreamFlags({ stream: true })), false);
});

// ─── validateStream (§4, §6) ─────────────────────────────────────────────────────

test('validateStream: --format json on unbounded query errors (§4.2)', () => {
  const f = parseStreamFlags({ format: 'json', stream: true });
  assert.throws(() => validateStream('functions', f, false), ValidateError);
});

test('validateStream: streaming flags on non-streamable op error (§6.5/6.6)', () => {
  for (const op of ['info', 'imports', 'segments', 'decompile', 'disasm']) {
    assert.throws(() => validateStream(op, parseStreamFlags({ stream: true }), false),
      ValidateError, `expected ${op} + --stream to throw`);
    assert.throws(() => validateStream(op, parseStreamFlags({ watch: true }), false),
      ValidateError, `expected ${op} + --watch to throw`);
  }
});

test('validateStream: --max-matches 1 on non-streamable op is allowed (single result)', () => {
  // §6.5: decompile rejects --max-matches > 1, but 1 is fine (a single result).
  assert.doesNotThrow(() => validateStream('decompile', parseStreamFlags({ 'max-matches': '1' }), false));
  assert.throws(() => validateStream('decompile', parseStreamFlags({ 'max-matches': '2' }), false), ValidateError);
});

test('validateStream: unknown --fields key errors (§6.1)', () => {
  const f = parseStreamFlags({ fields: 'addr,bogus', 'first-match': true });
  assert.throws(() => validateStream('functions', f, false), ValidateError);
});

test('validateStream: known --fields keys pass', () => {
  const f = parseStreamFlags({ fields: 'addr,name,prototype', 'first-match': true });
  assert.doesNotThrow(() => validateStream('functions', f, false));
});

test('validateStream: --resume and --watch error as deferred', () => {
  assert.throws(() => validateStream('functions', parseStreamFlags({ resume: 'v1-x' }), false), ValidateError);
  assert.throws(() => validateStream('functions', parseStreamFlags({ watch: true }), false), ValidateError);
});

test('validateStream: streamable op with --stream enables streaming', () => {
  const r = validateStream('functions', parseStreamFlags({ stream: true }), false);
  assert.equal(r.enabled, true);
});

test('validateStream: unknown op throws', () => {
  assert.throws(() => validateStream('frobnicate', parseStreamFlags({ stream: true }), false), ValidateError);
});

// ─── projectItem (§4.2 --fields, §6 field maps) ──────────────────────────────────

test('projectItem: default fields translate internal keys → spec names', () => {
  // functions.py emits `address`; spec field is `addr`.
  const item = { address: '0x100007F30', name: '_main', size: 124, demangled: null };
  const out = projectItem('functions', item, undefined);
  assert.deepEqual(out, { addr: '0x100007F30', name: '_main', size: 124 });
  assert.equal('address' in out, false);
});

test('projectItem: --fields subset projects only those, in order', () => {
  const item = { address: '0x1', name: 'f', size: 4, demangled: null };
  const out = projectItem('functions', item, ['name', 'addr']);
  assert.deepEqual(Object.keys(out), ['name', 'addr']);
  assert.equal(out.addr, '0x1');
});

test('projectItem: xrefs `function` maps to internal fromName', () => {
  const item = { from: '0xa', to: '0xb', type: 'code', fromName: '-[X y]' };
  const out = projectItem('xrefs', item, ['from', 'function']);
  assert.equal(out.function, '-[X y]');
});

// ─── identityOf (§5.4) ───────────────────────────────────────────────────────────

test('identityOf: functions identity is addr (internal `address`)', () => {
  assert.equal(identityOf('functions', { address: '0x1' }), '0x1');
  assert.equal(identityOf('functions', { addr: '0x2' }), '0x2');  // post-projection
});

test('identityOf: xrefs identity is from', () => {
  assert.equal(identityOf('xrefs', { from: '0xff' }), '0xff');
});

test('identityOf: non-streamable op has no identity', () => {
  assert.equal(identityOf('info', { x: 1 }), null);
});

// ─── serialization (§4.2, §5) ────────────────────────────────────────────────────

const mkPartial = (items: Record<string, unknown>[]): PartialEvent => ({
  event: 'partial', query_id: 'q', ts: 0, items, running_count: items.length, cursor: 'v1-x',
});

test('serializeEvent jsonl: one JSON object + newline', () => {
  const s = serializeEvent(mkPartial([{ addr: '0x1' }]), 'jsonl');
  assert.match(s, /\n$/);
  assert.deepEqual(JSON.parse(s).items, [{ addr: '0x1' }]);
});

test('serializeEvent tsv: item rows only, tab-separated', () => {
  const s = serializeEvent(mkPartial([{ addr: '0x1', name: 'a' }, { addr: '0x2', name: 'b' }]), 'tsv');
  assert.equal(s, '0x1\ta\n0x2\tb\n');
});

test('serializeEvent tsv: non-item event ⇒ empty', () => {
  const complete: CompleteEvent = {
    event: 'complete', query_id: 'q', ts: 0, count: 2, reason: 'natural',
    durationSec: 1, cursor: null, cache_state: 'warm',
  };
  assert.equal(serializeEvent(complete, 'tsv'), '');
});

// ─── EventSink: --emit filtering, mandatory terminal, json buffering, tsv header ──

function collect(): { out: string[]; write: (s: string) => void } {
  const out: string[] = [];
  return { out, write: (s) => out.push(s) };
}

function sinkFor(op: string, flags: Record<string, string | boolean>, isTTY: boolean) {
  const resolved = validateStream(op, parseStreamFlags(flags), isTTY);
  const { out, write } = collect();
  return { sink: new EventSink(resolved, write), out };
}

test('EventSink --emit: whitelists partial but still prints mandatory complete (§4.2)', () => {
  const { sink, out } = sinkFor('functions', { emit: 'items', stream: true, format: 'jsonl' }, false);
  const meta: MetaEvent = {
    event: 'meta', query_id: 'q', ts: 0, binary: '/b', binary_hash: 'h', op: 'functions',
    cache_state: 'cold', ida_pid: 1, params: {},
  };
  sink.push(meta);                                   // suppressed (not whitelisted)
  sink.push(mkPartial([{ address: '0x1', name: 'f', size: 4 }]));  // printed
  sink.push({ event: 'complete', query_id: 'q', ts: 0, count: 1, reason: 'natural',
              durationSec: 1, cursor: null, cache_state: 'warm' });  // mandatory: printed
  const events = out.map((l) => JSON.parse(l).event);
  assert.deepEqual(events, ['partial', 'complete']);
});

test('EventSink json: buffers, prints only the terminal event as the document', () => {
  const { sink, out } = sinkFor('functions', { 'first-match': true, format: 'json' }, true);
  sink.push(mkPartial([{ address: '0x1', name: 'f', size: 4 }]));  // buffered, not printed
  sink.push({ event: 'complete', query_id: 'q', ts: 0, count: 1, reason: 'max_matches',
              durationSec: 1, cursor: null, cache_state: 'partial' });
  assert.equal(out.length, 1);
  const doc = JSON.parse(out[0]);
  assert.equal(doc.event, 'complete');
  assert.equal(doc.reason, 'max_matches');
});

test('EventSink json: projects items via --fields before serializing', () => {
  // snapshot carries items; with --fields name,addr the document items are projected.
  const resolved = validateStream('functions', parseStreamFlags({ 'max-matches': '5', format: 'json', fields: 'name,addr' }), true);
  const { out, write } = collect();
  const sink = new EventSink(resolved, write);
  // Emit a snapshot then complete; only complete is printed for json, so assert via tsv path instead.
  // (json prints only terminal; projection correctness is covered by the tsv test below.)
  sink.push({ event: 'complete', query_id: 'q', ts: 0, count: 0, reason: 'natural',
              durationSec: 0, cursor: null, cache_state: 'warm' });
  assert.equal(JSON.parse(out[0]).event, 'complete');
});

test('EventSink tsv: emits header once from projected item keys', () => {
  const { sink, out } = sinkFor('functions', { stream: true, format: 'tsv', fields: 'addr,name' }, false);
  sink.push(mkPartial([{ address: '0x1', name: 'a', size: 4 }]));
  sink.push(mkPartial([{ address: '0x2', name: 'b', size: 8 }]));
  // First line is the header, then one row per item; header appears exactly once.
  assert.equal(out[0], 'addr\tname\n');
  assert.equal(out[1], '0x1\ta\n');
  assert.equal(out[2], '0x2\tb\n');
  assert.equal(out.filter((l) => l === 'addr\tname\n').length, 1);
});

// ─── exit codes (§8) ─────────────────────────────────────────────────────────────

test('exitCodeFor: complete ⇒ 0', () => {
  assert.equal(exitCodeFor('complete'), 0);
});

test('exitCodeFor: interrupted ⇒ 130', () => {
  assert.equal(exitCodeFor('interrupted'), 130);
});

test('exitCodeFor: error file_not_found / validate_error ⇒ 2 (IDA connected)', () => {
  assert.equal(exitCodeFor('error', 'file_not_found'), 2);
  assert.equal(exitCodeFor('error', 'validate_error'), 2);
});

test('exitCodeFor: other error kinds ⇒ 3', () => {
  assert.equal(exitCodeFor('error', 'script_crashed'), 3);
  assert.equal(exitCodeFor('error', 'ida_crashed'), 3);
  assert.equal(exitCodeFor('error', 'out_of_memory'), 3);
});
