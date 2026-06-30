// Streaming API (GitHub issue #13) — the CLI-side event envelope, flag parsing,
// validation, item projection, and serialization for the NDJSON streaming protocol.
//
// This module is deliberately IDA-free and pure: every function here can be unit-tested
// by feeding synthetic inputs, with no real disassembler run. The runner (runner.ts)
// owns wiring these into the daemon/one-shot execution path and is responsible for the
// "always terminate with a terminal event" guarantee at the process boundary.
//
// Spec: see `gh issue view 13` — §4 (flags), §5 (events), §6 (item schemas),
// §7 (state machine), §8 (exit codes). Where the spec is silent, we note it with a
// SPEC-GAP comment rather than inventing behavior.

import process from 'node:process';
import { randomUUID } from 'node:crypto';

// ─── Event types (§5) ─────────────────────────────────────────────────────────

export type EventName =
  | 'meta' | 'status' | 'progress' | 'partial' | 'snapshot'
  | 'delta' | 'complete' | 'error' | 'interrupted';

export type CacheState = 'cold' | 'partial' | 'warm' | 'stale';

// §5.7 complete.reason
export type CompleteReason =
  | 'natural' | 'max_matches' | 'max_wait' | 'cursor_exhausted' | 'db_settled';

// §5.8 error.kind
export type ErrorKind =
  | 'file_not_found' | 'validate_error' | 'bad_argument' | 'cache_corrupt'
  | 'ida_crashed' | 'script_crashed' | 'binary_arch_mismatch'
  | 'out_of_memory' | 'save_failed';

// Common fields on every event (§5).
interface EventBase {
  event: EventName;
  query_id: string;
  ts: number;
}

export interface MetaEvent extends EventBase {
  event: 'meta';
  binary: string;
  binary_hash: string;
  op: string;
  cache_state: CacheState;
  ida_pid: number | null;
  params: Record<string, unknown>;
}

export interface StatusEvent extends EventBase {
  event: 'status';
  stage: 'analyzing' | 'loading_idb' | 'swift_metadata' | 'decompiling' | 'indexing';
  etaSec: number | null;
}

export interface ProgressEvent extends EventBase {
  event: 'progress';
  items_emitted: number;
  phase: 'analyzing' | 'swift_metadata' | 'indexing' | 'decompiling' | 'idle' | 'done';
  percent: number | null;
  etaSec: number | null;
}

export interface PartialEvent extends EventBase {
  event: 'partial';
  items: Record<string, unknown>[];
  running_count: number;
  cursor: string | null;
}

export interface SnapshotEvent extends EventBase {
  event: 'snapshot';
  items: Record<string, unknown>[];
  count: number;
}

export interface DeltaEvent extends EventBase {
  event: 'delta';
  added: Record<string, unknown>[];
  removed: Record<string, unknown>[];
  mutation: 'functions_added' | 'functions_renamed' | 'functions_removed'
    | 'data_added' | 'user_annotation' | 'reanalysis';
}

export interface CompleteEvent extends EventBase {
  event: 'complete';
  count: number;
  reason: CompleteReason;
  durationSec: number;
  cursor: string | null;
  cache_state: CacheState;
}

export interface ErrorEvent extends EventBase {
  event: 'error';
  kind: ErrorKind;
  message: string;
  partial_count: number;
  log_excerpt: string | null;
}

export interface InterruptedEvent extends EventBase {
  event: 'interrupted';
  partial_count: number;
  cursor: string | null;
  cache_state: CacheState;
}

export type StreamEvent =
  | MetaEvent | StatusEvent | ProgressEvent | PartialEvent | SnapshotEvent
  | DeltaEvent | CompleteEvent | ErrorEvent | InterruptedEvent;

// Events that carry items and are therefore subject to --fields projection (§4.2).
const ITEM_EVENTS: ReadonlySet<EventName> = new Set(['partial', 'snapshot', 'delta']);
// Terminal events that MUST print even when --emit whitelists exclude them (§4.2).
const MANDATORY_EVENTS: ReadonlySet<EventName> = new Set(['complete', 'error', 'interrupted']);

// ─── Op metadata (§6) ──────────────────────────────────────────────────────────

export interface OpSpec {
  // Whether this op streams items. Non-streamable ops (§6.5–6.6) emit a single
  // snapshot then complete and reject streaming flags in validate.
  streamable: boolean;
  // Identity field used for within-query dedup (§5.4). null for non-streamable ops.
  identity: string | null;
  // Fields emitted by default when --fields is not given (§6).
  defaultFields: string[];
  // The full set of keys --fields may name (§6). Unknown keys are a validate_error.
  allowedFields: string[];
}

// Per-op schemas, transcribed verbatim from §6. The "internal" item keys produced by
// the IDA scripts differ from the spec's wire names (e.g. functions.py emits `address`,
// the spec field is `addr`); fieldMap below bridges that. Here we list SPEC field names.
export const OP_SPECS: Record<string, OpSpec> = {
  // §6.1
  functions: {
    streamable: true, identity: 'addr',
    defaultFields: ['addr', 'name', 'size', 'type'],
    allowedFields: ['addr', 'name', 'size', 'type', 'prototype', 'flags', 'start_ea', 'end_ea'],
  },
  // §6.2
  symbols: {
    streamable: true, identity: 'addr',
    defaultFields: ['addr', 'name', 'type'],
    allowedFields: ['addr', 'name', 'type', 'mangled', 'namespace', 'demangled'],
  },
  // §6.3
  strings: {
    streamable: true, identity: 'addr',
    defaultFields: ['addr', 'value', 'length'],
    allowedFields: ['addr', 'value', 'length', 'encoding', 'section'],
  },
  // §6.4
  xrefs: {
    streamable: true, identity: 'from',
    defaultFields: ['from', 'to', 'type', 'function'],
    allowedFields: ['from', 'to', 'type', 'function', 'is_call', 'is_data'],
  },
  // exports is not enumerated in §6; it is list-shaped like symbols. SPEC-GAP: §6 omits
  // `re exports`. We treat it as streamable with the symbols-style identity so it is not
  // silently broken, and flag it in the report. Conservative default fields mirror what
  // exports.py actually produces.
  exports: {
    streamable: true, identity: 'addr',
    defaultFields: ['addr', 'name'],
    allowedFields: ['addr', 'name', 'ordinal'],
  },
  // §6.5 — non-streamed single-result ops.
  disasm:    { streamable: false, identity: null, defaultFields: [], allowedFields: [] },
  decompile: { streamable: false, identity: null, defaultFields: [], allowedFields: [] },
  // §6.6 — non-streamed bulk ops.
  imports:   { streamable: false, identity: null, defaultFields: [], allowedFields: [] },
  segments:  { streamable: false, identity: null, defaultFields: [], allowedFields: [] },
  info:      { streamable: false, identity: null, defaultFields: [], allowedFields: [] },
};

// Map spec field names → the keys the existing IDA scripts actually emit. Only fields
// that differ are listed; anything not here passes through unchanged. This lets us honor
// the spec's wire schema (§6) without rewriting every per-op script's key names yet.
const FIELD_MAP: Record<string, Record<string, string>> = {
  functions: { addr: 'address' },
  symbols:   { addr: 'address' },
  strings:   { addr: 'address' },
  xrefs:     { function: 'fromName' },  // §6.4 `function` = containing fn at `from`
  exports:   { addr: 'address' },
};

// ─── Format & flag types (§4) ────────────────────────────────────────────────────

export type OutputFormat = 'json' | 'jsonl' | 'tsv' | 'pretty';

export interface StreamFlags {
  // §4.1 stop conditions
  maxMatches?: number;
  maxWait?: number;       // seconds
  minBatchSize: number;   // default 1
  // §4.2 output shape
  emit?: Set<EventName>;  // undefined = all
  format?: OutputFormat;  // undefined = apply default rules
  fields?: string[];      // undefined = op default
  // §4.3 lifecycle
  stream: boolean;
  watch: boolean;
  resume?: string;
  noMeta: boolean;
}

// Resolved knobs the runner needs once validation passed.
export interface ResolvedStream {
  enabled: boolean;          // is this query running in streaming mode at all?
  flags: StreamFlags;
  format: OutputFormat;
  op: string;
  spec: OpSpec;
  bounded: boolean;          // any stop condition set → a single bounded result is possible
}

// ─── Flag parsing (§4) ──────────────────────────────────────────────────────────

// Value-taking streaming flags, surfaced to main.ts so it can register them in VALUE_FLAGS.
export const STREAM_VALUE_FLAGS = [
  'max-matches', 'max-wait', 'min-batch-size', 'emit', 'fields',
  'resume', 'status-threshold',
] as const;

// True when any streaming flag is present — used by the runner to decide whether to take
// the streaming code path vs. the legacy single-blob path entirely.
export function hasStreamingFlags(flags: Record<string, string | boolean>): boolean {
  const keys = [
    'max-matches', 'first-match', 'max-wait', 'min-batch-size',
    'emit', 'fields', 'stream', 'watch', 'resume', 'no-meta',
  ];
  if (keys.some((k) => flags[k] !== undefined)) return true;
  // --format jsonl/tsv/pretty also imply event output; json alone does not (legacy).
  const fmt = flags['format'];
  return fmt === 'jsonl' || fmt === 'tsv';
}

export class ValidateError extends Error {
  constructor(message: string) { super(message); this.name = 'ValidateError'; }
}

function parsePositiveInt(raw: string | boolean | undefined, flag: string): number | undefined {
  if (raw === undefined) return undefined;
  if (raw === true || raw === false) throw new ValidateError(`${flag} requires an integer value`);
  const n = Number(raw);
  if (!Number.isInteger(n) || n <= 0) throw new ValidateError(`${flag} must be an integer > 0 (got: ${raw})`);
  return n;
}

const EVENT_NAMES: ReadonlySet<string> = new Set<EventName>([
  'meta', 'status', 'progress', 'partial', 'snapshot', 'delta', 'complete', 'error', 'interrupted',
]);
// §4.2 --emit aliases.
const EMIT_ALIASES: Record<string, EventName> = { items: 'partial', progress: 'progress', status: 'status' };

function parseEmit(raw: string | boolean | undefined): Set<EventName> | undefined {
  if (raw === undefined) return undefined;
  if (raw === true || raw === false) throw new ValidateError('--emit requires a comma-separated list');
  const out = new Set<EventName>();
  for (const tok of String(raw).split(',').map((s) => s.trim()).filter(Boolean)) {
    const name = EMIT_ALIASES[tok] ?? tok;
    if (!EVENT_NAMES.has(name)) throw new ValidateError(`--emit: unknown event '${tok}'`);
    out.add(name as EventName);
  }
  return out;
}

const FORMATS: ReadonlySet<string> = new Set<OutputFormat>(['json', 'jsonl', 'tsv', 'pretty']);

function parseFormat(raw: string | boolean | undefined): OutputFormat | undefined {
  if (raw === undefined) return undefined;
  const s = String(raw);
  if (!FORMATS.has(s)) throw new ValidateError(`--format: must be one of json|jsonl|tsv|pretty (got: ${s})`);
  return s as OutputFormat;
}

// Parse the raw flag bag into structured StreamFlags. Throws ValidateError on malformed
// values (these surface as exit code 1 / error.kind:"validate_error").
export function parseStreamFlags(flags: Record<string, string | boolean>): StreamFlags {
  const firstMatch = flags['first-match'] === true || flags['first-match'] === 'true';
  let maxMatches = parsePositiveInt(flags['max-matches'], '--max-matches');
  if (firstMatch) {
    // §4.1: --first-match is an alias for --max-matches 1. If both given, they must agree.
    if (maxMatches !== undefined && maxMatches !== 1) {
      throw new ValidateError('--first-match conflicts with --max-matches (it means --max-matches 1)');
    }
    maxMatches = 1;
  }
  return {
    maxMatches,
    maxWait: parsePositiveInt(flags['max-wait'], '--max-wait'),
    minBatchSize: parsePositiveInt(flags['min-batch-size'], '--min-batch-size') ?? 1,
    emit: parseEmit(flags['emit']),
    format: parseFormat(flags['format']),
    fields: parseFields(flags['fields']),
    stream: flags['stream'] === true || flags['stream'] === 'true',
    watch: flags['watch'] === true || flags['watch'] === 'true',
    resume: typeof flags['resume'] === 'string' ? flags['resume'] : undefined,
    noMeta: flags['meta'] === false || flags['no-meta'] === true,
  };
}

function parseFields(raw: string | boolean | undefined): string[] | undefined {
  if (raw === undefined) return undefined;
  if (raw === true || raw === false) throw new ValidateError('--fields requires a comma-separated list');
  return String(raw).split(',').map((s) => s.trim()).filter(Boolean);
}

// ─── Default-format rules (§4.2) ────────────────────────────────────────────────

export function resolveFormat(flags: StreamFlags, isTTY: boolean): OutputFormat {
  if (flags.format) return flags.format;
  // §4.2: --watch is always jsonl regardless of TTY.
  if (flags.watch) return 'jsonl';
  const bounded = isBounded(flags);
  if (isTTY) return bounded ? 'json' : 'pretty';
  return 'jsonl';
}

// A query is "bounded" iff at least one stop condition is set (§4.1). Only bounded
// queries can be rendered as a single JSON document.
export function isBounded(flags: StreamFlags): boolean {
  return flags.maxMatches !== undefined || flags.maxWait !== undefined;
}

// ─── Validation (§4, §6) — runs BEFORE connecting to IDA (exit 1 on failure) ────

// Validate the flag combination for the given op. Throws ValidateError (→ exit 1).
// `isTTY` is needed to resolve the effective format for the "json on unbounded" rule.
export function validateStream(op: string, flags: StreamFlags, isTTY: boolean): ResolvedStream {
  const spec = OP_SPECS[op];
  if (!spec) throw new ValidateError(`streaming not supported for op '${op}'`);

  const bounded = isBounded(flags);
  const format = resolveFormat(flags, isTTY);

  // §4.2: single-document JSON requires a bounded query.
  if (format === 'json' && !bounded) {
    throw new ValidateError(
      '--format json requires a bounded query (set --first-match, --max-matches, or --max-wait)');
  }

  // §6.5–6.6: non-streamable ops reject the streaming/iteration flags.
  if (!spec.streamable) {
    const offenders: string[] = [];
    if (flags.stream) offenders.push('--stream');
    if (flags.watch) offenders.push('--watch');
    if (flags.maxMatches !== undefined && flags.maxMatches > 1) offenders.push('--max-matches > 1');
    if (offenders.length) {
      throw new ValidateError(
        `op '${op}' produces a single result and cannot stream; remove: ${offenders.join(', ')}`);
    }
  }

  // §4.2 + §6: --fields must name known keys for this op.
  if (flags.fields) {
    if (!spec.streamable && flags.fields.length) {
      // SPEC-GAP: §6.5–6.6 don't define a --fields allow-list for non-streamable ops.
      // We reject --fields on them rather than silently ignore, and note it.
      throw new ValidateError(`--fields is not supported for op '${op}'`);
    }
    const unknown = flags.fields.filter((f) => !spec.allowedFields.includes(f));
    if (unknown.length) {
      throw new ValidateError(
        `--fields: unknown field(s) for '${op}': ${unknown.join(', ')} ` +
        `(allowed: ${spec.allowedFields.join(', ')})`);
    }
  }

  // §4.3 --resume / §5.6 --watch deferred — surface as validate errors so callers get a
  // crisp message instead of silent no-ops. (See report: deferred features.)
  if (flags.resume !== undefined) {
    throw new ValidateError('--resume is not yet implemented (issue #13: deferred)');
  }
  if (flags.watch) {
    throw new ValidateError('--watch is not yet implemented (issue #13: deferred)');
  }

  // Streaming "mode" is on whenever the op is streamable AND the caller asked for any
  // event-shaped output (stop conditions, --stream, or a non-json format).
  const enabled = spec.streamable &&
    (bounded || flags.stream || format === 'jsonl' || format === 'tsv' || flags.watch);

  return { enabled, flags, format, op, spec, bounded };
}

// ─── Item projection (§4.2 --fields) ────────────────────────────────────────────

// Project one item to the requested spec field names, translating spec→internal keys.
// When fields is undefined we still translate internal→spec names so the wire output
// always uses the §6 schema (e.g. `address` → `addr`).
export function projectItem(
  op: string,
  item: Record<string, unknown>,
  fields: string[] | undefined,
): Record<string, unknown> {
  const spec = OP_SPECS[op];
  const wanted = fields ?? spec?.defaultFields;
  const map = FIELD_MAP[op] ?? {};
  // Non-streamable ops have no field list — pass the item through untouched.
  if (!wanted || !wanted.length) return item;
  const out: Record<string, unknown> = {};
  for (const f of wanted) {
    const internalKey = map[f] ?? f;
    if (internalKey in item) out[f] = item[internalKey];
    else if (f in item) out[f] = item[f];  // already a spec-named key
  }
  return out;
}

// ─── Identity / dedup (§5.4) ─────────────────────────────────────────────────────

// Extract the identity value used for within-query dedup. Looks under both the spec
// field name and its internal alias so it works pre- and post-projection.
export function identityOf(op: string, item: Record<string, unknown>): string | null {
  const spec = OP_SPECS[op];
  if (!spec || !spec.identity) return null;
  const map = FIELD_MAP[op] ?? {};
  const key = spec.identity;
  const internal = map[key] ?? key;
  const v = item[key] ?? item[internal];
  return v == null ? null : String(v);
}

// ─── Event factory (§5) ──────────────────────────────────────────────────────────

export function newQueryId(): string {
  return randomUUID();
}

export function now(): number {
  return Date.now();
}

// ─── Serialization (§4.2, §5) ────────────────────────────────────────────────────

// Render a single event to its wire string for the given format. For `json` the caller
// is responsible for emitting exactly one (bounded) document — see EventSink below.
export function serializeEvent(ev: StreamEvent, format: OutputFormat): string {
  switch (format) {
    case 'pretty':
      return prettyEvent(ev);
    case 'tsv':
      return tsvEvent(ev);
    case 'jsonl':
    case 'json':
    default:
      return JSON.stringify(ev) + '\n';
  }
}

function prettyEvent(ev: StreamEvent): string {
  const lines: string[] = [`▸ ${ev.event}`];
  for (const [k, v] of Object.entries(ev)) {
    if (k === 'event' || k === 'query_id' || k === 'ts') continue;
    if (Array.isArray(v)) {
      lines.push(`  ${k}: [${v.length}]`);
      for (const item of v.slice(0, 200)) lines.push(`    ${JSON.stringify(item)}`);
    } else {
      lines.push(`  ${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
    }
  }
  return lines.join('\n') + '\n';
}

// TSV (§4.2): only item-bearing events produce rows; metadata events are dropped from the
// row stream (the header line is emitted once by the sink via `meta`). Each item → one
// tab-separated row, columns ordered by the item's own key order.
function tsvEvent(ev: StreamEvent): string {
  if (!ITEM_EVENTS.has(ev.event)) return '';
  const items = (ev as PartialEvent | SnapshotEvent).items
    ?? [...((ev as DeltaEvent).added ?? [])];
  if (!items || !items.length) return '';
  return items.map((it) => Object.values(it).map(tsvCell).join('\t')).join('\n') + '\n';
}

function tsvCell(v: unknown): string {
  if (v == null) return '';
  return String(v).replace(/[\t\n\r]/g, ' ');
}

// ─── Event sink — owns --emit filtering, TSV headers, and json buffering (§4.2) ──

// The sink is the single chokepoint all events flow through before hitting stdout. It
// enforces: the --emit whitelist (but never suppresses mandatory terminal events), the
// once-only TSV header line, and json single-document buffering.
export class EventSink {
  private readonly emit?: Set<EventName>;
  private readonly format: OutputFormat;
  private readonly op: string;
  private readonly fields: string[] | undefined;
  private tsvHeaderWritten = false;
  private buffered: StreamEvent[] = [];
  private write: (s: string) => void;

  constructor(resolved: ResolvedStream, write: (s: string) => void = (s) => process.stdout.write(s)) {
    this.emit = resolved.flags.emit;
    this.format = resolved.format;
    this.op = resolved.op;
    this.fields = resolved.flags.fields;
    this.write = write;
  }

  // Should this event be printed given the --emit whitelist? Mandatory terminal events
  // always print (§4.2).
  private allowed(name: EventName): boolean {
    if (!this.emit) return true;
    if (MANDATORY_EVENTS.has(name)) return true;
    return this.emit.has(name);
  }

  // Project the items inside an item-bearing event through --fields before serialization.
  private project(ev: StreamEvent): StreamEvent {
    if (!ITEM_EVENTS.has(ev.event)) return ev;
    const clone: any = { ...ev };
    if ('items' in clone && Array.isArray(clone.items)) {
      clone.items = clone.items.map((it: Record<string, unknown>) => projectItem(this.op, it, this.fields));
    }
    if ('added' in clone && Array.isArray(clone.added)) {
      clone.added = clone.added.map((it: Record<string, unknown>) => projectItem(this.op, it, this.fields));
    }
    if ('removed' in clone && Array.isArray(clone.removed)) {
      clone.removed = clone.removed.map((it: Record<string, unknown>) => projectItem(this.op, it, this.fields));
    }
    return clone as StreamEvent;
  }

  push(ev: StreamEvent): void {
    if (!this.allowed(ev.event)) return;
    const projected = this.project(ev);

    if (this.format === 'json') {
      // §4.2: a single bounded JSON document. We buffer and emit the terminal event as
      // the document (matching the spec's example 10.1, which prints only `complete`).
      // SPEC-GAP: §4.2 says "single JSON document" but examples show only the terminal
      // event printed — we follow the examples (print the terminal event object).
      this.buffered.push(projected);
      if (MANDATORY_EVENTS.has(projected.event)) {
        this.write(JSON.stringify(projected) + '\n');
      }
      return;
    }

    if (this.format === 'tsv' && !this.tsvHeaderWritten && ITEM_EVENTS.has(projected.event)) {
      const header = this.tsvHeader(projected);
      if (header) { this.write(header + '\n'); this.tsvHeaderWritten = true; }
    }

    const s = serializeEvent(projected, this.format);
    if (s) this.write(s);
  }

  // Derive the TSV header from the first item-bearing event's first item.
  private tsvHeader(ev: StreamEvent): string | null {
    const items = (ev as PartialEvent | SnapshotEvent).items
      ?? (ev as DeltaEvent).added;
    if (!items || !items.length) return null;
    return Object.keys(items[0]).join('\t');
  }
}
