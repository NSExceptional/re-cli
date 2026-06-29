// Heartbeat narration for long analyses. The backend (esp. IDA on Swift binaries)
// emits a torrent of near-identical log lines; echoing the latest one every tick
// produced "a fullscreen of `…13s elapsed SWIFT: …` repeats" (field feedback).
//
// Instead we surface: elapsed time, a coarse phase guessed from the log, and the
// most recent *distinct* informative line — collapsing unchanged ticks to a quiet
// "working…". IDA does not expose a thread-safe live progress %, so we report phase
// rather than fabricate a percentage.

import { openSync, fstatSync, readSync, closeSync } from 'node:fs';
import process from 'node:process';

// Read only the tail of a possibly-huge (tens of MB) analysis log.
export function tailRead(path: string, maxBytes = 16384): string {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'r');
    const size = fstatSync(fd).size;
    const len = Math.min(size, maxBytes);
    const buf = Buffer.alloc(len);
    readSync(fd, buf, 0, len, size - len);
    return buf.toString('utf8');
  } catch {
    return '';
  } finally {
    if (fd !== undefined) try { closeSync(fd); } catch {}
  }
}

// Ordered most-specific-first. Matched against recent log lines to label the phase.
const PHASES: [RegExp, string][] = [
  [/has been finished|final pass|already.*explore/i, 'finalizing'],
  [/ARM_REGTRACK|reg-?track/i, 'register tracking'],
  [/\bswift\b/i, 'Swift metadata'],
  [/propagat/i, 'type propagation'],
  [/analy[sz]|exploring|input file|disassembl/i, 'autoanalysis'],
];

function phaseOf(lines: string[]): string | undefined {
  for (let i = lines.length - 1; i >= 0 && i > lines.length - 60; i--) {
    for (const [re, name] of PHASES) if (re.test(lines[i])) return name;
  }
  return undefined;
}

export interface HbState { lastLine?: string; phase?: string; }

// Pure, unit-testable: build one heartbeat line from the current log tail. Threads
// HbState across ticks so an unchanged log line collapses to "working…" instead of
// repeating, and a phase persists once detected.
export function formatHeartbeat(logText: string, secs: number, prev: HbState): { line: string; state: HbState } {
  const lines = logText ? logText.split('\n').map((l) => l.trim()).filter(Boolean) : [];
  const last = lines.length ? lines[lines.length - 1] : '';
  const phase = phaseOf(lines) ?? prev.phase;

  let line = `[re] …${secs}s elapsed`;
  if (phase) line += ` · ${phase}`;
  if (last && last !== prev.lastLine) {
    line += ` · ${last.slice(0, 80)}`;
  } else if (last) {
    line += ' · working…';
  }
  return { line: line + '\n', state: { lastLine: last, phase } };
}

// Start narrating a long backend run to stderr. Silent for the first few seconds so
// fast cache reloads stay quiet; returns a stop() to clear timers. Shared by the
// one-shot (runner) and daemon-startup (daemon) paths.
export function startNarrator(logPath: string, label: string): () => void {
  const start = Date.now();
  let state: HbState = {};
  let heartbeat: ReturnType<typeof setInterval> | undefined;
  const banner = setTimeout(() => {
    process.stderr.write(`[re] ${label} — working, this can take several minutes…\n`);
    heartbeat = setInterval(() => {
      const secs = Math.round((Date.now() - start) / 1000);
      const r = formatHeartbeat(tailRead(logPath), secs, state);
      state = r.state;
      process.stderr.write(r.line);
    }, 10_000);
  }, 3_000);
  return () => { clearTimeout(banner); if (heartbeat) clearInterval(heartbeat); };
}
