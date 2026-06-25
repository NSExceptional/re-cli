# Design: persistent disassembler daemon (warm IDA/Hopper sessions)

**Issue:** [#1 — Sequential queries on large databases are slow](https://github.com/NSExceptional/re-cli/issues/1)
**Date:** 2026-06-24
**Status:** Approved-pending-review

## Problem

Every `re <command> <binary>` spawns a fresh backend process (`idat64 -A … <db>` or
`hopper -d <doc>`), which loads the entire analysis database into memory, runs one
short script, and exits. For a large target the cached database is multi-GB (e.g. a
752 MB framework → multi-GB `.i64`), so the per-query database-load cost dominates.

**N sequential queries against the same large binary = N full database loads.** The
result cache only helps on *repeat identical* queries; a sweep of distinct queries
(an `xrefs` pass over many call sites, a series of `decompile --function` calls) pays
the full reload every time. This is the reported slowness.

## Goal

Load a large database once and keep it warm, so a series of distinct queries against
it run at warm-cache speed (sub-second) instead of paying a cold load each time —
without changing the output contract, the result cache, or one-shot behavior for
small binaries.

## Core idea: a generic "exec server" inside a warm backend process

The only thing that makes a backend process single-shot is the trailer every command
script runs:

```python
try:    _re_write_result(_collect())
except Exception as _e: _re_write_error(type(_e).__name__, str(_e))
finally: _re_exit(0)      # idc.qexit() (IDA) / os._exit() (Hopper) — kills the process
```

So a daemon is simply: **keep one backend process alive with the database loaded, and
feed it the exact same composed scripts the CLI already builds — but neutralize
`_re_exit` so the process doesn't die after each query.**

This yields near-total reuse:

- **`_base.py` (both backends):** `_re_exit` becomes a no-op when `RE_DAEMON=1` is set
  in the process environment. The daemon sets that env; one-shot runs do not. **Command
  scripts are untouched.**
- **Per-request script:** composed by the existing `composeScript()` in `runner.ts`,
  verbatim. It still writes its JSON to the client-chosen `_RE_OUTPUT_PATH`.
- **Client post-processing:** reading the output file → standard envelope → result
  cache → idb-meta is all the existing `run()` logic, factored into a shared helper and
  reused by both the spawn path and the daemon path.

A single query therefore differs from today in exactly one way: instead of *spawning*
a backend, the client sends the composed script over a Unix-domain socket to an
*already-warm* process and awaits a "done"; the result is already on disk at the path
the client chose, read exactly as today.

The daemon is **generic** — it execs whatever script it is sent — so new commands need
**zero daemon changes**.

## Components

### 1. `scripts/ida/_base.py` / `scripts/hopper/_base.py` (change: ~2 lines each)

`_re_exit(code)` checks `os.environ.get('RE_DAEMON')`; if set, return without exiting.
One-shot behavior is unchanged (env unset → real `qexit`/`os._exit`).

### 2. `scripts/ida/_daemon.py` (new)

Bootstrap launched as the backend's `-S` script. Responsibilities:

1. If fresh analysis: `auto_wait()` then `save_database()` to the cache `.i64` path so
   future one-shot runs can reuse it. If opening a cached `.i64`: `auto_wait()` returns
   fast.
2. Create the Unix-domain socket **only after** analysis completes, so "client can
   connect" == "daemon ready".
3. Loop: read a length-prefixed JSON request, dispatch, reply, repeat. `accept()` uses
   a timeout equal to the idle timeout; on timeout (no requests) → clean shutdown.
4. On `quit` request or idle timeout: remove socket, `qexit`.

Request handling (`type: "exec"`): `exec(compile(script, "<re-request>", "exec"), ns)`
where `ns` is a fresh dict seeded from the daemon globals (so `Document` is present for
Hopper). Because `RE_DAEMON=1`, the script's `finally: _re_exit(0)` is a no-op; the
script has written its result to `_RE_OUTPUT_PATH`. Reply `{id, ok: true}`. If `exec`
itself raises before the script's own handler catches it, reply `{id, ok: false, error}`.
Requests are processed one at a time (single backend thread); concurrent clients queue
at the OS accept backlog.

### 3. `scripts/hopper/_daemon.py` (new)

Same shape, Hopper flavored: launched via `-Y`; uses the injected `Document` global
(seeded into each exec namespace); shutdown via `os._exit(0)` (Hopper has no quit API).
Hopper has no DSC support, so Hopper daemons are standalone-binary only.

Note: Hopper's one-shot path does not currently persist a `.hop` (its fresh
`buildHopperCommand` has no save step), so the existing `.hop` disk fast-path is dormant
and every one-shot Hopper query re-analyzes. The daemon therefore delivers an even
larger win for Hopper by keeping the analyzed `Document` warm **in memory**. Persisting
`.hop` to disk for one-shot reuse is best-effort/out of scope here and tracked
separately.

### 4. `src/daemon.ts` (new)

TS-side daemon manager — the one new unit of orchestration:

- **Registry:** `~/.cache/re-cli/daemons/<key>/meta.json` records `{ pid, socketPath,
  binaryPath, binHash, mtimeMs, size, backend, module?, startedAt }`. `<key>` =
  `binHash[+moduleSegment]`.
- **Socket path:** `/tmp/re-cli/<backendInitial><binHash>[<modHash>].sock` — a short,
  dedicated dir to stay under macOS's ~104-char UDS limit.
- **`ensureDaemon(...)`:** if a live, non-stale daemon serves this key, return its
  socket. Otherwise acquire a startup lock (atomic `mkdir` of `<key>/lock`), spawn the
  backend detached (`spawn(..., { detached: true, stdio: 'ignore' }).unref()`) with
  `RE_DAEMON=1`, then poll the socket for connectability while narrating progress by
  tailing the daemon's `-L` log (reusing the heartbeat helper extracted from
  `spawnTool`). Concurrent callers that lose the lock poll the same socket.
- **`sendScript(socketPath, script)`:** length-prefixed JSON request/response over the
  UDS; resolves when the daemon replies "done".
- **Staleness/health:** before use, compare recorded `mtimeMs`/`size` to the binary on
  disk; mismatch ⇒ `stop()` the daemon (stale DB) and re-analyze. A dead socket
  (`ECONNREFUSED`/missing) ⇒ remove registry entry, fall back to one-shot.
- **`stop(key | all)` / `list()`:** signal `quit` (or `SIGTERM`), clean registry + socket.

### 5. `src/runner.ts` (change)

In `run()`, after the result-cache fast-path and backend resolution, resolve a daemon
*mode* from `--daemon` (default `auto`) and decide the execution strategy for analysis
commands:

- **`off`** → always **one-shot** (today's path).
- **`auto`** → **one-shot** when `daemon.enabled=false`, `--no-idb-cache`, or binary
  size < `autostartMinMb`; otherwise the **daemon path**.
- **`on`** → **daemon path**, bypassing the size gate and overriding
  `daemon.enabled=false`. `--no-idb-cache` still forces one-shot (a daemon implies a
  persisted/warm DB, which contradicts forced fresh analysis); a stderr notice explains
  the downgrade.
- **Daemon path:** `ensureDaemon(...)` → `sendScript(...)` → read the output
  file and produce the `REResult` via the **shared post-processing helper** also used by
  the one-shot path. Result cache and idb-meta writing behave exactly as today (for a
  fresh daemon, idb-meta is written after the daemon reports analysis complete + saved).
- If the daemon path fails to start or connect, fall back to one-shot and log a notice
  to stderr.

The one-shot mechanics (`spawnTool`, `buildIdaCommand`/`buildHopperCommand`) are
unchanged; the daemon reuses `buildIdaCommand`/`buildHopperCommand` to construct its
launch args, passing `_daemon.py` as the script.

### 6. `src/main.ts` (change)

- New `re daemon` subcommand group: `start <binary>`, `stop <binary>` / `stop --all`,
  `list` (alias `status`). `start`/`stop` accept the same `--arch` / DSC source flags as
  analysis commands so they target the right key.
- New global flag `--daemon=auto|on|off` (default `auto`; accepts truthy/falsy values,
  e.g. `--daemon` → `on`, `--no-daemon`/`--daemon=false` → `off`). An unrecognized value
  is a usage error. A small normalizer maps the parsed flag to the `auto|on|off` mode.
- Help text updated.

### 7. `src/config.ts` (change)

Add a `daemon` block: `{ enabled: true, idleTimeout: 1800, autostartMinMb: 10 }`
(1800 s = 30 min). Merged with the same defaults pattern as the existing blocks.

### 8. `README.md` (change)

Document the daemon in "Performance & long-running analysis" and the command table:
auto-start behavior, the size gate, `re daemon` commands, `--no-daemon`, and config.

## Wire protocol (UDS, length-prefixed JSON)

- Frame: 4-byte big-endian length, then UTF-8 JSON.
- Request: `{ "id": N, "type": "exec" | "ping" | "quit", "script"?: "<python>" }`.
- Response: `{ "id": N, "ok": true }` | `{ "id": N, "ok": false, "error": "..." }`.
  `ping` → `{ "id": N, "ok": true, "meta": {...} }`.

The result payload itself is **not** sent over the socket — it is written by the script
to the client's `_RE_OUTPUT_PATH` (same machine, same user), and the client reads it
exactly as the one-shot path does after the daemon acknowledges completion. The client
deletes its temp dir only after receiving the acknowledgement.

## Behavior summary

| Scenario | Behavior |
| --- | --- |
| `re <cmd> <big binary>` (no daemon yet) | Auto-start daemon (analyze once), serve query; daemon stays warm |
| subsequent `re <cmd> <same binary>` | Routed to warm daemon, sub-second |
| `re <cmd> <small binary>` (< 10 MB) | One-shot (no daemon) |
| `--daemon=on <small binary>` | Force a daemon anyway (bypasses size gate) |
| `--daemon=off` (or `daemon.enabled=false` under `auto`) | Always one-shot |
| `--no-idb-cache` | One-shot fresh analysis (never daemonized) |
| binary changed on disk | Stale daemon stopped, re-analyzed |
| 30 min idle | Daemon self-shuts-down, frees RAM |
| `re daemon start/stop/list` | Explicit lifecycle control |

## Concurrency, safety, lifecycle

- **One request at a time per daemon** (single backend thread); OS accept backlog
  serializes concurrent clients.
- **Startup lock** (atomic `mkdir`) prevents two concurrent first-queries from
  double-spawning/double-analyzing; the loser polls the socket.
- **Detached** daemon outlives the foreground `re` process; survives until idle/stop.
- **Security:** UDS under a user-owned dir; nothing on TCP.
- **Crash recovery:** missing/refused socket ⇒ registry cleanup + one-shot fallback.

## Out of scope (possible follow-ups)

- Multi-DB sharing within one process (one process per database is simpler and isolates
  failures).
- A daemon RAM cap / LRU eviction across many daemons (idle timeout is the v1 control).
- Hopper DSC support (Hopper can't load DSC modules at all today).

## Testing

- **Smoke (small):** `re info /bin/ls` still works one-shot (under size gate); output
  identical to before.
- **Daemon lifecycle:** force a low `autostartMinMb` (or `re daemon start`) on `/bin/ls`;
  verify a daemon appears in `re daemon list`, a second query is served warm, identical
  JSON to one-shot, `re daemon stop` reaps it.
- **Both backends:** repeat the lifecycle test with `--backend ida` and
  `--backend hopper`; verify a looping Hopper `-Y` script services multiple requests
  (validates the persistence assumption).
- **Staleness:** `touch` the binary; verify the next query restarts the daemon.
- **Concurrency:** two queries launched together start exactly one daemon.
- **Fallback:** `--daemon=off` and `--no-idb-cache` take the one-shot path;
  `--daemon=on` forces a daemon for a sub-threshold binary.
- **Idle:** set a short idle timeout; verify the daemon self-exits.
- **Large binary:** confirm second distinct query is sub-second vs. a cold load.
- `npm run typecheck` clean.
