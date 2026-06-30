# _base.py — shared helpers included at the top of every IDA script (after preamble)
# _json, _os, _RE_OUTPUT_PATH, _RE_COMMAND, _RE_PARAMS are provided by the preamble.
# Do NOT import from re_cli — this runs inside IDA's embedded Python.

import os as _os_base
import idaapi as _idaapi
import idc as _idc
import ida_auto as _ida_auto


def _re_backend_version():
    try:
        return _idaapi.get_kernel_version()
    except Exception:
        return None


def _re_wait_analysis():
    """Block until IDA's autoanalysis queue is drained."""
    _ida_auto.auto_wait()


def _re_write_result(data, backend_version=None):
    result = {
        'status': 'ok',
        'data': data,
        'backendVersion': backend_version or _re_backend_version(),
    }
    with open(_RE_OUTPUT_PATH, 'w') as _f:
        _json.dump(result, _f)


def _re_write_error(exc_type, message, log_excerpt=None):
    err = {'type': exc_type, 'message': message}
    if log_excerpt:
        err['logExcerpt'] = log_excerpt
    result = {
        'status': 'error',
        'data': None,
        'backendVersion': _re_backend_version(),
        'error': err,
    }
    with open(_RE_OUTPUT_PATH, 'w') as _f:
        _json.dump(result, _f)


def _re_exit(code=0):
    # Inside a daemon process the per-query script still runs its
    # `finally: _re_exit(0)` trailer — but exiting would kill the warm database.
    # The daemon sets RE_DAEMON=1, so here we return instead and let the daemon
    # loop continue serving requests. One-shot runs (no env) exit as before.
    if _os_base.environ.get('RE_DAEMON'):
        return
    _idc.qexit(code)


# ─── Shared streaming driver (issue #13 phase 2) ────────────────────────────────────
#
# Factored out of the per-op *.stream.py bodies so the dedup / batching / deadline /
# should_stop / incremental-rescan logic lives in ONE place. A streaming op defines a
# `produce()` generator that yields (identity, row) pairs for the CURRENT database state;
# this driver handles everything else and is the piece that makes cold huge-binary
# streaming actually work (§11.2.1): after the first pass it keeps re-scanning as analysis
# discovers more items, emitting newly-appeared rows as additional `partial` events.
#
# It only runs inside the daemon's stream_exec, which injects _re_emit / _re_should_stop /
# _re_progress / _re_deadline_wait into the namespace; we read those from globals() so this
# file still imports cleanly in the one-shot path (where they're absent).

def _re_stream_run(produce, batch_max=200):
    g = globals()
    emit = g.get('_re_emit')
    should_stop = g.get('_re_should_stop', lambda: False)
    progress = g.get('_re_progress', lambda *a, **k: None)
    state = g.get('_re_stream_state', {})
    resume_seen = g.get('_RE_RESUME_SEEN', set())
    watch_pass = bool(g.get('_RE_WATCH_PASS', False))
    deadline_total = float(g.get('_RE_STREAM_DEADLINE', 600) or 600)

    if emit is None:
        raise RuntimeError('_re_stream_run requires the daemon stream_exec helpers')

    # `seen` starts seeded with the resume watermark so previously-delivered identities are
    # never re-emitted (server-side dedup, §5.4 / acceptance #4). Watch passes start empty
    # of resume state — the runner diffs full snapshots itself.
    seen = set() if watch_pass else set(resume_seen)

    def _scan_once():
        """Emit every not-yet-seen (identity, row) in the current DB. Returns the count of
        newly-emitted rows so the caller can tell whether progress is still being made."""
        batch = []
        new_count = 0
        scanned = 0

        def flush():
            if batch:
                emit(list(batch))
                del batch[:]

        for ident, row in produce():
            # Periodic cooperative-stop check so a client abandon / deadline is noticed mid-scan
            # even on a huge binary where nearly every ident is already delivered (no batch
            # flushes to gate on). The peek is cheap but not free — sample, don't check per row.
            scanned += 1
            if scanned % 4096 == 0 and should_stop():
                flush()
                return new_count, True
            if ident is not None:
                if ident in seen:
                    continue
                seen.add(ident)
            batch.append(row)
            new_count += 1
            if len(batch) >= batch_max:
                flush()
                if should_stop():
                    state['reason'] = 'max_matches'
                    return new_count, True
        flush()
        return new_count, should_stop()

    # ── Watch pass: a single snapshot scan, no deadline wait, no incremental rescan. ──
    if watch_pass:
        _scan_once()
        state['reason'] = 'natural'
        return

    # ── Normal streaming: first scan against current (possibly partial) state, then keep
    #    rescanning as analysis settles so late-discovered items stream too (§11.2.1). ──
    _, stopped = _scan_once()
    if stopped:
        return

    # Incremental loop (§11.2.1): ADVANCE analysis by a slice, then rescan and emit the
    # newly-discovered items, until the deadline / a stop condition / the database settling.
    # The daemon injects `_re_advance_analysis_chunk` (auto_wait_range over address windows):
    # in headless IDA, autoanalysis ONLY progresses while such a call runs on the main thread,
    # so the old `sleep(1.0)` advanced nothing and never streamed past the first scan on a
    # cold binary — the Phase-3 fix. We fall back to a plain sleep if the advancer is absent
    # (e.g. an older daemon), preserving the previous behavior.
    import time as _t
    advance = g.get('_re_advance_analysis_chunk')
    deadline = _t.time() + deadline_total
    idle_rescans = 0
    stalled_rounds = 0
    while _t.time() < deadline:
        if should_stop():
            state['reason'] = 'max_matches'
            return
        if advance is not None:
            advanced, settled = advance()
        else:
            _t.sleep(1.0)
            try:
                settled = _ida_auto.auto_is_ok()
            except Exception:
                settled = True
            advanced = not settled
        new_count, stopped = _scan_once()
        if stopped:
            return
        progress('done' if settled else 'analyzing', 100 if settled else None)
        if settled:
            stalled_rounds = 0
            # Analysis is done. One clean rescan with nothing new ⇒ the result set is final.
            if new_count == 0:
                idle_rescans += 1
                if idle_rescans >= 1:
                    state['settled'] = True
                    state['reason'] = 'db_settled'
                    return
            else:
                idle_rescans = 0
        elif not advanced:
            # Address-windowing is exhausted (stalled) but the queue never reported settled —
            # common when residual non-function work keeps auto_is_ok() False indefinitely. If
            # repeated rescans surface nothing new, no more items are coming via this mechanism,
            # so finish promptly with `natural` instead of idling out the whole --max-wait
            # budget. (A few grace rounds first, in case auto_queue_empty work is imminent.)
            if new_count == 0:
                stalled_rounds += 1
                if stalled_rounds >= 3:
                    state['reason'] = 'natural'
                    return
                _t.sleep(0.5)
            else:
                stalled_rounds = 0
        else:
            stalled_rounds = 0
    # Hit the deadline with analysis still going: stream is "natural" (more may exist later).
    state['reason'] = 'natural'
