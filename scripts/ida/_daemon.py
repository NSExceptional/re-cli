# _daemon.py — IDA bootstrap that keeps the database warm and serves queries.
#
# Launched as the backend `-S` script (NOT composed with the per-command preamble).
# In `-A` batch mode IDA would exit once this script returns, so we never return:
# after analysis we bind a Unix-domain socket and loop, exec'ing the exact same
# composed command scripts the CLI builds for one-shot runs. Those scripts end with
# `finally: _re_exit(0)`, but RE_DAEMON=1 (set by the launcher) makes `_re_exit` a
# no-op (see _base.py), so a query no longer kills the process.
#
# Parameters arrive via environment variables so the `-S<path>` form stays clean:
#   RE_DAEMON        = "1"            (also flips _re_exit to a no-op)
#   RE_DAEMON_SOCKET = <unix socket path to bind>
#   RE_DAEMON_IDLE   = <seconds idle before self-shutdown>
#   RE_DAEMON_SAVE_IDB = <path>       (fresh analysis only: persist the .i64 here)

import os
import sys
import json
import struct
import socket
import time

import idc
import idaapi
import ida_auto

try:
    import ida_loader
except ImportError:
    ida_loader = None

SOCK_PATH = os.environ.get('RE_DAEMON_SOCKET', '')
IDLE_SEC = float(os.environ.get('RE_DAEMON_IDLE', '1800') or '1800')
SAVE_IDB = os.environ.get('RE_DAEMON_SAVE_IDB', '')

# Live streaming-query telemetry for `re status` (issue #13 criterion #2). A streaming
# exec updates this; `ping` reports it so `re status <binary>` can surface items-emitted
# and a rough ETA WITHOUT consuming the query. Reset when a stream ends.
_STREAM_STATS = {
    'active': False,
    'op': None,
    'started': 0.0,
    'items': 0,
    'phase': None,
    'deadline': 0.0,   # absolute epoch deadline of the in-flight stream, for ETA
}


def _log(msg):
    # Goes to IDA's -L log, which the client tails for startup progress.
    sys.stderr.write('[re-daemon] %s\n' % msg)
    sys.stderr.flush()


def _save_database(path):
    # The daemon never calls qexit, so IDA's normal save-on-exit won't fire; persist
    # the freshly analyzed database explicitly so later one-shot runs can reuse it.
    try:
        if ida_loader is not None:
            ida_loader.save_database(path, 0)
        else:
            idc.save_database(path, 0)
        return True
    except Exception as e:
        _log('save_database failed (serving from memory): %s' % e)
        return False


# ─── Incremental analysis driver (issue #13 Phase 3) ────────────────────────────────
#
# Headless IDA is single-threaded: autoanalysis only progresses while an auto_wait* call
# runs on the main thread. The old daemon called one blocking auto_wait() up front (so the
# socket bound only after ~80 min on a huge Swift binary) and the streaming wait was a pure
# sleep() loop that never ADVANCED analysis. Both are fixed by advancing analysis in bounded
# address-window slices via auto_wait_range, so the daemon stays reachable AND a streaming
# query can emit partials + check its deadline between slices. The frontier is module-global
# so progress accumulates across the idle loop and successive queries.

_ADV = {
    'ranges': None,    # [(start,end)] code segments, computed lazily after load
    'frontier': None,  # next EA to sweep
    'swept': False,    # covered the whole span at least once this pass
    'last_qty': -1,    # func count at the end of the last completed sweep (stall detection)
    'stalled': False,  # windowing can no longer surface new work (e.g. undriveable queue)
}
# Window size for one analysis slice. Smaller = the daemon returns to its accept loop sooner
# (more responsive to new queries) and gives finer partials; larger = less per-slice overhead.
# 256 KB keeps a normal slice short; note a slice that drains the global queue can still
# trigger an uninterruptible global pass (e.g. Swift metadata) regardless of this size — the
# client's hard deadline is what bounds a query across such a slice.
ADVANCE_WINDOW = int(os.environ.get('RE_ADVANCE_WINDOW', '0x40000') or '0x40000', 16)


def _safe_auto_is_ok():
    try:
        return bool(ida_auto.auto_is_ok())
    except Exception:
        # If we can't tell, treat as settled so callers don't spin forever.
        return True


def _adv_ranges():
    if _ADV['ranges'] is None:
        rs = []
        try:
            import ida_segment
            seg = ida_segment.get_first_seg()
            while seg:
                try:
                    code = (seg.type == idaapi.SEG_CODE)
                except Exception:
                    code = True
                if code:
                    rs.append((seg.start_ea, seg.end_ea))
                seg = ida_segment.get_next_seg(seg.start_ea)
        except Exception:
            rs = []
        if not rs:
            try:
                rs = [(idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea())]
            except Exception:
                rs = []
        _ADV['ranges'] = rs
        _ADV['frontier'] = rs[0][0] if rs else None
    return _ADV['ranges']


def _advance_analysis_chunk():
    """Advance autoanalysis by ~one address window and return (advanced, settled).

    `advanced` is True if a slice ran (more may have appeared); `settled` is auto_is_ok().
    Re-sweeps after a full pass to pick up work enqueued by auto_queue_empty (e.g. the Swift
    metadata pass, which only fires once the global queue drains). If a whole sweep surfaces
    no new functions and the queue still isn't settled, sets `_ADV['stalled']` so callers
    stop spinning on work that address-windowing cannot drive."""
    if _safe_auto_is_ok():
        _ADV['stalled'] = False
        return (False, True)
    if not hasattr(ida_auto, 'auto_wait_range'):
        ida_auto.auto_wait()  # no incremental API on this IDA — one bounded full wait
        return (False, _safe_auto_is_ok())
    ranges = _adv_ranges()
    if not ranges:
        ida_auto.auto_wait()
        return (False, _safe_auto_is_ok())

    if not _ADV['swept']:
        f = _ADV['frontier'] if _ADV['frontier'] is not None else ranges[0][0]
        for (s, e) in ranges:
            if f < e:
                a = f if f > s else s
                b = a + ADVANCE_WINDOW
                if b > e:
                    b = e
                ida_auto.auto_wait_range(a, b)
                _ADV['frontier'] = b
                if b >= ranges[-1][1]:
                    _ADV['swept'] = True
                return (True, _safe_auto_is_ok())
        _ADV['swept'] = True

    # Whole span swept once and still not settled (top guard). If new functions appeared,
    # more work is likely queued (Swift pass) — re-sweep from the start to process it.
    try:
        import ida_funcs
        qty = ida_funcs.get_func_qty()
    except Exception:
        qty = -1
    if qty != _ADV['last_qty']:
        _ADV['last_qty'] = qty
        _ADV['swept'] = False
        _ADV['frontier'] = ranges[0][0]
        return (True, _safe_auto_is_ok())

    # A full sweep surfaced nothing new yet the queue isn't settled: address-windowing can't
    # drive whatever is left. Mark stalled so the idle loop stops advancing (a client query
    # that calls a full auto_wait can still finalize it).
    _ADV['stalled'] = True
    return (False, _safe_auto_is_ok())


def _maybe_save_settled(saved_flag):
    """Persist the freshly analyzed .i64 exactly once, only when analysis has truly settled.
    Saving a PARTIAL database to the cache path would let later one-shot runs reload it and
    serve incomplete results as if complete, so we never save mid-analysis (this intentionally
    narrows spec §11.4's 'save after every query' for one-shot cache correctness)."""
    if saved_flag[0] or not SAVE_IDB:
        return
    if _safe_auto_is_ok():
        _log('analysis settled; saving database to %s' % SAVE_IDB)
        _save_database(SAVE_IDB)
        saved_flag[0] = True


def _recvn(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _recv_frame(conn):
    hdr = _recvn(conn, 4)
    if hdr is None:
        return None
    (length,) = struct.unpack('>I', hdr)
    body = _recvn(conn, length)
    if body is None:
        return None
    return json.loads(body.decode('utf-8'))


def _send_frame(conn, obj):
    data = json.dumps(obj).encode('utf-8')
    conn.sendall(struct.pack('>I', len(data)) + data)


def _deadline_wait(deadline_sec):
    """Deadline-bounded replacement for raw auto_wait() (spec §11.3). Never blocks
    forever on a Swift-metadata queue that won't drain; streaming works against partial
    state. Returns True if analysis fully settled, False if we proceeded on the deadline."""
    deadline = time.time() + max(0.0, float(deadline_sec))
    while time.time() < deadline:
        try:
            busy = idaapi.is_auto_enabled() and not ida_auto.auto_is_ok()
        except Exception:
            # Older/newer IDA API drift — fall back to auto_is_ok alone.
            try:
                busy = not ida_auto.auto_is_ok()
            except Exception:
                busy = False
        if not busy:
            return True
        time.sleep(0.5)
    return False


def _stream_exec(conn, req):
    """Handle a streaming exec (issue #13). The composed script is given three helpers in
    its namespace — emit(items), should_stop(), progress(phase, percent) — and is expected
    to drive them, then the script ends. We always send a terminal `final` frame so the
    client never sees NoOutput. Frames are written directly to `conn`."""
    rid = req.get('id')
    script = req.get('script', '')
    deadline_sec = float(req.get('deadline', 600) or 600)

    state = {'count': 0, 'stopped': False, 'reason': 'natural', 'settled': False}

    # Publish live telemetry for `re status`. A --watch query re-runs many short passes; we
    # only mark a pass "active" so status sees the daemon is busy, and accumulate items.
    _STREAM_STATS.update({
        'active': True, 'op': req.get('op'), 'started': time.time(),
        'items': 0, 'phase': None, 'deadline': time.time() + deadline_sec,
    })

    def _emit(items):
        if not items:
            return
        state['count'] += len(items)
        _STREAM_STATS['items'] = state['count']
        _send_frame(conn, {'id': rid, 'kind': 'partial', 'items': items,
                           'count': state['count']})

    def _progress(phase=None, percent=None):
        _STREAM_STATS['phase'] = phase
        _send_frame(conn, {'id': rid, 'kind': 'progress',
                           'phase': phase, 'percent': percent})

    def _should_stop():
        # The client closes the connection to request a cooperative early stop; detect a
        # peer-closed socket without blocking. (Non-blocking peek.)
        if state['stopped']:
            return True
        try:
            conn.setblocking(False)
            try:
                peek = conn.recv(1, socket.MSG_PEEK)
                if peek == b'':
                    state['stopped'] = True
                    state['reason'] = 'client_closed'
            except (BlockingIOError, socket.error):
                pass
            finally:
                conn.setblocking(True)
        except Exception:
            pass
        return state['stopped']

    def _deadline(secs=None):
        return _deadline_wait(deadline_sec if secs is None else secs)

    ns = {
        '__name__': '__re_stream__',
        '__builtins__': __builtins__,
        '_re_emit': _emit,
        '_re_progress': _progress,
        '_re_should_stop': _should_stop,
        '_re_deadline_wait': _deadline,
        '_RE_STREAM_DEADLINE': deadline_sec,
        '_re_stream_state': state,
        # Phase 3: the chunked driver in _base.py uses this to ADVANCE analysis between
        # rescans (auto_wait_range slices) instead of sleeping while nothing progresses.
        '_re_advance_analysis_chunk': _advance_analysis_chunk,
    }
    try:
        exec(compile(script, '<re-stream>', 'exec'), ns)
        # The script may set its own terminal reason in _re_stream_state; default natural.
        final = {'id': rid, 'kind': 'final', 'final': True, 'ok': True,
                 'count': state['count'], 'reason': state.get('reason', 'natural')}
        _send_frame(conn, final)
    except BaseException as e:
        # Spec §5.8 / §11.2.4: a crashed streaming script must still yield a terminal frame.
        _send_frame(conn, {'id': rid, 'kind': 'final', 'final': True, 'ok': False,
                           'count': state['count'],
                           'error': '%s: %s' % (type(e).__name__, e)})
    finally:
        _STREAM_STATS['active'] = False


def _handle(req):
    """Return (response_dict, should_quit). Only for single-response request types;
    `stream_exec` is handled inline in the serve loop because it writes many frames."""
    rid = req.get('id')
    kind = req.get('type')

    if kind == 'quit':
        return {'id': rid, 'ok': True}, True

    if kind == 'ping':
        # Surface live streaming telemetry for `re status` (issue #13 #2): items emitted so
        # far, the coarse phase, elapsed, and a rough ETA = remaining budget to the stream's
        # deadline (honest "time until we stop waiting", since IDA gives no true completion
        # ETA). All null/absent when no stream is in flight.
        stream = None
        if _STREAM_STATS.get('active'):
            now_t = time.time()
            try:
                settled = ida_auto.auto_is_ok()
            except Exception:
                settled = None
            eta = None
            if not settled and _STREAM_STATS.get('deadline'):
                eta = max(0, int(round(_STREAM_STATS['deadline'] - now_t)))
            stream = {
                'op': _STREAM_STATS.get('op'),
                'itemsEmitted': _STREAM_STATS.get('items', 0),
                'phase': _STREAM_STATS.get('phase'),
                'elapsedSec': int(round(now_t - _STREAM_STATS.get('started', now_t))),
                'etaSec': 0 if settled else eta,
                'settled': settled,
            }
        return {'id': rid, 'ok': True, 'meta': {
            'pid': os.getpid(),
            'kernel': idaapi.get_kernel_version(),
            'input': idc.get_input_file_path(),
            # Phase 3: with the socket bound before analysis finishes, "connectable" no longer
            # means "done". Report a stable-state signal so `re status`/`re wait` show WARMING
            # vs READY truthfully: either the queue truly drained (auto_is_ok) OR address-
            # windowing exhausted (stalled). Some binaries keep auto_is_ok() False indefinitely
            # on residual non-function work, so stalled is what makes `re wait` terminate.
            'settled': _safe_auto_is_ok() or bool(_ADV.get('stalled')),
            'stream': stream,
        }}, False

    if kind == 'exec':
        script = req.get('script', '')
        try:
            # Fresh namespace per request: the composed script re-imports what it
            # needs and operates on IDA's process-global database, so request
            # isolation only needs a clean dict (requests are serialized anyway).
            ns = {'__name__': '__re_request__', '__builtins__': __builtins__}
            exec(compile(script, '<re-request>', 'exec'), ns)
            return {'id': rid, 'ok': True}, False
        except BaseException as e:
            return {'id': rid, 'ok': False,
                    'error': '%s: %s' % (type(e).__name__, e)}, False

    return {'id': rid, 'ok': False, 'error': 'unknown request type: %r' % kind}, False


def _serve():
    if not SOCK_PATH:
        _log('RE_DAEMON_SOCKET not set; aborting')
        idc.qexit(2)
        return

    # Bind BEFORE analysis finishes (Phase 3): the daemon must be reachable WHILE a huge
    # binary is still analyzing, so a streaming query can attach and drive/observe partial
    # results instead of the client blocking ~80 min waiting for the socket to appear. The
    # old code called a blocking auto_wait() here first — that was the cold-stream hang.
    try:
        os.makedirs(os.path.dirname(SOCK_PATH), exist_ok=True)
    except OSError:
        pass
    try:
        os.unlink(SOCK_PATH)
    except OSError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCK_PATH)
    srv.listen(16)
    _log('listening on %s (analysis in progress; idle timeout %ss)' % (SOCK_PATH, IDLE_SEC))

    # While warming with no client connected, advance analysis a slice between accept()
    # attempts so the database keeps progressing (and eventually settles + saves) in the
    # background. A short accept timeout keeps first-connect latency to about one slice.
    WARM_TICK = float(os.environ.get('RE_WARM_TICK', '0.5') or '0.5')
    saved = [False]

    quit_requested = False
    while not quit_requested:
        settled = _safe_auto_is_ok()
        if settled:
            _maybe_save_settled(saved)
        # Warming = not settled AND address-windowing can still surface new work. Once settled
        # or stalled, use the long idle timeout (the analysis cannot be advanced further here).
        warming = (not settled) and (not _ADV['stalled'])
        srv.settimeout(WARM_TICK if warming else IDLE_SEC)
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            if warming:
                _advance_analysis_chunk()  # background slice, then re-check for a client
                continue
            _log('idle timeout reached; shutting down')
            break
        except Exception as e:
            _log('accept error: %s' % e)
            break

        conn.settimeout(IDLE_SEC)
        try:
            while True:
                req = _recv_frame(conn)
                if req is None:
                    break  # client closed the connection
                if req.get('type') == 'stream_exec':
                    # Streaming requests write their own frames (many) then a terminal one.
                    _stream_exec(conn, req)
                    _maybe_save_settled(saved)  # the stream may have settled analysis
                    continue
                resp, should_quit = _handle(req)
                _send_frame(conn, resp)
                _maybe_save_settled(saved)  # a legacy full auto_wait() may have settled it
                if should_quit:
                    quit_requested = True
                    break
        except Exception as e:
            _log('connection error: %s' % e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    try:
        srv.close()
        os.unlink(SOCK_PATH)
    except OSError:
        pass
    _log('exiting')
    idc.qexit(0)


_serve()
