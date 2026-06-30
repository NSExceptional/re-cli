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

    def _emit(items):
        if not items:
            return
        state['count'] += len(items)
        _send_frame(conn, {'id': rid, 'kind': 'partial', 'items': items,
                           'count': state['count']})

    def _progress(phase=None, percent=None):
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


def _handle(req):
    """Return (response_dict, should_quit). Only for single-response request types;
    `stream_exec` is handled inline in the serve loop because it writes many frames."""
    rid = req.get('id')
    kind = req.get('type')

    if kind == 'quit':
        return {'id': rid, 'ok': True}, True

    if kind == 'ping':
        return {'id': rid, 'ok': True, 'meta': {
            'pid': os.getpid(),
            'kernel': idaapi.get_kernel_version(),
            'input': idc.get_input_file_path(),
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

    _log('analysis: waiting for autoanalysis to finish…')
    ida_auto.auto_wait()

    if SAVE_IDB:
        _log('saving database to %s' % SAVE_IDB)
        _save_database(SAVE_IDB)

    # Bind only now: the client treats "socket is connectable" as "daemon ready".
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
    srv.settimeout(IDLE_SEC)
    _log('ready, listening on %s (idle timeout %ss)' % (SOCK_PATH, IDLE_SEC))

    quit_requested = False
    while not quit_requested:
        try:
            conn, _ = srv.accept()
        except socket.timeout:
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
                    continue
                resp, should_quit = _handle(req)
                _send_frame(conn, resp)
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
