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


def _handle(req):
    """Return (response_dict, should_quit)."""
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
