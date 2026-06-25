# _daemon.py — Hopper bootstrap that keeps the document warm and serves queries.
#
# Launched as Hopper's `-Y` script (NOT composed with the per-command preamble).
# Hopper would exit once this script returns, so we never return: after analysis we
# bind a Unix-domain socket and loop, exec'ing the exact same composed command scripts
# the CLI builds for one-shot runs. Those scripts end with `finally: _re_exit(0)`, but
# RE_DAEMON=1 (set by the launcher) makes `_re_exit` a no-op (see _base.py), so a query
# no longer kills the process.
#
# Hopper has no .hop save step in the one-shot path and no DSC support, so this daemon
# simply keeps the analyzed `Document` warm in memory. `Document` is injected by Hopper
# into this script's globals; each request is exec'd in a copy of those globals so it
# stays visible.
#
# Parameters arrive via environment variables:
#   RE_DAEMON        = "1"            (also flips _re_exit to a no-op)
#   RE_DAEMON_SOCKET = <unix socket path to bind>
#   RE_DAEMON_IDLE   = <seconds idle before self-shutdown>

import os
import sys
import json
import struct
import socket

SOCK_PATH = os.environ.get('RE_DAEMON_SOCKET', '')
IDLE_SEC = float(os.environ.get('RE_DAEMON_IDLE', '1800') or '1800')


def _log(msg):
    sys.stderr.write('[re-daemon] %s\n' % msg)
    sys.stderr.flush()


def _wait_analysis():
    # Best-effort: ensure background analysis is finished before we serve.
    try:
        doc = Document.getCurrentDocument()
        waiter = getattr(doc, 'waitForBackgroundProcessToEnd', None)
        if callable(waiter):
            waiter()
    except Exception as e:
        _log('analysis wait skipped: %s' % e)


def _input_path():
    try:
        doc = Document.getCurrentDocument()
        for attr in ('getExecutablePath', 'executablePath', 'getFilePath'):
            fn = getattr(doc, attr, None)
            if callable(fn):
                try:
                    return fn()
                except Exception:
                    pass
    except Exception:
        pass
    return None


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
            'input': _input_path(),
        }}, False

    if kind == 'exec':
        script = req.get('script', '')
        try:
            # Seed the namespace from the daemon globals so Hopper's injected
            # `Document` (and anything else it provides) is visible to the script.
            ns = dict(globals())
            ns['__name__'] = '__re_request__'
            exec(compile(script, '<re-request>', 'exec'), ns)
            return {'id': rid, 'ok': True}, False
        except BaseException as e:
            return {'id': rid, 'ok': False,
                    'error': '%s: %s' % (type(e).__name__, e)}, False

    return {'id': rid, 'ok': False, 'error': 'unknown request type: %r' % kind}, False


def _serve():
    if not SOCK_PATH:
        _log('RE_DAEMON_SOCKET not set; aborting')
        os._exit(2)

    _log('analysis: waiting for Hopper background processing…')
    _wait_analysis()

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
    os._exit(0)


_serve()
