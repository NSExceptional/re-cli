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
