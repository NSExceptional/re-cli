# _base.py — Hopper version of shared helpers (after preamble)
# _json, _os, _RE_OUTPUT_PATH, _RE_COMMAND, _RE_PARAMS provided by preamble.
# 'Document' is injected by Hopper's Python runtime — no import needed.
# Exit via os._exit(0); Hopper has no headless quit API.

import os as _os_base


def _re_write_result(data):
    result = {
        'status': 'ok',
        'data': data,
        'backendVersion': None,  # Hopper doesn't expose its version to Python scripts
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
        'backendVersion': None,
        'error': err,
    }
    with open(_RE_OUTPUT_PATH, 'w') as _f:
        _json.dump(result, _f)


def _re_exit(code=0):
    # Inside a daemon process the per-query script still runs its
    # `finally: _re_exit(0)` trailer — but exiting would kill the warm document.
    # The daemon sets RE_DAEMON=1, so here we return instead and let the daemon
    # loop continue serving requests. One-shot runs (no env) exit as before.
    if _os_base.environ.get('RE_DAEMON'):
        return
    # Force-quit the Hopper process. os._exit skips cleanup but is reliable
    # in headless/automated use where we don't care about GUI teardown.
    _os_base._exit(code)
