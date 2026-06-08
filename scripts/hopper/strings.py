# strings.py (Hopper) — Hopper's Python API has no string enumeration iterator.
# Use --backend ida for this command.


def _collect():
    raise NotImplementedError(
        'Hopper backend does not support the strings command. '
        'Run with --backend ida instead.'
    )


try:
    _re_write_result(_collect())
except NotImplementedError as _e:
    _re_write_error('NotSupported', str(_e))
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)

