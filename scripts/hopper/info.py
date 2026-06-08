# info.py (Hopper) — binary metadata


def _collect():
    doc = Document.getCurrentDocument()

    path = None
    for attr in ('getExecutablePath', 'executablePath', 'getFilePath'):
        fn = getattr(doc, attr, None)
        if callable(fn):
            try:
                path = fn()
                break
            except Exception:
                pass

    return {
        'path':       path or 'unknown',
        'format':     'unknown',
        'arch':       'unknown',
        'bitness':    None,
        'entry':      None,
        'minAddress': None,
        'maxAddress': None,
    }


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
