# strings.py — extract string literals from the binary
import re as _re_mod
import idautils as _idautils

_ENCODINGS = {0: 'C', 1: 'Pascal', 2: 'LEN2', 3: 'UNICODE', 4: 'LEN4', 5: 'ULEN2', 6: 'ULEN4'}


def _collect():
    _re_wait_analysis()
    min_len = int(_RE_PARAMS.get('minLength') or 0)
    filt    = _RE_PARAMS.get('filter')

    sc = _idautils.Strings()
    sc.setup(strtypes=list(_ENCODINGS.keys()))

    results = []
    for s in sc:
        val = str(s)
        if min_len and len(val) < min_len:
            continue
        if filt and not _re_mod.search(filt, val):
            continue
        results.append({
            'address':  hex(s.ea),
            'length':   s.length,
            'encoding': _ENCODINGS.get(s.strtype, str(s.strtype)),
            'value':    val,
        })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
