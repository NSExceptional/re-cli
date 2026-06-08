# exports.py — list exported symbols / entry points
import idautils as _idautils
import idc as _idc


def _collect():
    _re_wait_analysis()
    results = []
    for _idx, ordinal, ea, name in _idautils.Entries():
        results.append({
            'address': hex(ea),
            'name':    name or _idc.get_name(ea) or f'ord_{ordinal}',
            'ordinal': ordinal,
        })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
