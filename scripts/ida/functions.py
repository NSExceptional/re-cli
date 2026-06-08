# functions.py — list all analyzed functions
import re as _re_mod
import idautils as _idautils
import ida_funcs as _ida_funcs


def _collect():
    _re_wait_analysis()
    filt = _RE_PARAMS.get('filter')
    results = []
    for func_ea in _idautils.Functions():
        name = _ida_funcs.get_func_name(func_ea)
        if filt and not _re_mod.search(filt, name):
            continue
        func = _ida_funcs.get_func(func_ea)
        results.append({
            'address': hex(func_ea),
            'name': name,
            'size': func.size() if func else None,
        })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
