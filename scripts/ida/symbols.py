# symbols.py — list all named addresses (functions + data labels)
import re as _re_mod
import idautils as _idautils
import idc as _idc


def _collect():
    _re_wait_analysis()
    filt = _RE_PARAMS.get('filter')
    sym_type = _RE_PARAMS.get('type', 'all')
    results = []
    for ea, name in _idautils.Names():
        if filt and not _re_mod.search(filt, name):
            continue
        flags = _idc.get_full_flags(ea)
        kind = 'function' if _idc.is_code(flags) else 'data'
        if sym_type != 'all' and sym_type != kind:
            continue
        demangled = _idc.demangle_name(name, _idc.get_inf_attr(_idc.INF_SHORT_DN)) or None
        results.append({
            'address': hex(ea),
            'name': name,
            'type': kind,
            'demangled': demangled,
        })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
