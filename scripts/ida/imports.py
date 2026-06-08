# imports.py — list imported symbols (dynamic dependencies)
import idaapi as _idaapi


def _collect():
    _re_wait_analysis()
    lib_filter = (_RE_PARAMS.get('library') or '').lower()
    results = []

    nimps = _idaapi.get_import_module_qty()
    for i in range(nimps):
        lib = _idaapi.get_import_module_name(i) or ''
        if lib_filter and lib_filter not in lib.lower():
            continue

        def _cb(ea, name, ordinal, _lib=lib):
            results.append({
                'address': hex(ea),
                'name':    name or f'ord_{ordinal}',
                'library': _lib,
                'ordinal': ordinal if ordinal not in (0, 0xFFFF, 0xFFFFFFFF) else None,
            })
            return True  # continue

        _idaapi.enum_import_names(i, _cb)

    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
