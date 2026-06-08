# decompile.py — decompile function(s) to pseudocode via Hex-Rays
import idaapi as _idaapi
import idc as _idc
import idautils as _idautils
import ida_funcs as _ida_funcs


def _ensure_hexrays():
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError('Hex-Rays plugin failed to initialize')
        return ida_hexrays
    except ImportError:
        raise RuntimeError('ida_hexrays not found — is the Hex-Rays decompiler installed?')


def _decompile_ea(hexrays, ea):
    func = _idaapi.get_func(ea)
    if not func:
        raise ValueError(f'No function at {hex(ea)}')
    cfunc = hexrays.decompile(func.start_ea)
    if cfunc is None:
        raise RuntimeError(f'Decompiler returned None for {hex(func.start_ea)}')
    return func, cfunc


def _collect():
    _re_wait_analysis()
    hexrays = _ensure_hexrays()

    func_name = _RE_PARAMS.get('function')
    address   = _RE_PARAMS.get('address')
    all_funcs = _RE_PARAMS.get('all', False)

    if all_funcs:
        results = []
        for func_ea in _idautils.Functions():
            try:
                cfunc = hexrays.decompile(func_ea)
                if cfunc:
                    results.append({
                        'address': hex(func_ea),
                        'name': _ida_funcs.get_func_name(func_ea),
                        'pseudocode': str(cfunc),
                    })
            except Exception:
                pass
        return results

    if func_name:
        ea = _idc.get_name_ea_simple(func_name)
        if ea == _idc.BADADDR:
            raise ValueError(f'Symbol not found: {func_name}')
    elif address:
        ea = int(address, 0)
    else:
        raise ValueError('Provide --function NAME or --address 0xADDR')

    func, cfunc = _decompile_ea(hexrays, ea)
    return {
        'function': func_name or _ida_funcs.get_func_name(func.start_ea),
        'address': hex(func.start_ea),
        'pseudocode': str(cfunc),
    }


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
