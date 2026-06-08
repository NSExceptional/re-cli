# disasm.py — disassemble a function or N instructions from an address
import idaapi as _idaapi
import idc as _idc
import idautils as _idautils
import ida_ua as _ida_ua


def _collect():
    _re_wait_analysis()
    func_name = _RE_PARAMS.get('function')
    address   = _RE_PARAMS.get('address')
    count     = int(_RE_PARAMS.get('count') or 0) or None

    if func_name:
        ea = _idc.get_name_ea_simple(func_name)
        if ea == _idc.BADADDR:
            raise ValueError(f'Symbol not found: {func_name}')
        func = _idaapi.get_func(ea)
        if not func:
            raise ValueError(f'No function at {func_name}')
        start, end = func.start_ea, func.end_ea
    elif address:
        ea = int(address, 0)
        func = _idaapi.get_func(ea)
        if func:
            start, end = ea, func.end_ea
        else:
            start = ea
            end = ea + 4 * (count or 64)
    else:
        raise ValueError('Provide --function NAME or --address 0xADDR')

    results = []
    for insn_ea in _idautils.Heads(start, end):
        insn = _ida_ua.insn_t()
        sz = _ida_ua.decode_insn(insn, insn_ea)
        raw = _idc.get_bytes(insn_ea, sz) if sz > 0 else b''
        results.append({
            'address':  hex(insn_ea),
            'bytes':    raw.hex() if raw else '',
            'mnemonic': _idc.print_insn_mnem(insn_ea),
            'operands': ' '.join(filter(None, [
                _idc.print_operand(insn_ea, i) for i in range(4)
            ])),
            'disasm':   _idc.generate_disasm_line(insn_ea, 0),
        })
        if count and len(results) >= count:
            break
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
