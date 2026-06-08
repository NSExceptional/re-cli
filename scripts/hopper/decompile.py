# decompile.py (Hopper) — decompile a function to Hopper pseudocode
def _find_proc(doc, ea):
    for si in range(doc.getSegmentCount()):
        seg  = doc.getSegment(si)
        proc = seg.getProcedureAtAddress(ea)
        if proc is not None:
            return seg, proc
    return None, None


def _collect():
    doc       = Document.getCurrentDocument()
    func_name = _RE_PARAMS.get('function')
    address   = _RE_PARAMS.get('address')

    if func_name:
        ea = doc.getAddressForName(func_name)
        if ea is None or ea == 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f'Symbol not found: {func_name}')
    elif address:
        ea = int(address, 0)
    else:
        raise ValueError('Provide --function NAME or --address 0xADDR')

    seg, proc = _find_proc(doc, ea)
    if proc is None:
        raise ValueError(f'No analyzed procedure at {hex(ea)}')

    pseudo = proc.decompile()
    if pseudo is None:
        raise RuntimeError(
            f'Hopper could not decompile {hex(ea)} '
            '(function may be too small, thunk, or decompiler unavailable)'
        )

    entry = proc.getEntryPoint()
    name  = seg.getNameAtAddress(entry) if seg else hex(entry)
    return {
        'function':   func_name or name,
        'address':    hex(entry),
        'pseudocode': pseudo,
    }


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
