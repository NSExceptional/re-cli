# disasm.py (Hopper) — disassemble a function
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
    count     = int(_RE_PARAMS.get('count') or 0) or None

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

    results = []
    for bi in range(proc.getBasicBlockCount()):
        bb = proc.getBasicBlock(bi)
        for ii in range(bb.getInstructionCount()):
            insn = bb.getInstructionAtIndex(ii)
            results.append({
                'address':  hex(insn.getInstructionAddress()),
                'bytes':    '',
                'mnemonic': insn.getInstructionString(),
                'operands': '',
                'disasm':   insn.getInstructionString(),
            })
            if count and len(results) >= count:
                return results
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
