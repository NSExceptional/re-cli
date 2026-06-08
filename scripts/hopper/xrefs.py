# xrefs.py (Hopper) — cross-references (limited API in Hopper)
def _resolve(doc, sym_or_addr):
    if sym_or_addr.startswith('0x') or sym_or_addr.startswith('0X'):
        return int(sym_or_addr, 0)
    ea = doc.getAddressForName(sym_or_addr)
    if ea is None or ea == 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f'Symbol not found: {sym_or_addr}')
    return ea


def _collect():
    doc         = Document.getCurrentDocument()
    to_target   = _RE_PARAMS.get('to')
    from_target = _RE_PARAMS.get('from')

    if not to_target and not from_target:
        raise ValueError('Provide --to NAME or --from NAME')

    ea = _resolve(doc, to_target or from_target)

    results = []
    for si in range(doc.getSegmentCount()):
        seg = doc.getSegment(si)
        for pi in range(seg.getProcedureCount()):
            proc = seg.getProcedureAtIndex(pi)
            for ref in proc.getCallees() if to_target else proc.getCallers():
                ref_ea = ref if isinstance(ref, int) else ref.getInstructionAddress()
                if to_target and ref_ea == ea:
                    results.append({
                        'from': hex(proc.getEntryPoint()),
                        'fromName': seg.getNameAtAddress(proc.getEntryPoint()) or None,
                        'to': hex(ea),
                        'toName': to_target,
                        'type': 'code',
                    })
                elif from_target and proc.getEntryPoint() == ea:
                    results.append({
                        'from': hex(ea),
                        'fromName': from_target,
                        'to': hex(ref_ea),
                        'toName': None,
                        'type': 'code',
                    })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
