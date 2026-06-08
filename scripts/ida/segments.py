# segments.py — list binary segments / sections
import idautils as _idautils
import idaapi as _idaapi
import idc as _idc

_SEG_TYPES = {0: 'UNKNOWN', 1: 'BSS', 2: 'CODE', 3: 'DATA', 4: 'NULL', 8: 'XTRN'}


def _collect():
    _re_wait_analysis()
    results = []
    for ea in _idautils.Segments():
        seg = _idaapi.getseg(ea)
        if not seg:
            continue
        results.append({
            'name':  _idc.get_segm_name(ea),
            'start': hex(seg.start_ea),
            'end':   hex(seg.end_ea),
            'size':  seg.end_ea - seg.start_ea,
            'type':  _SEG_TYPES.get(seg.type, str(seg.type)),
        })
    return results


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
