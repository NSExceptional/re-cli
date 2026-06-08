# info.py — binary metadata (arch, format, entry point, address range)
import idaapi as _idaapi
import idc as _idc
import ida_ida as _ida_ida


_ARCH_IDS = {}
try:
    _ARCH_IDS = {
        _idaapi.PLFM_386:  'x86',
        _idaapi.PLFM_ARM:  'ARM',
        _idaapi.PLFM_PPC:  'PowerPC',
        _idaapi.PLFM_MIPS: 'MIPS',
    }
except AttributeError:
    pass


def _collect():
    _re_wait_analysis()

    is_64 = _ida_ida.inf_is_64bit()

    try:
        arch = _ARCH_IDS.get(_idaapi.ph.id, f'unknown({_idaapi.ph.id})')
    except Exception:
        arch = 'unknown'

    try:
        file_type = _idaapi.get_file_type_name()
    except Exception:
        file_type = 'unknown'

    entry = _idc.get_inf_attr(_idc.INF_START_EA)

    return {
        'path':       _idc.get_input_file_path(),
        'format':     file_type,
        'arch':       arch,
        'bitness':    64 if is_64 else 32,
        'entry':      hex(entry) if entry != _idc.BADADDR else None,
        'minAddress': hex(_ida_ida.inf_get_min_ea()),
        'maxAddress': hex(_ida_ida.inf_get_max_ea()),
    }


try:
    _re_write_result(_collect())
except Exception as _e:
    _re_write_error(type(_e).__name__, str(_e))
finally:
    _re_exit(0)
