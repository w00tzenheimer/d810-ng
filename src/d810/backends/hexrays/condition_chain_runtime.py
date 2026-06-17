"""Hex-Rays runtime helpers for legacy condition-chain microcode analysis."""

from __future__ import annotations

from functools import lru_cache


@lru_cache(maxsize=1)
def _idaapi():
    import idaapi

    return idaapi


def is_available() -> bool:
    try:
        _idaapi()
    except (ImportError, ModuleNotFoundError):
        return False
    return True


def build_opcode_map() -> dict[int, str]:
    try:
        idaapi = _idaapi()
    except (ImportError, ModuleNotFoundError):
        return {}
    opcode_map: dict[int, str] = {}
    for name in dir(idaapi):
        if not name.startswith("m_"):
            continue
        try:
            value = getattr(idaapi, name)
        except Exception:
            continue
        if isinstance(value, int):
            opcode_map[value] = name
    return opcode_map


def build_mop_type_map() -> dict[int, str]:
    try:
        idaapi = _idaapi()
    except (ImportError, ModuleNotFoundError):
        return {}
    mop_type_map: dict[int, str] = {}
    for name in dir(idaapi):
        if not name.startswith("mop_"):
            continue
        try:
            value = getattr(idaapi, name)
        except Exception:
            continue
        if isinstance(value, int):
            mop_type_map[value] = name
    return mop_type_map


def opcode_value(name: str, default: int | None = None) -> int | None:
    try:
        return getattr(_idaapi(), name, default)
    except (ImportError, ModuleNotFoundError):
        return default


def mop_type_value(name: str, default: int | None = None) -> int | None:
    try:
        return getattr(_idaapi(), name, default)
    except (ImportError, ModuleNotFoundError):
        return default


def fetch_idb_value(address: int, size: int) -> int | None:
    try:
        idaapi = _idaapi()
    except (ImportError, ModuleNotFoundError):
        return None
    readers = {
        1: getattr(idaapi, "get_byte", None),
        2: getattr(idaapi, "get_word", None),
        4: getattr(idaapi, "get_dword", None),
        8: getattr(idaapi, "get_qword", None),
    }
    reader = readers.get(size)
    if reader is None:
        return None
    return int(reader(address))


def segment_is_read_only(addr: int) -> bool:
    try:
        idaapi = _idaapi()
    except (ImportError, ModuleNotFoundError):
        return False
    getseg = getattr(idaapi, "getseg", None)
    if getseg is None:
        return False
    seg = getseg(addr)
    if seg is None:
        return False
    read_perm = getattr(idaapi, "SEGPERM_READ", 1)
    write_perm = getattr(idaapi, "SEGPERM_WRITE", 2)
    perm = int(getattr(seg, "perm", 0) or 0)
    return (perm & read_perm) != 0 and (perm & write_perm) == 0


def is_never_written_var(address: int) -> bool:
    try:
        idaapi = _idaapi()
    except (ImportError, ModuleNotFoundError):
        return False
    xrefblk_t = getattr(idaapi, "xrefblk_t", None)
    if xrefblk_t is None:
        return False
    ref_finder = xrefblk_t()
    xref_data = getattr(idaapi, "XREF_DATA", 1)
    dr_w = getattr(idaapi, "dr_W", None)
    is_ok = ref_finder.first_to(address, xref_data)
    while is_ok:
        if dr_w is not None and ref_finder.type == dr_w:
            return False
        is_ok = ref_finder.next_to()
    return True
