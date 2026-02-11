"""Pure logic for export disassembly action.

This module contains the business logic for exporting disassembly to various
formats (ASM, LST, MAP, IDC), separated from IDA dependencies to enable unit testing.

All functions in this module can be imported and tested without IDA Pro.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DisasmExportSettings:
    """Settings for disassembly export.

    Attributes:
        format: Output format (ASM, LST, MAP, IDC)
        include_headers: Include file header comments
        include_segments: Include segment information
        output_path: Path to output file
    """
    format: str = "LST"
    include_headers: bool = True
    include_segments: bool = True
    output_path: str = ""


# Format choices for UI combo box: (format_id, description)
DISASM_FORMATS: list[tuple[str, str]] = [
    ("ASM", "Assembly (.asm) - Plain assembly listing"),
    ("LST", "LST (.lst) - Assembly with addresses and bytes"),
    ("MAP", "MAP (.map) - Memory map with symbols"),
    ("IDC", "IDC (.idc) - IDC script format"),
]


def to_ida_format_int(fmt: str) -> int:
    """Map format string to IDA loader format constant.

    Maps to ida_loader.OFILE_* constants:
    - MAP = OFILE_MAP = 0
    - IDC = OFILE_IDC = 2
    - LST = OFILE_LST = 3
    - ASM = OFILE_ASM = 4

    Args:
        fmt: Format string (ASM, LST, MAP, IDC)

    Returns:
        Integer constant matching ida_loader.OFILE_* value

    Raises:
        ValueError: If format is not recognized

    Examples:
        >>> to_ida_format_int("ASM")
        4
        >>> to_ida_format_int("LST")
        3
        >>> to_ida_format_int("MAP")
        0
        >>> to_ida_format_int("IDC")
        2
    """
    format_map = {
        "ASM": 4,  # OFILE_ASM
        "LST": 3,  # OFILE_LST
        "MAP": 0,  # OFILE_MAP
        "IDC": 2,  # OFILE_IDC
    }

    if fmt not in format_map:
        raise ValueError(f"Unknown format: {fmt}. Expected one of: {list(format_map.keys())}")

    return format_map[fmt]


def to_ida_flags(settings: DisasmExportSettings) -> int:
    """Build IDA loader flags bitmask from export settings.

    Maps to ida_loader.GENFLG_* constants:
    - GENFLG_GENHTML = 0x0001 (not used here)
    - GENFLG_ASMTYPE = 0x0002 (use assembler-specific formatting)
    - GENFLG_MAPDMNG = 0x0004 (demangle names in MAP output)
    - GENFLG_MAPNAME = 0x0008 (include names in MAP)
    - GENFLG_MAPADR  = 0x0010 (include addresses in MAP)
    - GENFLG_MAPATTRS = 0x0020 (include attributes in MAP)
    - GENFLG_MAPDEM  = 0x0040 (demangle C++ names)

    For simplicity, we use standard flag combinations:
    - include_headers: adds GENFLG_ASMTYPE (0x0002)
    - include_segments: adds MAP flags (0x007C for full MAP output)

    Args:
        settings: Export settings with format and options

    Returns:
        Integer bitmask of flags

    Examples:
        >>> s = DisasmExportSettings(format="LST", include_headers=True, include_segments=True)
        >>> to_ida_flags(s)
        126
        >>> s = DisasmExportSettings(format="ASM", include_headers=False, include_segments=False)
        >>> to_ida_flags(s)
        0
    """
    flags = 0

    # GENFLG_ASMTYPE = 0x0002 - use assembler-specific formatting
    if settings.include_headers:
        flags |= 0x0002

    # For MAP output with segments, include all MAP flags
    if settings.include_segments:
        # GENFLG_MAPDMNG | GENFLG_MAPNAME | GENFLG_MAPADR | GENFLG_MAPATTRS | GENFLG_MAPDEM
        flags |= 0x007C  # 0x04 | 0x08 | 0x10 | 0x20 | 0x40

    return flags


def suggest_disasm_filename(func_name: str, fmt: str) -> str:
    """Generate suggested filename for disassembly export.

    Sanitizes function name and adds appropriate extension based on format.

    Args:
        func_name: Function name to sanitize
        fmt: Output format (ASM, LST, MAP, IDC)

    Returns:
        Sanitized filename with extension

    Examples:
        >>> suggest_disasm_filename("my_function", "ASM")
        'my_function.asm'
        >>> suggest_disasm_filename("operator<<", "LST")
        'operator__.lst'
        >>> suggest_disasm_filename("my::func<int>", "MAP")
        'my__func_int_.map'
        >>> suggest_disasm_filename("test", "IDC")
        'test.idc'
    """
    # Sanitize function name (remove invalid filename characters)
    import re
    sanitized = re.sub(r'[<>:"/\\|?*]', "_", func_name)
    sanitized = sanitized.replace(" ", "_")

    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]

    # Map format to extension
    extension_map = {
        "ASM": "asm",
        "LST": "lst",
        "MAP": "map",
        "IDC": "idc",
    }

    ext = extension_map.get(fmt, "txt")
    return f"{sanitized}.{ext}"
