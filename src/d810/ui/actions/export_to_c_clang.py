"""Clang-based post-processor for export-to-C output.

Uses libclang to parse the generated C and apply automatic fixits,
making the output compilable when clang suggests corrections.
"""

from __future__ import annotations

import pathlib
import re
from d810.core import typing
from d810.core.logging import getLogger

logger = getLogger("D810.ui")

# Strip #include directives for headers we replace with inline preamble,
# so clang parses a self-contained unit.
_INCLUDE_PATTERN = re.compile(
    r'^\s*#\s*include\s+["<](?:polyfill|platform|ida_types)\.h[">]\s*\n?',
    re.MULTILINE | re.IGNORECASE,
)

# Preamble that allows parsing IDA-style C without external includes.
# Must define types and macros used in decompiler output.
EXPORT_CLANG_PREAMBLE = """
typedef unsigned int _DWORD;
typedef unsigned long long _QWORD;
typedef unsigned short _WORD;
typedef unsigned char _BYTE;
typedef long long __int64;
typedef int __int32;
typedef short __int16;
typedef signed char __int8;
typedef unsigned long long _OWORD;
typedef void* HANDLE;
typedef void* LPVOID;
typedef void* LPCVOID;
typedef unsigned long long SIZE_T;
typedef unsigned long DWORD;
typedef int BOOL;
typedef void (*LPFIBER_START_ROUTINE)(void*);
typedef struct _CONTEXT CONTEXT;
typedef CONTEXT* LPCONTEXT;
typedef struct _UNKNOWN { char _dummy; } _UNKNOWN;
#define __fastcall
#define __stdcall
#define __cdecl
#ifndef JUMPOUT
#define JUMPOUT(addr) do { (void)(addr); } while (0)
#endif
"""


def _get_clang_index(idaapi_mod: typing.Any | None = None) -> typing.Any | None:
    """Create and return a clang Index, or None if libclang is unavailable.

    Args:
        idaapi_mod: Optional IDA API module for getting IDA installation directory
    """
    try:
        from d810._vendor.clang.cindex import Config, Index
    except ImportError:
        return None

    # Try to load libclang from IDA installation or common locations
    system = __import__("platform").system()
    lib_names = {"Linux": "libclang.so", "Darwin": "libclang.dylib", "Windows": "libclang.dll"}
    lib_name = lib_names.get(system, "libclang.so")

    paths_to_try: list[pathlib.Path] = []

    # IDA install dir (when running inside IDA)
    if idaapi_mod is not None and hasattr(idaapi_mod, "get_ida_directory"):
        try:
            ida_dir = pathlib.Path(idaapi_mod.get_ida_directory())
            if ida_dir.exists():
                paths_to_try.append(ida_dir / lib_name)
        except Exception:
            pass

    # Project-relative (development)
    try:
        pkg_root = pathlib.Path(__file__).resolve()
        for _ in range(5):
            pkg_root = pkg_root.parent
            cand = pkg_root / lib_name
            if cand.exists():
                paths_to_try.append(cand)
                break
    except Exception:
        pass

    # System (e.g. pip install clang)
    for p in paths_to_try:
        if p.exists():
            try:
                Config.set_library_file(str(p.resolve()))
                return Index.create()
            except Exception as e:
                logger.debug("Failed to load libclang from %s: %s", p, e)
    return None


def _apply_fixits(content: str, tu: typing.Any) -> str:
    """Apply all fixits from translation unit diagnostics. Returns modified content."""
    from d810._vendor.clang.cindex import Diagnostic

    edits: list[tuple[int, int, str]] = []  # (start, end, replacement)

    for diag in tu.diagnostics:
        if diag.severity < Diagnostic.Error:
            continue
        for fixit in diag.fixits:
            try:
                start = fixit.range.start.offset
                end = fixit.range.end.offset
            except Exception:
                continue
            if start < 0 or end > len(content) or start > end:
                continue
            edits.append((start, end, fixit.value))

    if not edits:
        return content

    # Apply edits from end to start to preserve offsets
    edits.sort(key=lambda x: x[0], reverse=True)
    result = content
    for start, end, replacement in edits:
        result = result[:start] + replacement + result[end:]
    return result


def make_compilable(c_source: str, max_rounds: int = 5, idaapi_mod: typing.Any | None = None) -> str:
    """Parse C source with clang and apply fixits until it compiles or max_rounds.

    Strips polyfill/platform includes and prepends a minimal typedef preamble
    for parsing. Applies clang's suggested fixits. Returns the modified source
    with original includes restored (fixits are applied before include restoration).

    Args:
        c_source: The C source code to process
        max_rounds: Maximum number of fixit rounds to apply
        idaapi_mod: Optional IDA API module for getting IDA installation directory
    """
    try:
        from d810._vendor.clang.cindex import Index
    except ImportError:
        return c_source

    index = _get_clang_index(idaapi_mod)
    if index is None:
        return c_source

    # Remove includes we replace with preamble (avoids missing file / redef errors)
    parse_content = _INCLUDE_PATTERN.sub("", c_source)

    filename = "export.c"
    full_content = EXPORT_CLANG_PREAMBLE + "\n" + parse_content

    args = [
        "-target", "x86_64-pc-windows-msvc",
        "-fms-extensions",
        "-fms-compatibility",
        "-w",
        "-std=c11",
    ]

    content = full_content
    preamble_len = len(EXPORT_CLANG_PREAMBLE) + 1

    for _ in range(max_rounds):
        try:
            tu = index.parse(
                filename,
                args=args,
                unsaved_files=[(filename, content)],
                options=0,
            )
        except Exception as e:
            logger.debug("Clang parse failed: %s", e)
            break

        has_error = any(d.severity >= 3 for d in tu.diagnostics)
        if not has_error:
            break

        # Check if any fixits apply to our main file
        new_content = _apply_fixits(content, tu)
        if new_content == content:
            logger.debug("No fixits to apply, stopping")
            break
        content = new_content

    # Strip preamble to get our modified content
    result = content[preamble_len:] if len(content) > preamble_len else parse_content

    # Restore original includes (after header comment if present)
    include_lines = [m.group(0).rstrip() for m in _INCLUDE_PATTERN.finditer(c_source)]
    if include_lines:
        insert = "\n".join(include_lines) + "\n\n"
        if not result.strip().startswith("#include"):
            if result.strip().startswith("/*"):
                idx = result.find("*/")
                if idx >= 0:
                    result = result[: idx + 3] + "\n\n" + insert + result[idx + 3 :].lstrip()
                else:
                    result = insert + result
            else:
                result = insert + result
    return result
