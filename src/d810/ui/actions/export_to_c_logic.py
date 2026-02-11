"""Pure logic for export to C file action.

This module contains the business logic for exporting decompiled functions to
compilable C source files, separated from IDA dependencies to enable unit testing.

All functions in this module can be imported and tested without IDA Pro.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class CExportSettings:
    """Settings for C export.

    Attributes:
        sample_compatible: If True, export in sample-compatible format with EXPORT macro
        recursion_depth: Depth of recursive export (0 = current function only)
        export_globals: If True, include referenced global declarations
        output_path: Path to output .c file
    """
    sample_compatible: bool = False
    recursion_depth: int = 0
    export_globals: bool = False
    output_path: str = ""


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename.

    Removes invalid filename characters and limits length.

    Args:
        name: The raw function name or identifier

    Returns:
        A safe filename (without extension)

    Examples:
        >>> sanitize_filename("my::func<int>")
        'my__func_int_'
        >>> sanitize_filename("operator<<")
        'operator__'
        >>> sanitize_filename("a" * 200)[:10]
        'aaaaaaaaaa'
    """
    # Remove invalid filename characters
    sanitized = re.sub(r'[<>:"/\\|?*]', "_", name)
    # Replace spaces with underscores
    sanitized = sanitized.replace(" ", "_")
    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    return sanitized


def suggest_filename(func_name: str) -> str:
    """Generate a suggested filename for a C export.

    Args:
        func_name: The function name

    Returns:
        A sanitized filename with .c extension

    Examples:
        >>> suggest_filename("my_function")
        'my_function.c'
        >>> suggest_filename("operator<<")
        'operator__.c'
    """
    safe_name = sanitize_filename(func_name)
    return f"{safe_name}.c"


def sanitize_c_identifier(name: str) -> str:
    """Sanitize a name to make it a valid C identifier.

    Args:
        name: The raw identifier name

    Returns:
        A valid C identifier

    Examples:
        >>> sanitize_c_identifier("my::func")
        'my__func'
        >>> sanitize_c_identifier("123start")
        '_123start'
    """
    # Replace invalid C identifier characters with underscores
    sanitized = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    # Ensure it doesn't start with a digit
    if sanitized and sanitized[0].isdigit():
        sanitized = "_" + sanitized
    return sanitized


def build_metadata_comment(stats: dict[str, Any] | None) -> str:
    """Format d810ng statistics as a C block comment.

    Args:
        stats: Dictionary containing deobfuscation statistics, or None

    Returns:
        Formatted C block comment string, or empty string if no stats

    Examples:
        >>> stats = {
        ...     "optimizer_matches": {"OpaquePredicate": 5},
        ...     "rule_matches": {"MBARule_Add": 3},
        ...     "total_rule_firings": 8
        ... }
        >>> comment = build_metadata_comment(stats)
        >>> "OpaquePredicate: 5" in comment
        True
        >>> "Total rule firings: 8" in comment
        True
    """
    if not stats:
        return ""

    lines = ["/*", " * d810ng Deobfuscation Metadata", " * --------------------------------"]

    opt_matches = stats.get("optimizer_matches", {})
    if opt_matches:
        lines.append(" * Optimizer matches:")
        for name, count in sorted(opt_matches.items()):
            lines.append(f" *   {name}: {count}")

    rule_matches = stats.get("rule_matches", {})
    if rule_matches:
        lines.append(" * Rule matches:")
        for name, count in sorted(rule_matches.items()):
            lines.append(f" *   {name}: {count}")

    cfg_patches = stats.get("cfg_patches", {})
    if cfg_patches:
        lines.append(" * CFG rule patches:")
        for name, info in sorted(cfg_patches.items()):
            lines.append(
                f" *   {name}: {info['uses']} uses, {info['total_patches']} patches"
            )

    total = stats.get("total_rule_firings", 0)
    cycles = stats.get("total_cycles_detected", 0)
    if total or cycles:
        lines.append(" *")
        if total:
            lines.append(f" * Total rule firings: {total}")
        if cycles:
            lines.append(f" * Cycles detected and broken: {cycles}")

    lines.append(" */")
    return "\n".join(lines)


def format_c_output(
    func_name: str,
    func_ea: int,
    pseudocode_lines: list[str],
    local_types: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Generate compilable C source with metadata and standard headers.

    Args:
        func_name: The function name
        func_ea: The function entry address
        pseudocode_lines: Lines of decompiled pseudocode
        local_types: Optional list of local type declarations
        metadata: Optional d810ng deobfuscation statistics

    Returns:
        Complete C source file content

    Examples:
        >>> output = format_c_output(
        ...     "my_func",
        ...     0x401000,
        ...     ["int my_func(int x) {", "  return x + 1;", "}"]
        ... )
        >>> "my_func" in output
        True
        >>> "0x401000" in output
        True
        >>> "#include <stdint.h>" in output
        True
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "/*",
        f" * Function: {func_name}",
        f" * Address: {func_ea:#x}",
        f" * Exported: {timestamp}",
        f" * Tool: d810ng (IDA Pro deobfuscation plugin)",
        " */",
        "",
    ]

    # Add deobfuscation metadata if available
    metadata_comment = build_metadata_comment(metadata)
    if metadata_comment:
        lines.append(metadata_comment)
        lines.append("")

    # Standard includes for IDA types
    lines.extend(
        [
            "#include <stdint.h>",
            "#include <stdbool.h>",
            "#include <stddef.h>",
            "",
            "// Common IDA type aliases",
            "typedef uint8_t _BYTE;",
            "typedef uint16_t _WORD;",
            "typedef uint32_t _DWORD;",
            "typedef uint64_t _QWORD;",
            "typedef int8_t __int8;",
            "typedef int16_t __int16;",
            "typedef int32_t __int32;",
            "typedef int64_t __int64;",
            "typedef bool _BOOL1;",
            "typedef int32_t _BOOL4;",
            "",
        ]
    )

    # Add local type declarations if provided
    if local_types:
        lines.append("// Local type declarations")
        lines.extend(local_types)
        lines.append("")

    # Add the function body
    lines.append(f"// Function: {func_name} at {func_ea:#x}")
    lines.extend(pseudocode_lines)
    lines.append("")

    return "\n".join(lines)


def build_sample_header_comment(
    func_name: str, func_ea: int, metadata: dict[str, Any] | None = None
) -> str:
    """Build header comment for sample-compatible C output.

    Matches the convention in samples/src/c/ files:
    - Function name and address
    - Optional d810ng deobfuscation metadata
    - Compilation flags suggestion

    Args:
        func_name: Function name
        func_ea: Function entry address
        metadata: Optional d810ng deobfuscation statistics

    Returns:
        Multi-line C comment string

    Examples:
        >>> comment = build_sample_header_comment("test_func", 0x401000)
        >>> "test_func" in comment
        True
        >>> "0x401000" in comment
        True
        >>> "-O0 -g -fno-inline" in comment
        True
    """
    lines = ["/**"]
    lines.append(f" * Function: {func_name}")
    lines.append(f" * Address: {func_ea:#x}")
    lines.append(" *")

    # Add metadata if available
    if metadata:
        lines.append(" * d810ng Deobfuscation Applied:")
        opt_matches = metadata.get("optimizer_matches", {})
        if opt_matches:
            for name, count in sorted(opt_matches.items()):
                lines.append(f" *   {name}: {count} matches")

        rule_matches = metadata.get("rule_matches", {})
        if rule_matches:
            total = sum(rule_matches.values())
            lines.append(f" *   MBA rules: {total} simplifications")

        lines.append(" *")

    # Compilation flags
    lines.append(" * Compilation flags (recommended):")
    lines.append(" *   -O0 -g -fno-inline -fno-builtin")
    lines.append(" */")

    return "\n".join(lines)


def format_sample_compatible_c(
    func_name: str,
    func_ea: int,
    pseudocode_lines: list[str],
    local_types: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    global_declarations: list[str] | None = None,
) -> str:
    """Generate sample-compatible C source.

    Follows the format used in samples/src/c/:
    - #include "ida_types.h" for IDA type definitions
    - #include "export.h" for EXPORT macro
    - volatile int g_<func>_sink for preventing optimization
    - Referenced globals as volatile declarations
    - EXPORT __attribute__((noinline)) on function
    - Header comment with metadata and compilation flags

    Args:
        func_name: Function name
        func_ea: Function entry address
        pseudocode_lines: Lines of decompiled pseudocode
        local_types: Optional local type declarations
        metadata: Optional d810ng deobfuscation statistics
        global_declarations: Optional list of global variable declarations

    Returns:
        Complete C source file content in sample format

    Examples:
        >>> output = format_sample_compatible_c(
        ...     "test_func",
        ...     0x401000,
        ...     ["int test_func(int x) {", "  return x + 1;", "}"]
        ... )
        >>> '#include "ida_types.h"' in output
        True
        >>> '#include "export.h"' in output
        True
        >>> "volatile int g_test_func_sink" in output
        True
        >>> "EXPORT __attribute__((noinline))" in output
        True
    """
    lines = []

    # Header comment with metadata
    header_comment = build_sample_header_comment(func_name, func_ea, metadata)
    lines.append(header_comment)
    lines.append("")

    # Standard includes for sample format
    lines.append('#include "ida_types.h"')
    lines.append('#include "export.h"')
    lines.append("")

    # Global declarations if provided
    if global_declarations:
        lines.append("// Referenced globals")
        for decl in global_declarations:
            # Make globals volatile to prevent optimization
            if "volatile" not in decl:
                decl = decl.replace("extern ", "extern volatile ", 1)
                if not decl.startswith("extern"):
                    decl = "volatile " + decl
            lines.append(decl)
        lines.append("")

    # Local type declarations if provided
    if local_types:
        lines.append("// Local type declarations")
        lines.extend(local_types)
        lines.append("")

    # Sink variable to prevent dead code elimination
    safe_name = sanitize_c_identifier(func_name)
    lines.append(f"// Sink variable to prevent optimization")
    lines.append(f"volatile int g_{safe_name}_sink = 0;")
    lines.append("")

    # Function with EXPORT and noinline attributes
    lines.append(f"// Function: {func_name} at {func_ea:#x}")

    # Insert EXPORT and __attribute__((noinline)) before function signature
    # Find the function signature line (usually first line with opening brace or semicolon)
    modified_code = []
    for i, line in enumerate(pseudocode_lines):
        if i == 0:
            # First line is the function signature - add attributes
            modified_code.append(f"EXPORT __attribute__((noinline)) {line}")
        else:
            modified_code.append(line)

    lines.extend(modified_code)
    lines.append("")

    return "\n".join(lines)
