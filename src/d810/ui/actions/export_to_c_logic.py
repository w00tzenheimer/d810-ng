"""Pure logic for export to C file action.

This module contains the business logic for exporting decompiled functions to
compilable C source files, separated from IDA dependencies to enable unit testing.

All functions in this module can be imported and tested without IDA Pro.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from d810.core.typing import Any

_GLOBAL_NAME_RE = re.compile(
    r"\b((?:byte|word|dword|qword|xmmword|ymmword|zmmword|off|unk|asc|flt|dbl)_[0-9A-Fa-f]+)\b"
)
_TEMP_LOCAL_RE = re.compile(r"\bv(\d+)\b")
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_ADDR_OF_NAME_RE = re.compile(r"&\s*([A-Za-z_][A-Za-z0-9_]*)\b")

_CALL_EXCLUDE = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "__ROL1__",
    "__ROL2__",
    "__ROL4__",
    "__ROL8__",
    "__ROR1__",
    "__ROR2__",
    "__ROR4__",
    "__ROR8__",
    "__PAIR16__",
    "__PAIR32__",
    "__PAIR64__",
    "__PAIR128__",
    "JUMPOUT",
}

_FORWARD_DECL_EXCLUDE = _CALL_EXCLUDE | {
    # ida_types.h / polyfill.h helpers/macros
    "LOBYTE",
    "HIBYTE",
    "LOWORD",
    "HIWORD",
    "BYTE1",
    "BYTE2",
    "BYTE3",
    "BYTE4",
    "BYTE5",
    "BYTE6",
    "BYTE7",
    "WORD1",
    "WORD2",
    "WORD3",
    "DWORD1",
    "DWORD2",
    "DWORD3",
    "QWORD1",
    # polyfill API declarations
    "NtCurrentTeb",
    "ConvertThreadToFiber",
    "CreateFiber",
    "GetThreadContext",
    "IsThreadAFiber",
    "RtlAcquireSRWLockExclusive",
    "RtlReleaseSRWLockExclusive",
    "SetThreadContext",
    "SwitchToFiber",
    "TlsGetValue",
    "TlsSetValue",
}

_GLOBAL_TYPE_BY_PREFIX = {
    "byte": "unsigned __int8",
    "word": "unsigned __int16",
    "dword": "unsigned __int32",
    "qword": "unsigned __int64",
    "xmmword": "__int128",
    "ymmword": "__int128",
    "zmmword": "__int128",
    "off": "unsigned __int64",
    "unk": "unsigned __int64",
    "asc": "char",
    "flt": "float",
    "dbl": "double",
}

_FUNC_SYMBOL_RE = re.compile(r"^(?:sub|nullsub|loc|j)_[A-Za-z0-9_]+$")
_FUNC_PTR_ARG_RE = re.compile(
    r"(?:^|[(,\s])&?\s*((?:sub|nullsub|loc|j)_[A-Za-z0-9_]+)\s*(?=,|\))"
)


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


def _guess_global_type(symbol_name: str) -> str:
    """Guess C type for an IDA-style generated global symbol name."""
    prefix = symbol_name.split("_", 1)[0].lower()
    return _GLOBAL_TYPE_BY_PREFIX.get(prefix, "unsigned __int64")


def infer_global_declarations(pseudocode_lines: list[str]) -> list[str]:
    """Infer global declarations from pseudocode text.

    This builds conservative extern declarations to make output compile.
    """
    code = "\n".join(pseudocode_lines)
    globals_found = set(_GLOBAL_NAME_RE.findall(code))
    declarations = [
        f"extern volatile {_guess_global_type(name)} {name};"
        for name in sorted(globals_found)
    ]

    if "_security_cookie" in code:
        declarations.append("extern unsigned __int64 _security_cookie;")
    if "__security_cookie" in code:
        declarations.append("extern unsigned __int64 __security_cookie;")

    return declarations


def get_imported_function_names(pseudocode_lines: list[str]) -> list[str]:
    """Return sorted list of imported/API function names referenced in pseudocode.

    These are names in _FORWARD_DECL_EXCLUDE (e.g. ConvertThreadToFiber, TlsGetValue)
    that appear as function calls. IDA exports them as function pointer declarations.
    """
    code = "\n".join(pseudocode_lines)
    found = set()
    for name in _CALL_NAME_RE.findall(code):
        if name in _FORWARD_DECL_EXCLUDE:
            found.add(name)
    return sorted(found)


def get_forward_declaration_names(
    func_name: str, pseudocode_lines: list[str]
) -> list[str]:
    """Return sorted list of names that need forward declarations."""
    code = "\n".join(pseudocode_lines)
    globals_found = set(_GLOBAL_NAME_RE.findall(code))
    names = set()

    for name in _CALL_NAME_RE.findall(code):
        if name == func_name or name in _FORWARD_DECL_EXCLUDE or name in globals_found or name.startswith("__"):
            continue
        names.add(name)

    for name in _ADDR_OF_NAME_RE.findall(code):
        if name == func_name or name in _FORWARD_DECL_EXCLUDE or name in globals_found:
            continue
        if not _FUNC_SYMBOL_RE.match(name):
            continue
        names.add(name)

    for name in _FUNC_PTR_ARG_RE.findall(code):
        if name == func_name or name in _FORWARD_DECL_EXCLUDE or name in globals_found:
            continue
        names.add(name)

    return sorted(names)


def infer_forward_declarations(
    func_name: str, pseudocode_lines: list[str]
) -> list[str]:
    """Infer conservative forward declarations for external calls/symbol refs."""
    names = get_forward_declaration_names(func_name, pseudocode_lines)
    return [f"extern int {name}();" for name in names]


def build_compilation_shims(pseudocode_lines: list[str]) -> list[str]:
    """Build lightweight compatibility macros/typedefs for exported code."""
    code = "\n".join(pseudocode_lines)
    shims = [
        "#ifndef __fastcall",
        "#define __fastcall",
        "#endif",
        "#ifndef __stdcall",
        "#define __stdcall",
        "#endif",
        "#ifndef __cdecl",
        "#define __cdecl",
        "#endif",
    ]

    if "JUMPOUT(" in code:
        shims.extend(
            [
                "#ifndef JUMPOUT",
                "#define JUMPOUT(addr) do { (void)(addr); } while (0)",
                "#endif",
            ]
        )

    return shims


def _prepend_signature_decorator(
    pseudocode_lines: list[str], decorator: str
) -> list[str]:
    """Prefix the first non-comment pseudocode line with a decorator."""
    modified = list(pseudocode_lines)
    for idx, line in enumerate(modified):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith("EXPORT "):
            return modified
        modified[idx] = f"{decorator}{line}"
        return modified
    return modified


def _infer_parameter_names(pseudocode_lines: list[str]) -> set[str]:
    """Infer parameter identifiers from the function signature."""
    signature_lines: list[str] = []
    for line in pseudocode_lines:
        signature_lines.append(line)
        if "{" in line:
            break
    signature_text = " ".join(signature_lines)
    match = re.search(r"\((.*)\)", signature_text)
    if not match:
        return set()

    params = set()
    for raw in match.group(1).split(","):
        part = raw.strip()
        if not part or part == "void":
            continue
        name_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*$", part)
        if name_match:
            params.add(name_match.group(1))
    return params


def infer_collapsed_local_declarations(pseudocode_lines: list[str]) -> list[str]:
    """Infer fallback local declarations when IDA collapses local declarations."""
    if not any("COLLAPSED LOCAL DECLARATIONS" in line for line in pseudocode_lines):
        return []

    param_names = _infer_parameter_names(pseudocode_lines)
    ids = set()
    for line in pseudocode_lines:
        for match in _TEMP_LOCAL_RE.findall(line):
            name = f"v{match}"
            if name in param_names:
                continue
            ids.add(int(match))

    return [f"v{i}" for i in sorted(ids)]


def inject_inferred_local_declarations(pseudocode_lines: list[str]) -> list[str]:
    """Inject inferred locals into function body after collapsed-locals comment."""
    names = infer_collapsed_local_declarations(pseudocode_lines)
    if not names:
        return list(pseudocode_lines)

    marker_idx = next(
        (
            idx
            for idx, line in enumerate(pseudocode_lines)
            if "COLLAPSED LOCAL DECLARATIONS" in line
        ),
        None,
    )
    if marker_idx is None:
        return list(pseudocode_lines)

    indent_match = re.match(r"^(\s*)", pseudocode_lines[marker_idx])
    indent = indent_match.group(1) if indent_match else "    "
    decl_lines = [f"{indent}__int64 {name};" for name in names]

    modified = list(pseudocode_lines)
    insert_at = marker_idx + 1
    modified[insert_at:insert_at] = decl_lines + [""]
    return modified


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
    effective_pseudocode_lines = inject_inferred_local_declarations(pseudocode_lines)
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
            "typedef uint32_t DWORD;",
            "typedef bool _BOOL1;",
            "typedef int32_t _BOOL4;",
            "typedef int64_t _BOOL8;",
            "",
        ]
    )

    # Add compile shims/macros to keep decompiler artifacts buildable.
    lines.append("// Compatibility shims for decompiler-emitted syntax")
    lines.extend(build_compilation_shims(effective_pseudocode_lines))
    lines.append("")

    inferred_globals = infer_global_declarations(effective_pseudocode_lines)
    if inferred_globals:
        lines.append("// Inferred referenced globals")
        lines.extend(inferred_globals)
        lines.append("")

    inferred_forwards = infer_forward_declarations(func_name, effective_pseudocode_lines)
    if inferred_forwards:
        lines.append("// Inferred forward declarations")
        lines.extend(inferred_forwards)
        lines.append("")

    # Add local type declarations if provided
    if local_types:
        lines.append("// Local type declarations")
        lines.extend(local_types)
        lines.append("")

    # Add the function body
    lines.append(f"// Function: {func_name} at {func_ea:#x}")
    lines.extend(effective_pseudocode_lines)
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
    forward_declarations: list[str] | None = None,
    imported_function_declarations: list[str] | None = None,
) -> str:
    """Generate sample-compatible C source.

    Follows the format used in samples/src/c/:
    - #include "polyfill.h" for IDA/Win32 type and API compatibility
    - #include "platform.h" for EXPORT macro
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
    forward_declarations: Optional list of function forward declarations (with full signatures)
    imported_function_declarations: Optional list of imported function pointer declarations

    Returns:
        Complete C source file content in sample format

    Examples:
        >>> output = format_sample_compatible_c(
        ...     "test_func",
        ...     0x401000,
        ...     ["int test_func(int x) {", "  return x + 1;", "}"]
        ... )
        >>> '#include "polyfill.h"' in output
        True
        >>> '#include "platform.h"' in output
        True
        >>> "volatile int g_test_func_sink" in output
        True
        >>> "EXPORT __attribute__((noinline))" in output
        True
    """
    effective_pseudocode_lines = inject_inferred_local_declarations(pseudocode_lines)
    lines = []

    # Header comment with metadata
    header_comment = build_sample_header_comment(func_name, func_ea, metadata)
    lines.append(header_comment)
    lines.append("")

    # Standard includes for sample format
    lines.append('#include "polyfill.h"')
    lines.append('#include "platform.h"')
    lines.append("")
    lines.append("// Compatibility shims for decompiler-emitted syntax")
    lines.extend(build_compilation_shims(effective_pseudocode_lines))
    lines.append("")

    # Global declarations from caller, or inferred from pseudocode.
    effective_global_decls = (
        list(global_declarations)
        if global_declarations is not None
        else infer_global_declarations(effective_pseudocode_lines)
    )
    if effective_global_decls:
        lines.append("// Referenced globals")
        for decl in effective_global_decls:
            # Make globals volatile to prevent optimization
            if "volatile" not in decl:
                decl = decl.replace("extern ", "extern volatile ", 1)
                if not decl.startswith("extern"):
                    decl = "volatile " + decl
            lines.append(decl)
        lines.append("")

    effective_forwards = (
        forward_declarations
        if forward_declarations is not None
        else infer_forward_declarations(func_name, effective_pseudocode_lines)
    )
    if effective_forwards:
        lines.append("// Forward declarations")
        lines.extend(effective_forwards)
        lines.append("")

    if imported_function_declarations:
        lines.append("// Imported / external function pointers")
        lines.extend(imported_function_declarations)
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

    # Insert EXPORT and noinline before the function signature line.
    modified_code = _prepend_signature_decorator(
        effective_pseudocode_lines, "EXPORT __attribute__((noinline)) "
    )

    lines.extend(modified_code)
    lines.append("")

    return "\n".join(lines)
