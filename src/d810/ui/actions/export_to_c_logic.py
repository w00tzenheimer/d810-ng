"""Pure logic for export to C file action.

This module contains the business logic for exporting decompiled functions to
compilable C source files, separated from IDA dependencies to enable unit testing.

All functions in this module can be imported and tested without IDA Pro.
"""

from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass
from datetime import datetime

from d810.core.clang_loader import load_clang_index
from d810.core.logging import getLogger
from d810.core.typing import Any

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
#define EXPORT
#define D810_NOINLINE __declspec(noinline)
"""

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
    "xmmword": "_OWORD",
    "ymmword": "_OWORD",
    "zmmword": "_OWORD",
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

# Match _OWORD assignments for replacement with STORE_OWORD_N
_OWORD_STORE_IDX0_RE = re.compile(
    r"\*\s*\(\s*_OWORD\s*\*\s*\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"((?:xmmword|ymmword|zmmword)_[0-9A-Fa-f]+|0)\s*;"
)
_OWORD_STORE_IDXN_RE = re.compile(
    r"\*\s*\(\s*\(\s*_OWORD\s*\*\s*\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(0x[0-9A-Fa-f]+|\d+)\s*\)\s*=\s*"
    r"((?:xmmword|ymmword|zmmword)_[0-9A-Fa-f]+|0)\s*;"
)
_OWORD_STORE_OFFSET_RE = re.compile(
    r"\*\s*\(\s*_OWORD\s*\*\s*\)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*"
    r"(0x[0-9A-Fa-f]+|\d+)\s*\)\s*=\s*"
    r"((?:xmmword|ymmword|zmmword)_[0-9A-Fa-f]+|0)\s*;"
)

_D810_ZERO_OWORD = "D810_ZERO_OWORD"
_HANDLE_INIT_RE = re.compile(
    r"^(\s*(?:static\s+)?(?:extern\s+)?(?:volatile\s+)?HANDLE\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*)([^;]+)(;\s*)$"
)
_SUBCALL_FIRST_ARG_RE = re.compile(r"\b(sub_[A-Za-z0-9_]+)\s*\(\s*([^,\)]+)\s*,")
_SUBCALL_SECOND_ARG_PTR_RE = re.compile(
    r"(\bsub_[A-Za-z0-9_]+\(\s*[^,]+,\s*)([A-Za-z_][A-Za-z0-9_]*\[[^\]]+\])(\s*,)"
)
_SUBCALL_THIRD_ARG_IDENT_RE = re.compile(
    r"(\bsub_[A-Za-z0-9_]+\(\s*[^,]+,\s*[^,]+,\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*,)"
)
_SEC_COOKIE_RE = re.compile(r"(?<!_)_security_cookie\b")

_IMPORTED_DECL_NORMALIZATIONS = {
    "ConvertThreadToFiber": "extern LPVOID (__stdcall *ConvertThreadToFiber)(LPVOID lpParameter);",
    "CreateFiber": "extern LPVOID (__stdcall *CreateFiber)(SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter);",
    "GetThreadContext": "extern BOOL (__stdcall *GetThreadContext)(HANDLE hThread, LPCONTEXT lpContext);",
    "IsThreadAFiber": "extern BOOL (__stdcall *IsThreadAFiber)(void);",
    "RtlAcquireSRWLockExclusive": "extern void (__stdcall *RtlAcquireSRWLockExclusive)(void *SRWLock);",
    "RtlReleaseSRWLockExclusive": "extern void (__stdcall *RtlReleaseSRWLockExclusive)(void *SRWLock);",
    "SetThreadContext": "extern BOOL (__stdcall *SetThreadContext)(HANDLE hThread, const CONTEXT *lpContext);",
    "SwitchToFiber": "extern void (__stdcall *SwitchToFiber)(LPVOID lpFiber);",
    "TlsGetValue": "extern LPVOID (__stdcall *TlsGetValue)(DWORD dwTlsIndex);",
    "TlsSetValue": "extern BOOL (__stdcall *TlsSetValue)(DWORD dwTlsIndex, LPVOID lpTlsValue);",
}


def _wrap_qword_expr(expr: str) -> str:
    expr = expr.strip()
    if expr.startswith("(_QWORD)") or expr.startswith("D810_PTR_TO_QWORD("):
        return expr
    return f"(_QWORD)({expr})"


def apply_compile_safety_rewrites(lines: list[str]) -> list[str]:
    """Apply conservative, compiler-oriented rewrites to improve C export buildability.

    This pass is syntax-driven (no compiler invocation) and targets recurring
    decompiler patterns that trigger pointer/integer conversion errors.
    """
    rewritten: list[str] = []

    pending_qword_call_cast = False
    pending_subcall_arg_idx: int | None = None

    for line in lines:
        m = _HANDLE_INIT_RE.match(line)
        if m:
            prefix, rhs, suffix = m.groups()
            rhs_s = rhs.strip()
            if not rhs_s.startswith("(HANDLE)"):
                line = f"{prefix}(HANDLE)(ULONG_PTR)({rhs_s}){suffix}"

        if "=" in line:
            lhs, rhs = line.split("=", 1)
            rhs_expr = rhs.rstrip()
            if (
                "_QWORD *)" in lhs
                and lhs.lstrip().startswith("*")
                and rhs_expr.endswith(";")
            ):
                rhs_no_semicolon = rhs_expr[:-1].strip()
                line = f"{lhs}= {_wrap_qword_expr(rhs_no_semicolon)};"
            elif (
                "_QWORD *)" in lhs
                and lhs.lstrip().startswith("*")
                and rhs_expr.strip().endswith("(")
                and "(_QWORD)(" not in rhs_expr
            ):
                line = f"{lhs}= (_QWORD)({rhs_expr.strip()}"
                pending_qword_call_cast = True

        if pending_qword_call_cast and line.strip().endswith(");") and not line.strip().endswith("));"):
            line = line.rsplit(");", 1)[0] + "));"
            pending_qword_call_cast = False

        if pending_subcall_arg_idx is not None:
            stripped = line.strip()
            # Third argument in multiline sub_* call: cast Value to _QWORD.
            if pending_subcall_arg_idx == 2 and re.match(r"Value\s*,\s*$", stripped):
                line = line.replace("Value", "(_QWORD)(Value)", 1)
                stripped = line.strip()
            if stripped.endswith(","):
                pending_subcall_arg_idx += 1
            if stripped.endswith(");"):
                pending_subcall_arg_idx = None

        # Most generated sub_* forward declarations use _QWORD parameters.
        # Cast the first argument when it isn't already cast.
        m = _SUBCALL_FIRST_ARG_RE.search(line)
        if m:
            callee = m.group(1)
            arg0 = m.group(2).strip()
            if not arg0.startswith("(_QWORD)") and not arg0.startswith(
                "(unsigned __int64)"
            ):
                casted = f"{callee}((_QWORD)({arg0}),"
                line = line[: m.start()] + casted + line[m.end() :]

        # Track multiline sub_* calls to patch third argument lines.
        if re.search(r"\bsub_[A-Za-z0-9_]+\s*\(\s*$", line):
            pending_subcall_arg_idx = 0

        line = _SUBCALL_SECOND_ARG_PTR_RE.sub(r"\1(_QWORD)(\2)\3", line)
        line = _SUBCALL_THIRD_ARG_IDENT_RE.sub(
            lambda m: (
                f"{m.group(1)}(_QWORD)({m.group(2)}){m.group(3)}"
                if m.group(2) in {"Value"}
                else m.group(0)
            ),
            line,
        )
        line = line.replace("SetThreadContext(hThread,", "SetThreadContext(qword_7FFB208C0058,")
        line = _SEC_COOKIE_RE.sub("__security_cookie", line)

        rewritten.append(line)

    return rewritten


def normalize_imported_function_declarations(declarations: list[str]) -> list[str]:
    """Normalize imported declarations to known-good signatures from polyfill.h."""
    normalized: list[str] = []
    seen_names: set[str] = set()

    for decl in declarations:
        replaced = decl
        for name, canonical in _IMPORTED_DECL_NORMALIZATIONS.items():
            if re.search(rf"\b{name}\b", decl):
                replaced = canonical
                if name in seen_names:
                    replaced = ""
                else:
                    seen_names.add(name)
                break
        if replaced:
            normalized.append(replaced)
    return normalized


def replace_oword_assignments(lines: list[str]) -> tuple[list[str], bool]:
    """Replace _OWORD assignments with STORE_OWORD_N macros.

    Transforms:
      *(_OWORD *)Base = xmmword_XXX;       -> STORE_OWORD_N(Base, 0, &xmmword_XXX);
      *((_OWORD *)Base + N) = xmmword_XXX;  -> STORE_OWORD_N(Base, N, &xmmword_XXX);
      *(_OWORD *)(Base + offset) = xmmword; -> STORE_OWORD_N(Base, offset/16, &xmmword);
      ... = 0;                             -> STORE_OWORD_N(Base, idx, &D810_ZERO_OWORD);

    Returns (modified_lines, needs_zero_oword).
    """
    out: list[str] = []
    needs_zero = False

    def make_replacement(base: str, idx_val: str, rhs: str) -> tuple[str, bool]:
        src = f"&{rhs}" if rhs != "0" else f"&{_D810_ZERO_OWORD}"
        zero = rhs == "0"
        return f"STORE_OWORD_N({base}, {idx_val}, {src});", zero

    for line in lines:
        matches: list[tuple[int, int, str]] = []

        for pat, idx_fn in [
            (_OWORD_STORE_IDX0_RE, lambda m: ("0", m.group(2))),
            (_OWORD_STORE_IDXN_RE, lambda m: (m.group(2), m.group(3))),
            (
                _OWORD_STORE_OFFSET_RE,
                lambda m: (str(int(m.group(2), 0) // 16), m.group(3)),
            ),
        ]:
            for m in pat.finditer(line):
                idx_val, rhs = idx_fn(m)
                base = m.group(1)
                repl, z = make_replacement(base, idx_val, rhs)
                if z:
                    needs_zero = True
                matches.append((m.start(), m.end(), repl))

        # Replace from end to start to preserve positions
        for start, end, repl in sorted(matches, key=lambda x: -x[0]):
            line = line[:start] + repl + line[end:]

        out.append(line)

    return out, needs_zero


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
    header_metadata_text: str = ""


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

    lines = [
        "/*",
        " * d810ng Deobfuscation Metadata",
        " * --------------------------------",
    ]

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
        if (
            name == func_name
            or name in _FORWARD_DECL_EXCLUDE
            or name in globals_found
            or name.startswith("__")
        ):
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
    user_header_text: str = "",
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
    ]
    if user_header_text:
        lines.append(" *")
        lines.append(" * User metadata:")
        for note_line in user_header_text.splitlines():
            lines.append(f" *   {note_line}")
    lines.extend(
        [
            " */",
            "",
        ]
    )

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

    inferred_forwards = infer_forward_declarations(
        func_name, effective_pseudocode_lines
    )
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
    func_name: str,
    func_ea: int,
    metadata: dict[str, Any] | None = None,
    user_header_text: str = "",
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

    if user_header_text:
        lines.append(" * User metadata:")
        for note_line in user_header_text.splitlines():
            lines.append(f" *   {note_line}")
        lines.append(" *")

    # Add metadata if available
    if metadata:
        deobfs_applied = []
        opt_matches = metadata.get("optimizer_matches", {})
        if opt_matches:

            for name, count in sorted(opt_matches.items()):
                deobfs_applied.append(f" *   {name}: {count} matches")

        rule_matches = metadata.get("rule_matches", {})
        if rule_matches:
            total = sum(rule_matches.values())
            deobfs_applied.append(f" *   MBA rules: {total} simplifications")
        if deobfs_applied:
            lines.append(" * Deobfuscation applied:")
            lines.extend(deobfs_applied)

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
    user_header_text: str = "",
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
    - EXPORT D810_NOINLINE on function
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
        >>> "EXPORT D810_NOINLINE" in output
        True
    """
    effective_pseudocode_lines = inject_inferred_local_declarations(pseudocode_lines)
    effective_pseudocode_lines = apply_compile_safety_rewrites(
        effective_pseudocode_lines
    )
    effective_pseudocode_lines, _ = replace_oword_assignments(
        effective_pseudocode_lines
    )
    lines = []

    # Header comment with metadata
    header_comment = build_sample_header_comment(
        func_name, func_ea, metadata, user_header_text=user_header_text
    )
    lines.append(header_comment)
    lines.append("")

    # Standard includes for sample format
    lines.append('#include "polyfill.h"')
    lines.append('#include "platform.h"')
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
            m = _HANDLE_INIT_RE.match(decl)
            if m:
                prefix, rhs, suffix = m.groups()
                rhs_s = rhs.strip()
                if not rhs_s.startswith("(HANDLE)"):
                    decl = f"{prefix}(HANDLE)(ULONG_PTR)({rhs_s}){suffix}"
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
        lines.extend(
            normalize_imported_function_declarations(imported_function_declarations)
        )
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

    # Function with EXPORT and D810_NOINLINE (from platform.h)
    lines.append(f"// Function: {func_name} at {func_ea:#x}")

    # Insert EXPORT and D810_NOINLINE before the function signature line.
    modified_code = _prepend_signature_decorator(
        effective_pseudocode_lines, "EXPORT D810_NOINLINE "
    )

    lines.extend(modified_code)
    lines.append("")

    return "\n".join(lines)


def _get_clang_index(idaapi_mod: Any | None = None) -> Any:
    """Create and return a clang Index.

    Args:
        idaapi_mod: Optional IDA API module for getting IDA installation directory
    """
    ida_dir: pathlib.Path | None = None
    if idaapi_mod is not None and hasattr(idaapi_mod, "get_ida_directory"):
        try:
            ida_dir = pathlib.Path(idaapi_mod.get_ida_directory())
        except Exception:
            ida_dir = None

    project_root = pathlib.Path(__file__).resolve().parents[4]
    index, path, tried = load_clang_index(
        ida_directory=ida_dir,
        project_root=project_root,
    )
    if index is None:
        tried_text = ", ".join(str(p) for p in tried) if tried else "<none>"
        raise RuntimeError(f"libclang is required but unavailable. Tried: {tried_text}")
    if path is not None:
        logger.debug("Loaded libclang from %s", path)
    return index


def _apply_fixits(content: str, tu: Any) -> str:
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

    edits.sort(key=lambda x: x[0], reverse=True)
    result = content
    for start, end, replacement in edits:
        result = result[:start] + replacement + result[end:]
    return result


def _apply_edits(content: str, edits: list[tuple[int, int, str]]) -> str:
    """Apply text edits in descending offset order."""
    if not edits:
        return content
    result = content
    for start, end, replacement in sorted(edits, key=lambda e: e[0], reverse=True):
        result = result[:start] + replacement + result[end:]
    return result


def _range_offsets(extent: Any, content_len: int) -> tuple[int, int] | None:
    """Return validated [start, end) offsets from a clang SourceRange."""
    try:
        start = extent.start.offset
        end = extent.end.offset
    except Exception:
        return None
    if start < 0 or end < start or end > content_len:
        return None
    return start, end


def _is_integer_type(c_type: Any) -> bool:
    """True when the canonical clang type is an integer kind."""
    from d810._vendor.clang.cindex import TypeKind

    kind = c_type.get_canonical().kind
    return kind in {
        TypeKind.BOOL,
        TypeKind.CHAR_U,
        TypeKind.UCHAR,
        TypeKind.CHAR16,
        TypeKind.CHAR32,
        TypeKind.USHORT,
        TypeKind.UINT,
        TypeKind.ULONG,
        TypeKind.ULONGLONG,
        TypeKind.UINT128,
        TypeKind.CHAR_S,
        TypeKind.SCHAR,
        TypeKind.WCHAR,
        TypeKind.SHORT,
        TypeKind.INT,
        TypeKind.LONG,
        TypeKind.LONGLONG,
        TypeKind.INT128,
        TypeKind.ENUM,
    }


def _is_pointer_type(c_type: Any) -> bool:
    """True when the canonical clang type is pointer-like."""
    from d810._vendor.clang.cindex import TypeKind

    kind = c_type.get_canonical().kind
    return kind in {
        TypeKind.POINTER,
        TypeKind.OBJCOBJECTPOINTER,
        TypeKind.MEMBERPOINTER,
    }


def _needs_cast(expr_text: str, target_type: str) -> bool:
    """Avoid adding duplicate casts when expression is already cast."""
    stripped = expr_text.strip()
    return not (
        stripped.startswith(f"({target_type})")
        or stripped.startswith("(void *)")
        or stripped.startswith("(void*)")
        or stripped.startswith("(_QWORD)")
    )


def _get_call_param_types(call_cursor: Any) -> list[Any]:
    """Best-effort extraction of call parameter types from clang AST."""
    try:
        ref = call_cursor.referenced
    except Exception:
        ref = None

    if ref is not None:
        params = [arg.type for arg in ref.get_arguments() if arg is not None]
        if params:
            return params

    children = list(call_cursor.get_children())
    if not children:
        return []

    callee_type = children[0].type.get_canonical()
    try:
        from d810._vendor.clang.cindex import TypeKind
    except Exception:
        return []

    if callee_type.kind == TypeKind.POINTER:
        callee_type = callee_type.get_pointee().get_canonical()

    if callee_type.kind != TypeKind.FUNCTIONPROTO:
        return []

    try:
        return [t for t in callee_type.argument_types()]
    except Exception:
        return []


def _collect_ast_cast_edits(
    content: str, tu: Any, preamble_len: int
) -> list[tuple[int, int, str]]:
    """Collect AST-guided cast edits for common pointer/integer incompatibilities."""
    from d810._vendor.clang.cindex import CursorKind

    edits: list[tuple[int, int, str]] = []
    seen_ranges: set[tuple[int, int]] = set()

    def has_function_ancestor(cur: Any) -> bool:
        parent = cur.semantic_parent
        while parent is not None:
            if parent.kind == CursorKind.FUNCTION_DECL:
                return True
            parent = parent.semantic_parent
        return False

    def maybe_add_cast(extent: Any, target_type: str) -> None:
        off = _range_offsets(extent, len(content))
        if off is None:
            return
        start, end = off
        if start < preamble_len:
            return
        if (start, end) in seen_ranges:
            return
        expr_text = content[start:end]
        if not _needs_cast(expr_text, target_type):
            return
        edits.append((start, end, f"({target_type})({expr_text.strip()})"))
        seen_ranges.add((start, end))

    for cur in tu.cursor.walk_preorder():
        if cur.kind == CursorKind.VAR_DECL:
            if not _is_pointer_type(cur.type):
                continue
            try:
                tok_text = " ".join(tok.spelling for tok in cur.get_tokens())
            except Exception:
                tok_text = ""
            if "=" not in tok_text or " extern " in f" {tok_text} ":
                continue
            children = [c for c in cur.get_children()]
            if not children:
                continue
            init_expr = children[-1]
            try:
                if _is_integer_type(init_expr.type):
                    maybe_add_cast(init_expr.extent, cur.type.spelling)
            except Exception:
                continue
            continue

        if cur.kind == CursorKind.CALL_EXPR:
            if not has_function_ancestor(cur):
                continue
            params = _get_call_param_types(cur)
            if not params:
                continue
            args = [a for a in cur.get_arguments() if a is not None]
            for idx, arg in enumerate(args):
                if idx >= len(params):
                    break
                param_t = params[idx]
                try:
                    if _is_integer_type(param_t) and _is_pointer_type(arg.type):
                        maybe_add_cast(arg.extent, param_t.spelling)
                    elif _is_pointer_type(param_t) and _is_integer_type(arg.type):
                        maybe_add_cast(arg.extent, param_t.spelling)
                except Exception:
                    continue
            continue

        if cur.kind == CursorKind.BINARY_OPERATOR:
            if not has_function_ancestor(cur):
                continue
            try:
                tokens = [tok.spelling for tok in cur.get_tokens()]
            except Exception:
                continue
            if "=" not in tokens:
                continue

            operands = [c for c in cur.get_children()]
            if len(operands) < 2:
                continue
            lhs = operands[0]
            rhs = operands[-1]
            try:
                if _is_integer_type(lhs.type) and _is_pointer_type(rhs.type):
                    maybe_add_cast(rhs.extent, lhs.type.spelling)
                elif _is_pointer_type(lhs.type) and _is_integer_type(rhs.type):
                    maybe_add_cast(rhs.extent, lhs.type.spelling)
            except Exception:
                continue

    return edits


def _apply_ast_typed_cast_rewrites(
    content: str, tu: Any, preamble_len: int
) -> str:
    """Apply AST-driven cast rewrites for typed pointer/integer mismatches."""
    edits = _collect_ast_cast_edits(content, tu, preamble_len)
    if not edits:
        return content
    return _apply_edits(content, edits)


def make_compilable(c_source: str, max_rounds: int = 5, idaapi_mod: Any | None = None) -> str:
    """Parse C source with clang and apply fixits until it compiles or max_rounds."""
    index = _get_clang_index(idaapi_mod)

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

        ast_rewritten = _apply_ast_typed_cast_rewrites(content, tu, preamble_len)
        if ast_rewritten != content:
            content = ast_rewritten
            continue

        fixit_rewritten = _apply_fixits(content, tu)
        if fixit_rewritten == content:
            logger.debug("No fixits to apply, stopping")
            break
        content = fixit_rewritten

    result = content[preamble_len:] if len(content) > preamble_len else parse_content

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
