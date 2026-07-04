"""Behavioral semantic-equivalence oracle for deobfuscation tests.

``must_change`` only asks *did the code change*; it passed on real
miscompilations (ticket d81-c733: an OLLVM conditional dispatcher that d810
"unflattened" to ``return 3*(a1-5)/2`` -- the whole ``if`` dropped -- still
satisfied ``must_change`` and a fully green suite).  AST/text comparison against
``expected_code`` is stronger but brittle to decompiler rendering.

This module is the strongest, most rendering-robust oracle: it COMPILES d810's
deobfuscated AFTER pseudocode next to the reference SOURCE function and diffs
their outputs over an input range.  Two functions that agree on every input are
behaviorally equivalent regardless of how either is spelled.  Pure Python plus a
host C compiler -- no IDA -- so the logic is unit-testable.

Scope: single ``int``-argument reference functions (the dispatcher-pattern
family in ``samples/src/c/dispatcher_patterns.c``).  Multi-argument references
are a future extension.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

# src/d810/testing/semantic_equivalence.py -> repo root is three parents up.
_REPO_ROOT = Path(__file__).resolve().parents[3]

__all__ = [
    "SemanticOracleUnavailable",
    "find_c_compiler",
    "extract_reference_body",
    "pseudocode_to_c_function",
    "build_equivalence_program",
    "check_semantic_equivalence",
    "assert_semantic_equivalence",
]


class SemanticOracleUnavailable(Exception):
    """The semantic oracle could not run for an infrastructural reason.

    Raised (and, in the runner, turned into a ``pytest.skip``) when no host C
    compiler is available.  A *misconfigured* case -- reference function absent,
    pseudocode that will not compile, or an actual behavioral mismatch -- is a
    hard :class:`AssertionError`, never this.
    """


def find_c_compiler() -> str | None:
    """Return the path to a host C compiler, or ``None`` if none is installed."""
    for candidate in ("cc", "gcc", "clang"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def _repo_path(rel: str) -> Path:
    p = Path(rel)
    return p if p.is_absolute() else _REPO_ROOT / p


def extract_reference_body(source_text: str, function: str) -> str | None:
    """Extract the full ``int function(int input){...}`` definition from C source.

    Returns the whole definition text (signature + brace-balanced body), or
    ``None`` if a single-``int``-argument definition of ``function`` is absent.
    """
    m = re.search(
        r"\bint\s+" + re.escape(function) + r"\s*\(\s*int\s+input\s*\)\s*\{",
        source_text,
    )
    if not m:
        return None
    depth = 0
    open_brace = m.end() - 1
    for j in range(open_brace, len(source_text)):
        if source_text[j] == "{":
            depth += 1
        elif source_text[j] == "}":
            depth -= 1
            if depth == 0:
                return source_text[m.start(): j + 1]
    return None


def pseudocode_to_c_function(
    after: str, function: str, *, new_name: str = "deob"
) -> str:
    """Rewrite IDA AFTER pseudocode into a compilable ``unsigned new_name(int input)``.

    IDA renders the decompiled function as e.g.
    ``__int64 __fastcall high_fan_in_pattern(int a1)`` (or ``unsigned int a1``);
    normalize the signature to ``unsigned new_name(int input)`` and rename the
    ``a1`` parameter to ``input`` so it can be compiled and driven directly.
    """
    body = re.sub(
        r"(?:unsigned\s+)?(?:__int64|__int32|int)\s+__fastcall\s+"
        + re.escape(function)
        + r"\s*\(\s*(?:unsigned\s+)?int\s+a1\s*\)",
        f"unsigned {new_name}(int input)",
        after,
        count=1,
    )
    return re.sub(r"\ba1\b", "input", body)


def build_equivalence_program(
    reference_body: str, deob_body: str, *, lo: int, hi: int
) -> str:
    """Assemble a self-contained C program that diffs ``ref`` vs ``deob``."""
    ref = re.sub(
        r"\bint\s+\w+\s*\(\s*int\s+input\s*\)",
        "unsigned ref(int input)",
        reference_body,
        count=1,
    )
    return f"""#include <stdio.h>
#include <stdint.h>
typedef long long __int64;
{ref}
{deob_body}
int main(void) {{
    int bad = 0;
    for (int input = {lo}; input <= {hi}; input++) {{
        if (ref(input) != deob(input)) {{
            if (bad < 6)
                printf("MISMATCH input=%d ref=%u deob=%u\\n", input, ref(input), deob(input));
            bad++;
        }}
    }}
    printf("%s %d\\n", bad ? "SEMANTIC_FAIL" : "SEMANTIC_OK", bad);
    return bad ? 1 : 0;
}}
"""


def check_semantic_equivalence(
    after: str,
    function: str,
    reference_source: str,
    *,
    lo: int = -256,
    hi: int = 256,
    compiler: str | None = None,
) -> tuple[bool | None, str]:
    """Compile-and-diff the AFTER pseudocode against the reference source function.

    Returns ``(ok, detail)``.  ``ok`` is ``None`` only when no compiler is
    available (an infrastructural skip); ``True``/``False`` is the behavioral
    verdict.  ``detail`` carries the run output or the failing program.
    """
    cc = compiler or find_c_compiler()
    if cc is None:
        return None, "no C compiler available"
    ref_body = extract_reference_body(reference_source, function)
    if ref_body is None:
        return False, f"reference function 'int {function}(int input)' not found in source"
    deob_body = pseudocode_to_c_function(after, function)
    program = build_equivalence_program(ref_body, deob_body, lo=lo, hi=hi)
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "eq.c"
        binary = Path(tmp) / "eq.bin"
        src.write_text(program)
        compiled = subprocess.run(
            [cc, "-O0", "-w", "-fwrapv", "-o", str(binary), str(src)],
            capture_output=True,
            text=True,
        )
        if compiled.returncode != 0:
            return False, f"compile failed: {compiled.stderr[-600:]}\n--- program ---\n{program}"
        run = subprocess.run([str(binary)], capture_output=True, text=True)
        out = (run.stdout or "").strip()
        ok = "SEMANTIC_OK" in out and run.returncode == 0
        return ok, out


def assert_semantic_equivalence(
    after: str,
    function: str,
    reference_source_path: str,
    *,
    lo: int = -256,
    hi: int = 256,
) -> None:
    """Assert the AFTER pseudocode is behaviorally equal to the reference function.

    ``reference_source_path`` is a repo-root-relative C source file containing
    ``int function(int input){...}``.  Raises :class:`SemanticOracleUnavailable`
    when no compiler exists (skip), or :class:`AssertionError` on a real
    mismatch, a compile failure, or a missing reference.
    """
    source_text = _repo_path(reference_source_path).read_text(errors="replace")
    ok, detail = check_semantic_equivalence(
        after, function, source_text, lo=lo, hi=hi
    )
    if ok is None:
        raise SemanticOracleUnavailable(detail)
    if not ok:
        raise AssertionError(
            f"Semantic-equivalence oracle FAILED for '{function}': the deobfuscated "
            f"output is NOT behaviorally equivalent to the reference source "
            f"'{reference_source_path}'.\n{detail}\n--- AFTER pseudocode ---\n{after}"
        )
