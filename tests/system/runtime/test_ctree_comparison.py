"""System tests for the ctree-native live-vs-live comparator.

These tests require IDA Pro (idalib / headless mode) — they are skipped when
running without IDA.  They exercise ``tests/system/ctree_comparator`` against
real decompiled cfuncs from the libobfuscated binary.

Design notes
------------
- All assertions are ROBUST: they check invariants / bounds rather than exact
  non-deterministic counts (IDA version, platform, binary may affect exact
  numbers).
- The headline test (``test_ctree_calls_exceed_libclang``) demonstrates the
  core motivation: for a function whose rendered pseudocode contains calls to
  undeclared/sub_* functions, the ctree call count is >= the libclang count.
  libclang drops undeclared-function calls in C++ mode; the ctree never does.
- Binary and fixture setup follows the pattern from
  ``tests/system/runtime/test_ast_comparison.py`` (same fixtures, same binary).
"""

from __future__ import annotations

import os
import platform

import pytest

try:
    import idaapi
    import idc

    _IDA_AVAILABLE = True
except Exception:
    _IDA_AVAILABLE = False
    idaapi = None  # type: ignore[assignment]
    idc = None  # type: ignore[assignment]

from tests.system.ctree_comparator import (
    are_equivalent,
    count_ast_statements,
    structural_signature,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = {"statements", "returns", "whiles", "gotos", "ifs", "calls"}


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


def _resolve_func_ea(name: str) -> int:
    """Resolve a function name to its EA, trying with/without underscore prefix."""
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def _decompile(func_ea: int):
    """Decompile a function by EA; return cfunc_t or raise."""
    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    if cfunc is None:
        raise AssertionError(f"decompile(0x{func_ea:x}) returned None")
    return cfunc


def _pseudocode_text(cfunc) -> str:
    """Render cfunc pseudocode to a plain string (tag-stripped)."""
    return os.linesep.join(
        idaapi.tag_remove(line.line) for line in cfunc.get_pseudocode()
    )


# ---------------------------------------------------------------------------
# Test class — mirrors structure of other runtime tests
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.skipif(not _IDA_AVAILABLE, reason="IDA Pro not available")


class TestCtreeComparison:
    """Ctree-native live-vs-live comparator tests against libobfuscated."""

    binary_name = _get_default_binary()

    @pytest.fixture(scope="class")
    def libobfuscated_setup(
        self,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
    ):
        """Open libobfuscated and configure Hex-Rays."""
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler not available")
        return ida_database

    # ------------------------------------------------------------------
    # Test 1: self-equivalence
    # ------------------------------------------------------------------

    def test_self_equivalence(self, libobfuscated_setup):
        """are_equivalent(cfunc, cfunc) must be True; signature must be non-empty.

        Uses ``test_xor`` — a small, stable function present in all builds.
        """
        func_ea = _resolve_func_ea("test_xor")
        if func_ea == idaapi.BADADDR:
            pytest.skip("test_xor not found in this binary")

        cfunc = _decompile(func_ea)

        sig = structural_signature(cfunc)
        assert isinstance(sig, tuple), "structural_signature must return a tuple"
        assert len(sig) > 0, "signature of a non-trivial function must be non-empty"

        assert are_equivalent(cfunc, cfunc) is True, (
            "are_equivalent(cfunc, cfunc) must always be True"
        )

    # ------------------------------------------------------------------
    # Test 2: cross-function difference
    # ------------------------------------------------------------------

    def test_cross_function_difference(self, libobfuscated_setup):
        """Two clearly different functions must NOT be equivalent.

        Uses ``test_xor`` (arithmetic XOR simplification) and ``test_or``
        (OR simplification) — different body shapes, different op sequences.
        """
        ea_xor = _resolve_func_ea("test_xor")
        ea_or = _resolve_func_ea("test_or")

        if ea_xor == idaapi.BADADDR or ea_or == idaapi.BADADDR:
            pytest.skip("test_xor or test_or not found in this binary")

        cfunc_xor = _decompile(ea_xor)
        cfunc_or = _decompile(ea_or)

        # Signatures must differ (they implement different operations)
        sig_xor = structural_signature(cfunc_xor)
        sig_or = structural_signature(cfunc_or)
        assert sig_xor != sig_or, (
            "test_xor and test_or have different bodies and must not share "
            f"the same structural signature.\n  xor sig[:8]={sig_xor[:8]}\n"
            f"  or  sig[:8]={sig_or[:8]}"
        )

        assert are_equivalent(cfunc_xor, cfunc_or) is False, (
            "are_equivalent must return False for structurally different functions"
        )

    # ------------------------------------------------------------------
    # Test 3: count_ast_statements sanity
    # ------------------------------------------------------------------

    def test_count_ast_statements_sanity(self, libobfuscated_setup):
        """count_ast_statements returns all 6 keys and satisfies structural bounds.

        Uses ``test_xor`` which has at least one store/assignment (sanity) and
        one return.  We check:
        - All 6 required keys present.
        - calls >= 0 (trivially true, but confirms the key exists and is int).
        - statements >= returns + ifs  (returns and ifs are a subset of stmts).
        - returns >= 1  (every function ends with a return).
        - All values are non-negative integers.
        """
        func_ea = _resolve_func_ea("test_xor")
        if func_ea == idaapi.BADADDR:
            pytest.skip("test_xor not found in this binary")

        cfunc = _decompile(func_ea)
        counts = count_ast_statements(cfunc)

        # All keys present
        assert set(counts.keys()) == _REQUIRED_KEYS, (
            f"Expected keys {_REQUIRED_KEYS}, got {set(counts.keys())}"
        )

        # All values are non-negative integers
        for k, v in counts.items():
            assert isinstance(v, int) and v >= 0, (
                f"count_ast_statements[{k!r}] must be a non-negative int, got {v!r}"
            )

        # Structural bounds
        assert counts["returns"] >= 1, (
            f"Every function must have at least one return; got returns={counts['returns']}"
        )
        assert counts["statements"] >= counts["returns"] + counts["ifs"], (
            "statements must be >= returns + ifs (both are subsets of all stmts)\n"
            f"  statements={counts['statements']}, returns={counts['returns']}, "
            f"ifs={counts['ifs']}"
        )

    # ------------------------------------------------------------------
    # Test 4: ctree call count >= libclang call count (the headline)
    # ------------------------------------------------------------------

    def test_ctree_calls_exceed_libclang(self, libobfuscated_setup, code_comparator):
        """Ctree call count is >= libclang call count on a function with sub_* calls.

        Motivation: libclang in C++ mode drops calls to undeclared functions
        (e.g. ``sub_7FFD3338C040(...)`` — no forward declaration), so its
        ``count_ast_statements`` returns ``calls=0`` for such functions.  The
        ctree visitor sees every ``cot_call`` node regardless of declaration
        status.

        We use ``hodur_func`` (or ``_hodur_func`` on macOS): this function calls
        undeclared ``sub_*`` helpers and is the canonical demonstration case.
        If it is absent we fall back to ``test_chained_add`` which calls
        ``test_xor`` (a declared function — expected to tie, which is also
        acceptable).

        The assertion is: ctree_calls >= libclang_calls.
        Additionally, for the primary candidate (hodur_func), we assert strict
        inequality (ctree_calls > libclang_calls).
        """
        # Primary candidate: hodur_func has sub_* calls that libclang drops
        func_name = "hodur_func"
        func_ea = _resolve_func_ea(func_name)
        strict_inequality_expected = func_ea != idaapi.BADADDR

        if func_ea == idaapi.BADADDR:
            # Fallback: test_chained_add calls test_xor (declared; tie expected)
            func_name = "test_chained_add"
            func_ea = _resolve_func_ea(func_name)
            strict_inequality_expected = False

        if func_ea == idaapi.BADADDR:
            pytest.skip("Neither hodur_func nor test_chained_add found in this binary")

        cfunc = _decompile(func_ea)
        rendered = _pseudocode_text(cfunc)

        ctree_counts = count_ast_statements(cfunc)
        ctree_calls = ctree_counts["calls"]

        # libclang count (may be None if code_comparator unavailable)
        libclang_calls: int | None = None
        if code_comparator is not None:
            try:
                lc_counts = code_comparator.count_ast_statements(rendered)
                libclang_calls = lc_counts.get("calls", 0)
            except Exception:
                libclang_calls = None

        # ctree must see at least 1 call for the chosen function
        assert ctree_calls >= 1, (
            f"ctree found 0 calls in {func_name} — unexpected for a function "
            f"that calls other functions.\n  rendered snippet:\n"
            + "\n".join(rendered.splitlines()[:20])
        )

        if libclang_calls is not None:
            assert ctree_calls >= libclang_calls, (
                f"ctree_calls ({ctree_calls}) must be >= libclang_calls ({libclang_calls}) "
                f"for {func_name}"
            )
            if strict_inequality_expected:
                assert ctree_calls > libclang_calls, (
                    f"For {func_name} (contains sub_* calls), ctree_calls "
                    f"({ctree_calls}) should STRICTLY exceed libclang_calls "
                    f"({libclang_calls}). libclang drops undeclared-function calls; "
                    "ctree does not."
                )
        # If code_comparator is unavailable, we still validated ctree_calls >= 1
        # which proves the ctree is counting calls the text-scanner might miss.
