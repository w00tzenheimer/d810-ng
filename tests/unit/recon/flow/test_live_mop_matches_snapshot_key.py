"""Unit cover for hodur's ``_live_mop_matches_snapshot_key`` shape.

The actual function is in
``d810.optimizers.microcode.flow.flattening.hodur.analysis`` which
imports ``ida_hexrays`` -- can't be exercised from a unit test.
What we CAN cover here is the *protocol* the function implements:
its result must be the same as
``mop_snapshot_key(snapshot_of_the_same_operand) == key``.

So we verify that ``mop_snapshot_key`` produces the canonical
key strings (``r{}`` / ``S{}`` / ``v{}`` / ``l{}``) that the live
matcher in hodur compares against.  If a future edit drifts the
key formula on one side but not the other, this test catches it.

The runtime side (live ``mop_t`` -> matcher) is exercised by the
existing system suite via Docker.
"""

from __future__ import annotations

from d810.cfg.flowgraph import MopSnapshot, OperandKind
from d810.cfg.mop_identity import mop_snapshot_key


class TestLiveMopMatcherProtocol:
    """Pin the key-string formulas hodur's ``_live_mop_matches_snapshot_key``
    relies on.  The live-side formulas live in
    ``hodur/analysis.py:_live_mop_matches_snapshot_key`` and MUST
    track these:

    * REGISTER  -> ``"r{reg}"``
    * STACK     -> ``"S{stkoff}"``
    * GLOBAL    -> ``"v{gaddr}"``
    * LVAR      -> ``"l{lvar_off}"``
    """

    def test_register_key_formula(self) -> None:
        m = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        assert mop_snapshot_key(m) == "r3"

    def test_stack_key_formula(self) -> None:
        m = MopSnapshot(t=4, size=4, stkoff=0x40, kind=OperandKind.STACK)
        assert mop_snapshot_key(m) == "S64"

    def test_global_key_formula(self) -> None:
        m = MopSnapshot(t=8, size=8, gaddr=0x140002000, kind=OperandKind.GLOBAL)
        assert mop_snapshot_key(m) == "v5368717312"

    def test_lvar_key_formula(self) -> None:
        m = MopSnapshot(t=9, size=4, lvar_off=8, kind=OperandKind.LVAR)
        assert mop_snapshot_key(m) == "l8"

    def test_register_and_stack_distinct_at_same_numeric_value(self) -> None:
        """The prefix scheme prevents ``r3`` from matching a stack
        operand at offset 3.  This is the actual reason the cache
        match restoration is safe -- the key encodes the operand
        kind, not just the integer."""
        r = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        s = MopSnapshot(t=4, size=4, stkoff=3, kind=OperandKind.STACK)
        assert mop_snapshot_key(r) != mop_snapshot_key(s)


class TestHodurMatcherSourceContainsMirrorFormulas:
    """Architectural regression cover: hodur's
    ``_live_mop_matches_snapshot_key`` MUST contain the same key
    formula strings.  If a future edit changes one side and forgets
    the other, the cache-driven state-variable selection drifts
    silently.

    Source-level inspection (string search) is the right granularity
    -- a behavior-level test would require a live ``mop_t``.
    """

    def test_hodur_matcher_contains_register_formula(self) -> None:
        import inspect

        # Import the module file by reading its source (not by
        # importing the module -- that would pull in ida_hexrays
        # and fail under unit-tests-no-hexrays).
        from pathlib import Path

        hodur_analysis_path = (
            Path(__file__).resolve().parents[4]
            / "src"
            / "d810"
            / "optimizers"
            / "microcode"
            / "flow"
            / "flattening"
            / "hodur"
            / "analysis.py"
        )
        src = hodur_analysis_path.read_text()
        assert 'f"r{mop.r}"' in src, (
            "hodur _live_mop_matches_snapshot_key must produce r{reg} "
            "to match mop_snapshot_key's REGISTER formula"
        )
        assert 'f"S{mop.s.off}"' in src, (
            "hodur _live_mop_matches_snapshot_key must produce S{stkoff}"
        )
        assert 'f"v{mop.g}"' in src, (
            "hodur _live_mop_matches_snapshot_key must produce v{gaddr}"
        )
        assert 'f"l{mop.l.off}"' in src, (
            "hodur _live_mop_matches_snapshot_key must produce l{lvar_off}"
        )
