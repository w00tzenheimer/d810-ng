"""Unit cover for hodur's ``_live_mop_matches_snapshot_key`` shape.

The actual function is in
``d810.backends.hexrays.evidence.analysis`` which
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

from d810.ir.flowgraph import MopSnapshot, OperandKind
from d810.ir.mop_identity import mop_snapshot_key


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

    def _hodur_analysis_src(self) -> str:
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
        return hodur_analysis_path.read_text()

    def test_hodur_matcher_contains_register_formula(self) -> None:
        src = self._hodur_analysis_src()
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

    def test_cache_driven_selection_iterates_hodur_state_check_blocks(
        self,
    ) -> None:
        """Scope invariant pin: the P2 cache-driven selection loop
        in ``HodurStateMachineDetector._find_state_machine`` MUST
        iterate ``state_check_blocks`` (hodur's filtered list),
        NOT ``cached.comparison_blocks`` (dispatcher cache's full
        set across the whole function).

        If the iteration drifts to the cache's list, hodur could
        select a live operand from a block hodur already rejected
        as a non-state-check, violating hodur's filtering
        invariant.  This test asserts the loop targets the right
        collection via source-string inspection (the runtime
        behavior is exercised via Docker since constructing live
        ``mba_t`` / ``state_check_blocks`` in unit isn't feasible).
        """
        src = self._hodur_analysis_src()
        # The cache-driven selection block exists between these
        # canonical markers.  ``marker_open`` pins the SCOPE INVARIANT
        # comment that documents the iteration target; the E5
        # DispatcherCache cleanup (67f6c9edb) reworded the older
        # "the cache's selection logic" marker, so anchor on the
        # invariant comment that must survive any future rewording.
        marker_open = "SCOPE INVARIANT: we iterate"
        marker_close = "if state_var is None:"
        assert marker_open in src
        assert marker_close in src
        # Extract the selection block.
        open_idx = src.index(marker_open)
        close_idx = src.index(marker_close, open_idx)
        selection_block = src[open_idx:close_idx]

        # The loop MUST iterate ``state_check_blocks``...
        assert "for blk_serial, _, _ in state_check_blocks:" in selection_block, (
            "Cache-driven selection must iterate hodur's "
            "``state_check_blocks``, not the cache's "
            "``comparison_blocks``.  If you changed the iteration "
            "target, verify the scope invariant in the comment "
            "above the loop still holds."
        )
        # ...and MUST NOT iterate ``cached.comparison_blocks``
        # as a code statement.  (The substring may appear in
        # comments that explain the scope invariant; the test
        # asserts no iteration form.)
        forbidden_iterations = (
            "for blk_serial in cached.comparison_blocks",
            "for blk_serial, _ in cached.comparison_blocks",
            "for blk_serial, _, _ in cached.comparison_blocks",
            "in cached.comparison_blocks:",
        )
        for forbidden in forbidden_iterations:
            assert forbidden not in selection_block, (
                "Scope violation: cache-driven selection iterates "
                f"{forbidden!r}, but it MUST iterate hodur's local "
                "``state_check_blocks`` instead.  Iterating the "
                "cache's full comparison set would let hodur select "
                "a live operand from a block hodur already rejected."
            )
