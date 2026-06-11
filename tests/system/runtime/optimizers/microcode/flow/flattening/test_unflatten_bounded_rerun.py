"""Bounded re-run gate for StateMachineCffUnflattener (ticket llr-3gn4).

A single spine-redirect pass can leave the dispatcher's comparison ENTRY block
reachable; the equality-chain / switch profile re-runs (bounded) so a later round
recovers + redirects that residual dispatcher and IDA's optimize_global converges
to the clean dispatcher-free graph (approov_real_pattern needs the 2nd round). The
INDIRECT_JUMP profile keeps the historical one-shot contract.

These exercise the pure gate (``_should_run_unflatten_round`` / ``_mark_ea_converged``)
— no live ``mba`` — but the rule's module imports ``ida_hexrays`` at top level, so the
test lives under ``tests/system`` where the conftest boots IDA headlessly (Test
Placement Rule: never mock IDA in unit tests).
"""
from __future__ import annotations

import pytest

from d810.optimizers.microcode.flow.flattening.state_machine_cff_unflattener import (
    StateMachineCffUnflattener,
)


_EA = 0x1800017F0


def _fresh_rule() -> StateMachineCffUnflattener:
    rule = StateMachineCffUnflattener.__new__(StateMachineCffUnflattener)
    # Initialise only the re-run bookkeeping (skip the heavy ComposedUnflatteningRule
    # __init__ / IDA lifecycle — the gate is pure and reads nothing else).
    rule._unflat_round_count = {}
    rule._unflat_done_eas = set()
    return rule


class TestUnflattenBoundedRerunGate:
    def test_non_indirect_reruns_until_converged(self) -> None:
        """The equality-chain profile re-runs across rounds until recovery converges."""
        rule = _fresh_rule()
        # First two rounds proceed (each emits the spine then the residual-dispatcher
        # redirect on the re-lifted graph).
        assert rule._should_run_unflatten_round(_EA, is_indirect=False) is True
        assert rule._should_run_unflatten_round(_EA, is_indirect=False) is True
        # Recovery finds no dispatcher -> converged -> terminal.
        rule._mark_ea_converged(_EA)
        assert rule._should_run_unflatten_round(_EA, is_indirect=False) is False

    def test_indirect_is_one_shot(self) -> None:
        """The INDIRECT_JUMP profile runs exactly once (no re-run, no body drop)."""
        rule = _fresh_rule()
        assert rule._should_run_unflatten_round(_EA, is_indirect=True) is True
        # Second invocation is refused even though the ea was never marked converged.
        assert rule._should_run_unflatten_round(_EA, is_indirect=True) is False

    def test_non_indirect_round_cap_is_terminal(self) -> None:
        """A non-converging non-indirect graph stops at the hard round cap (no infinite loop)."""
        rule = _fresh_rule()
        cap = StateMachineCffUnflattener._MAX_UNFLATTEN_ROUNDS
        for _ in range(cap):
            assert rule._should_run_unflatten_round(_EA, is_indirect=False) is True
        # Cap reached -> refused and marked terminal.
        assert rule._should_run_unflatten_round(_EA, is_indirect=False) is False
        assert _EA in rule._unflat_done_eas

    def test_converged_ea_stays_terminal(self) -> None:
        """Once marked converged, an ea never runs again (idempotent terminal)."""
        rule = _fresh_rule()
        rule._mark_ea_converged(_EA)
        assert rule._should_run_unflatten_round(_EA, is_indirect=False) is False
        assert rule._should_run_unflatten_round(_EA, is_indirect=True) is False

    def test_distinct_eas_are_independent(self) -> None:
        """Re-run bookkeeping is per function ea, not global."""
        rule = _fresh_rule()
        other = _EA + 0x1000
        rule._mark_ea_converged(_EA)
        # The converged ea is terminal but a different function still runs.
        assert rule._should_run_unflatten_round(_EA, is_indirect=False) is False
        assert rule._should_run_unflatten_round(other, is_indirect=False) is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
