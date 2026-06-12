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

import ida_hexrays
import pytest

from d810.optimizers.microcode.flow.flattening.state_machine_cff_unflattener import (
    StateMachineCffUnflattener,
)


_EA = 0x1800017F0
#: Two distinct recovery maturities -- the gate now budgets re-runs per-(ea,maturity)
#: (ticket llr-a93i), so a cap at one maturity must leave the other's budget intact.
_MAT = ida_hexrays.MMAT_GLBOPT1
_MAT2 = ida_hexrays.MMAT_CALLS


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
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is True
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is True
        # Recovery finds no dispatcher -> converged -> terminal (every maturity).
        rule._mark_ea_converged(_EA)
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is False

    def test_indirect_is_one_shot(self) -> None:
        """The INDIRECT_JUMP profile runs exactly once (no re-run, no body drop)."""
        rule = _fresh_rule()
        assert rule._should_run_unflatten_round(_EA, is_indirect=True, maturity=_MAT) is True
        # Second invocation is refused even though the ea was never marked converged.
        assert rule._should_run_unflatten_round(_EA, is_indirect=True, maturity=_MAT) is False

    def test_non_indirect_round_cap_stops_only_that_maturity(self) -> None:
        """The hard round cap stops a single (ea, maturity) -- not the whole function.

        Per-(ea,maturity) budgeting (ticket llr-a93i): a maturity that loops to the cap
        without converging must NOT mark the ea globally done, or a later maturity would
        never get to recover a dispatcher this one could not (the folded equality-chain
        recovers early; a 36-back-edge machine recovers later).
        """
        rule = _fresh_rule()
        cap = StateMachineCffUnflattener._MAX_UNFLATTEN_ROUNDS
        for _ in range(cap):
            assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is True
        # Cap reached for _MAT -> refused there, but the ea is NOT globally terminal.
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is False
        assert _EA not in rule._unflat_done_eas
        # A DIFFERENT maturity still gets its own full budget.
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT2) is True

    def test_converged_ea_stays_terminal_across_maturities(self) -> None:
        """Once marked converged, an ea never runs again at ANY maturity (idempotent)."""
        rule = _fresh_rule()
        rule._mark_ea_converged(_EA)
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is False
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT2) is False
        assert rule._should_run_unflatten_round(_EA, is_indirect=True, maturity=_MAT) is False

    def test_distinct_eas_are_independent(self) -> None:
        """Re-run bookkeeping is per function ea, not global."""
        rule = _fresh_rule()
        other = _EA + 0x1000
        rule._mark_ea_converged(_EA)
        # The converged ea is terminal but a different function still runs.
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is False
        assert rule._should_run_unflatten_round(other, is_indirect=False, maturity=_MAT) is True


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
