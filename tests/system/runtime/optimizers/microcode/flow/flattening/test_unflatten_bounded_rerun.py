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

from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.optimizers.microcode.flow.flattening.state_machine_cff_unflattener import (
    StateMachineCffUnflattener,
)
from d810.passes.unflatten.state_machine import LOWER_STATE_MACHINE_PLAN_METADATA
from d810.transforms.minimal_unflatten_emit import (
    TERMINAL_CARRIER_CONVERGENCE_METADATA,
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

    def test_terminal_carrier_plan_metadata_requests_convergence(self) -> None:
        """A terminal stack-alias guard split is a scoped early-convergence signal."""
        rule = _fresh_rule()
        facts = SimpleNamespace(
            get_analysis=lambda name, default=None: (
                {TERMINAL_CARRIER_CONVERGENCE_METADATA: True}
                if name == LOWER_STATE_MACHINE_PLAN_METADATA
                else default
            )
        )

        assert rule._lower_plan_requested_terminal_convergence(facts) is True


class TestTigressIndirectMaterializationConfig:
    def test_non_tigress_profile_does_not_register_materialization(self, monkeypatch) -> None:
        """OLLVM/state-map configs must not arm Tigress indirect materialization."""
        calls: list[str] = []

        from d810.core import project as project_mod
        from d810.hexrays.preanalysis import indirect_jump_labels as label_mod

        monkeypatch.setattr(
            project_mod,
            "register_project_reload_cleanup",
            lambda *_args, **_kwargs: calls.append("cleanup"),
        )
        monkeypatch.setattr(
            label_mod,
            "register_indirect_materialization",
            lambda *_args, **_kwargs: calls.append("register"),
        )
        monkeypatch.setattr(
            label_mod,
            "materialize_discovered_indirect_label_targets",
            lambda *_args, **_kwargs: calls.append("idb_scan"),
        )

        rule = StateMachineCffUnflattener()
        rule.configure({"profile": "state_dispatcher_map"})

        assert calls == []

    def test_tigress_profile_registers_current_function_materialization_only(
        self,
        monkeypatch,
    ) -> None:
        """Tigress indirect arms flowchart events but never scans the whole IDB."""
        calls: list[tuple[str, object]] = []

        from d810.core import project as project_mod
        from d810.hexrays.preanalysis import indirect_jump_labels as label_mod

        monkeypatch.setattr(
            project_mod,
            "register_project_reload_cleanup",
            lambda name, _callback: calls.append(("cleanup", name)),
        )
        monkeypatch.setattr(
            label_mod,
            "reset_indirect_materialization",
            lambda: calls.append(("reset", None)),
        )
        monkeypatch.setattr(
            label_mod,
            "register_indirect_materialization",
            lambda info: calls.append(("register", dict(info))),
        )

        def _fail_idb_scan(*_args, **_kwargs):
            raise AssertionError("whole-IDB Tigress prepass must not run")

        monkeypatch.setattr(
            label_mod,
            "materialize_discovered_indirect_label_targets",
            _fail_idb_scan,
        )

        rule = StateMachineCffUnflattener()
        rule.configure({"profile": "tigress_indirect"})

        assert calls == [
            ("cleanup", "hexrays.indirect_jump_label_materialization"),
            ("reset", None),
            ("register", {}),
        ]

    def test_tigress_profile_preserves_configured_goto_table_info(self, monkeypatch) -> None:
        """Configured layout remains supported as the precise override path."""
        registered: list[dict] = []

        from d810.core import project as project_mod
        from d810.hexrays.preanalysis import indirect_jump_labels as label_mod

        monkeypatch.setattr(
            project_mod,
            "register_project_reload_cleanup",
            lambda *_args, **_kwargs: None,
        )
        monkeypatch.setattr(label_mod, "reset_indirect_materialization", lambda: None)
        monkeypatch.setattr(
            label_mod,
            "register_indirect_materialization",
            lambda info: registered.append(dict(info)),
        )

        goto_table_info = {
            "0x1800175c0": {
                "table_address": "0x180019f10",
                "table_nb_elt": 37,
            },
        }
        rule = StateMachineCffUnflattener()
        rule.configure(
            {
                "profile": "tigress_indirect",
                "goto_table_info": goto_table_info,
            }
        )

        assert registered == [goto_table_info]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
