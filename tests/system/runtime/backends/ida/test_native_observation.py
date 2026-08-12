"""Task 0.3: the observation handler must produce evidence and write nothing.

"Read-only" is asserted with the Task 0.2 witness rather than declared, and the
witness covers item and function events as well as bytes, so a handler that
reshaped the database without patching would still be caught.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime, pytest.mark.hexrays]

ida_funcs = pytest.importorskip("ida_funcs")
ida_hexrays = pytest.importorskip("ida_hexrays")
idaapi = pytest.importorskip("idaapi")

from d810.backends.ida.native_patch.observation import (  # noqa: E402
    HANDLER_NAME,
    clear_observation_optins,
    install_native_observation,
    observe_function,
    on_flowchart_preanalysis,
    opt_in_function,
    uninstall_native_observation,
)
from d810.core.normalization_policy import (  # noqa: E402
    NormalizationDecision,
    PolicyVerdict,
    set_normalization_policy,
)
from d810.hexrays.preanalysis.flowchart_preanalysis import (  # noqa: E402
    _FLOWCHART_PREANALYSIS_HANDLERS,
    run_flowchart_preanalysis_handlers,
)
from tests.system.runtime.support.mutation_witness import (  # noqa: E402
    MutationWitness,
)

TARGET = "fake_jump_opaque_predicate"


@pytest.fixture(autouse=True)
def _isolate():
    clear_observation_optins()
    set_normalization_policy(None)
    yield
    uninstall_native_observation()
    clear_observation_optins()
    set_normalization_policy(None)


def _target_ea() -> int:
    ea = idaapi.get_name_ea(idaapi.BADADDR, TARGET)
    if ea == idaapi.BADADDR:
        pytest.skip(f"{TARGET} not in fixture")
    return ida_funcs.get_func(ea).start_ea


class TestNativeObservation:
    binary_name = "fake_jumps.dll"

    def test_observation_finds_lowerable_candidates(self, ida_database):
        observation = observe_function(_target_ea())

        assert observation is not None
        assert observation.branches, "fixture should contain conditional branches"
        assert observation.lowerable_count >= 1, observation.describe()

    def test_every_proposal_fills_its_region_exactly(self, ida_database):
        observation = observe_function(_target_ea())

        for branch in observation.branches:
            if branch.proposed_bytes is None:
                continue
            assert len(branch.proposed_bytes) == branch.size, (
                f"{branch.site_ea:#x}: proposal must fill the region exactly"
            )

    def test_proposal_preserves_the_taken_target(self, ida_database):
        observation = observe_function(_target_ea())
        lowerable = [b for b in observation.branches if b.lowerable]
        assert lowerable

        for branch in lowerable:
            # jmp rel8 = EB disp; the taken target must survive the rewrite.
            assert branch.proposed_bytes[0] == 0xEB
            disp = int.from_bytes(branch.proposed_bytes[1:2], "little", signed=True)
            assert branch.site_ea + branch.size + disp == branch.taken_target

    def test_observing_mutates_nothing(self, ida_database):
        ea = _target_ea()
        with MutationWitness() as witness:
            observe_function(ea)
            reading = witness.assert_clean("observe_function")

        assert reading.clean, reading.describe()

    def test_handler_is_registered_read_only(self, ida_database):
        install_native_observation()

        entry = _FLOWCHART_PREANALYSIS_HANDLERS[HANDLER_NAME]

        assert entry.read_only is True

    def test_handler_never_requests_a_redo(self, ida_database):
        ea = _target_ea()
        opt_in_function(ea)
        decision: dict = {"request_redo": False}

        on_flowchart_preanalysis(function_ea=ea, mba=object(), decision=decision)

        assert decision["request_redo"] is False
        assert "observation_receipt" in decision
        assert decision["proposals"]

    def test_handler_ignores_functions_that_did_not_opt_in(self, ida_database):
        decision: dict = {"request_redo": False}

        on_flowchart_preanalysis(
            function_ea=_target_ea(), mba=object(), decision=decision
        )

        assert "observation_receipt" not in decision
        assert "proposals" not in decision

    def test_handler_runs_under_suppress_mutators(self, ida_database):
        """The point of declaring read-only: survive mutator suppression."""
        ea = _target_ea()
        opt_in_function(ea)
        install_native_observation()

        class _Policy:
            def decide(self, function_ea, seam):
                return PolicyVerdict(NormalizationDecision.SUPPRESS_MUTATORS, "t")

        set_normalization_policy(_Policy())
        decision: dict = {"request_redo": False}

        run_flowchart_preanalysis_handlers(
            function_ea=ea, mba=object(), decision=decision
        )

        assert "observation_receipt" in decision

    def test_handler_is_suppressed_under_suppress_all(self, ida_database):
        ea = _target_ea()
        opt_in_function(ea)
        install_native_observation()

        class _Policy:
            def decide(self, function_ea, seam):
                return PolicyVerdict(NormalizationDecision.SUPPRESS_ALL, "t")

        set_normalization_policy(_Policy())
        decision: dict = {"request_redo": False}

        run_flowchart_preanalysis_handlers(
            function_ea=ea, mba=object(), decision=decision
        )

        assert "observation_receipt" not in decision

    def test_a_full_decompile_with_the_handler_installed_mutates_nothing(
        self, ida_database, configure_hexrays
    ):
        """End-to-end: the handler is live during a real decompilation."""
        ea = _target_ea()
        opt_in_function(ea)
        install_native_observation()

        with MutationWitness() as witness:
            ida_hexrays.mark_cfunc_dirty(ea)
            cfunc = ida_hexrays.decompile(ea)
            assert cfunc is not None
            reading = witness.reading("decompile with observation installed")

        assert reading.clean, reading.describe()
