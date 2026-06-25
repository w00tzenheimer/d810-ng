"""Tests for the OLLVM carrier profile boundary."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.core import project as project_callbacks
from d810.backends.facts.ida import ensure_hexrays_lifter_registered
from d810.families.state_machine_cff import ollvm_carrier_profile
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.insn_projection import InstructionProjection
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


@pytest.mark.ida_required
class TestOllvmCarrierLifterBoundary:
    """Live ``mba_t`` -> ``mba_to_fact_target`` -> collector boundary.

    S10 (ticket llr-3b41) made ``mba_to_fact_target`` (and therefore the
    ``HexRaysMicrocodeLifter`` that delegates to it) emit the canonical
    :class:`~d810.ir.flowgraph.FlowGraph` the pre-D810 path produces -- blocks
    carry ``insn_snapshots`` -- instead of a flat ``SimpleNamespace`` whose rows
    exposed only flat operand fields.  This test pins the live boundary: the
    lifter is selected for a real mba, the adapted target reaches the collector
    with the correct provider phase, AND the adapted target is now a canonical
    ``FlowGraph`` that projects to portable ``Instruction`` records (the EMBRACE
    that retires the meta-less ``_InstructionView`` fallback)."""

    binary_name = "libobfuscated.dylib"  # macOS default (CI uses libobfuscated.dll)

    @pytest.fixture(scope="class")
    def real_mba(self, libobfuscated_setup):
        """A real ``mba_t`` at MMAT_CALLS from a known libobfuscated function.

        Mirrors the ``real_asts`` conftest fixture: try a list of known
        functions, then fall back to scanning the binary so the test never
        skips spuriously when a name is absent on a given build."""
        import ida_hexrays
        import idaapi
        import idautils

        def _mba_for(func_ea: int):
            if func_ea == idaapi.BADADDR:
                return None
            mba = gen_microcode_at_maturity(func_ea, ida_hexrays.MMAT_CALLS)
            if mba is not None and int(getattr(mba, "qty", 0) or 0) > 0:
                return mba
            return None

        for func_name in (
            "test_chained_add",
            "test_xor",
            "test_cst_simplification",
            "test_mba_guessing",
        ):
            func_ea = get_func_ea(func_name)
            mba = _mba_for(func_ea)
            if mba is not None:
                return mba, func_ea

        for idx, func_ea in enumerate(idautils.Functions()):
            if idx >= 128:
                break
            mba = _mba_for(func_ea)
            if mba is not None:
                return mba, func_ea

        pytest.skip("Could not generate microcode for any function")

    def test_raw_semantic_carrier_facts_collect_from_adapted_target(
        self, real_mba, monkeypatch
    ) -> None:
        mba, func_ea = real_mba
        seen: dict[str, object] = {}

        class FakeCollector:
            def collect(self, target, *, func_ea, maturity, phase):
                seen.update(
                    {
                        "target": target,
                        "func_ea": func_ea,
                        "maturity": maturity,
                        "phase": phase,
                    }
                )
                return ("raw_fact",)

        monkeypatch.setattr(
            "d810.families.state_machine_cff.ollvm_carrier_profile."
            "OllvmCarrierRawEvidenceCollector",
            FakeCollector,
        )

        ensure_hexrays_lifter_registered()
        facts = ollvm_carrier_profile.collect_ollvm_raw_semantic_carrier_facts(mba)

        # The lifter boundary still wires the adapted target through to the
        # collector with the correct provider phase.
        assert facts == ("raw_fact",)
        assert seen["func_ea"] == int(mba.entry_ea)
        assert seen["maturity"] == int(mba.maturity)
        assert seen["phase"] == "pre_d810"

        # S10: the adapted target is now a canonical ``FlowGraph`` whose blocks
        # carry ``insn_snapshots`` (the meta-rich currency), NOT a flat
        # ``SimpleNamespace`` of operand-less rows.
        target = seen["target"]
        assert isinstance(target, FlowGraph)
        assert int(target.func_ea) == int(mba.entry_ea)
        assert target.num_blocks == int(mba.qty)

        # Every block exposes ``insn_snapshots`` and projects to portable
        # ``Instruction`` records via the canonical projection -- the branch the
        # collectors take for meta-rich sources.
        projected_total = 0
        for block in target.blocks.values():
            assert isinstance(block, BlockSnapshot)
            assert block.insn_snapshots is not None
            projected_total += len(InstructionProjection.from_block(block))
        assert projected_total > 0


def test_raw_semantic_carrier_facts_return_empty_for_empty_target() -> None:
    facts = ollvm_carrier_profile.collect_ollvm_raw_semantic_carrier_facts(object())

    assert facts == ()


def test_collector_target_reuses_existing_snapshot_target() -> None:
    target = SimpleNamespace(blocks={})

    assert ollvm_carrier_profile._collector_target(target) is target


def test_profile_registration_requires_explicit_project_opt_in(monkeypatch) -> None:
    monkeypatch.setattr(
        project_callbacks,
        "_recon_fact_collector_registration_handlers",
        {},
    )
    project_callbacks.register_recon_fact_collector_registration_handler(
        ollvm_carrier_profile._OLLVM_CARRIER_REGISTRATION_HANDLER,
        ollvm_carrier_profile._register_ollvm_carrier_fact_collectors,
    )

    class Runtime:
        def __init__(self) -> None:
            self.collectors: list[object] = []

        def register_fact_collector(self, collector: object) -> None:
            self.collectors.append(collector)

    runtime = Runtime()
    project_callbacks.emit_recon_fact_collector_registration(
        runtime=runtime,
        project_config={},
    )

    assert runtime.collectors == []

    project_callbacks.emit_recon_fact_collector_registration(
        runtime=runtime,
        project_config={
            "recon_fact_profile_modules": [
                ollvm_carrier_profile.OLLVM_CARRIER_PROFILE_MODULE,
            ],
        },
    )

    assert [
        getattr(collector, "name", None)
        for collector in runtime.collectors
    ] == ["OllvmCarrierProfileFactCollector"]
