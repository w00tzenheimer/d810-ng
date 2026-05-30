"""Tests for the OLLVM carrier backend adapter boundary."""
from __future__ import annotations

from types import SimpleNamespace

from d810.optimizers.microcode.flow.flattening import ollvm_carrier_backend
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES


def test_raw_semantic_carrier_facts_collect_from_adapted_target(monkeypatch) -> None:
    import ida_hexrays

    stack_mop = SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=0x28), size=4)
    const_mop = SimpleNamespace(
        t=ida_hexrays.mop_n,
        nnn=SimpleNamespace(value=0x42),
        size=4,
    )
    insn = SimpleNamespace(
        opcode=ida_hexrays.m_add,
        ea=0x18000E7A0,
        d=stack_mop,
        l=stack_mop,
        r=const_mop,
        next=None,
        dstr=lambda: "add %var_28.4, #0x42.4, %var_28.4",
    )
    block = SimpleNamespace(serial=7, head=insn)
    live_mba = SimpleNamespace(
        entry_ea=0x18000E790,
        maturity=_MATURITY_VALUES["MMAT_CALLS"],
        qty=1,
        blocks="live-mba-internal-blocks",
        get_mblock=lambda index: block if index == 0 else None,
    )
    seen: dict[str, object] = {}

    class FakeCollector:
        def collect(self, target, *, func_ea, maturity, phase):
            seen.update({
                "target": target,
                "func_ea": func_ea,
                "maturity": maturity,
                "phase": phase,
            })
            return ("raw_fact",)

    monkeypatch.setattr(
        "d810.analyses.value_flow.ollvm_semantic_carrier.OllvmValueFlowEvidenceCollector",
        FakeCollector,
    )

    facts = ollvm_carrier_backend.collect_ollvm_raw_semantic_carrier_facts(live_mba)

    assert facts == ("raw_fact",)
    assert seen["func_ea"] == 0x18000E790
    assert seen["maturity"] == _MATURITY_VALUES["MMAT_CALLS"]
    assert seen["phase"] == "pre_d810"
    adapted_blocks = getattr(seen["target"], "blocks")
    assert tuple(adapted_blocks) == (7,)
    adapted_insn = adapted_blocks[7].instructions[0]
    assert adapted_insn.opcode_name == "m_add"
    assert adapted_insn.dest_type == "mop_S"
    assert adapted_insn.dest_stkoff == 0x28
    assert adapted_insn.src_l_stkoff == 0x28
    assert adapted_insn.src_r_value == 0x42
    assert adapted_insn.dstr == "add %var_28.4, #0x42.4, %var_28.4"


def test_raw_semantic_carrier_facts_return_empty_for_empty_target() -> None:
    facts = ollvm_carrier_backend.collect_ollvm_raw_semantic_carrier_facts(object())

    assert facts == ()


def test_collector_target_reuses_existing_snapshot_target() -> None:
    target = SimpleNamespace(blocks={})

    assert ollvm_carrier_backend._collector_target(target) is target
