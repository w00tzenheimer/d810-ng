"""Pass-owned native state proof publication for lower_state_machine."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.capabilities.native_cfg_normalization import NativeEdgeStateProofCapability
from d810.capabilities.resolver import CapabilitySet
from d810.ir.edge_state_contract import EdgeStateContract
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.passes.unflatten.state_machine import native_cfg_edge_contracts_for_plan
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.plan import (
    PatchConvertToGoto,
    PatchNopInstructions,
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
)

pytestmark = pytest.mark.pure_python


def _block(serial: int, successors: tuple[int, ...], ea: int) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=successors,
        preds=(),
        flags=0,
        start_ea=ea,
        native_start_ea=ea,
        insn_snapshots=(
            InsnSnapshot(
                opcode=1,
                ea=ea,
                native_ea=ea,
                operands=(),
                kind=(
                    InsnKind.COND_JUMP
                    if len(successors) == 2
                    else InsnKind.GOTO
                    if successors
                    else InsnKind.RET
                ),
            ),
        ),
    )


_GRAPH = FlowGraph(
    blocks={
        0: _block(0, (1,), 0x1000),
        1: _block(1, (), 0x1010),
        2: _block(2, (), 0x1020),
        3: _block(3, (1, 2), 0x1030),
        4: _block(4, (1,), 0x1040),
    },
    entry_serial=0,
    func_ea=0x1000,
)


class _ProofCapability:
    def __init__(self, *, abstain_on_source: int | None = None) -> None:
        self.abstain_on_source = abstain_on_source
        self.calls: list[dict[str, object]] = []

    def prove_edge_transition(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs["source_block"] == self.abstain_on_source:
            return None
        return EdgeStateContract(
            source_stack_delta=0,
            target_stack_delta=0,
            proof_ids=kwargs["semantic_proof_ids"],
        )


def _ref(serial: int) -> LogicalBlockRef:
    return LogicalBlockRef("stage-c-pass", f"block:{serial}", 0)


def _plan(*steps, new_blocks=()) -> PatchPlan:
    referenced = {_ref(serial): serial for serial in range(5)}
    return PatchPlan(
        plan_id="lower-plan",
        snapshot_id="lower-snapshot",
        steps=tuple(steps),
        new_blocks=tuple(new_blocks),
        source_coordinates=tuple(referenced.items()),
    )


def _context(capability: _ProofCapability):
    return SimpleNamespace(
        graph=_GRAPH,
        capabilities=CapabilitySet({NativeEdgeStateProofCapability: capability}),
    )


@pytest.mark.parametrize(
    ("step", "source", "inherited", "final"),
    (
        (PatchRedirectGoto(_ref(0), _ref(1), _ref(2)), 0, (1,), (2,)),
        (PatchRedirectBranch(_ref(3), _ref(2), _ref(4)), 3, (1, 2), (1, 4)),
        (PatchConvertToGoto(_ref(3), _ref(2)), 3, (1, 2), (2,)),
    ),
)
def test_edge_only_steps_publish_exact_pass_owned_contract(
    step, source: int, inherited: tuple[int, ...], final: tuple[int, ...]
) -> None:
    capability = _ProofCapability()

    contracts = native_cfg_edge_contracts_for_plan(_context(capability), _plan(step))

    assert len(contracts) == 1
    assert contracts[0].source_block == source
    assert contracts[0].inherited_successors == inherited
    assert contracts[0].final_successors == final
    assert contracts[0].contract.permits_control_only_relink is True
    assert capability.calls[0]["graph"] is _GRAPH
    assert capability.calls[0]["semantic_proof_ids"] == contracts[0].contract.proof_ids


@pytest.mark.parametrize(
    "plan",
    (
        _plan(PatchNopInstructions(_ref(0), (0x1000,))),
        _plan(
            PatchRedirectGoto(_ref(0), _ref(1), _ref(2)),
            PatchNopInstructions(_ref(4), (0x1040,)),
        ),
    ),
)
def test_non_edge_or_mixed_plan_is_atomically_ineligible(plan: PatchPlan) -> None:
    capability = _ProofCapability()

    assert native_cfg_edge_contracts_for_plan(_context(capability), plan) == ()
    assert capability.calls == []


def test_one_unproved_sibling_makes_complete_plan_ineligible() -> None:
    capability = _ProofCapability(abstain_on_source=4)
    plan = _plan(
        PatchRedirectGoto(_ref(0), _ref(1), _ref(2)),
        PatchRedirectGoto(_ref(4), _ref(1), _ref(2)),
    )

    assert native_cfg_edge_contracts_for_plan(_context(capability), plan) == ()
    assert [call["source_block"] for call in capability.calls] == [0, 4]


def test_missing_proof_capability_abstains() -> None:
    context = SimpleNamespace(graph=_GRAPH, capabilities=CapabilitySet())
    plan = _plan(PatchRedirectGoto(_ref(0), _ref(1), _ref(2)))

    assert native_cfg_edge_contracts_for_plan(context, plan) == ()
