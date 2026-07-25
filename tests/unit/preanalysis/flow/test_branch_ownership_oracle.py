from __future__ import annotations

import inspect
from dataclasses import replace
from types import SimpleNamespace

import d810.analyses.control_flow.branch_ownership_oracle as oracle_mod
from d810.analyses.value_flow.model import FactObservation
from d810.backends.hexrays.evidence.ollvm_carrier import (
    OllvmCarrierBranchOwnershipOracle,
    project_ollvm_value_flow_evidence,
)
from d810.analyses.control_flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
    collect_branch_ownership_proofs,
)
from d810.analyses.control_flow.branch_ownership_oracle import (
    MopTrackerBranchOwnershipOracle,
    PredicateOwnershipKind,
    PredicateOwnershipResult,
    PredicateRef,
    Z3BranchOwnershipOracle,
    _opcode_name,
)
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.semantics import PredicateKind, ValueOpKind


# ---------------------------------------------------------------------------
# Portable FlowGraph fixtures + fake provers (no IDA).  The engine-backed
# MopTracker/Z3 proofs themselves are now in the backend adapter
# (branch_ownership_prover.py) and are exercised by the Docker corridor; here
# we test the PORTABLE refiner (gate + classification + proof construction +
# FlowGraph side-effect guard) against injected fake provers.
# ---------------------------------------------------------------------------


def _const_mop(value: int) -> MopSnapshot:
    return MopSnapshot(size=4, value=value, kind=OperandKind.NUMBER)


def _block_ref_mop(serial: int) -> MopSnapshot:
    return MopSnapshot(size=8, block_ref=serial, kind=OperandKind.BLOCK)


def _cond_tail(
    *,
    ea: int,
    predicate: PredicateKind = PredicateKind.EQ,
    jump_target: int = 9,
    left: MopSnapshot | None = None,
    right: MopSnapshot | None = None,
    display_text: str = "",
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0,
        ea=ea,
        operands=(),
        kind=InsnKind.EQUALITY_JUMP
        if predicate in {PredicateKind.EQ, PredicateKind.NE}
        else InsnKind.COND_JUMP,
        predicate_kind=predicate,
        l=left,
        r=right,
        d=_block_ref_mop(jump_target),
        display_text=display_text,
    )


def _store_insn(*, ea: int, display_text: str = "stx #1.1, [payload]") -> InsnSnapshot:
    return InsnSnapshot(
        opcode=0,
        ea=ea,
        operands=(),
        kind=InsnKind.STORE,
        value_op_kind=ValueOpKind.STORE,
        display_text=display_text,
    )


def _block(
    *,
    serial: int,
    succs: tuple[int, ...] = (),
    insns: tuple[InsnSnapshot, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=tuple(succs),
        preds=(),
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=tuple(insns),
    )


def _flow_graph(*blocks: BlockSnapshot) -> FlowGraph:
    block_map = {blk.serial: blk for blk in blocks}
    return FlowGraph(blocks=block_map, entry_serial=blocks[0].serial, func_ea=0x1000)


class _FakePredicateProver:
    """PredicateOwnershipProver returning a fixed result for any predicate."""

    def __init__(self, result: PredicateOwnershipResult | None):
        self._result = result
        self.calls: list[PredicateRef] = []

    def resolve(self, predicate: PredicateRef) -> PredicateOwnershipResult | None:
        self.calls.append(predicate)
        return self._result


class _FakeJumpTakenProver:
    """JumpTakenProver returning a fixed tri-state for any predicate."""

    def __init__(self, taken: bool | None):
        self._taken = taken
        self.calls: list[PredicateRef] = []

    def prove_jump_taken(self, predicate: PredicateRef) -> bool | None:
        self.calls.append(predicate)
        return self._taken


# Carrier-only fakes (the OllvmCarrierBranchOwnershipOracle still takes a live
# ``mba`` and reads ``block.tail`` text; F1/F4 did not change its surface).
class _FakeBlock:
    def __init__(self, tail: object, head: object | None = None):
        self.tail = tail
        self.head = head

    def nsucc(self) -> int:
        return 2


class _FakeMba:
    def __init__(self, blocks: dict[int, _FakeBlock]):
        self._blocks = blocks
        self.qty = max(blocks) + 1 if blocks else 0

    def get_mblock(self, serial: int) -> _FakeBlock | None:
        return self._blocks.get(int(serial))


def _edge(
    *,
    source_state: int = 0x10,
    target_state: int | None = 0x20,
    kind: str = "CONDITIONAL_TRANSITION",
    source_block: int | None = 5,
    branch_arm: int | None = 0,
    target_entry: int | None = 9,
    ordered_path: tuple[int, ...] = (4, 5, 9),
):
    return SimpleNamespace(
        kind=SimpleNamespace(name=kind),
        source_key=SimpleNamespace(state_const=source_state),
        target_key=(
            SimpleNamespace(state_const=target_state)
            if target_state is not None
            else None
        ),
        target_entry_anchor=target_entry,
        source_anchor=(
            SimpleNamespace(
                block_serial=source_block,
                branch_arm=branch_arm,
            )
            if source_block is not None or branch_arm is not None
            else None
        ),
        ordered_path=ordered_path,
    )


def _insn(opcode: str, *, text: str = ""):
    return SimpleNamespace(opcode=opcode, next=None, text=text)


def _chain(*insns: object) -> object | None:
    for current, nxt in zip(insns, insns[1:]):
        current.next = nxt
    return insns[0] if insns else None


def test_opcode_name_uses_injected_resolver_for_numeric_opcode():
    assert (
        _opcode_name(
            SimpleNamespace(opcode=object()),
            lambda _insn: "jz",
        )
        == "jz"
    )


def test_opcode_name_normalizes_known_conditional_opcode_without_live_ida():
    assert _opcode_name(SimpleNamespace(opcode=44)) == "jz"


def test_branch_ownership_oracle_does_not_import_live_hexrays():
    assert "import ida_hexrays" not in inspect.getsource(oracle_mod)


def test_branch_ownership_oracle_has_no_lazy_import_or_seam():
    source = inspect.getsource(oracle_mod)
    # No lazy import laundering, no condition-chain block-lookup seam.
    assert "importlib" not in source
    assert "get_condition_chain_walkers" not in source
    # No import (lazy or top-level) of any upper-layer engine module.  Docstrings
    # may *name* the backend adapter, so check import statements specifically.
    import_lines = [
        line
        for line in source.splitlines()
        if line.lstrip().startswith(("import ", "from "))
    ]
    for forbidden in ("d810.evaluator", "d810.backends", "d810.hexrays"):
        assert not any(forbidden in line for line in import_lines), forbidden


def _carrier_fact(
    *,
    role: str,
    token: str,
    block: int,
    text: str,
):
    raw = FactObservation(
        fact_id=f"ollvm:{role}:{token}:blk={block}",
        kind="OllvmValueFlowEvidence",
        semantic_key=f"ollvm_carrier:{role}:{token}",
        maturity="MMAT_CALLS",
        phase="pre_d810",
        confidence=0.8,
        source_block=block,
        source_ea=0x180000000 + block,
        block_fingerprint=f"blk[{block}].0:m_setb",
        mop_signature=f"ollvm_carrier:{role}:{token}",
        payload={
            "role": role,
            "carrier_token": token,
            "source_block": block,
            "instruction_index": 0,
            "instruction_ea": 0x180000000 + block,
            "instruction_dstr": text,
        },
        evidence=(text,),
    )
    (projected,) = project_ollvm_value_flow_evidence((raw,))
    return projected


def _raw_carrier_fact(
    *,
    role: str,
    token: str,
    block: int,
    text: str,
) -> FactObservation:
    return FactObservation(
        fact_id=f"ollvm:{role}:{token}:blk={block}",
        kind="OllvmValueFlowEvidence",
        semantic_key=f"ollvm_carrier:{role}:{token}",
        maturity="MMAT_CALLS",
        phase="pre_d810",
        confidence=0.8,
        source_block=block,
        source_ea=0x180000000 + block,
        block_fingerprint=f"blk[{block}].0:m_setb",
        mop_signature=f"ollvm_carrier:{role}:{token}",
        payload={
            "role": role,
            "carrier_token": token,
            "source_block": block,
            "instruction_index": 0,
            "instruction_ea": 0x180000000 + block,
            "instruction_dstr": text,
        },
        evidence=(text,),
    )


def _moptracker_flow_graph() -> FlowGraph:
    """Two-way source block 5 (the gate target) plus two arm blocks."""
    return _flow_graph(
        _block(
            serial=5,
            succs=(8, 9),
            insns=(_cond_tail(ea=0x500, predicate=PredicateKind.EQ, jump_target=9),),
        ),
        _block(serial=8, succs=()),
        _block(serial=9, succs=()),
    )


def _proofs_for(
    *edges: object,
    result: PredicateOwnershipResult,
):
    oracle = MopTrackerBranchOwnershipOracle(
        flow_graph=_moptracker_flow_graph(),
        predicate_resolver=_FakePredicateProver(result),
    )
    return collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=edges),
        proof_refiner=oracle.refine,
    )


def _proofs_for_z3(
    *,
    predicate: PredicateKind = PredicateKind.EQ,
    jump_target: int = 9,
    taken: bool | None = None,
    discarded_store: bool = False,
    left: MopSnapshot | None = None,
    right: MopSnapshot | None = None,
):
    discarded_insns = (_store_insn(ea=0x800),) if discarded_store else ()
    flow_graph = _flow_graph(
        _block(
            serial=5,
            succs=(8, 9),
            insns=(
                _cond_tail(
                    ea=0x500,
                    predicate=predicate,
                    jump_target=jump_target,
                    left=left,
                    right=right,
                ),
            ),
        ),
        _block(serial=8, succs=(), insns=discarded_insns),
        _block(serial=9, succs=()),
    )
    oracle = Z3BranchOwnershipOracle(
        flow_graph=flow_graph,
        jump_taken_prover=(
            _FakeJumpTakenProver(taken) if taken is not None or left is None else None
        ),
    )
    return collect_branch_ownership_proofs(
        dag=SimpleNamespace(
            edges=(
                _edge(branch_arm=0, target_state=0x20, target_entry=8),
                _edge(branch_arm=1, target_state=0x30, target_entry=9),
            )
        ),
        proof_refiner=oracle.refine,
    )


def _proof_by_arm(proofs, arm: int) -> BranchOwnershipProof:
    matches = [
        proof for proof in proofs if proof.source_block == 5 and proof.branch_arm == arm
    ]
    assert len(matches) == 1
    return matches[0]


def test_moptracker_oracle_with_no_prover_leaves_arm_unresolved():
    oracle = MopTrackerBranchOwnershipOracle(
        flow_graph=_moptracker_flow_graph(),
        predicate_resolver=None,
    )
    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=(_edge(branch_arm=0, target_state=0x20),)),
        proof_refiner=oracle.refine,
    )
    assert proofs[0].proof_kind == BranchOwnershipProofKind.UNRESOLVED
    assert proofs[0].trusted is False


def test_path_constant_predicate_marks_non_taken_arm_as_obfuscation_residue():
    proofs = _proofs_for(
        _edge(branch_arm=0, target_state=0x20),
        _edge(branch_arm=1, target_state=0x30),
        result=PredicateOwnershipResult(
            PredicateOwnershipKind.PATH_CONSTANT,
            "synthetic_moptracker_constant",
            taken=True,
            evidence={"synthetic": True},
        ),
    )

    residue = proofs[0]
    taken = proofs[1]
    assert residue.proof_kind == BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM
    assert residue.trusted is True
    assert residue.authorizes_nonsemantic_branch_rewrite is True
    assert residue.source_state == 0x10
    assert residue.target_state == 0x20
    assert residue.target_entry == 9
    assert residue.branch_arm == 0
    assert residue.evidence["taken_arm"] == 1
    assert taken.proof_kind == BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE
    assert taken.trusted is True
    assert taken.authorizes_nonsemantic_branch_rewrite is False
    assert taken.evidence["path_constant_arm"] == 1


def test_path_constant_predicate_does_not_downgrade_terminal_frontier_arm():
    proofs = _proofs_for(
        _edge(branch_arm=0, target_state=0x20),
        _edge(
            source_state=0x20,
            target_state=None,
            kind="CONDITIONAL_RETURN",
            source_block=7,
            branch_arm=0,
        ),
        result=PredicateOwnershipResult(
            PredicateOwnershipKind.PATH_CONSTANT,
            "synthetic_moptracker_constant",
            taken=True,
        ),
    )

    assert proofs[0].proof_kind == BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER
    assert proofs[0].trusted is True
    assert proofs[0].authorizes_nonsemantic_branch_rewrite is False


def test_path_constant_false_predicate_marks_selected_arm_as_opaque_false():
    proofs = _proofs_for(
        _edge(branch_arm=0, target_state=0x20),
        _edge(branch_arm=1, target_state=0x30),
        result=PredicateOwnershipResult(
            PredicateOwnershipKind.PATH_CONSTANT,
            "synthetic_moptracker_constant",
            taken=False,
        ),
    )

    selected = proofs[0]
    residue = proofs[1]
    assert selected.proof_kind == BranchOwnershipProofKind.OPAQUE_ALWAYS_FALSE
    assert selected.trusted is True
    assert selected.authorizes_nonsemantic_branch_rewrite is False
    assert selected.evidence["path_constant_arm"] == 0
    assert residue.proof_kind == BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM
    assert residue.authorizes_nonsemantic_branch_rewrite is True


def test_terminal_selector_backedge_adds_separate_residue_proof_for_selected_arm():
    selector_state = 0x49FD3A3
    payload_state = 0x2AC056AD
    return_state = 0xBFF7ACB5
    proofs = _proofs_for(
        _edge(
            source_state=payload_state,
            target_state=selector_state,
            kind="TRANSITION",
            source_block=13,
            branch_arm=0,
            target_entry=5,
        ),
        _edge(
            source_state=selector_state,
            target_state=payload_state,
            source_block=5,
            branch_arm=1,
            target_entry=13,
        ),
        _edge(
            source_state=selector_state,
            target_state=return_state,
            source_block=5,
            branch_arm=0,
            target_entry=21,
        ),
        _edge(
            source_state=return_state,
            target_state=None,
            kind="CONDITIONAL_RETURN",
            source_block=21,
            branch_arm=0,
            target_entry=21,
        ),
        result=PredicateOwnershipResult(
            PredicateOwnershipKind.PATH_CONSTANT,
            "synthetic_moptracker_constant",
            taken=True,
        ),
    )

    selected = [
        proof
        for proof in proofs
        if (
            proof.source_state == selector_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]
    assert [proof.proof_kind for proof in selected] == [
        BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
        BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
    ]
    assert selected[0].authorizes_nonsemantic_branch_rewrite is False
    assert selected[1].authorizes_nonsemantic_branch_rewrite is True
    assert selected[1].reason == "opaque_selected_terminal_selector_backedge_residue"
    assert selected[1].evidence["opaque_selected_proof_id"] == selected[0].proof_id


def test_terminal_selector_backedge_requires_payload_private_to_selector():
    selector_state = 0x49FD3A3
    payload_state = 0x2AC056AD
    return_state = 0xBFF7ACB5
    proofs = _proofs_for(
        _edge(
            source_state=payload_state,
            target_state=selector_state,
            kind="TRANSITION",
            source_block=13,
            branch_arm=0,
            target_entry=5,
        ),
        _edge(
            source_state=0x1111,
            target_state=payload_state,
            kind="TRANSITION",
            source_block=12,
            branch_arm=0,
            target_entry=13,
        ),
        _edge(
            source_state=selector_state,
            target_state=payload_state,
            source_block=5,
            branch_arm=1,
            target_entry=13,
        ),
        _edge(
            source_state=selector_state,
            target_state=return_state,
            source_block=5,
            branch_arm=0,
            target_entry=21,
        ),
        _edge(
            source_state=return_state,
            target_state=None,
            kind="CONDITIONAL_RETURN",
            source_block=21,
            branch_arm=0,
            target_entry=21,
        ),
        result=PredicateOwnershipResult(
            PredicateOwnershipKind.PATH_CONSTANT,
            "synthetic_moptracker_constant",
            taken=True,
        ),
    )

    selected = [
        proof
        for proof in proofs
        if (
            proof.source_state == selector_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]
    assert [proof.proof_kind for proof in selected] == [
        BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
        BranchOwnershipProofKind.UNRESOLVED,
    ]
    assert selected[0].authorizes_nonsemantic_branch_rewrite is False
    assert selected[1].trusted is False
    assert selected[1].reason == "terminal_selector_backedge_payload_not_private"
    assert selected[1].authorizes_nonsemantic_branch_rewrite is False
    assert selected[1].evidence["payload_incoming_source_states"] == (
        "0x0000000000001111",
        "0x00000000049fd3a3",
    )


def test_terminal_selector_backedge_accepts_nonsemantic_external_incoming_edge():
    selector_state = 0x49FD3A3
    payload_state = 0x2AC056AD
    external_state = 0x3CFC5AAB
    return_state = 0xBFF7ACB5
    proofs = _proofs_for(
        _edge(
            source_state=payload_state,
            target_state=selector_state,
            kind="TRANSITION",
            source_block=13,
            branch_arm=0,
            target_entry=5,
        ),
        _edge(
            source_state=selector_state,
            target_state=payload_state,
            source_block=5,
            branch_arm=1,
            target_entry=13,
        ),
        _edge(
            source_state=selector_state,
            target_state=return_state,
            source_block=5,
            branch_arm=0,
            target_entry=21,
        ),
        _edge(
            source_state=external_state,
            target_state=payload_state,
            source_block=5,
            branch_arm=0,
            target_entry=13,
        ),
        _edge(
            source_state=external_state,
            target_state=selector_state,
            source_block=5,
            branch_arm=1,
            target_entry=5,
        ),
        _edge(
            source_state=return_state,
            target_state=None,
            kind="CONDITIONAL_RETURN",
            source_block=21,
            branch_arm=0,
            target_entry=21,
        ),
        result=PredicateOwnershipResult(
            PredicateOwnershipKind.PATH_CONSTANT,
            "synthetic_moptracker_constant",
            taken=True,
        ),
    )

    selected = [
        proof
        for proof in proofs
        if (
            proof.source_state == selector_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]
    external = [
        proof
        for proof in proofs
        if (
            proof.source_state == external_state
            and proof.target_state == payload_state
            and proof.branch_arm == 0
        )
    ]
    assert [proof.proof_kind for proof in selected] == [
        BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
        BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
    ]
    assert external[0].proof_kind == BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM
    assert selected[1].reason == "opaque_selected_terminal_selector_backedge_residue"
    assert selected[1].evidence["requires_cfg_split"] is True
    assert selected[1].evidence["payload_private_to_selector"] is False
    assert selected[1].evidence["payload_incoming_source_states"] == (
        "0x000000003cfc5aab",
    )
    assert selected[1].evidence["external_incoming_residue_proof_ids"] == (
        external[0].proof_id,
    )


def test_terminal_selector_backedge_rejects_semantic_external_edge_identity():
    selector_state = 0x49FD3A3
    payload_state = 0x2AC056AD
    external_state = 0x3CFC5AAB
    return_state = 0xBFF7ACB5
    edges = (
        _edge(
            source_state=payload_state,
            target_state=selector_state,
            kind="TRANSITION",
            source_block=13,
            branch_arm=0,
            target_entry=5,
        ),
        _edge(
            source_state=selector_state,
            target_state=payload_state,
            source_block=5,
            branch_arm=1,
            target_entry=13,
        ),
        _edge(
            source_state=selector_state,
            target_state=return_state,
            source_block=5,
            branch_arm=0,
            target_entry=21,
        ),
        _edge(
            source_state=external_state,
            target_state=payload_state,
            source_block=42,
            branch_arm=0,
            target_entry=13,
        ),
        _edge(
            source_state=external_state,
            target_state=payload_state,
            source_block=42,
            branch_arm=1,
            target_entry=13,
        ),
        _edge(
            source_state=return_state,
            target_state=None,
            kind="CONDITIONAL_RETURN",
            source_block=21,
            branch_arm=0,
            target_entry=21,
        ),
    )

    def _refine(
        proof: BranchOwnershipProof,
        _edge_obj: object,
    ) -> BranchOwnershipProof:
        if proof.source_state == selector_state and proof.target_state == payload_state:
            return replace(
                proof,
                proof_kind=BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
                trusted=True,
                reason="synthetic_selector_path_constant",
                oracle_kind="fixture",
            )
        if (
            proof.source_state == external_state
            and proof.target_state == payload_state
            and proof.branch_arm == 0
        ):
            return replace(
                proof,
                proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
                trusted=True,
                reason="synthetic_external_residue",
                oracle_kind="fixture",
            )
        if (
            proof.source_state == external_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        ):
            return replace(
                proof,
                proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
                trusted=True,
                reason="synthetic_external_semantic",
                oracle_kind="fixture",
            )
        return proof

    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=edges),
        proof_refiner=_refine,
    )
    selected = [
        proof
        for proof in proofs
        if (
            proof.source_state == selector_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]
    semantic_external = [
        proof
        for proof in proofs
        if (
            proof.source_state == external_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]

    assert [proof.proof_kind for proof in selected] == [
        BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
        BranchOwnershipProofKind.UNRESOLVED,
    ]
    assert selected[1].reason == "terminal_selector_backedge_payload_not_private"
    assert selected[1].authorizes_nonsemantic_branch_rewrite is False
    assert selected[1].evidence["external_incoming_semantic_proof_ids"] == (
        semantic_external[0].proof_id,
    )


def test_terminal_selector_backedge_rejects_unanchored_external_residue_identity():
    selector_state = 0x49FD3A3
    payload_state = 0x2AC056AD
    external_state = 0x3CFC5AAB
    return_state = 0xBFF7ACB5
    edges = (
        _edge(
            source_state=payload_state,
            target_state=selector_state,
            kind="TRANSITION",
            source_block=13,
            branch_arm=0,
            target_entry=5,
        ),
        _edge(
            source_state=selector_state,
            target_state=payload_state,
            source_block=5,
            branch_arm=1,
            target_entry=13,
        ),
        _edge(
            source_state=selector_state,
            target_state=return_state,
            source_block=5,
            branch_arm=0,
            target_entry=21,
        ),
        _edge(
            source_state=external_state,
            target_state=payload_state,
            source_block=None,
            branch_arm=None,
            target_entry=13,
        ),
        _edge(
            source_state=return_state,
            target_state=None,
            kind="CONDITIONAL_RETURN",
            source_block=21,
            branch_arm=0,
            target_entry=21,
        ),
    )

    def _refine(
        proof: BranchOwnershipProof,
        _edge_obj: object,
    ) -> BranchOwnershipProof:
        if proof.source_state == selector_state and proof.target_state == payload_state:
            return replace(
                proof,
                proof_kind=BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
                trusted=True,
                reason="synthetic_selector_path_constant",
                oracle_kind="fixture",
            )
        if proof.source_state == external_state and proof.target_state == payload_state:
            return replace(
                proof,
                proof_kind=BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
                trusted=True,
                reason="synthetic_unanchored_external_residue",
                oracle_kind="fixture",
            )
        return proof

    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=edges),
        proof_refiner=_refine,
    )
    selected = [
        proof
        for proof in proofs
        if (
            proof.source_state == selector_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]

    assert [proof.proof_kind for proof in selected] == [
        BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
        BranchOwnershipProofKind.UNRESOLVED,
    ]
    assert selected[1].reason == "terminal_selector_backedge_payload_not_private"
    assert selected[1].authorizes_nonsemantic_branch_rewrite is False
    assert selected[1].evidence["unproven_external_incoming_edges"] == 1
    assert selected[1].evidence["external_incoming_residue_proof_ids"] == ()


def test_terminal_selector_backedge_reports_side_effect_materialization_gap():
    selector_state = 0x49FD3A3
    payload_state = 0x2AC056AD
    external_state = 0x3CFC5AAB
    return_state = 0xBFF7ACB5
    edges = (
        _edge(
            source_state=payload_state,
            target_state=selector_state,
            kind="TRANSITION",
            source_block=13,
            branch_arm=0,
            target_entry=5,
        ),
        _edge(
            source_state=selector_state,
            target_state=payload_state,
            source_block=5,
            branch_arm=1,
            target_entry=13,
        ),
        _edge(
            source_state=selector_state,
            target_state=return_state,
            source_block=5,
            branch_arm=0,
            target_entry=21,
        ),
        _edge(
            source_state=external_state,
            target_state=payload_state,
            source_block=42,
            branch_arm=1,
            target_entry=13,
        ),
        _edge(
            source_state=return_state,
            target_state=None,
            kind="CONDITIONAL_RETURN",
            source_block=21,
            branch_arm=0,
            target_entry=21,
        ),
    )

    def _refine(
        proof: BranchOwnershipProof,
        _edge_obj: object,
    ) -> BranchOwnershipProof:
        if proof.source_state == selector_state and proof.target_state == payload_state:
            return replace(
                proof,
                proof_kind=BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
                trusted=True,
                reason="synthetic_selector_path_constant",
                oracle_kind="fixture",
            )
        if proof.source_state == external_state and proof.target_state == payload_state:
            return replace(
                proof,
                proof_kind=BranchOwnershipProofKind.UNRESOLVED,
                trusted=False,
                reason="z3_jumpfixer_discarded_arm_side_effect_guard",
                oracle_kind="fixture",
                evidence={
                    **proof.evidence,
                    "side_effect_guard_reason": "discarded_arm_contains_payload_store",
                },
            )
        return proof

    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=edges),
        proof_refiner=_refine,
    )
    selected = [
        proof
        for proof in proofs
        if (
            proof.source_state == selector_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]
    external_veto = [
        proof
        for proof in proofs
        if (
            proof.source_state == external_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]

    assert [proof.proof_kind for proof in selected] == [
        BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
        BranchOwnershipProofKind.UNRESOLVED,
    ]
    assert (
        selected[1].reason
        == "terminal_selector_backedge_requires_side_effect_materialization"
    )
    assert selected[1].authorizes_nonsemantic_branch_rewrite is False
    assert selected[1].evidence["requires_side_effect_materialization"] is True
    assert selected[1].evidence["external_incoming_materialization_veto_proof_ids"] == (
        external_veto[0].proof_id,
    )
    assert selected[1].evidence["external_incoming_side_effect_guard_reasons"] == (
        "discarded_arm_contains_payload_store",
    )
    assert selected[1].evidence["unproven_external_incoming_edges"] == 0


def test_real_data_dependent_predicate_marks_arm_as_semantic_branch_authority():
    proofs = _proofs_for(
        _edge(branch_arm=0),
        result=PredicateOwnershipResult(
            PredicateOwnershipKind.REAL_DATA_DEPENDENT,
            "synthetic_password_input",
            evidence={"source": "argv"},
        ),
    )

    assert proofs[0].proof_kind == BranchOwnershipProofKind.REAL_DATA_DEPENDENT
    assert proofs[0].trusted is True
    assert proofs[0].authorizes_semantic_branch_bridge is True
    assert proofs[0].authorizes_nonsemantic_branch_rewrite is False


def test_ollvm_carrier_oracle_marks_password_compare_predicate_semantic():
    compare = (
        "low    call $0x180000000<fast:_QWORD &(%var_98).8,"
        "_QWORD &($aSecret).8,_QWORD #0x64.8> => __int64 .8, %var_58.4"
    )
    derive = "or     %var_58.4, #1.4, %var_18.4"
    tail = SimpleNamespace(
        opcode="jnz",
        text="jnz    %var_18.4, #0.4, @9",
    )
    mba = _FakeMba(
        {
            5: _FakeBlock(
                tail,
                head=_chain(
                    _insn("call", text=compare),
                    _insn("m_or", text=derive),
                ),
            ),
        }
    )
    oracle = OllvmCarrierBranchOwnershipOracle(
        mba=mba,
        carrier_facts=(
            _carrier_fact(
                role="PASSWORD_COMPARE_RESULT",
                token="%var_58",
                block=5,
                text=compare,
            ),
        ),
    )

    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(
            edges=(
                _edge(branch_arm=0, target_state=0x20),
                _edge(branch_arm=1, target_state=0x30),
            )
        ),
        proof_refiner=oracle.refine,
    )

    assert [proof.proof_kind for proof in proofs] == [
        BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
        BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
    ]
    assert all(proof.trusted for proof in proofs)
    assert all(proof.authorizes_semantic_branch_bridge for proof in proofs)
    assert not any(proof.authorizes_nonsemantic_branch_rewrite for proof in proofs)
    assert proofs[0].reason == "ollvm_carrier_password_compare_predicate"
    assert proofs[0].evidence["carrier_kind"] == "call_result"
    assert proofs[0].evidence["expression_class"] == "call_result"
    assert proofs[0].evidence["predicate_tokens"] == ("%var_18",)


def test_ollvm_carrier_oracle_ignores_raw_profile_evidence():
    compare = (
        "low    call $0x180000000<fast:_QWORD &(%var_98).8,"
        "_QWORD &($aSecret).8,_QWORD #0x64.8> => __int64 .8, %var_58.4"
    )
    derive = "or     %var_58.4, #1.4, %var_18.4"
    tail = SimpleNamespace(
        opcode="jnz",
        text="jnz    %var_18.4, #0.4, @9",
    )
    mba = _FakeMba(
        {
            5: _FakeBlock(
                tail,
                head=_chain(
                    _insn("call", text=compare),
                    _insn("m_or", text=derive),
                ),
            ),
        }
    )
    oracle = OllvmCarrierBranchOwnershipOracle(
        mba=mba,
        carrier_facts=(
            _raw_carrier_fact(
                role="PASSWORD_COMPARE_RESULT",
                token="%var_58",
                block=5,
                text=compare,
            ),
        ),
    )

    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=(_edge(branch_arm=0, target_state=0x20),)),
        proof_refiner=oracle.refine,
    )

    assert proofs[0].proof_kind == BranchOwnershipProofKind.UNRESOLVED
    assert proofs[0].trusted is False


def test_ollvm_carrier_oracle_marks_loop_index_predicate_semantic():
    bound = "setb   [ds.2:%var_398.8].4, #0x64.4, %var_3A1.1"
    tail = SimpleNamespace(
        opcode="jz",
        text="jz     %var_3A1.1, #0.1, @9",
    )
    mba = _FakeMba(
        {
            5: _FakeBlock(
                tail,
                head=_chain(_insn("m_setb", text=bound)),
            ),
        }
    )
    oracle = OllvmCarrierBranchOwnershipOracle(
        mba=mba,
        carrier_facts=(
            _carrier_fact(
                role="LOOP_INDEX_CARRIER",
                token="%var_398",
                block=5,
                text=bound,
            ),
        ),
    )

    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(
            edges=(
                _edge(branch_arm=0, target_state=0x20),
                _edge(branch_arm=1, target_state=0x30),
            )
        ),
        proof_refiner=oracle.refine,
    )

    assert [proof.proof_kind for proof in proofs] == [
        BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
        BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
    ]
    assert proofs[0].reason == "ollvm_carrier_loop_index_predicate"
    assert proofs[0].evidence["carrier_kind"] == "induction"
    assert proofs[0].evidence["expression_class"] == "loop_predicate_carrier"
    assert proofs[0].evidence["predicate_tokens"] == ("%var_3A1",)


def test_ollvm_carrier_oracle_preserves_semantic_branch_to_return_frontier():
    bound = "setb   [ds.2:%var_398.8].4, #0x64.4, %var_3A1.1"
    tail = SimpleNamespace(
        opcode="jz",
        text="jz     %var_3A1.1, #0.1, @9",
    )
    mba = _FakeMba(
        {
            5: _FakeBlock(
                tail,
                head=_chain(_insn("m_setb", text=bound)),
            ),
        }
    )
    oracle = OllvmCarrierBranchOwnershipOracle(
        mba=mba,
        carrier_facts=(
            _carrier_fact(
                role="LOOP_INDEX_CARRIER",
                token="%var_398",
                block=5,
                text=bound,
            ),
        ),
    )

    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(
            edges=(
                _edge(branch_arm=0, target_state=0x20),
                _edge(
                    source_state=0x20,
                    target_state=None,
                    kind="CONDITIONAL_RETURN",
                    source_block=7,
                    branch_arm=0,
                    target_entry=None,
                ),
            )
        ),
        proof_refiner=oracle.refine,
    )

    assert proofs[0].proof_kind == BranchOwnershipProofKind.REAL_DATA_DEPENDENT
    assert proofs[0].reason == "ollvm_carrier_loop_index_predicate"
    assert proofs[0].authorizes_semantic_branch_bridge is True
    assert proofs[1].proof_kind == BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER
    assert proofs[1].reason == "edge_kind_terminal_return_frontier"


def test_ollvm_carrier_oracle_leaves_unrelated_predicate_unresolved():
    tail = SimpleNamespace(
        opcode="jz",
        text="jz     %var_DEAD.1, #0.1, @9",
    )
    mba = _FakeMba(
        {
            5: _FakeBlock(
                tail,
                head=_chain(
                    _insn(
                        "m_setb",
                        text="setb   [ds.2:%var_398.8].4, #0x64.4, %var_3A1.1",
                    )
                ),
            ),
        }
    )
    oracle = OllvmCarrierBranchOwnershipOracle(
        mba=mba,
        carrier_facts=(
            _carrier_fact(
                role="LOOP_INDEX_CARRIER",
                token="%var_398",
                block=5,
                text="setb [ds.2:%var_398.8].4, #0x64.4, %var_3A1.1",
            ),
        ),
    )

    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=(_edge(branch_arm=0, target_state=0x20),)),
        proof_refiner=oracle.refine,
    )

    assert proofs[0].proof_kind == BranchOwnershipProofKind.UNRESOLVED
    assert proofs[0].trusted is False


def test_incomplete_edge_identity_does_not_create_trusted_rewrite_proof():
    proofs = _proofs_for(
        _edge(target_entry=None),
        result=PredicateOwnershipResult(
            PredicateOwnershipKind.PATH_CONSTANT,
            "synthetic_moptracker_constant",
            taken=True,
        ),
    )

    assert proofs[0].proof_kind == BranchOwnershipProofKind.UNRESOLVED
    assert proofs[0].trusted is False


def test_z3_jz_equal_chooses_jump_target_arm():
    proofs = _proofs_for_z3(
        predicate=PredicateKind.EQ,
        jump_target=9,
        taken=True,
    )

    fallthrough = _proof_by_arm(proofs, 0)
    jumped = _proof_by_arm(proofs, 1)
    assert jumped.proof_kind == BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE
    assert jumped.trusted is True
    assert jumped.authorizes_nonsemantic_branch_rewrite is False
    assert jumped.evidence["opcode_sense"] == "jump_if_equal"
    assert jumped.evidence["chosen_target"] == 9
    assert jumped.evidence["discarded_target"] == 8
    assert fallthrough.proof_kind == BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM
    assert fallthrough.authorizes_nonsemantic_branch_rewrite is True
    assert fallthrough.target_entry == 8


def test_z3_jnz_equal_chooses_fallthrough_arm():
    # jnz with proven-equal operands is NOT taken -> chosen = fallthrough (8).
    proofs = _proofs_for_z3(
        predicate=PredicateKind.NE,
        jump_target=9,
        taken=False,
    )

    fallthrough = _proof_by_arm(proofs, 0)
    jumped = _proof_by_arm(proofs, 1)
    assert fallthrough.proof_kind == BranchOwnershipProofKind.OPAQUE_ALWAYS_FALSE
    assert fallthrough.trusted is True
    assert fallthrough.evidence["chosen_target"] == 8
    assert fallthrough.evidence["discarded_target"] == 9
    assert jumped.proof_kind == BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM
    assert jumped.authorizes_nonsemantic_branch_rewrite is True


def test_z3_jcnd_constant_nonzero_chooses_jump_target_arm():
    # jcnd with a constant nonzero condition is statically taken.
    proofs = _proofs_for_z3(
        predicate=PredicateKind.TRUTHY,
        jump_target=9,
        left=_const_mop(1),
    )

    fallthrough = _proof_by_arm(proofs, 0)
    jumped = _proof_by_arm(proofs, 1)
    assert jumped.proof_kind == BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE
    assert jumped.evidence["opcode_sense"] == "jump_if_nonzero"
    assert jumped.evidence["taken_arm"] == 1
    assert fallthrough.proof_kind == BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM


def test_z3_sibling_arm_proof_does_not_authorize_wrong_edge():
    proofs = _proofs_for_z3(
        predicate=PredicateKind.EQ,
        jump_target=9,
        taken=True,
    )

    residue = _proof_by_arm(proofs, 0)
    selected = _proof_by_arm(proofs, 1)
    assert residue.authorizes_nonsemantic_branch_rewrite is True
    assert residue.branch_arm == 0
    assert residue.target_state == 0x20
    assert residue.target_entry == 8
    assert selected.branch_arm == 1
    assert selected.target_state == 0x30
    assert selected.target_entry == 9
    assert selected.authorizes_nonsemantic_branch_rewrite is False


def test_z3_discarded_payload_store_blocks_rewrite_authority():
    proofs = _proofs_for_z3(
        predicate=PredicateKind.EQ,
        jump_target=9,
        taken=True,
        discarded_store=True,
    )

    fallthrough = _proof_by_arm(proofs, 0)
    jumped = _proof_by_arm(proofs, 1)
    assert jumped.proof_kind == BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE
    assert fallthrough.proof_kind == BranchOwnershipProofKind.UNRESOLVED
    assert fallthrough.trusted is False
    assert fallthrough.authorizes_nonsemantic_branch_rewrite is False
    assert fallthrough.reason == "z3_jumpfixer_discarded_arm_side_effect_guard"
    assert fallthrough.evidence["side_effect_guard_reason"] == (
        "discarded_arm_contains_payload_store"
    )
