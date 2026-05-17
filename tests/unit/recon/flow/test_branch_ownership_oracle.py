from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from d810.recon.flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
    collect_branch_ownership_proofs,
)
from d810.recon.flow.branch_ownership_oracle import (
    MopTrackerBranchOwnershipOracle,
    PredicateOwnershipKind,
    PredicateOwnershipResult,
    Z3BranchOwnershipOracle,
)


class _FakeBlock:
    def __init__(self, tail: object):
        self.tail = tail

    def nsucc(self) -> int:
        return 2


class _FakeMba:
    def __init__(self, blocks: dict[int, _FakeBlock]):
        self._blocks = blocks
        self.qty = max(blocks) + 1 if blocks else 0

    def get_mblock(self, serial: int) -> _FakeBlock | None:
        return self._blocks.get(int(serial))


class _FakeCfgBlock:
    def __init__(
        self,
        *,
        serial: int,
        tail: object | None = None,
        next_serial: int | None = None,
        succs: tuple[int, ...] = (),
        head: object | None = None,
    ):
        self.serial = serial
        self.tail = tail
        self.nextb = (
            SimpleNamespace(serial=next_serial)
            if next_serial is not None else None
        )
        self._succs = tuple(int(succ) for succ in succs)
        self.head = head

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, index: int) -> int:
        return self._succs[index]


class _FakeProver:
    def __init__(
        self,
        *,
        equal: bool = False,
        unequal: bool = False,
        zero: bool = False,
        nonzero: bool = False,
    ):
        self.equal = equal
        self.unequal = unequal
        self.zero = zero
        self.nonzero = nonzero

    def are_equal(self, *_args, **_kwargs) -> bool:
        return self.equal

    def are_unequal(self, *_args, **_kwargs) -> bool:
        return self.unequal

    def is_always_zero(self, *_args, **_kwargs) -> bool:
        return self.zero

    def is_always_nonzero(self, *_args, **_kwargs) -> bool:
        return self.nonzero


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
            if target_state is not None else None
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


def _mop(value: int | None = None):
    return SimpleNamespace(t="mop_n" if value is not None else "mop_r", value=value, size=4)


def _block_ref(serial: int):
    return SimpleNamespace(t="mop_b", b=serial)


def _tail(opcode: str, *, jump_target: int, left: object, right: object | None = None):
    return SimpleNamespace(opcode=opcode, l=left, r=right, d=_block_ref(jump_target))


def _insn(opcode: str, *, text: str = ""):
    return SimpleNamespace(opcode=opcode, next=None, text=text)


def _proofs_for(
    *edges: object,
    result: PredicateOwnershipResult,
):
    tail = SimpleNamespace(opcode="m_jz")
    mba = _FakeMba({5: _FakeBlock(tail)})
    oracle = MopTrackerBranchOwnershipOracle(
        mba=mba,
        predicate_resolver=lambda _tail, _block, _via_pred: result,
    )
    return collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=edges),
        proof_refiner=oracle.refine,
    )


def _proofs_for_z3(
    *,
    tail: object,
    prover: _FakeProver | None = None,
    discarded_head: object | None = None,
):
    mba = _FakeMba({
        5: _FakeCfgBlock(
            serial=5,
            tail=tail,
            next_serial=8,
            succs=(8, 9),
        ),
        8: _FakeCfgBlock(serial=8, succs=(), head=discarded_head),
        9: _FakeCfgBlock(serial=9, succs=()),
    })
    oracle = Z3BranchOwnershipOracle(
        mba=mba,
        prover_factory=(lambda: prover) if prover is not None else None,
    )
    return collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=(
            _edge(branch_arm=0, target_state=0x20, target_entry=8),
            _edge(branch_arm=1, target_state=0x30, target_entry=9),
        )),
        proof_refiner=oracle.refine,
    )


def _proof_by_arm(proofs, arm: int) -> BranchOwnershipProof:
    matches = [
        proof for proof in proofs
        if proof.source_block == 5 and proof.branch_arm == arm
    ]
    assert len(matches) == 1
    return matches[0]


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
        proof for proof in proofs
        if (
            proof.source_state == selector_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]
    assert [
        proof.proof_kind for proof in selected
    ] == [
        BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
        BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM,
    ]
    assert selected[0].authorizes_nonsemantic_branch_rewrite is False
    assert selected[1].authorizes_nonsemantic_branch_rewrite is True
    assert selected[1].reason == "opaque_selected_terminal_selector_backedge_residue"
    assert (
        selected[1].evidence["opaque_selected_proof_id"]
        == selected[0].proof_id
    )


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
        proof for proof in proofs
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
        proof for proof in proofs
        if (
            proof.source_state == selector_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]
    external = [
        proof for proof in proofs
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
        proof for proof in proofs
        if (
            proof.source_state == selector_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]
    semantic_external = [
        proof for proof in proofs
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
        proof for proof in proofs
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
        proof for proof in proofs
        if (
            proof.source_state == selector_state
            and proof.target_state == payload_state
            and proof.branch_arm == 1
        )
    ]
    external_veto = [
        proof for proof in proofs
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
        tail=_tail("m_jz", jump_target=9, left=_mop(), right=_mop()),
        prover=_FakeProver(equal=True),
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
    proofs = _proofs_for_z3(
        tail=_tail("m_jnz", jump_target=9, left=_mop(), right=_mop()),
        prover=_FakeProver(equal=True),
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
    proofs = _proofs_for_z3(
        tail=_tail("m_jcnd", jump_target=9, left=_mop(1)),
    )

    fallthrough = _proof_by_arm(proofs, 0)
    jumped = _proof_by_arm(proofs, 1)
    assert jumped.proof_kind == BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE
    assert jumped.evidence["opcode_sense"] == "jump_if_nonzero"
    assert jumped.evidence["taken_arm"] == 1
    assert fallthrough.proof_kind == BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM


def test_z3_sibling_arm_proof_does_not_authorize_wrong_edge():
    proofs = _proofs_for_z3(
        tail=_tail("m_jz", jump_target=9, left=_mop(), right=_mop()),
        prover=_FakeProver(equal=True),
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
        tail=_tail("m_jz", jump_target=9, left=_mop(), right=_mop()),
        prover=_FakeProver(equal=True),
        discarded_head=_insn("m_stx", text="stx #1.1, [payload]"),
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
