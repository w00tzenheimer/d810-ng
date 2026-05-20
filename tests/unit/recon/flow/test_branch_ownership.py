from __future__ import annotations

from types import SimpleNamespace

from d810.recon.flow.branch_ownership import (
    BranchOwnershipProof,
    BranchOwnershipProofKind,
    branch_ownership_proof_from_any,
    collect_branch_ownership_proofs,
)


def _key(state: int):
    return SimpleNamespace(state_const=state)


def _edge(
    *,
    source: int,
    target: int | None,
    kind: str = "CONDITIONAL_TRANSITION",
    block: int = 10,
    arm: int = 0,
    target_entry: int = 20,
    provenance_kind: str | None = None,
):
    return SimpleNamespace(
        source_key=_key(source),
        target_key=(_key(target) if target is not None else None),
        kind=kind,
        source_anchor=SimpleNamespace(
            block_serial=block,
            branch_arm=arm,
            provenance_kind=provenance_kind,
        ),
        target_entry_anchor=target_entry,
    )


def test_collect_branch_ownership_defaults_unresolved() -> None:
    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=(
            _edge(source=0x10, target=0x20, block=4, arm=1),
        )),
    )

    assert len(proofs) == 1
    assert proofs[0].proof_kind == BranchOwnershipProofKind.UNRESOLVED
    assert proofs[0].trusted is False
    assert proofs[0].source_block == 4
    assert proofs[0].branch_arm == 1


def test_collect_branch_ownership_records_trusted_opaque_provenance() -> None:
    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=(
            _edge(
                source=0x10,
                target=0x20,
                provenance_kind="ollvm_bcf_opaque_predicate",
            ),
        )),
    )

    assert proofs[0].proof_kind == BranchOwnershipProofKind.OBFUSCATION_RESIDUE_ARM
    assert proofs[0].trusted is True
    assert proofs[0].authorizes_nonsemantic_branch_rewrite is True
    assert proofs[0].authorizes_semantic_branch_bridge is False
    assert proofs[0].oracle_kind == "explicit_opaque_provenance"


def test_collect_branch_ownership_records_terminal_return_frontier() -> None:
    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=(
            _edge(
                source=0x10,
                target=None,
                kind="CONDITIONAL_RETURN",
                target_entry=99,
            ),
        )),
    )

    assert proofs[0].proof_kind == BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER
    assert proofs[0].trusted is True
    assert proofs[0].target_entry == 99


def test_collect_branch_ownership_marks_edges_to_terminal_states_as_frontiers() -> None:
    proofs = collect_branch_ownership_proofs(
        dag=SimpleNamespace(edges=(
            _edge(source=0x10, target=0x20, block=4, arm=1),
            _edge(
                source=0x20,
                target=None,
                kind="CONDITIONAL_RETURN",
                block=7,
                target_entry=99,
            ),
        )),
    )

    assert proofs[0].proof_kind == BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER
    assert proofs[0].trusted is True
    assert proofs[0].reason == "target_state_terminal_return_frontier"
    assert proofs[0].authorizes_nonsemantic_branch_rewrite is False
    assert proofs[1].proof_kind == BranchOwnershipProofKind.TERMINAL_RETURN_FRONTIER


def test_branch_ownership_proof_coerces_dict_for_consumers() -> None:
    proof = branch_ownership_proof_from_any({
        "proof_id": "p",
        "proof_kind": "OBFUSCATION_RESIDUE_ARM",
        "trusted": True,
        "reason": "fixture",
        "source_state": "0x10",
        "target_state": "0x20",
    })

    assert isinstance(proof, BranchOwnershipProof)
    assert proof.source_state == 0x10
    assert proof.target_state == 0x20
    assert proof.authorizes_nonsemantic_branch_rewrite is True


def test_real_data_dependent_is_semantic_not_rewrite_authority() -> None:
    proof = BranchOwnershipProof(
        proof_id="real",
        proof_kind=BranchOwnershipProofKind.REAL_DATA_DEPENDENT,
        trusted=True,
        reason="input_dependent_branch",
    )

    assert proof.authorizes_semantic_branch_bridge is True
    assert proof.authorizes_nonsemantic_branch_rewrite is False


def test_opaque_predicate_proof_is_not_rewrite_authority_by_itself() -> None:
    proof = BranchOwnershipProof(
        proof_id="opaque",
        proof_kind=BranchOwnershipProofKind.OPAQUE_ALWAYS_TRUE,
        trusted=True,
        reason="moptracker_path_constant_taken_arm",
    )

    assert proof.authorizes_semantic_branch_bridge is False
    assert proof.authorizes_nonsemantic_branch_rewrite is False
