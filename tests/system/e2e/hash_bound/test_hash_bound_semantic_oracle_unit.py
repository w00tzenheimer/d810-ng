from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.system.e2e.hash_bound.hash_bound_semantic_oracle import (
    Effect,
    Exit,
    FixtureReference,
    RecoveredSemantics,
    Transition,
    evaluate_fixture_semantics,
    load_fixture_references,
    recovered_semantics_from_proposals,
    transition_from_native_receipt,
)
from tests.system.e2e.hash_bound.native_transition_oracle import (
    NativeImageSlice,
    NativeInstruction,
    NativeTransitionReceipt,
    NativeTransitionRequest,
    NativeTransitionStatus,
)


_REPO_ROOT = Path(__file__).resolve().parents[4]
_REFERENCE_PATH = (
    _REPO_ROOT / "samples" / "src" / "masm" / "hash_bound_seven_semantics.json"
)


def _transition(
    partition: str,
    *,
    predecessor_ea: int,
    target_rva: int,
    constraint: str,
) -> Transition:
    return Transition(
        partition=partition,
        predecessor_eas=(predecessor_ea,),
        constraints=(constraint,),
        target_rvas=(target_rva,),
    )


@pytest.fixture
def reference() -> FixtureReference:
    return FixtureReference(
        function="fixture",
        entry_rva=0x1000,
        extent=0x100,
        linked_sha256="1" * 64,
        transitions=(
            _transition(
                "input_zero",
                predecessor_ea=0x1010,
                target_rva=0x1040,
                constraint="a1 == 0",
            ),
            _transition(
                "input_nonzero",
                predecessor_ea=0x1020,
                target_rva=0x1060,
                constraint="a1 != 0",
            ),
        ),
        effects=(
            Effect(order=0, kind="memory_write", ea=0x1048, width=4, value="result"),
            Effect(order=1, kind="call", ea=0x1070, target="summarized_helper"),
        ),
        exits=(Exit(kind="return", ea=0x1080, value="result"),),
        assumptions=("summarized_helper preserves nonvolatile registers",),
    )


@pytest.fixture
def recovered(reference: FixtureReference) -> RecoveredSemantics:
    return RecoveredSemantics(
        function=reference.function,
        entry_rva=reference.entry_rva,
        extent=reference.extent,
        linked_sha256=reference.linked_sha256,
        transitions=reference.transitions,
        effects=reference.effects,
        exits=reference.exits,
    )


def _blocker_codes(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> set[str]:
    return {
        blocker.code
        for blocker in evaluate_fixture_semantics(reference, recovered).blockers
    }


def test_exact_semantics_pass(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    result = evaluate_fixture_semantics(reference, recovered)
    assert result.passed is True
    assert result.blockers == ()
    assert all(diff.matches for diff in result.transition_diffs)
    assert all(diff.matches for diff in result.effect_diffs)


def test_missing_feasible_predecessor_fails(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    damaged = replace(recovered, transitions=recovered.transitions[:1])
    assert "missing_transition_partition" in _blocker_codes(reference, damaged)


def test_wrong_target_fails(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    wrong = replace(recovered.transitions[0], target_rvas=(0x1050,))
    damaged = replace(recovered, transitions=(wrong, recovered.transitions[1]))
    assert "transition_target_mismatch" in _blocker_codes(reference, damaged)


def test_extra_target_fails(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    extra = replace(recovered.transitions[0], target_rvas=(0x1040, 0x1050))
    damaged = replace(recovered, transitions=(extra, recovered.transitions[1]))
    assert "transition_target_mismatch" in _blocker_codes(reference, damaged)


def test_branch_partition_mismatch_fails(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    wrong = replace(recovered.transitions[0], constraints=("a1 <= 0",))
    damaged = replace(recovered, transitions=(wrong, recovered.transitions[1]))
    assert "transition_partition_mismatch" in _blocker_codes(reference, damaged)


def test_out_of_extent_transfer_fails(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    wrong = replace(recovered.transitions[0], target_rvas=(0x1100,))
    damaged = replace(recovered, transitions=(wrong, recovered.transitions[1]))
    assert "out_of_extent_transfer" in _blocker_codes(reference, damaged)


def test_reordered_effects_fail(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    damaged = replace(recovered, effects=tuple(reversed(recovered.effects)))
    assert "effect_trace_mismatch" in _blocker_codes(reference, damaged)


def test_missing_exit_fails(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    assert "exit_trace_mismatch" in _blocker_codes(
        reference, replace(recovered, exits=())
    )


def test_raw_computed_dispatcher_jump_fails(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    damaged = replace(recovered, raw_computed_dispatcher_jump=True)
    assert "raw_computed_dispatcher_jump" in _blocker_codes(reference, damaged)


def test_clean_pseudocode_cannot_hide_wrong_semantics(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    wrong = replace(recovered.transitions[1], target_rvas=(0x1040,))
    damaged = replace(
        recovered,
        transitions=(recovered.transitions[0], wrong),
        pseudocode="return result;",
    )
    result = evaluate_fixture_semantics(reference, damaged)
    assert result.passed is False
    assert "transition_target_mismatch" in {blocker.code for blocker in result.blockers}


@pytest.mark.parametrize("side", ["reference", "recovered"])
def test_unresolved_entries_fail_closed(
    side: str, reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    if side == "reference":
        reference = replace(reference, unresolved=("native call summary missing",))
    else:
        recovered = replace(recovered, unresolved=("transition proof missing",))
    assert f"{side}_unresolved" in _blocker_codes(reference, recovered)


def test_identity_mismatch_fails(
    reference: FixtureReference, recovered: RecoveredSemantics
) -> None:
    damaged = replace(recovered, linked_sha256="2" * 64)
    assert "fixture_identity_mismatch" in _blocker_codes(reference, damaged)


def test_proposal_routes_are_normalized_to_function_relative_partitions() -> None:
    proof = SimpleNamespace(
        proof_id="proof-one",
        proof_kind=SimpleNamespace(value="state_assignment"),
        source_anchor_ea=0x180001020,
        destinations=(
            SimpleNamespace(
                state_constant=0xAABBCCDD,
                target_anchor_ea=0x180001080,
            ),
        ),
    )
    proposal = SimpleNamespace(
        route_evidence=SimpleNamespace(route_proofs=(proof,)),
        claims=(SimpleNamespace(route_proof_ids=("proof-one",)),),
    )

    recovered = recovered_semantics_from_proposals(
        function="fixture",
        function_ea=0x180001000,
        entry_rva=0x1000,
        extent=0x100,
        linked_sha256="1" * 64,
        proposals=(proposal,),
    )

    assert recovered.unresolved == ()
    assert recovered.transitions == (
        Transition(
            partition="src=0x1020:state=0xAABBCCDD",
            predecessor_eas=(0x1020,),
            constraints=("selector_state == 0xAABBCCDD",),
            target_rvas=(0x1080,),
        ),
    )


def test_proposal_route_conflict_fails_closed() -> None:
    def proposal(target_ea: int):
        proof = SimpleNamespace(
            proof_id=f"proof-{target_ea:x}",
            proof_kind=SimpleNamespace(value="state_assignment"),
            source_anchor_ea=0x180001020,
            destinations=(
                SimpleNamespace(
                    state_constant=7,
                    target_anchor_ea=target_ea,
                ),
            ),
        )
        return SimpleNamespace(
            route_evidence=SimpleNamespace(route_proofs=(proof,)),
            claims=(SimpleNamespace(route_proof_ids=(proof.proof_id,)),),
        )

    recovered = recovered_semantics_from_proposals(
        function="fixture",
        function_ea=0x180001000,
        entry_rva=0x1000,
        extent=0x100,
        linked_sha256="1" * 64,
        proposals=(proposal(0x180001040), proposal(0x180001060)),
    )

    assert recovered.transitions == ()
    assert recovered.unresolved == (
        "conflicting route partition src=0x1020:state=0x00000007",
    )


def test_unclaimed_proposal_proof_is_not_semantic_output() -> None:
    proof = SimpleNamespace(
        proof_id="available-only",
        proof_kind=SimpleNamespace(value="bootstrap"),
        source_anchor_ea=0x180001020,
        destinations=(SimpleNamespace(state_constant=1, target_anchor_ea=0x180001040),),
    )
    recovered = recovered_semantics_from_proposals(
        function="fixture",
        function_ea=0x180001000,
        entry_rva=0x1000,
        extent=0x100,
        linked_sha256="1" * 64,
        proposals=(
            SimpleNamespace(
                route_evidence=SimpleNamespace(route_proofs=(proof,)),
                claims=(),
            ),
        ),
    )

    assert recovered.transitions == ()
    assert recovered.unresolved == ("no published semantic route proofs",)


def test_reference_loader_rejects_unknown_schema(tmp_path: Path) -> None:
    path = tmp_path / "semantics.json"
    path.write_text('{"schema": "wrong", "fixtures": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported"):
        load_fixture_references(path)


def test_v2_reference_loader_rebases_function_relative_routes(
    tmp_path: Path,
) -> None:
    from d810.testing.hash_bound_build_receipt import (
        generate_hash_bound_build_receipt,
    )

    linked_image = _REPO_ROOT / "samples" / "bins" / "libobfuscated.dll"
    manifest_path = tmp_path / "manifest.json"
    receipt_path = tmp_path / "receipt.json"
    semantics_path = tmp_path / "semantics.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema": "d810.hash-bound-masm-fixtures.v4",
                "fixtures": [
                    {
                        "function": "sub_7FFB0E1E69E0",
                        "linked_text_size": "0x15A",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    receipt_path.write_text(
        json.dumps(
            generate_hash_bound_build_receipt(
                manifest_path=manifest_path,
                linked_image_path=linked_image,
            )
        ),
        encoding="utf-8",
    )
    semantics_path.write_text(
        json.dumps(
            {
                "schema": "d810.hash-bound-seven-semantics.v2",
                "source": {
                    "fixture_manifest": manifest_path.name,
                    "build_receipt": receipt_path.name,
                    "reference_policy": "exact_bytes_dispatcher_routes_only",
                },
                "fixtures": [
                    {
                        "function": "sub_7FFB0E1E69E0",
                        "transitions": [
                            {
                                "source_offset": "0x10",
                                "state": "0x12345678",
                                "target_offsets": ["0x20"],
                            }
                        ],
                        "effects": [],
                        "exits": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    reference = load_fixture_references(
        semantics_path,
        linked_image_path=linked_image,
    )["sub_7FFB0E1E69E0"]

    assert reference.entry_rva == 0xA6EA0
    assert reference.extent == 0x15A
    assert reference.transitions == (
        Transition(
            partition="src=0xA6EB0:state=0x12345678",
            predecessor_eas=(0xA6EB0,),
            constraints=("selector_state == 0x12345678",),
            target_rvas=(0xA6EC0,),
        ),
    )


def test_reference_loader_rejects_undeclared_whole_semantics_scope(
    tmp_path: Path,
) -> None:
    path = tmp_path / "semantics.json"
    path.write_text(
        '{"schema":"d810.hash-bound-seven-semantics.v2","fixtures":[]}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="route-only scope"):
        load_fixture_references(path)


def test_reference_loader_rejects_duplicate_partitions(tmp_path: Path) -> None:
    manifest_path = (
        _REPO_ROOT / "samples/src/masm/hash_bound_seven_manifest.json"
    ).resolve()
    receipt_path = (
        _REPO_ROOT / "samples/src/masm/hash_bound_seven_build_receipt.json"
    ).resolve()
    linked_image = _REPO_ROOT / "samples/bins/libobfuscated.dll"
    payload = json.loads(_REFERENCE_PATH.read_text(encoding="utf-8"))
    payload["source"]["fixture_manifest"] = str(manifest_path)
    payload["source"]["build_receipt"] = str(receipt_path)
    payload["fixtures"][0]["transitions"].append(
        dict(payload["fixtures"][0]["transitions"][0])
    )
    path = tmp_path / "semantics.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate transition partition"):
        load_fixture_references(path, linked_image_path=linked_image)


def test_native_receipt_projects_an_independent_route_transition() -> None:
    image_base = 0x180000000
    request = NativeTransitionRequest(
        instructions=(NativeInstruction(image_base + 0x1234, b"\x90"),),
        entry_ea=image_base + 0x1234,
        target_partitions=(("handler", (image_base + 0x1456,)),),
        register_assumptions=(),
        memory_assumptions=(),
        instruction_budget=1,
    )
    image_slice = NativeImageSlice(
        image_base=image_base,
        request=request,
        linked_memory=(),
    )
    receipt = NativeTransitionReceipt(
        status=NativeTransitionStatus.RESOLVED,
        target="handler",
        reason="",
        instruction_eas=(image_base + 0x1234,),
        wall_seconds=0.001,
        request_fingerprint="sha256:" + "1" * 64,
        selector_value=0x12345678,
    )

    assert transition_from_native_receipt(image_slice, receipt) == Transition(
        partition="src=0x1234:state=0x12345678",
        predecessor_eas=(0x1234,),
        constraints=("selector_state == 0x12345678",),
        target_rvas=(0x1456,),
    )


def test_tracked_references_are_exactly_the_seven_resolved_fixtures() -> None:
    references = load_fixture_references(_REFERENCE_PATH)
    assert set(references) == {
        "sub_7FFB0E53C420",
        "sub_7FFB0DE51120",
        "sub_7FFB0DF992D0",
        "sub_7FFB0DFD1D70",
        "sub_7FFB0E1E69E0",
        "sub_7FFB0E0A2C90",
        "sub_7FFB0E086BE0",
    }
    assert all(not reference.unresolved for reference in references.values())
    assert all(reference.transitions for reference in references.values())
    e086_partitions = {
        transition.predecessor_eas[0]
        - references["sub_7FFB0E086BE0"].entry_rva
        for transition in references["sub_7FFB0E086BE0"].transitions
    }
    assert len(e086_partitions) == 21
    assert {
        0x40EB,
        0x6010,
        0x62E5,
        0x6C12,
        0x821B,
    } <= e086_partitions


def test_tracked_references_match_the_generated_build_receipt() -> None:
    receipt_path = _REPO_ROOT / (
        "samples/src/masm/hash_bound_seven_build_receipt.json"
    )
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    references = load_fixture_references(_REFERENCE_PATH)

    for fixture in receipt["fixtures"]:
        reference = references[fixture["function"]]
        assert reference.entry_rva == int(fixture["entry_rva"], 0)
        assert reference.extent == int(fixture["extent"], 0)
        assert reference.linked_sha256 == fixture["linked_sha256"]


def test_tracked_reference_set_names_the_exact_linked_dll() -> None:
    receipt_path = _REPO_ROOT / (
        "samples/src/masm/hash_bound_seven_build_receipt.json"
    )
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    linked_dll = _REPO_ROOT / "samples" / "bins" / "libobfuscated.dll"

    assert receipt["linked_dll_sha256"] == hashlib.sha256(
        linked_dll.read_bytes()
    ).hexdigest()
