"""Focused tests for the strict legacy compatibility codec."""

from __future__ import annotations

import hashlib
import importlib
import inspect
import copy
from dataclasses import replace
from types import SimpleNamespace

import pytest


from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity

from d810.transforms.unflatten_authority.model import (
    UnflattenAuthorityReason,
    UnflattenPlanRoute,
)
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.proposal import LEGACY_UNFLATTEN_KEYS
from d810.transforms.unflatten_authority.legacy_keys import EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA
from d810.transforms.unflatten_authority.legacy_keys import NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA
from d810.transforms.unflatten_authority.ids import authority_id
from d810.analyses.control_flow.semantic_route_evidence import canonical_semantic_evidence_from_proofs


def _recanonicalize(evidence, proofs):
    return canonical_semantic_evidence_from_proofs(
        native_key=evidence.native_key,
        generation=evidence.generation,
        proofs=tuple(proofs),
    )


def _codec():
    return importlib.import_module("d810.transforms.unflatten_authority.legacy_codec")


def _metadata():
    values = {
        key: {"nested": [key, (1, 2)], "scalar": 3}
        for key in LEGACY_UNFLATTEN_KEYS
    }
    return (("ordinary", ["keep", ("shape",)]), *values.items())


def _persistence_envelope(metadata, *, plan_id="plan", snapshot_id="snapshot", generation=3):
    codec = _codec()
    ordinary = []
    entries = []
    for key, value in metadata:
        if key not in LEGACY_UNFLATTEN_KEYS:
            ordinary.append((key, value))
            continue
        payload = codec.legacy_canonical_bytes(value)
        entries.append(model.LegacyShadowEntry(
            key, payload, hashlib.sha256(payload).hexdigest(),
        ))
    envelope = model.LegacyUnflattenShadowEnvelope(
        1, plan_id, snapshot_id, generation, tuple(sorted(entries, key=lambda item: item.key)),
    )
    return tuple(ordinary), envelope


def _decode_context(codec, *, evidence=None, generation=3, ref=None):
    source = FlowGraph(
        {0: BlockSnapshot(
            0, 0, (), (), 0, 0x1000,
            (InsnSnapshot(0, 0x1000, (), kind=InsnKind.RET, native_ea=0x1000),),
            kind=BlockKind.STOP,
        )},
        0,
        0x1000,
    )
    return codec.LegacyUnflattenDecodeContext(
        "plan", source, generation,
        ((0, ref or LogicalBlockRef("legacy", "b0", 1)),), evidence,
    )


def test_native_bound_route_receipts_project_to_typed_codec_values():
    codec = _codec()
    row = {
        "fact_id": "transition:codec",
        "native_ea": 0x1000,
        "native_ea_hex": "0x1000",
        "current_block": "blk[10]@0x1280",
        "state": 0x20,
        "target": 20,
        "target_block": "blk[20]@0x1500",
        "operation_key": ("block_goto_change", 10, 2, 20),
    }
    plan = SimpleNamespace(
        metadata_dict=lambda: {
            NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA: (row,),
        }
    )

    projection = codec.native_bound_transition_route_receipts_from_plan(plan)

    assert len(projection) == 1
    assert type(projection[0]) is codec.NativeBoundTransitionRouteReceipt
    assert projection[0].operation_key == ("block_goto_change", 10, 2, 20)


def test_legacy_retirement_anchor_only_lookup_rejects_shared_native_anchor() -> None:
    codec = _codec()
    key = NativePreanalysisKey(
        "legacy-shared-anchor", "x86", 64, 0,
        "f" * 64, "p" * 64, "s" * 64,
    )

    def native_ref(origin: int) -> NativeBlockRef:
        return NativeBlockRef(StableBlockIdentity.from_intervals(
            (NativeEaInterval(0x1000, 0x1020),),
            native_key=key,
            exact_instruction_eas=(origin,),
        ))

    first, second = native_ref(0x1004), native_ref(0x1014)
    catalog = model.SourceIdentityCatalog(
        key,
        0,
        (
            model.SourceBlockIdentityWitness(first, 0x1000, (0x1004,)),
            model.SourceBlockIdentityWitness(second, 0x1000, (0x1014,)),
        ),
    )
    proposal = object.__new__(model.ProposedUnflattenContract)
    object.__setattr__(proposal, "source_identity_catalog", catalog)
    with pytest.raises(ValueError, match="ambiguous"):
        codec.retirement_claim_from_legacy_proof(
            {},
            proposal=proposal,
            block_refs_by_serial={0: first, 1: second},
        )


def _corridor_metadata(*, covered=True, path=None, **overrides):
    """Return one analyzer-shaped corridor record for the logical fixture."""

    # _valid_proposal intentionally uses three source-catalog rows whose
    # anchors are 0x1000, 0x1300, and 0x1100.  The dispatcher is serial 0;
    # the path ends there and its penultimate row is the feeder.
    path = path or [
        {"serial": 1, "ea": 0x1300, "label": "blk1@0x1300"},
        {"serial": 2, "ea": 0x1100, "label": "blk2@0x1100"},
        {"serial": 0, "ea": 0x1000, "label": "blk0@0x1000"},
    ]
    row = {
        "source": path[0],
        "state_merge": path[0],
        "dispatcher_feeder": path[-2],
        "dispatcher": path[-1],
        "path": path,
        "label": " -> ".join(item["label"] for item in path),
    }
    payload = {
        "function_ea": 0x1000,
        "dispatcher": path[-1],
        "completion_status": "pending_patch_application",
        "planned_completion_status": (
            "planned_dispatcher_corridors_covered"
            if covered else "planned_partial_residual_dispatcher"
        ),
        "application_status": "pending",
        "full_unflattening_claim": False,
        "enumeration_complete": True,
        "covered_corridors": [row] if covered else [],
        "residual_corridors": [] if covered else [row],
        "semantic_exclusions": [],
    }
    payload.update(overrides)
    return payload


def _corridor_fixture():
    from .test_model import _valid_proposal

    model = importlib.import_module("d810.transforms.unflatten_authority.model")
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    refs = {
        serial: item.block_ref
        for serial, item in enumerate(proposal.source_identity_catalog.blocks)
    }
    return model, proposal, refs


def _without(payload, key):
    result = dict(payload)
    result.pop(key)
    return result


def _real_full_shadow_fixture():
    """Build one analyzer-shaped envelope covering every migrated family."""

    from .helpers import exact_fixture
    from d810.transforms.unflatten_authority import producer_api

    source, route_base, exclusion, refs = exact_fixture()
    proof = replace(
        route_base.route_evidence.route_proofs[0],
        diagnostic_provenance=route_base.route_evidence.route_proofs[0].diagnostic_provenance + (
            ("source_kinds", "legacy"), ("fact_id", "legacy-fact"),
        ),
    )
    route_evidence = _recanonicalize(route_base.route_evidence, (proof,))
    proposal = producer_api.build_proposal(
        plan_id=route_base.plan_id,
        source=source,
        block_refs_by_serial=refs,
        source_generation=1,
        canonical_route_evidence=route_evidence,
        selected_route_proof_ids=(proof.proof_id,),
        exact_state_effect_exclusions=(exclusion,),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=route_base.plan_inputs.state_identity,
        use_def_witness=route_base.use_def_witness,
    )
    catalog = proposal.source_identity_catalog.blocks

    def anchor(serial):
        block = catalog[serial]
        return {"serial": serial, "ea": block.anchor_ea, "label": f"blk{serial}@0x{block.anchor_ea:x}"}

    path = [anchor(0), anchor(2), anchor(1)]
    corridor_row = {
        "source": dict(path[0]), "state_merge": dict(path[0]),
        "dispatcher_feeder": dict(path[-2]), "dispatcher": dict(path[-1]),
        "path": [dict(item) for item in path],
        "label": " -> ".join(item["label"] for item in path),
    }
    corridor = {
        "function_ea": source.func_ea, "dispatcher": dict(path[-1]),
        "completion_status": "pending_patch_application",
        "planned_completion_status": "planned_dispatcher_corridors_covered",
        "application_status": "pending", "full_unflattening_claim": False,
        "enumeration_complete": True, "covered_corridors": [corridor_row],
        "residual_corridors": [], "semantic_exclusions": [],
    }
    forecast = _codec().corridor_coverage_forecast_from_legacy_metadata(
        corridor, proposal=proposal, block_refs_by_serial=refs,
        source_function_ea=source.func_ea,
    )
    proposal = replace(proposal, corridor_coverage_forecast=forecast)
    removal = {
        "retired_infrastructure": tuple(
            {
                "role": "comparison_dispatcher" if serial == 0 else "comparison_corridor",
                "anchor": {"serial": serial, "ea": catalog[serial].anchor_ea},
                "retired": serial == 0,
            }
            for serial in (0, 1)
        ),
    }
    removal_claim = _codec().retirement_claim_from_legacy_proof(
        removal, proposal=proposal, block_refs_by_serial=refs,
    )
    proposal = replace(
        proposal,
        claims=tuple(sorted((*proposal.claims, removal_claim), key=lambda claim: claim.claim_id)),
        retirement_candidate_catalog=removal_claim.candidate_catalog,
    )
    metadata = {
        "concrete_state_route_provenance": [{
            "site": "entry", "normalized_state": 7,
            "target_handler": 2, "source_kinds": ("legacy",),
        }],
        "native_bound_transition_route_receipts": [{
            "fact_id": "legacy-fact", "native_ea": 0x1000,
            "native_ea_hex": "0x1000", "current_block": "blk0@0x1000",
            "state": 7, "target": 2, "target_block": "blk2@0x3000",
        }],
        "dispatcher_corridor_coverage": corridor,
        "full_unflattening_claim": False,
        "unflatten_completion_status": "pending_patch_application",
        "use_def_severance_audit": {
            "function_ea": source.func_ea, "executed": True,
            "fragment_atomic": True, "severance_count": 0, "violations": (),
        },
        "exact_state_branch_effect_exclusions": (exclusion.to_metadata(),),
        "dispatcher_removal_preflight_proof": removal,
    }
    context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, proposal.plan_inputs,
        proposal.use_def_witness, proposal,
    )
    return proposal, context, metadata


def test_legacy_corridor_metadata_converts_exact_analyzer_shape_and_statuses() -> None:
    codec = _codec()
    _model, proposal, refs = _corridor_fixture()
    forecast = codec.corridor_coverage_forecast_from_legacy_metadata(
        _corridor_metadata(), proposal=proposal,
        block_refs_by_serial=refs, source_function_ea=0x1000,
    )
    assert forecast.plan_id == proposal.plan_id
    assert forecast.function_ea == 0x1000
    assert forecast.source_native_key == proposal.source_identity_catalog.native_key
    assert forecast.source_generation == proposal.source_identity_catalog.generation
    assert forecast.enumeration_complete is True
    assert forecast.covered_path_ids == (forecast.paths[0].path_id,)
    assert forecast.residual_path_ids == ()
    assert forecast.paths[0].nodes[-1].block_ref == proposal.plan_inputs.dispatcher_entry_ref
    assert forecast.paths[0].nodes[-2].block_ref == refs[2]
    assert forecast.paths[0].state_merge == forecast.paths[0].nodes[-3]
    residual = codec.corridor_coverage_forecast_from_legacy_metadata(
        _corridor_metadata(covered=False), proposal=proposal,
        block_refs_by_serial=refs, source_function_ea=0x1000,
    )
    assert residual.covered_path_ids == ()
    assert residual.residual_path_ids == (residual.paths[0].path_id,)
    assert residual.paths[0].disposition.value == "residual"


@pytest.mark.parametrize(
    "field,value",
    [
        ("dispatcher", None),
        ("dispatcher", {"serial": 0}),
        ("dispatcher", {"serial": 0, "ea": 0x1000, "label": "wrong"}),
        ("function_ea", 0x1004),
        ("completion_status", "complete"),
        ("application_status", "applied"),
        ("full_unflattening_claim", True),
    ],
)
def test_legacy_corridor_supported_fields_reject_none_malformed_or_foreign(field, value) -> None:
    codec = _codec()
    _model, proposal, refs = _corridor_fixture()
    payload = _corridor_metadata(**{field: value})
    with pytest.raises((TypeError, ValueError)):
        codec.corridor_coverage_forecast_from_legacy_metadata(
            payload, proposal=proposal, block_refs_by_serial=refs,
            source_function_ea=0x1000,
        )


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda p: {**p, "covered_corridors": p["covered_corridors"] * 2}, "unique"),
        (lambda p: _without(p, "covered_corridors"), "incomplete"),
        (lambda p: {**p, "planned_completion_status": "planned_partial_residual_dispatcher", "covered_corridors": [p["covered_corridors"][0]], "residual_corridors": [p["covered_corridors"][0]]}, "unique"),
        (lambda p: {**p, "covered_corridors": [{**p["covered_corridors"][0], "source": p["covered_corridors"][0]["dispatcher"]}]}, "endpoints"),
        (lambda p: {**p, "covered_corridors": [{**p["covered_corridors"][0], "dispatcher_feeder": p["covered_corridors"][0]["dispatcher"]}]}, "penultimate"),
        (lambda p: {**p, "covered_corridors": [{**p["covered_corridors"][0], "state_merge": p["covered_corridors"][0]["dispatcher"]}]}, r"path\[-3\]"),
        (lambda p: {**p, "covered_corridors": [{**p["covered_corridors"][0], "path": list(reversed(p["covered_corridors"][0]["path"]))}]}, "endpoints"),
    ],
)
def test_legacy_corridor_duplicate_overlap_omission_and_substitution_fail_closed(mutation, match) -> None:
    codec = _codec()
    _model, proposal, refs = _corridor_fixture()
    with pytest.raises((TypeError, ValueError), match=match):
        codec.corridor_coverage_forecast_from_legacy_metadata(
            mutation(_corridor_metadata()), proposal=proposal,
            block_refs_by_serial=refs, source_function_ea=0x1000,
        )


def test_legacy_corridor_foreign_catalog_native_key_generation_dispatcher_and_anchor_reject() -> None:
    codec = _codec()
    model, proposal, refs = _corridor_fixture()
    payload = _corridor_metadata()
    # A serial map with a foreign ref is rejected before any path can be minted.
    foreign = dict(refs)
    foreign[2] = LogicalBlockRef("foreign", "b2", 1)
    with pytest.raises((TypeError, ValueError), match="catalog|foreign"):
        codec.corridor_coverage_forecast_from_legacy_metadata(
            payload, proposal=proposal, block_refs_by_serial=foreign,
            source_function_ea=0x1000,
        )
    with pytest.raises(ValueError, match="function"):
        codec.corridor_coverage_forecast_from_legacy_metadata(
            payload, proposal=proposal, block_refs_by_serial=refs,
            source_function_ea=0x1004,
        )
    bad_dispatcher = _corridor_metadata(dispatcher={"serial": 1, "ea": 0x1300, "label": "blk1@0x1300"})
    with pytest.raises(ValueError, match="dispatcher"):
        codec.corridor_coverage_forecast_from_legacy_metadata(
            bad_dispatcher, proposal=proposal, block_refs_by_serial=refs,
            source_function_ea=0x1000,
        )
    bad_anchor = _corridor_metadata(path=[
        {"serial": 1, "ea": 0x1301, "label": "blk1@0x1301"},
        {"serial": 2, "ea": 0x1100, "label": "blk2@0x1100"},
        {"serial": 0, "ea": 0x1000, "label": "blk0@0x1000"},
    ])
    with pytest.raises(ValueError, match="catalog|foreign"):
        codec.corridor_coverage_forecast_from_legacy_metadata(
            bad_anchor, proposal=proposal, block_refs_by_serial=refs,
            source_function_ea=0x1000,
        )


def test_legacy_corridor_path_identity_changes_for_each_authoritative_component() -> None:
    model, proposal, refs = _corridor_fixture()
    codec = _codec()
    base = codec.corridor_coverage_forecast_from_legacy_metadata(
        _corridor_metadata(), proposal=proposal, block_refs_by_serial=refs,
        source_function_ea=0x1000,
    ).paths[0]
    def mint(nodes, state_merge, disposition):
        return model.CorridorCoveragePath(
            authority_id(("unflatten.corridor-coverage-path.v1", nodes, state_merge, disposition, ())),
            nodes, state_merge, disposition, (),
        )

    variants = [
        mint((base.nodes[0], model.CorridorCoveragePathNode(LogicalBlockRef("foreign", "node", 1), 0x1100), base.nodes[-1]), base.state_merge, base.disposition),
        mint((base.nodes[0], model.CorridorCoveragePathNode(refs[2], 0x1101), base.nodes[-1]), base.state_merge, base.disposition),
        mint((base.nodes[1], base.nodes[0], base.nodes[-1]), base.nodes[0], base.disposition),
        mint(base.nodes, None, base.disposition),
        mint(base.nodes, base.state_merge, model.CorridorPathDisposition.RESIDUAL),
    ]
    assert len({item.path_id for item in variants} | {base.path_id}) == 6


def test_legacy_corridor_semantic_exclusions_are_reserved_and_fail_closed() -> None:
    codec = _codec()
    _model, proposal, refs = _corridor_fixture()
    with pytest.raises(ValueError, match="Task15|semantic exclusion"):
        codec.corridor_coverage_forecast_from_legacy_metadata(
            _corridor_metadata(semantic_exclusions=[{}]), proposal=proposal,
            block_refs_by_serial=refs, source_function_ea=0x1000,
        )


def _legacy_route_proposal(*, duplicate: bool = False):
    from dataclasses import replace
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture
    from d810.transforms.unflatten_authority import producer_api

    source, original, exclusion, refs = exact_fixture()
    proof = original.route_evidence.route_proofs[0]
    proof = replace(
        proof,
        diagnostic_provenance=proof.diagnostic_provenance + (
            ("source_kinds", "legacy"),
            ("fact_id", "legacy-fact"),
        ),
    )
    evidence = _recanonicalize(original.route_evidence, (proof,))
    if duplicate:
        sibling = replace(
            proof,
            proof_id=f"{proof.proof_id}:legacy-sibling",
            predicate=replace(proof.predicate, compare_constant=6),
        )
        evidence = _recanonicalize(evidence, (proof, sibling))
        selected = tuple(item.proof_id for item in evidence.route_proofs)
    else:
        selected = (proof.proof_id,)
    proposal = producer_api.build_proposal(
        plan_id=original.plan_id,
        source=source,
        block_refs_by_serial=refs,
        source_generation=1,
        canonical_route_evidence=evidence,
        selected_route_proof_ids=selected,
        exact_state_effect_exclusions=(),
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=original.plan_inputs.state_identity,
        use_def_witness=original.use_def_witness,
    )
    return source, proposal, refs, proof


def test_legacy_route_selector_requires_exact_provenance_and_cardinality() -> None:
    codec = _codec()
    _source, proposal, refs, proof = _legacy_route_proposal()
    native_row = {
        "fact_id": "legacy-fact",
        "native_ea": 0x1000,
        "native_ea_hex": "0x1000",
        "current_block": "blk0@0x1000",
        "state": 7,
        "target": 2,
        "target_block": "blk2@0x3000",
    }
    assert codec.equivalent_route_claims_from_legacy_metadata(
        [native_row], proposal=proposal,
        key="native_bound_transition_route_receipts", block_refs_by_serial=refs,
    )
    concrete_row = {
        "site": "entry", "normalized_state": 7, "target_handler": 2,
        "source_kinds": ("legacy",),
    }
    assert codec.equivalent_route_claims_from_legacy_metadata(
        [concrete_row], proposal=proposal,
        key="concrete_state_route_provenance", block_refs_by_serial=refs,
    )

    with pytest.raises(ValueError):
        codec.equivalent_route_claims_from_legacy_metadata(
            [{**native_row, "state": 0x100000007}], proposal=proposal,
            key="native_bound_transition_route_receipts", block_refs_by_serial=refs,
        )
    for field, value in (("fact_id", "forged"), ("current_block", "foreign"), ("target_block", "foreign")):
        with pytest.raises(ValueError):
            codec.equivalent_route_claims_from_legacy_metadata(
                [{**native_row, field: value}], proposal=proposal,
                key="native_bound_transition_route_receipts", block_refs_by_serial=refs,
            )
    with pytest.raises(ValueError):
        codec.equivalent_route_claims_from_legacy_metadata(
            [concrete_row, concrete_row], proposal=proposal,
            key="concrete_state_route_provenance", block_refs_by_serial=refs,
        )

    _source, ambiguous, refs, _proof = _legacy_route_proposal(duplicate=True)
    assert len(ambiguous.route_evidence.route_proofs) == 2
    assert len({item.proof_id for item in ambiguous.route_evidence.route_proofs}) == 2
    with pytest.raises(ValueError, match="multiple"):
        codec.equivalent_route_claims_from_legacy_metadata(
            [native_row], proposal=ambiguous,
            key="native_bound_transition_route_receipts", block_refs_by_serial=refs,
        )


def test_legacy_decode_selects_row_proof_ids_before_building_proposal(monkeypatch) -> None:
    """Legacy transport rows must not promote every canonical proof first."""

    from dataclasses import replace
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, original, _exclusion, refs = exact_fixture()
    proof = replace(
        original.route_evidence.route_proofs[0],
        diagnostic_provenance=(
            *original.route_evidence.route_proofs[0].diagnostic_provenance,
            ("fact_id", "legacy-fact"),
        ),
    )
    sibling = replace(
        proof,
        proof_id=f"{proof.proof_id}:legacy-sibling",
        predicate=replace(proof.predicate, compare_constant=6),
        diagnostic_provenance=tuple(
            (key, "sibling-fact" if key == "fact_id" else value)
            for key, value in proof.diagnostic_provenance
        ),
    )
    evidence = _recanonicalize(original.route_evidence, (proof, sibling))
    proof, sibling = evidence.route_proofs
    proposal = producer_api.build_proposal(
        plan_id=original.plan_id, source=source, block_refs_by_serial=refs,
        source_generation=1, canonical_route_evidence=evidence,
        selected_route_proof_ids=(proof.proof_id, sibling.proof_id),
        exact_state_effect_exclusions=(), dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1), authoritative_handler_serials=(2,),
        state_identity=original.plan_inputs.state_identity,
        use_def_witness=original.use_def_witness,
    )
    codec = _codec()
    context = codec.LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())), evidence,
        proposal.plan_inputs, proposal.use_def_witness,
    )
    row = {
        "fact_id": "legacy-fact", "native_ea": 0x1000,
        "native_ea_hex": "0x1000", "current_block": "blk0@0x1000",
        "state": 7, "target": 2, "target_block": "blk2@0x3000",
    }
    captured: list[tuple[str, ...]] = []
    original_builder = producer_api.build_proposal

    def spy(*args, **kwargs):
        captured.append(tuple(kwargs.get("selected_route_proof_ids", ())))
        return original_builder(*args, **kwargs)

    monkeypatch.setattr(producer_api, "build_proposal", spy)
    result = codec.decode_legacy_unflatten_contract(
        (("native_bound_transition_route_receipts", [row]),), context=context,
    )
    assert captured == [(proof.proof_id,)]
    assert result.route is UnflattenPlanRoute.LEGACY_ADAPTED


def test_shadow_codec_receipt_requires_each_reserved_key_exactly_once() -> None:
    codec = _codec()
    _cleaned, shadow = _persistence_envelope(_metadata())
    assert shadow is not None
    receipt = codec.LegacyShadowCodecReceipt(
        shadow,
        tuple(
            codec.LegacyFamilyAdaptation(
                entry.key, "fixture", (entry.key,),
                entry.canonical_payload, entry.payload_sha256,
            )
            for entry in shadow.entries
        ),
    )
    assert receipt.consumed_keys == tuple(sorted(LEGACY_UNFLATTEN_KEYS))
    assert receipt.payloads[0][1] == shadow.entries[0].canonical_payload
    with pytest.raises(ValueError, match="exactly once"):
        codec.LegacyShadowCodecReceipt(
            shadow,
            tuple(
                codec.LegacyFamilyAdaptation(
                    entry.key, "fixture", (entry.key,),
                    entry.canonical_payload, entry.payload_sha256,
                )
                for entry in shadow.entries[:-1]
            ),
        )


def test_full_shadow_adapter_mints_receipt_for_all_eight_families_and_rejects_mutations() -> None:
    codec = _codec()
    proposal, context, metadata = _real_full_shadow_fixture()
    _ordinary, shadow = _persistence_envelope(
        tuple((key, copy.deepcopy(value)) for key, value in metadata.items()),
        plan_id=proposal.plan_id, generation=1,
    )
    assert shadow is not None
    receipt = codec.adapt_legacy_unflatten_shadow(shadow, context=context)
    assert receipt.consumed_keys == tuple(sorted(
        LEGACY_UNFLATTEN_KEYS - {"detached_dead_handler_component"}
    ))
    assert receipt.payloads == tuple(
        (entry.key, entry.canonical_payload, entry.payload_sha256)
        for entry in shadow.entries
    )
    subset = tuple(
        (key, copy.deepcopy(metadata[key]))
        for key in (
            "dispatcher_corridor_coverage",
            "dispatcher_removal_preflight_proof",
        )
    )
    _ordinary, subset_shadow = _persistence_envelope(
        subset, plan_id=proposal.plan_id, generation=1,
    )
    assert subset_shadow is not None
    subset_receipt = codec.adapt_legacy_unflatten_shadow(subset_shadow, context=context)
    assert subset_receipt.consumed_keys == tuple(key for key, _value in subset)
    exact_only = (
        ("exact_state_branch_effect_exclusions", copy.deepcopy(metadata["exact_state_branch_effect_exclusions"])),
    )
    _ordinary, exact_shadow = _persistence_envelope(
        exact_only, plan_id=proposal.plan_id, generation=1,
    )
    assert exact_shadow is not None
    exact_receipt = codec.adapt_legacy_unflatten_shadow(exact_shadow, context=context)
    assert exact_receipt.consumed_keys == ("exact_state_branch_effect_exclusions",)

    mutations = {
        "concrete_state_route_provenance": lambda value: [{**value[0], "target_handler": 99}],
        "native_bound_transition_route_receipts": lambda value: [{**value[0], "target": 99}],
        "dispatcher_corridor_coverage": lambda value: {**value, "completion_status": "complete"},
        "full_unflattening_claim": lambda _value: True,
        "unflatten_completion_status": lambda _value: "complete",
        "use_def_severance_audit": lambda value: {**value, "executed": False},
        "exact_state_branch_effect_exclusions": lambda value: (
            {**value[0], "normalized_state": value[0]["normalized_state"] + 1},
        ),
        "dispatcher_removal_preflight_proof": lambda value: {
            **value,
            "retired_infrastructure": tuple(
                {**row, "retired": not row["retired"]}
                for row in value["retired_infrastructure"]
            ),
        },
    }
    for key, mutate in mutations.items():
        mutated = dict(metadata)
        mutated[key] = mutate(mutated[key])
        _ordinary, mutated_shadow = _persistence_envelope(
            tuple((name, copy.deepcopy(value)) for name, value in mutated.items()),
            plan_id=proposal.plan_id, generation=1,
        )
        assert mutated_shadow is not None
        with pytest.raises((TypeError, ValueError), match="legacy|canonical|claim|coverage|proof|family"):
            codec.adapt_legacy_unflatten_shadow(mutated_shadow, context=context)


def test_full_shadow_adapter_uses_direct_sealed_family_adapters_once(monkeypatch) -> None:
    codec = _codec()
    proposal, context, metadata = _real_full_shadow_fixture()
    _ordinary, shadow = _persistence_envelope(
        tuple((key, copy.deepcopy(value)) for key, value in metadata.items()),
        plan_id=proposal.plan_id, generation=1,
    )
    assert shadow is not None
    from d810.transforms.unflatten_authority import legacy_codec
    from d810.transforms.unflatten_authority import producer_api

    monkeypatch.setattr(
        producer_api, "build_proposal",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("shadow adaptation must not rebuild a proposal")
        ),
    )
    route_calls = 0
    exact_calls = 0
    original_routes = legacy_codec.equivalent_route_claims_from_legacy_metadata
    original_exact = legacy_codec.exact_state_branch_effect_exclusion_from_metadata

    def wrapped_routes(*args, **kwargs):
        nonlocal route_calls
        route_calls += 1
        return original_routes(*args, **kwargs)

    def wrapped_exact(*args, **kwargs):
        nonlocal exact_calls
        exact_calls += 1
        return original_exact(*args, **kwargs)

    monkeypatch.setattr(
        legacy_codec, "equivalent_route_claims_from_legacy_metadata", wrapped_routes,
    )
    monkeypatch.setattr(
        legacy_codec, "exact_state_branch_effect_exclusion_from_metadata", wrapped_exact,
    )
    receipt = codec.adapt_legacy_unflatten_shadow(shadow, context=context)
    route_entry_count = sum(
        key in {
            "concrete_state_route_provenance",
            "native_bound_transition_route_receipts",
        }
        for key, _value in metadata.items()
    )
    exact_row_count = len(metadata["exact_state_branch_effect_exclusions"])
    assert route_calls == route_entry_count
    assert exact_calls == exact_row_count
    assert receipt.consumed_keys == tuple(entry.key for entry in shadow.entries)


def test_decode_is_absent_without_reserved_and_requires_route_evidence() -> None:
    codec = _codec()
    context = _decode_context(codec)
    absent = codec.decode_legacy_unflatten_contract((("ordinary", 1),), context=context)
    assert absent.route is UnflattenPlanRoute.ORDINARY
    missing = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", {"value": [1, (2,)]}),), context=context
    )
    assert missing.reason is UnflattenAuthorityReason.LEGACY_ROUTE_EVIDENCE_MISSING


def test_missing_route_precedes_reserved_duplicate_and_malformed_details() -> None:
    codec = _codec()
    context = _decode_context(codec)
    result = codec.decode_legacy_unflatten_contract(
        (
            ("dispatcher_corridor_coverage", {"serial": 7}),
            ("dispatcher_corridor_coverage", {"generation": "stale"}),
            ("unknown_authority_receipt", object()),
        ),
        context=context,
    )
    assert result.reason is UnflattenAuthorityReason.LEGACY_ROUTE_EVIDENCE_MISSING
    assert result.detail_code == "legacy_route_evidence_missing"


def test_hostile_nested_mapping_is_typed_rejection() -> None:
    codec = _codec()
    from .test_model import _canonical_evidence, import_authority_model
    from d810.transforms.cfg_transaction import NativeBlockRef

    model = import_authority_model()
    evidence, identity = _canonical_evidence(model)

    class HostileMapping(dict):
        def __iter__(self):
            raise RuntimeError("hostile")

        def items(self):
            raise RuntimeError("hostile")

    result = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", HostileMapping()),),
        context=_decode_context(codec, evidence=evidence, ref=NativeBlockRef(identity)),
    )
    assert result.detail_code == "legacy_payload_shape_invalid"


def test_decode_rejects_strict_shape_failures_and_defers_known_families() -> None:
    codec = _codec()
    from .test_model import _canonical_evidence, import_authority_model
    model = import_authority_model()
    evidence, identity = _canonical_evidence(model)
    from d810.transforms.cfg_transaction import NativeBlockRef
    context = _decode_context(codec, evidence=evidence, ref=NativeBlockRef(identity))
    serial = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", {"serial": 7}),), context=context
    )
    assert serial.detail_code == "legacy_serial_requires_ea"
    stale = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", {"generation": 9}),), context=context
    )
    assert stale.detail_code == "legacy_source_generation_mismatch"
    deferred = codec.decode_legacy_unflatten_contract(
        (("exact_state_branch_effect_exclusions", {"value": [1, (2,)]}),),
        context=context,
    )
    assert deferred.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert deferred.detail_code == "legacy_exact_effect_not_enabled"


def test_exact_decode_context_accepts_only_owned_typed_inputs() -> None:
    codec = _codec()
    fields = set(inspect.signature(codec.LegacyUnflattenDecodeContext).parameters)
    assert {"plan_inputs", "use_def_witness"} <= fields
    assert not {
        "dispatcher_entry_serial", "dispatcher_member_serials",
        "authoritative_handler_serials", "redirect_digest",
    } & fields
    with pytest.raises(TypeError):
        codec.LegacyUnflattenDecodeContext(
            "plan", _decode_context(codec).source, 3,
            ((0, LogicalBlockRef("legacy", "b0", 1)),), None,
            dispatcher_entry_serial=0,
        )


def test_exact_legacy_decode_roundtrips_through_the_producer_builder() -> None:
    from dataclasses import replace
    from .test_bind import _exact_fixture
    source, proposal, exclusion, refs = _exact_fixture()
    context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, proposal.plan_inputs, proposal.use_def_witness,
    )
    payload = ((EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA, (exclusion.to_metadata(),)),)
    decoded = _codec().decode_legacy_unflatten_contract(payload, context=context)
    assert decoded.route is UnflattenPlanRoute.LEGACY_ADAPTED
    assert decoded.proposal is not None
    assert decoded.proposal.claims == proposal.claims
    assert decoded.proposal.plan_inputs == proposal.plan_inputs
    assert _codec().decode_legacy_value(_codec().encode_legacy_value(payload)) == payload
    foreign_ref = LogicalBlockRef("foreign", "b9", 9)
    foreign = replace(
        proposal.plan_inputs, dispatcher_entry_ref=foreign_ref,
        dispatcher_member_refs=(foreign_ref, *proposal.plan_inputs.dispatcher_member_refs[1:]),
    )
    with pytest.raises(ValueError, match="foreign ref"):
        _codec().LegacyUnflattenDecodeContext(
            proposal.plan_id, source, 1, tuple(sorted(refs.items())),
            proposal.route_evidence, foreign, proposal.use_def_witness,
        )
    substituted_handler = replace(
        proposal.plan_inputs,
        authoritative_handlers=(replace(
            proposal.plan_inputs.authoritative_handlers[0], block_ref=foreign_ref,
        ),),
    )
    with pytest.raises(ValueError, match="foreign ref"):
        _codec().LegacyUnflattenDecodeContext(
            proposal.plan_id, source, 1, tuple(sorted(refs.items())),
            proposal.route_evidence, substituted_handler, proposal.use_def_witness,
        )
    with pytest.raises(TypeError, match="use-def witness"):
        _codec().LegacyUnflattenDecodeContext(
            proposal.plan_id, source, 1, tuple(sorted(refs.items())),
            proposal.route_evidence, proposal.plan_inputs, None,
        )
    with pytest.raises(ValueError, match="incomplete"):
        _codec().LegacyUnflattenDecodeContext(
            proposal.plan_id, source, 1, tuple(sorted(refs.items())),
            proposal.route_evidence, None, proposal.use_def_witness,
        )
    foreign_owner = replace(
        proposal.use_def_witness,
        redirect_owner_refs=(LogicalBlockRef("foreign", "owner", 11),),
    )
    with pytest.raises(ValueError, match="foreign ref"):
        _codec().LegacyUnflattenDecodeContext(
            proposal.plan_id, source, 1, tuple(sorted(refs.items())),
            proposal.route_evidence, proposal.plan_inputs, foreign_owner,
        )
    mutated = replace(
        proposal.use_def_witness,
        state_identity=type(proposal.plan_inputs.state_identity)(
            proposal.plan_inputs.state_identity.kind,
            proposal.plan_inputs.state_identity.offset + 1,
        ),
    )
    mutated_context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, proposal.plan_inputs, mutated,
    )
    rejected = _codec().decode_legacy_unflatten_contract(payload, context=mutated_context)
    assert rejected.detail_code == "legacy_exact_effect_payload_invalid"
    from d810.transforms.unflatten_authority import model
    shape_context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, replace(
            proposal.plan_inputs, shape=model.UnflattenPlanShape.EXACT_EFFECT_ONLY,
        ), proposal.use_def_witness,
    )
    exact_only = _codec().decode_legacy_unflatten_contract(
        payload, context=shape_context,
    )
    assert exact_only.route is UnflattenPlanRoute.LEGACY_ADAPTED
    assert exact_only.proposal.plan_inputs == shape_context.plan_inputs
    assert all(
        claim.kind is model.UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT
        for claim in exact_only.proposal.claims
    )
    handler = proposal.plan_inputs.authoritative_handlers[0]
    handler_context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, replace(
            proposal.plan_inputs,
            authoritative_handlers=(replace(handler, normalized_states=(99,)),),
        ), proposal.use_def_witness,
    )
    assert _codec().decode_legacy_unflatten_contract(
        payload, context=handler_context,
    ).detail_code == "legacy_exact_effect_payload_invalid"


def test_exact_exclusion_metadata_schema_preserves_old_and_new_rows() -> None:
    """The closed codec defaults old rows and preserves new site specificity."""
    from .test_bind import _exact_fixture

    codec = _codec()
    source, proposal, exclusion, refs = _exact_fixture()
    current = exclusion.to_metadata()
    old = dict(current)
    del old["site_specific"]

    assert codec.exact_state_branch_effect_exclusion_from_metadata(old) == replace(
        exclusion, site_specific=False,
    )
    old_payload = ((EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA, (old,)),)
    old_context = codec.LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, proposal.plan_inputs, proposal.use_def_witness,
    )
    old_decoded = codec.decode_legacy_unflatten_contract(
        old_payload, context=old_context,
    )
    assert old_decoded.route is UnflattenPlanRoute.LEGACY_ADAPTED
    assert old_decoded.proposal.claims == proposal.claims
    assert codec.exact_state_branch_effect_exclusion_from_metadata(current) == exclusion

    site_specific = {**current, "site_specific": True}
    assert codec.exact_state_branch_effect_exclusion_from_metadata(
        site_specific,
    ) == replace(exclusion, site_specific=True)

    class IntSubclass(int):
        pass

    for foreign in (0, 1, "true", None, IntSubclass(1)):
        assert codec.exact_state_branch_effect_exclusion_from_metadata(
            {**current, "site_specific": foreign},
        ) is None
    assert codec.exact_state_branch_effect_exclusion_from_metadata(
        {**current, "unknown": False},
    ) is None


def test_exact_multi_site_legacy_roundtrip_preserves_site_specific_exclusions() -> None:
    """A persisted two-site exact bundle rebuilds one canonical proposal."""
    from .helpers import exact_fixture

    source, proposal, exclusions, refs = exact_fixture(
        discarded_effect_kind="call_store",
    )
    assert all(exclusion.site_specific is True for exclusion in exclusions)
    payload = ((
        EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA,
        tuple(exclusion.to_metadata() for exclusion in exclusions),
    ),)
    context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, proposal.plan_inputs, proposal.use_def_witness,
    )

    decoded = _codec().decode_legacy_unflatten_contract(payload, context=context)

    assert decoded.route is UnflattenPlanRoute.LEGACY_ADAPTED
    assert decoded.proposal is not None
    assert decoded.proposal.claims == proposal.claims
    assert decoded.proposal.plan_inputs == proposal.plan_inputs
    assert _codec().decode_legacy_value(
        _codec().encode_legacy_value(payload),
    ) == payload


def test_exact_raw_codec_rejects_lossy_scalar_and_shape_coercions() -> None:
    from .test_bind import _exact_fixture

    codec = _codec()
    _source, _proposal, exclusion, _refs = _exact_fixture()
    base = exclusion.to_metadata()

    class IntSubclass(int):
        pass

    for value in (0.9, +0.9, True, "7", IntSubclass(7)):
        payload = dict(base)
        payload["normalized_state"] = value
        assert codec.exact_state_branch_effect_exclusion_from_metadata(payload) is None

    nested = dict(base)
    nested["source"] = list(base["source"].items())
    assert codec.exact_state_branch_effect_exclusion_from_metadata(nested) is None


def test_exact_legacy_decode_rejects_mixed_reserved_families() -> None:
    from .test_bind import _exact_fixture

    source, proposal, exclusion, refs = _exact_fixture()
    context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, proposal.plan_inputs, proposal.use_def_witness,
    )
    payload = (
        (EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA, (exclusion.to_metadata(),)),
        ("dispatcher_corridor_coverage", {"serial": 1, "ea": 0x1000}),
    )
    rejected = _codec().decode_legacy_unflatten_contract(payload, context=context)
    assert rejected.detail_code == "legacy_exact_effect_mixed_reserved_families"


def test_r2_requires_dedicated_lossless_wire_and_neutral_key_owner() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    keys = importlib.import_module("d810.transforms.unflatten_authority.legacy_keys")
    value = {"nested": [1, (2, -0.0)], "text": "cafe"}
    encoded = wire.encode_legacy_value(value)
    assert wire.decode_legacy_value(encoded) == value
    assert keys.LEGACY_UNFLATTEN_KEYS == LEGACY_UNFLATTEN_KEYS


@pytest.mark.parametrize(
    "value",
    [None, False, True, 0, -1, 2**130, -2**130, -0.0, 1.25, "utf-8 cafe", b"raw", [], (),
     {"a": [1, (2,)]}],
)
def test_legacy_wire_roundtrips_closed_values(value) -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    encoded = wire.encode_legacy_value(value)
    decoded = wire.decode_legacy_value(encoded)
    if isinstance(value, float) and value != value:
        assert decoded != decoded
    else:
        assert decoded == value
    assert wire.encode_legacy_value(decoded) == encoded


def test_legacy_wire_preserves_float_bits_container_shapes_and_dict_order() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    import struct

    negative_zero = struct.unpack(">d", bytes.fromhex("8000000000000000"))[0]
    nan_bits = bytes.fromhex("7ff8000000000042")
    nan_value = struct.unpack(">d", nan_bits)[0]
    first = {"a": [negative_zero, (nan_value,)]}
    second = {"b": 1, "a": 2}
    reversed_second = {"a": 2, "b": 1}
    first_wire = wire.encode_legacy_value(first)
    assert wire.encode_legacy_value(wire.decode_legacy_value(first_wire)) == first_wire
    decoded_nan = wire.decode_legacy_value(first_wire)["a"][1][0]
    assert struct.pack(">d", decoded_nan) == nan_bits
    assert wire.encode_legacy_value(second) != wire.encode_legacy_value(reversed_second)


def test_legacy_wire_rejects_subclasses_cycles_and_mutated_framing() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")

    class IntSubclass(int):
        pass

    class DictSubclass(dict):
        pass

    with pytest.raises(TypeError):
        wire.encode_legacy_value(IntSubclass(1))
    with pytest.raises(TypeError):
        wire.encode_legacy_value(DictSubclass(a=1))
    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError):
        wire.encode_legacy_value(cyclic)

    encoded = wire.encode_legacy_value([1])
    for mutated in (encoded + b"\x00", encoded[:-1], bytes((0x7F,))):
        with pytest.raises((TypeError, ValueError)):
            wire.decode_legacy_value(mutated)


def test_legacy_wire_rejects_nonminimal_integer_and_length_encodings() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    # int(1) with a two-byte magnitude length, and list count encoded as 0x80 0x00.
    with pytest.raises(ValueError):
        wire.decode_legacy_value(bytes((2, 0, 2, 0, 1)))
    with pytest.raises(ValueError):
        wire.decode_legacy_value(bytes((6, 0x80, 0x00)))


def test_legacy_wire_enforces_documented_depth_limit() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    limit = wire.MAX_LEGACY_WIRE_DEPTH

    def nested(depth):
        value = 0
        for _ in range(depth):
            value = [value]
        return value

    assert wire.decode_legacy_value(wire.encode_legacy_value(nested(limit))) == nested(limit)
    with pytest.raises(ValueError):
        wire.encode_legacy_value(nested(limit + 1))
    with pytest.raises(ValueError):
        wire.decode_legacy_value(b"\x06\x01" + wire.encode_legacy_value(nested(limit)))


def test_legacy_wire_rejects_shared_mutable_identity() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    shared_list = [1]
    shared_dict = {"value": 1}
    with pytest.raises(ValueError):
        wire.encode_legacy_value([shared_list, shared_list])
    with pytest.raises(ValueError):
        wire.encode_legacy_value({"a": shared_dict, "b": [shared_dict]})


def test_legacy_wire_roundtrips_lone_surrogates_with_surrogatepass() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    for value in ("\ud800", "\udfff", "ok-\ud800-\udfff"):
        encoded = wire.encode_legacy_value(value)
        assert wire.decode_legacy_value(encoded) == value


def test_shadow_envelope_requires_exact_identifier_and_generation_primitives() -> None:
    from d810.transforms.unflatten_authority.legacy_wire import encode_legacy_value
    from d810.transforms.unflatten_authority.model import (
        LegacyShadowEntry,
        LegacyUnflattenShadowEnvelope,
    )

    payload = encode_legacy_value(1)
    entry = LegacyShadowEntry(
        "dispatcher_corridor_coverage", payload, hashlib.sha256(payload).hexdigest()
    )

    class TextSubclass(str):
        pass

    for plan_id, snapshot_id, generation in (
        (TextSubclass("plan"), "snapshot", 1),
        ("plan", TextSubclass("snapshot"), 1),
        ("plan", "snapshot", True),
    ):
        with pytest.raises((TypeError, ValueError)):
            LegacyUnflattenShadowEnvelope(1, plan_id, snapshot_id, generation, (entry,))


def test_family_detail_registry_is_immutable_and_complete() -> None:
    keys = importlib.import_module("d810.transforms.unflatten_authority.legacy_keys")
    assert set(keys.LEGACY_FAMILY_DETAIL_CODES) == set(keys.LEGACY_UNFLATTEN_KEYS)
    with pytest.raises(TypeError):
        keys.LEGACY_FAMILY_DETAIL_CODES["new"] = "bad"


def test_context_rejects_bool_source_block_serial() -> None:
    codec = _codec()
    source = FlowGraph(
        {0: BlockSnapshot(
            True, 0, (), (), 0, 0x1000,
            (InsnSnapshot(0, 0x1000, (), kind=InsnKind.RET, native_ea=0x1000),),
            kind=BlockKind.STOP,
        )},
        0,
        0x1000,
    )
    with pytest.raises((TypeError, ValueError)):
        codec.LegacyUnflattenDecodeContext(
            "plan", source, 3,
            ((0, LogicalBlockRef("legacy", "b0", 1)),), None,
        )


def test_deep_route_validation_is_typed_rejection() -> None:
    codec = _codec()
    from .test_model import _canonical_evidence, import_authority_model
    from d810.transforms.cfg_transaction import NativeBlockRef

    model = import_authority_model()
    evidence, identity = _canonical_evidence(model)
    value = 0
    for _ in range(1500):
        value = [value]
    result = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", value),),
        context=_decode_context(codec, evidence=evidence, ref=NativeBlockRef(identity)),
    )
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL


def test_decode_revalidates_mutated_context_before_route_presence() -> None:
    codec = _codec()
    context = _decode_context(codec)
    reserved = (("dispatcher_corridor_coverage", {"value": 1}),)

    class TextSubclass(str):
        pass

    mutations = (
        ("plan_id", TextSubclass("plan")),
        ("source", object()),
        ("source_generation", True),
        ("block_refs_by_serial", ()),
        ("canonical_route_evidence", object()),
    )
    for field, value in mutations:
        object.__setattr__(context, field, value)
        result = codec.decode_legacy_unflatten_contract(reserved, context=context)
        assert type(result) is codec.LegacyUnflattenRejected
        assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
        assert result.detail_code == "legacy_decode_context_invalid"
        object.__setattr__(context, field, getattr(_decode_context(codec), field))
    invalid = codec.decode_legacy_unflatten_contract(reserved, context=object())
    assert invalid.detail_code == "legacy_decode_context_invalid"


def test_decode_genuine_no_route_context_still_reports_route_missing() -> None:
    codec = _codec()
    result = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", {"value": 1}),),
        context=_decode_context(codec),
    )
    assert result.reason is UnflattenAuthorityReason.LEGACY_ROUTE_EVIDENCE_MISSING


def test_decode_scans_all_nested_generation_values() -> None:
    codec = _codec()
    from .test_model import _canonical_evidence, import_authority_model
    from d810.transforms.cfg_transaction import NativeBlockRef
    model = import_authority_model()
    evidence, identity = _canonical_evidence(model)
    result = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", {"rows": [{"generation": 3}, {"generation": 9}]}),),
        context=_decode_context(codec, evidence=evidence, ref=NativeBlockRef(identity)),
    )
    assert result.detail_code == "legacy_source_generation_mismatch"


def test_legacy_retirement_conversion_is_serial_free_and_exact() -> None:
    from d810.transforms.unflatten_authority import model
    from d810.transforms.unflatten_authority.legacy_codec import retirement_claim_from_legacy_proof
    from .test_model import _valid_proposal

    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    catalog = proposal.source_identity_catalog
    refs = {7: catalog.blocks[0].block_ref, 11: catalog.blocks[1].block_ref, 23: catalog.blocks[2].block_ref}
    payload = {
        "retired_infrastructure": (
            {"role": "comparison_dispatcher", "anchor": {"serial": 7, "ea": 0x1000}},
            {"role": "comparison_corridor", "anchor": {"serial": 11, "ea": 0x1300}},
        ),
    }
    claim = retirement_claim_from_legacy_proof(
        payload, proposal=proposal, block_refs_by_serial=refs,
    )
    assert {subject.block_ref for subject in claim.member_subjects} == set(
        proposal.plan_inputs.dispatcher_member_refs
    )
    assert all("serial" not in repr(subject.locator) for subject in claim.member_subjects)
    for malformed in (
            {"retired_infrastructure": payload["retired_infrastructure"] + (payload["retired_infrastructure"][0],)},
        {"unknown": ()},
        {"retired_infrastructure": [{"role": "unknown", "anchor": {"serial": 0, "ea": 0x1000}}]},
        {"retired_infrastructure": [{"role": "comparison_dispatcher", "anchor": {"serial": 0, "ea": 0x1001}}]},
    ):
        with pytest.raises((TypeError, ValueError)):
            retirement_claim_from_legacy_proof(
                malformed, proposal=proposal, block_refs_by_serial=refs,
            )


def test_terminal_cycle_conversion_binds_terminal_route_and_actual_stop() -> None:
    from d810.transforms.unflatten_authority.legacy_codec import (
        terminal_cycle_claim_from_legacy_proof,
    )
    from .test_bind import _terminal_cycle_fixture

    proposal, _existing_claim = _terminal_cycle_fixture()
    route = proposal.route_evidence.route_proofs[0]
    refs = {
        int(witness.block_ref.proxy_token[1:]): witness.block_ref
        for witness in proposal.source_identity_catalog.blocks
    }

    def anchor(serial: int, ea: int) -> dict[str, object]:
        return {"serial": serial, "ea": ea, "label": f"blk{serial}@0x{ea:x}"}

    dispatcher = anchor(0, 0x1000)
    cleanup = anchor(1, 0x1300)
    carrier = anchor(2, 0x1100)
    terminal_source = anchor(3, 0x1400)
    terminal = anchor(4, 0x1500)
    proof = {
        "function_ea": 0x1000,
        "dispatcher": dispatcher,
        "proof_status": "rejected",
        "reason": "untyped_lost_block",
        "authoritative_handlers": (carrier,),
        "post_reachable_handlers": (carrier,),
        "pre_reachable_terminals": (terminal,),
        "post_reachable_terminals": (terminal,),
        "retired_infrastructure": (),
        "lost_blocks": (dispatcher, cleanup),
        "state_plumbing": (),
        "producer_safety": None,
        "coverage_enumeration_complete": True,
        "residual_corridor_count": 0,
    }
    payload = {
        "validation_status": "accepted",
        "reason": "terminal_switch_cycle_break",
        "proof": proof,
        "terminal_switch_cycle_break": {
            "dispatcher": dispatcher,
            "terminal_source": terminal_source,
            "shared_merge": cleanup,
            "terminal_target": carrier,
            "terminal_stop": terminal,
            "retired_residue": (dispatcher, cleanup),
        },
    }
    claim = terminal_cycle_claim_from_legacy_proof(
        payload,
        proposal=proposal,
        block_refs_by_serial=refs,
    )
    assert claim.cycle_subject.locator.member_refs == tuple(
        sorted(
            (refs[0], refs[1]),
            key=model._structural_key,
        )
    )
    assert claim.cleanup_source_subject.block_ref == refs[1]
    assert claim.terminal_subject.block_ref == refs[4]
    assert claim.terminal_subject.locator.instruction_ea == 0x1500
    assert claim.terminal_route_proof_ids == (route.proof_id,)

    nonterminal_route = replace(
        proposal,
        route_evidence=_recanonicalize(
            proposal.route_evidence,
            (replace(
                route,
                destinations=tuple(
                    replace(destination, terminal=False)
                    for destination in route.destinations
                ),
            ),),
        ),
    )
    with pytest.raises(ValueError, match="canonical route"):
        terminal_cycle_claim_from_legacy_proof(
            payload,
            proposal=nonterminal_route,
            block_refs_by_serial=refs,
        )

    wrong_source = {
        **payload,
        "terminal_switch_cycle_break": {
            **payload["terminal_switch_cycle_break"],
            "terminal_source": carrier,
        },
    }
    with pytest.raises(ValueError, match="canonical route"):
        terminal_cycle_claim_from_legacy_proof(
            wrong_source,
            proposal=proposal,
            block_refs_by_serial=refs,
        )
