"""Focused tests for canonical unflatten-authority identities."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import json
from types import MappingProxyType

import pytest

from d810.transforms.unflatten_authority.ids import (
    DigestFixture,
    GraphRecord,
    SUBJECT_SCHEMA,
    canonical_bytes,
    canonical_decode,
    content_id,
    semantic_graph_fingerprint,
    subject_id,
    _graph_projection,
    _claim_factory,
    _evidence_factory,
    _subject_factory,
    claim_id,
    evidence_id,
)
from d810.transforms.unflatten_authority import model
from .helpers import authority_id, block_ref, realize_projected_routes_for_test

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.semantics import PredicateKind
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind

UnflattenAuthorityPhase = model.UnflattenAuthorityPhase


def _13_1_phase_fixture():
    """Return the real registered projected phase used by ID-only nodes."""
    from .test_bind import _c_complete_kwargs
    from d810.transforms.unflatten_authority import bind

    result = bind.realize_projected_routes(**_c_complete_kwargs(
        __import__("tests.unit.transforms.unflatten_authority.test_bind", fromlist=["_compiler_redirect_goto_case"])._compiler_redirect_goto_case,
    ))
    assert type(result) is model.ProjectedRouteRealizationAccepted
    return result.realization.site_phase_result


def _13_1_clone(value, **changes):
    clone = object.__new__(type(value))
    for field in type(value).__dataclass_fields__:
        object.__setattr__(clone, field, getattr(value, field))
    for name, item in changes.items():
        object.__setattr__(clone, name, item)
    return clone


def test_13_1_09_phase_id_commits_each_envelope_and_nested_input() -> None:
    """Each phase-ID input has an independent preimage mutation."""
    from dataclasses import replace
    from d810.transforms.unflatten_authority.ids import projected_semantic_site_phase_result_id

    phase = _13_1_phase_fixture()
    original = projected_semantic_site_phase_result_id(phase)
    fields = {
        "authority_id": authority_id("13-1-authority"),
        "source_authority_id": authority_id("13-1-source-authority"),
        "attempt_id": replace(phase.attempt_id, attempt_id=authority_id("13-1-attempt")),
        "phase": UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        "plan_id": authority_id("13-1-plan"),
        "source_inventory_digest": authority_id("13-1-source-inventory"),
        "projected_inventory_digest": authority_id("13-1-projected-inventory"),
        "source_fingerprint": authority_id("13-1-source-fingerprint"),
        "projected_fingerprint": authority_id("13-1-projected-fingerprint"),
        "source_generation": phase.source_generation + 1,
        "projected_generation": phase.projected_generation + 1,
        "relation_ids": (authority_id("13-1-relation"),),
        "raw_effect_gate_fact": _13_1_clone(
            phase.raw_effect_gate_fact,
            generic_raw_payload_digest=authority_id("13-1-raw-payload"),
        ),
        "effect_results": (
            _13_1_clone(phase.effect_results[0], result_id=authority_id("13-1-effect")),
        ),
        "terminal_results": (
            _13_1_clone(phase.terminal_results[0], result_id=authority_id("13-1-terminal")),
        ),
        "derived_effect_gate_fact_id": authority_id("13-1-derived"),
    }
    mutated_ids = {
        name: projected_semantic_site_phase_result_id(_13_1_clone(phase, **{name: value}))
        for name, value in fields.items()
    }
    assert all(value != original for value in mutated_ids.values())
    assert len(mutated_ids) == len(set(mutated_ids.values()))


def test_13_1_09_exact_and_local_phase_id_inputs_are_pinned_until_binders_mint() -> None:
    """Exact and local rows are produced by their respective sealed binders."""
    from .test_bind import (
        _task_15_direct_vertical_case,
        _task_15_exact_direct_case,
        _task_15_vertical_inputs_from_claim_inventory,
        _task_15_vertical_inputs,
    )
    from d810.transforms.unflatten_authority import bind

    exact = bind.realize_projected_routes(**_task_15_vertical_inputs(
        lambda: _task_15_exact_direct_case("call"),
    )).realization.site_phase_result
    authority, _plan, _source, projected, _lineage, attempt, derived = (
        _task_15_direct_vertical_case(local_alias=True, derive_transaction=True)
    )
    assert derived is not None
    inventory = bind._bind_transaction_projected_claim_inventory(
        derived=derived,
        source_authority=authority,
        attempt_id=attempt,
        projected_inventory=projected,
    )
    local_values = _task_15_vertical_inputs_from_claim_inventory(inventory)
    local = bind._realize_projected_routes_from_claim_inventory(
        authority_id=local_values["authority_id"],
        claim_inventory=inventory,
        raw_effect_gate_fact=local_values["raw_effect_gate_fact"],
        legacy_effective_gate_facts=local_values["legacy_effective_gate_facts"],
    ).realization.site_phase_result
    assert exact.exact_effect_bindings
    assert local.local_alias_bindings


def test_13_1_10_exact_and_local_binding_ids_are_model_owned_contracts() -> None:
    """The exact/local ID APIs reject non-model records and are not caller minting APIs."""
    from d810.transforms.unflatten_authority.ids import (
        exact_effect_binding_result_id, local_alias_binding_result_id,
    )

    with pytest.raises(TypeError):
        exact_effect_binding_result_id(object())
    with pytest.raises(TypeError):
        local_alias_binding_result_id(object())
    assert model.ExactEffectBindingResult.__module__.endswith("model")
    assert model.LocalAliasScalarizationBindingResult.__module__.endswith("model")



def test_patch_step_fact_id_is_content_derived_before_authority_evidence_exists() -> None:
    from d810.transforms.unflatten_authority.ids import patch_step_fact_id
    from d810.transforms.unflatten_authority.model import PatchStepEvidencePayload
    from d810.transforms.unflatten_authority.ids import projected_authority_id

    payload = PatchStepEvidencePayload(
        authority_id("3b4a-plan"), 0, "redirect_goto", block_ref("3b4a-owner"),
        authority_id("3b4a-step"), 0x401000, 7, 8,
    )
    first = patch_step_fact_id(payload)
    assert first.startswith("sha256:")
    mutations = (
        {"plan_id": authority_id("3b4a-other-plan")},
        {"step_index": 1}, {"step_type": "redirect_branch"},
        {"owner_ref": block_ref("3b4a-other-owner")},
        {"step_digest": authority_id("3b4a-other-step")},
        {"host_ea": 0x401001}, {"host_opcode": 8}, {"value_size": 16},
        {"creation_spec_digest": authority_id("3b4a-creation")},
    )
    assert all(patch_step_fact_id(replace(payload, **mutation)) != first for mutation in mutations)


def test_authority_id_covers_attempt_and_raw_fact_but_no_phase_result_id() -> None:
    from dataclasses import replace
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.unflatten_authority import bind, transaction_api
    from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
    from .test_bind import _3b4a_inventory_pair

    plan, source_inventory, projected_inventory = _3b4a_inventory_pair(two_effects=True)
    serials = frozenset(row.owner_serial for row in source_inventory.effects)
    raw = bind.bind_raw_effect_gate_phase_fact(
        source_inventory=source_inventory,
        projected_inventory=projected_inventory,
        raw_gate_facts=GenericEffectfulGateFacts(True, serials, serials, frozenset(), "raw-ok"),
    )
    attempt = TransactionAttemptId(
        plan.plan_id, "3b4a-session", 1, authority_id("3b4a-attempt"),
    )
    from d810.transforms.unflatten_authority.ids import projected_authority_id
    first = projected_authority_id(
        attempt_id=attempt, proposal_id=plan.unflatten_proposal.plan_id,
        source_authority_id=authority_id("3b4a-source-authority"), plan_id=plan.plan_id,
        claims=plan.unflatten_proposal.claims, patch_step_facts=(),
        source_inventory=source_inventory, projected_inventory=projected_inventory,
        raw_effect_gate_fact=raw,
    )
    second = projected_authority_id(
        attempt_id=replace(attempt, attempt_id=authority_id("3b4a-other-attempt")),
        proposal_id=plan.unflatten_proposal.plan_id,
        source_authority_id=authority_id("3b4a-source-authority"), plan_id=plan.plan_id,
        claims=plan.unflatten_proposal.claims, patch_step_facts=(),
        source_inventory=source_inventory, projected_inventory=projected_inventory,
        raw_effect_gate_fact=raw,
    )
    assert first != second


def test_authority_id_rejects_unsealed_envelope_values_and_cross_correlations() -> None:
    from dataclasses import replace
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
    from .test_bind import _3b4a_inventory_pair

    plan, source_inventory, projected_inventory = _3b4a_inventory_pair(two_effects=True)
    serials = frozenset(row.owner_serial for row in source_inventory.effects)
    raw = bind.bind_raw_effect_gate_phase_fact(
        source_inventory=source_inventory, projected_inventory=projected_inventory,
        raw_gate_facts=GenericEffectfulGateFacts(True, serials, serials, frozenset(), "raw-ok"),
    )
    attempt = TransactionAttemptId(plan.plan_id, "3b4a-session", 1, authority_id("3b4a-attempt"))
    from d810.transforms.unflatten_authority.ids import projected_authority_id
    valid = dict(
        attempt_id=attempt, proposal_id=plan.unflatten_proposal.plan_id,
        source_authority_id=authority_id("3b4a-source-authority"), plan_id=plan.plan_id,
        claims=plan.unflatten_proposal.claims, patch_step_facts=(),
        source_inventory=source_inventory, projected_inventory=projected_inventory,
        raw_effect_gate_fact=raw,
    )
    invalid = (
        {"claims": ("arbitrary",)},
        {"patch_step_facts": ("arbitrary",)},
        {"attempt_id": replace(attempt, plan_id=authority_id("foreign-plan"))},
        {"attempt_id": replace(attempt, generation=7)},
        {"source_inventory": projected_inventory},
    )
    for mutation in invalid:
        with pytest.raises((TypeError, ValueError)):
            projected_authority_id(**{**valid, **mutation})


def test_authority_id_rejects_phase_correct_foreign_inventory_pair() -> None:
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
    from d810.transforms.unflatten_authority.ids import projected_authority_id
    from .test_bind import _3b4a_inventory_pair

    _plan, _source_inventory, _projected_inventory = _3b4a_inventory_pair()
    foreign_plan, foreign_source, foreign_projected = _3b4a_inventory_pair(two_effects=True)
    _empty_plan, _empty_source, foreign_projected_empty = _3b4a_inventory_pair(
        two_effects=True, foreign_projected_source_subjects=True,
    )
    serials = frozenset(row.owner_serial for row in foreign_source.effects)
    raw = bind.bind_raw_effect_gate_phase_fact(
        source_inventory=foreign_source,
        projected_inventory=foreign_projected,
        raw_gate_facts=GenericEffectfulGateFacts(
            True, serials, serials, frozenset(), "foreign-authority-lineage",
        ),
    )
    values = dict(
        attempt_id=TransactionAttemptId(foreign_plan.plan_id, "3b4a-session", 1, authority_id("foreign-pair-attempt")),
        proposal_id=foreign_plan.unflatten_proposal.plan_id,
        source_authority_id=authority_id("foreign-pair-source-authority"),
        plan_id=foreign_plan.plan_id,
        claims=foreign_plan.unflatten_proposal.claims,
        patch_step_facts=(),
        source_inventory=foreign_source,
        projected_inventory=foreign_projected_empty,
        raw_effect_gate_fact=raw,
    )
    with pytest.raises(ValueError, match="lineage|source subject"):
        projected_authority_id(**values)


def test_authority_id_rejects_canonically_minted_foreign_generation_claim() -> None:
    from dataclasses import fields
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
    from d810.transforms.unflatten_authority.ids import _claim_factory
    from d810.transforms.unflatten_authority.ids import projected_authority_id
    from .test_bind import _3b4a_inventory_pair

    plan, source_inventory, projected_inventory = _3b4a_inventory_pair(two_effects=True)
    serials = frozenset(row.owner_serial for row in source_inventory.effects)
    raw = bind.bind_raw_effect_gate_phase_fact(
        source_inventory=source_inventory, projected_inventory=projected_inventory,
        raw_gate_facts=GenericEffectfulGateFacts(True, serials, serials, frozenset(), "foreign-claim"),
    )
    original = next(
        claim for claim in plan.unflatten_proposal.claims
        if type(claim) is model.ExactInfeasibleEffectClaim
    )
    payload = {
        field.name: getattr(original, field.name)
        for field in fields(type(original))
        if field.name != "claim_id"
    }
    payload["source_generation"] = 2
    foreign_claim = _claim_factory(type(original), **payload)
    values = dict(
        attempt_id=TransactionAttemptId(plan.plan_id, "3b4a-session", 1, authority_id("foreign-claim-attempt")),
        proposal_id=plan.unflatten_proposal.plan_id,
        source_authority_id=authority_id("foreign-claim-source-authority"),
        plan_id=plan.plan_id,
        claims=(foreign_claim,),
        patch_step_facts=(),
        source_inventory=source_inventory,
        projected_inventory=projected_inventory,
        raw_effect_gate_fact=raw,
    )
    with pytest.raises(ValueError, match="generation"):
        projected_authority_id(**values)


def test_authority_id_rejects_foreign_patch_owner_session_plan_and_missing_owner() -> None:
    from d810.transforms.cfg_transaction import (
        LogicalBlockRef, NativeBlockRef, PlanBlockRef, TransactionAttemptId,
    )
    from d810.ir.block_identity import StableBlockIdentity
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
    from d810.transforms.unflatten_authority.ids import projected_authority_id
    from d810.transforms.unflatten_authority.model import PatchStepEvidencePayload
    from .test_bind import _3b4a_inventory_pair

    plan, source_inventory, projected_inventory = _3b4a_inventory_pair(two_effects=True)
    serials = frozenset(row.owner_serial for row in source_inventory.effects)
    raw = bind.bind_raw_effect_gate_phase_fact(
        source_inventory=source_inventory, projected_inventory=projected_inventory,
        raw_gate_facts=GenericEffectfulGateFacts(True, serials, serials, frozenset(), "foreign-owner"),
    )
    attempt = TransactionAttemptId(plan.plan_id, "3b4a-session", 1, authority_id("foreign-owner-attempt"))
    valid = dict(
        attempt_id=attempt,
        proposal_id=plan.unflatten_proposal.plan_id,
        source_authority_id=authority_id("foreign-owner-source-authority"),
        plan_id=plan.plan_id,
        claims=plan.unflatten_proposal.claims,
        source_inventory=source_inventory,
        projected_inventory=projected_inventory,
        raw_effect_gate_fact=raw,
    )
    facts = (
        PatchStepEvidencePayload(
            plan.plan_id, 0, "redirect_goto",
            LogicalBlockRef("foreign-session", "proxy", 1), authority_id("foreign-session-step"),
            0x401000, 7, 8,
        ),
        PatchStepEvidencePayload(
            plan.plan_id, 0, "redirect_goto",
            PlanBlockRef(authority_id("foreign-plan"), "block-0"), authority_id("foreign-plan-step"),
            0x401000, 7, 8,
        ),
        PatchStepEvidencePayload(
            plan.plan_id, 0, "redirect_goto",
            LogicalBlockRef("3b4a-session", "missing-proxy", 1), authority_id("missing-owner-step"),
            0x401000, 7, 8,
        ),
        PatchStepEvidencePayload(
            plan.plan_id, 0, "redirect_goto",
            NativeBlockRef(StableBlockIdentity.from_instruction_eas(
                (0xDEAD,), native_key=source_inventory.blocks[0].block_ref.identity.native_key,
            )), authority_id("missing-native-owner-step"), 0x401000, 7, 8,
        ),
        PatchStepEvidencePayload(
            plan.plan_id, 0, "redirect_goto",
            PlanBlockRef(plan.plan_id, "missing-plan-owner"), authority_id("missing-plan-owner-step"),
            0x401000, 7, 8,
        ),
    )
    for fact in facts:
        with pytest.raises((TypeError, ValueError), match="session|plan|inventory|owner"):
            projected_authority_id(**{**valid, "patch_step_facts": (fact,)})


def test_authority_id_uses_exact_scalar_preimage_and_canonical_patch_order() -> None:
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
    from d810.transforms.unflatten_authority.model import PatchStepEvidencePayload
    from d810.transforms.unflatten_authority.ids import projected_authority_id
    from .test_bind import _3b4a_inventory_pair

    plan, source_inventory, projected_inventory = _3b4a_inventory_pair(two_effects=True)
    serials = frozenset(row.owner_serial for row in source_inventory.effects)
    raw = bind.bind_raw_effect_gate_phase_fact(
        source_inventory=source_inventory, projected_inventory=projected_inventory,
        raw_gate_facts=GenericEffectfulGateFacts(True, serials, serials, frozenset(), "raw-ok"),
    )
    attempt = TransactionAttemptId(plan.plan_id, "3b4a-session", 1, authority_id("3b4a-attempt-preimage"))
    owner = source_inventory.blocks[0].block_ref
    facts = (
        PatchStepEvidencePayload(plan.plan_id, 0, "alpha", owner, authority_id("step-alpha"), 0x1000, 1, 4),
        PatchStepEvidencePayload(plan.plan_id, 1, "beta", owner, authority_id("step-beta"), 0x1001, 2, 4),
    )
    facts = tuple(sorted(facts, key=lambda fact: __import__(
        "d810.transforms.unflatten_authority.ids", fromlist=["patch_step_fact_id"]
    ).patch_step_fact_id(fact)))
    values = dict(
        attempt_id=attempt, proposal_id=plan.unflatten_proposal.plan_id,
        source_authority_id=authority_id("3b4a-source-preimage"), plan_id=plan.plan_id,
        claims=plan.unflatten_proposal.claims, patch_step_facts=facts,
        source_inventory=source_inventory, projected_inventory=projected_inventory,
        raw_effect_gate_fact=raw,
    )
    result = projected_authority_id(**values)
    patch_ids = tuple(
        __import__("d810.transforms.unflatten_authority.ids", fromlist=["patch_step_fact_id"]).patch_step_fact_id(fact)
        for fact in facts
    )
    expected = content_id(
        "unflatten.projected-authority.v2",
        (
            attempt, values["proposal_id"], values["source_authority_id"], plan.plan_id,
            values["claims"], tuple(zip(patch_ids, facts)),
            (source_inventory.inventory_digest, source_inventory.graph_fingerprint, source_inventory.generation),
            (projected_inventory.inventory_digest, projected_inventory.graph_fingerprint, projected_inventory.generation),
            raw.fact_id,
        ),
    )
    assert result == expected
    with pytest.raises(ValueError, match="canonical|sorted|unique"):
        projected_authority_id(**{**values, "patch_step_facts": tuple(reversed(facts))})


def test_authority_id_rejects_duplicate_and_noncanonical_claims_and_patch_facts() -> None:
    from dataclasses import fields
    from d810.transforms.cfg_transaction import TransactionAttemptId
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
    from d810.transforms.unflatten_authority.ids import (
        _claim_factory, patch_step_fact_id, projected_authority_id,
    )
    from d810.transforms.unflatten_authority.model import PatchStepEvidencePayload
    from .test_bind import _3b4a_inventory_pair

    plan, source_inventory, projected_inventory = _3b4a_inventory_pair(two_effects=True)
    serials = frozenset(row.owner_serial for row in source_inventory.effects)
    raw = bind.bind_raw_effect_gate_phase_fact(
        source_inventory=source_inventory, projected_inventory=projected_inventory,
        raw_gate_facts=GenericEffectfulGateFacts(True, serials, serials, frozenset(), "duplicate-matrix"),
    )
    attempt = TransactionAttemptId(plan.plan_id, "3b4a-session", 1, authority_id("duplicate-matrix-attempt"))
    owner = source_inventory.blocks[0].block_ref
    facts = (
        PatchStepEvidencePayload(plan.plan_id, 0, "alpha", owner, authority_id("duplicate-alpha"), 0x1000, 1, 4),
        PatchStepEvidencePayload(plan.plan_id, 1, "beta", owner, authority_id("duplicate-beta"), 0x1001, 2, 4),
    )
    original = next(
        claim for claim in plan.unflatten_proposal.claims
        if type(claim) is model.ExactInfeasibleEffectClaim
    )
    payload = {
        field.name: getattr(original, field.name)
        for field in fields(type(original))
        if field.name != "claim_id"
    }
    payload["normalized_state"] = original.normalized_state + 1
    second_claim = _claim_factory(type(original), **payload)
    canonical_claims = tuple(sorted((original, second_claim), key=lambda claim: claim.claim_id))
    claims = tuple(reversed(canonical_claims))
    values = dict(
        attempt_id=attempt,
        proposal_id=plan.unflatten_proposal.plan_id,
        source_authority_id=authority_id("duplicate-matrix-source-authority"),
        plan_id=plan.plan_id,
        claims=plan.unflatten_proposal.claims,
        patch_step_facts=(),
        source_inventory=source_inventory,
        projected_inventory=projected_inventory,
        raw_effect_gate_fact=raw,
    )
    with pytest.raises(ValueError, match="duplicate|canonical|unique|sorted"):
        projected_authority_id(**{**values, "claims": (original, original)})
    with pytest.raises(ValueError, match="canonical|sorted|unique"):
        projected_authority_id(**{**values, "claims": claims})
    ordered_facts = tuple(sorted(facts, key=patch_step_fact_id))
    with pytest.raises(ValueError, match="duplicate|unique"):
        projected_authority_id(**{**values, "patch_step_facts": (ordered_facts[0], ordered_facts[0])})
    with pytest.raises(ValueError, match="canonical"):
        projected_authority_id(**{**values, "patch_step_facts": tuple(reversed(ordered_facts))})


def test_task15c_operation_and_observed_ids_are_not_registered() -> None:
    from d810.transforms.unflatten_authority import ids

    assert not hasattr(ids, "planned_operation_id")
    assert not hasattr(ids, "patch_realization_operation_id")
    assert not hasattr(ids, "patch_realization_observation_id")
    assert not hasattr(ids, "observed_route_realization_id")


_PINNED_DIGEST = "sha256:07fd10c22a620eaab0a3639ae738586023c380b1027b2b84684be9fd4a5a9165"


def test_canonical_digest_fixture_is_pinned() -> None:
    fixture = DigestFixture(4198400, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native", None))
    assert canonical_bytes(fixture) == (
        b'{"n":"DigestFixture","t":"record","v":[["ea",{"t":"int","v":"4198400"}],'
        b'["phase",{"n":"UnflattenAuthorityPhase","t":"enum","v":{"t":"str","v":"projected_preflight"}}],'
        b'["refs",{"t":"tuple","v":[{"t":"str","v":"native"},{"t":"none"}]}]]}'
    )
    assert content_id("digest-fixture.v1", fixture) == _PINNED_DIGEST


def test_canonical_encoding_preserves_sequence_and_inverse_types() -> None:
    values = ([1, 2], (1, 2), frozenset({1, 2}))
    encoded = tuple(canonical_bytes(value) for value in values)
    assert len(set(encoded)) == 3
    assert canonical_decode(encoded[0]) == [1, 2]
    assert canonical_decode(encoded[1]) == (1, 2)
    assert canonical_decode(encoded[2]) == frozenset({1, 2})


def test_canonical_encoding_rejects_omitted_unknown_and_float_values() -> None:
    with pytest.raises((TypeError, ValueError)):
        canonical_bytes(object())
    with pytest.raises((TypeError, ValueError)):
        canonical_bytes(1.5)
    assert content_id("optional.v1", {"value": None}) != content_id("optional.v1", {})


def test_canonical_encoding_rejects_recursive_root_and_record_cycles() -> None:
    recursive_mapping = {}
    recursive_mapping["self"] = recursive_mapping
    recursive_list = []
    recursive_list.append(recursive_list)
    recursive_record_mapping = {}
    recursive_record_mapping["self"] = recursive_record_mapping
    forged_external = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    object.__setattr__(forged_external, "input_identity", forged_external)
    values = (
        recursive_mapping,
        recursive_list,
        DigestFixture(3, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, (recursive_record_mapping,)),
        forged_external,
    )
    for value in values:
        with pytest.raises(ValueError):
            canonical_bytes(value)
        with pytest.raises(ValueError):
            content_id("cycle.v1", value)


def test_canonical_mapping_order_and_object_identity_do_not_change_digest() -> None:
    @dataclass(frozen=True)
    class Unknown:
        value: int

    assert content_id("mapping.v1", {"a": 1, "b": 2}) == content_id("mapping.v1", {"b": 2, "a": 1})
    assert content_id("fixture.v1", DigestFixture(3, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",))) == content_id("fixture.v1", DigestFixture(3, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",)))
    with pytest.raises((TypeError, ValueError)):
        canonical_bytes(Unknown(3))

    with pytest.raises((TypeError, ValueError)):
        canonical_bytes({"unknown": Unknown(3)})


def test_canonical_mapping_reader_accepts_only_exact_dict_or_exact_dict_proxy() -> None:
    """Canonical encoding never invokes a producer-owned mapping protocol."""
    exact = {"nested": {"value": 1}, "phase": "observed"}
    proxy = MappingProxyType(exact)
    assert canonical_bytes(exact) == canonical_bytes(proxy)
    assert canonical_decode(canonical_bytes(proxy)) == exact

    callbacks: list[str] = []

    class CallbackDict(dict):
        def items(self):
            callbacks.append("items")
            return super().items()

        def __iter__(self):
            callbacks.append("iter")
            return super().__iter__()

    class CallbackMapping(Mapping):
        def __getitem__(self, key):
            callbacks.append(f"get:{key}")
            return 1

        def __iter__(self):
            callbacks.append("iter")
            return iter(("foreign",))

        def __len__(self):
            callbacks.append("len")
            return 1

    for value in (
        CallbackDict({"bad": 1}),
        CallbackMapping(),
        MappingProxyType(CallbackMapping()),
    ):
        with pytest.raises(TypeError):
            canonical_bytes(value)
        assert callbacks == []


def test_subject_id_uses_only_exact_kind_role_locator_preimage() -> None:
    locator = model.BlockSubjectLocator(block_ref("subject"), 0x1000)
    expected = content_id(SUBJECT_SCHEMA, (
        model.SemanticSubjectKind.BLOCK,
        model.SemanticSubjectRole.SOURCE_ENTRY,
        locator,
    ))
    assert subject_id(model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_ENTRY, locator) == expected
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=locator.block_ref,
        anchor_ea=locator.anchor_ea,
        locator=locator,
    )
    with pytest.raises(ValueError):
        model.SemanticSubjectRef(
            subject.kind, subject.role, "sha256:" + "0" * 64,
            subject.block_ref, subject.anchor_ea, subject.locator,
        )
    assert subject.subject_id == expected


def test_inverse_decodes_exact_registered_types_and_rejects_noncanonical_wire() -> None:
    fixture = DigestFixture(3, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("x", None))
    encoded = canonical_bytes(fixture)
    assert canonical_decode(encoded) == fixture
    assert type(canonical_decode(encoded)) is DigestFixture
    assert canonical_decode(canonical_bytes(UnflattenAuthorityPhase.PROJECTED_PREFLIGHT)) is UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    with pytest.raises(ValueError):
        canonical_decode(encoded.replace(b'"n":"DigestFixture"', b'"n":"Unknown"'))
    with pytest.raises(ValueError):
        canonical_decode(encoded.replace(b'"n":"UnflattenAuthorityPhase"', b'"n":"UnknownEnum"'))
    with pytest.raises(ValueError):
        canonical_decode(encoded.replace(b'projected_preflight', b'unknown_value'))
    with pytest.raises(ValueError):
        canonical_decode(encoded.replace(b'"v":[["ea"', b'"v":[["extra",{"t":"none"}],["ea"'))
    parsed = json.loads(encoded)
    parsed["v"] = parsed["v"][:-1]
    with pytest.raises(ValueError):
        canonical_decode(json.dumps(parsed, separators=(",", ":")).encode())
    parsed = json.loads(encoded)
    parsed["v"].append(parsed["v"][0])
    with pytest.raises(ValueError):
        canonical_decode(json.dumps(parsed, separators=(",", ":")).encode())
    with pytest.raises(ValueError):
        canonical_decode(b'{"t":"record","n":"DigestFixture","v":{}}')
    with pytest.raises(ValueError):
        canonical_decode(b'{"t":"none","v":null}')
    with pytest.raises(ValueError):
        canonical_decode(b'{"t":"map","v":[[{"t":"str","v":"a"},{"t":"int","v":"1"}],[{"t":"str","v":"a"},{"t":"int","v":"2"}]]}')
    with pytest.raises(ValueError):
        canonical_decode(b' {"t":"none"} ')
    with pytest.raises(ValueError):
        canonical_decode(encoded.replace(b'"n":"DigestFixture","t":"record"', b'"t":"record","n":"DigestFixture"'))


def test_inverse_round_trips_representative_model_and_external_records() -> None:
    locator = model.BlockSubjectLocator(block_ref("roundtrip"), 0x1000)
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=locator.block_ref,
        anchor_ea=locator.anchor_ea,
        locator=locator,
    )
    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    storage = StorageIdentity(StorageIdentityKind.REGISTER, 1)
    for value in (subject, key, storage):
        decoded = canonical_decode(canonical_bytes(value))
        assert type(decoded) is type(value)
        assert decoded == value


def test_closed_portable_instruction_encoding_is_stable_distinct_and_exact() -> None:
    from d810.ir.instructions import (
        Instruction, InstructionControl, InstructionEffect,
        InstructionEffectKind,
    )
    from d810.ir.semantics import ControlTransferKind
    from d810.ir.varnode import Space, Varnode
    from d810.ir.expressions import Const

    source = Varnode(Space.CONST, 7, 4)
    result = Varnode(Space.REGISTER, 16, 4)
    instruction = Instruction(
        ValueOpKind.MOVE,
        inputs=(source,),
        result=result,
        effects=(InstructionEffect(InstructionEffectKind.STORE, target=result),),
        control=InstructionControl(transfer=ControlTransferKind.GOTO, target=9),
        attrs=MappingProxyType({"raw_opcode": 0}),
        input_exprs=(Const(7),),
    )
    encoded = canonical_bytes(instruction)
    assert encoded == canonical_bytes(instruction)
    assert encoded != canonical_bytes(replace(instruction, result=Varnode(Space.REGISTER, 17, 4)))
    decoded = canonical_decode(encoded)
    assert type(decoded) is type(instruction)
    assert decoded == instruction
    assert type(decoded.attrs) is MappingProxyType

    class VarnodeChild(Varnode):
        pass

    with pytest.raises(TypeError):
        canonical_bytes(VarnodeChild(Space.REGISTER, 16, 4))


@pytest.mark.parametrize(
    "proof_kind",
    ("STATE_TRANSFORM", "STATE_CARRIER"),
)
def test_state_proof_evidence_proposal_and_source_authority_round_trip(proof_kind: str) -> None:
    from d810.analyses.control_flow import semantic_route_evidence as route
    from tests.unit.transforms.unflatten_authority.test_bind import (
        _compiler_corridor_unsupported_case,
    )

    authority, _plan, _source, _projected, _facts, _attempt = (
        _compiler_corridor_unsupported_case(
            proof_kind=getattr(route.SemanticRouteProofKind, proof_kind),
        )
    )
    evidence = authority.proposal.route_evidence
    proof = evidence.route_proofs[0]
    nested = (
        proof.state_transform if proof_kind == "STATE_TRANSFORM" else proof.state_carrier
    )
    assert nested is not None
    for value in (nested, evidence, authority.proposal, authority):
        decoded = canonical_decode(canonical_bytes(value))
        assert type(decoded) is type(value)
        assert canonical_bytes(decoded) == canonical_bytes(value)


def test_claim_and_evidence_factories_recompute_ids_and_reject_forgery() -> None:
    locator = model.BlockSubjectLocator(block_ref("authority"), 0x1000)
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=locator.block_ref,
        anchor_ea=locator.anchor_ea,
        locator=locator,
    )
    claim = _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=subject,
        step_index=0,
        host_ea=0x1000,
        host_opcode=1,
        alias_token="alias",
        base_token="base",
        host_text_sha1=None,
        value_size=None,
        step_digest="sha256:" + "1" * 64,
        source_generation=0,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence,
        kind=model.AuthorityEvidenceKind.REACHABILITY,
        subject=subject,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        payload=model.ReachabilityEvidencePayload(subject.subject_id, subject.subject_id, True, (subject.subject_id,)),
    )
    assert claim.claim_id == claim_id(claim)
    assert evidence.evidence_id == evidence_id(evidence)
    with pytest.raises(ValueError):
        replace(claim, claim_id="sha256:" + "0" * 64)
    with pytest.raises(ValueError):
        replace(evidence, evidence_id="sha256:" + "0" * 64)


def test_graph_projection_has_pinned_record_shapes_and_rejects_malformed_graphs() -> None:
    graph = _graph()
    projected = _graph_projection(graph)
    assert type(projected) is GraphRecord
    assert tuple(field.name for field in projected.__dataclass_fields__.values()) == (
        "func_ea", "entry_serial", "blocks",
    )
    assert tuple(field.name for field in projected.blocks[0].__dataclass_fields__.values()) == (
        "serial", "block_type", "raw_block_type", "kind", "flags", "start_ea",
        "native_start_ea", "succs", "preds", "tail_opcode", "raw_tail_opcode",
        "tail_kind", "instructions",
    )
    instruction_fields = tuple(field.name for field in projected.blocks[0].instructions[0].__dataclass_fields__.values())
    assert instruction_fields == (
        "opcode", "raw_opcode", "kind", "ea", "native_ea", "value_op_kind",
        "control_transfer_kind", "call_kind", "predicate_kind", "branch_predicate",
        "compare_width", "is_conditional_jump", "is_unconditional_jump", "is_call",
        "l", "r", "d", "opcode_attrs", "display_text_sha256",
    )
    assert tuple(field.name for field in projected.blocks[0].instructions[0].l.__dataclass_fields__.values()) == (
        "t", "raw_operand_type", "kind", "size", "value", "stkoff", "reg",
        "block_ref", "gaddr", "lvar_off", "lvar_stkoff", "switch_cases",
        "stack_refs", "sub_kind", "sub_value_op_kind", "sub_raw_opcode",
        "sub_predicate_kind", "sub_l", "sub_r", "args",
    )
    assert type(canonical_decode(canonical_bytes(projected))) is GraphRecord
    with pytest.raises(ValueError):
        semantic_graph_fingerprint(replace(graph, blocks={7: graph.blocks[0], 1: graph.blocks[1]}))
    with pytest.raises(ValueError):
        semantic_graph_fingerprint(replace(graph, blocks={
            0: replace(graph.blocks[0], succs=()), 1: graph.blocks[1],
        }))
    legacy = replace(graph.blocks[0].insn_snapshots[0], l=None, operands=("legacy",))
    legacy_graph = replace(graph, blocks={
        **graph.blocks, 0: replace(graph.blocks[0], insn_snapshots=(legacy,)),
    })
    with pytest.raises(ValueError):
        semantic_graph_fingerprint(legacy_graph)


def test_typed_operand_correspondence_manifest_is_closed() -> None:
    graph = _graph()
    insn = graph.blocks[0].insn_snapshots[0]
    left_operand = insn.l
    r = MopSnapshot(t=1, size=4, reg=1, kind=OperandKind.REGISTER)
    d = MopSnapshot(t=1, size=4, reg=2, kind=OperandKind.REGISTER)

    def with_insn(changed):
        return replace(graph, blocks={
            **graph.blocks, 0: replace(graph.blocks[0], insn_snapshots=(changed,)),
        })

    malformed = (
        replace(insn, operands=(left_operand, r), operand_slots=(("l", left_operand), ("r", r))),
        replace(insn, operand_slots=()),
        replace(insn, operands=(left_operand, left_operand), operand_slots=(("l", left_operand), ("l", left_operand))),
        replace(insn, operands=(left_operand, r), operand_slots=(("r", r), ("l", left_operand)), r=r),
        replace(insn, operands=(left_operand, r), operand_slots=(("l", left_operand),), r=r),
    )
    for changed in malformed:
        with pytest.raises((TypeError, ValueError)):
            semantic_graph_fingerprint(with_insn(changed))

    typed_only = replace(insn, operands=(), operand_slots=())
    assert semantic_graph_fingerprint(with_insn(typed_only))
    operandless = replace(insn, l=None, r=None, d=None, operands=(), operand_slots=())
    assert semantic_graph_fingerprint(with_insn(operandless))

    complete = replace(
        insn,
        r=r,
        d=d,
        operands=(left_operand, r, d),
        operand_slots=(("l", left_operand), ("r", r), ("d", d)),
    )
    complete_graph = with_insn(complete)
    baseline = semantic_graph_fingerprint(complete_graph)
    changed_transitional = replace(
        complete,
        operands=(object(), object(), object()),
        operand_slots=(("l", object()), ("r", object()), ("d", object())),
    )
    assert semantic_graph_fingerprint(with_insn(changed_transitional)) == baseline


def test_pinned_internal_records_reject_wrong_runtime_field_types() -> None:
    fixture = DigestFixture(3, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("x", None))
    projected = _graph_projection(_graph())
    block = projected.blocks[0]
    insn = block.instructions[0]
    mop = insn.l
    invalid = (
        replace(fixture, ea=True),
        replace(fixture, phase="projected_preflight"),
        replace(fixture, refs=["x"]),
        replace(mop, t=True),
        replace(mop, kind=InsnKind.MOV),
        replace(mop, switch_cases=[]),
        replace(mop, stack_refs=("bad",)),
        replace(mop, args=[mop]),
        replace(insn, opcode=True),
        replace(insn, kind=OperandKind.REGISTER),
        replace(insn, value_op_kind=InsnKind.MOV),
        replace(insn, is_call=1),
        replace(insn, l=1),
        replace(insn, opcode_attrs={1: "bad"}),
        replace(insn, display_text_sha256="A" * 64),
        replace(block, serial=True),
        replace(block, succs=[1]),
        replace(block, instructions=[insn]),
        replace(block, tail_kind=OperandKind.REGISTER),
        replace(projected, func_ea=True),
        replace(projected, entry_serial="0"),
        replace(projected, blocks=[block]),
        replace(projected, blocks=(projected.blocks[1], projected.blocks[0])),
        replace(projected, blocks=(replace(block, succs=(1, 1)), projected.blocks[1])),
    )
    for value in invalid:
        with pytest.raises((TypeError, ValueError)):
            canonical_bytes(value)

    encoded = canonical_bytes(projected)
    malformed = encoded.replace(
        b'["func_ea",{"t":"int","v":"4096"}]',
        b'["func_ea",{"t":"str","v":"4096"}]',
    )
    with pytest.raises((TypeError, ValueError)):
        canonical_decode(malformed)


def _graph() -> FlowGraph:
    instruction = InsnSnapshot(
        opcode=1,
        raw_opcode=1,
        ea=0x1000,
        operands=(MopSnapshot(t=1, size=4, reg=0, kind=OperandKind.REGISTER),),
        operand_slots=(("l", MopSnapshot(t=1, size=4, reg=0, kind=OperandKind.REGISTER)),),
        l=MopSnapshot(t=1, size=4, reg=0, kind=OperandKind.REGISTER),
        display_text="mov r0, r1",
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
        predicate_kind=None,
        compare_width=4,
        native_ea=0x1000,
    )
    return FlowGraph(
        {
            0: BlockSnapshot(0, 1, (1,), (), 0, 0x1000, (instruction,)),
            1: BlockSnapshot(1, 1, (), (0,), 0, 0x1010, ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], opcode=2),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], raw_opcode=2),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], kind=InsnKind.STORE),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], value_op_kind=ValueOpKind.STORE),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], predicate_kind=PredicateKind.EQ),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], branch_predicate=PredicateKind.EQ),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], compare_width=8),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], l=MopSnapshot(t=1, size=4, reg=1, kind=OperandKind.REGISTER)),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], l=MopSnapshot(t=2, size=4, value=7, kind=OperandKind.NUMBER)),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], native_ea=0x1004),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], display_text="mov r0, r2"),
    ],
)
def test_semantic_graph_fingerprint_changes_for_instruction_semantics(change) -> None:
    baseline = _graph()
    changed_insn = change(baseline)
    changed = replace(
        baseline,
        blocks={**baseline.blocks, 0: replace(baseline.blocks[0], insn_snapshots=(changed_insn,))},
    )
    assert semantic_graph_fingerprint(baseline) != semantic_graph_fingerprint(changed)


def test_semantic_graph_fingerprint_changes_for_topology_and_entry() -> None:
    baseline = semantic_graph_fingerprint(_graph())
    graph = _graph()
    topology = replace(
        graph,
        blocks={
            **graph.blocks,
            0: replace(graph.blocks[0], succs=()),
            1: replace(graph.blocks[1], preds=()),
        },
    )
    alternate_entry = replace(_graph(), entry_serial=1)
    assert baseline != semantic_graph_fingerprint(topology)
    assert baseline != semantic_graph_fingerprint(alternate_entry)
def test_3b3_binder_route_records_have_stable_encode_only_codec_and_reject_forgery() -> None:
    from d810.transforms.unflatten_authority import ids
    from d810.transforms.unflatten_authority import bind
    from tests.unit.transforms.unflatten_authority import test_bind as bind_tests

    values = []
    for fixture in (
        "_compiler_direct_branch_case", "_compiler_helper_branch_case",
        "_three_b3_one_block_corridor_case",
    ):
        authority, plan, source, projected, facts, attempt, *_ = getattr(bind_tests, fixture)()
        result = realize_projected_routes_for_test(
            source_authority=authority, plan=plan, source_inventory=source,
            projected_inventory=projected, patch_step_facts=facts, attempt_id=attempt,
        )
        assert type(result).__name__ == "ProjectedRouteRealizationAccepted"
        relation = result.realization.rows[0].relation
        values.append(relation)
        if type(relation) is model.ClonedRouteCorridorRealization:
            values.extend((relation.semantic_prefixes[0], relation.semantic_prefixes[0].instruction_origins[0]))
    assert {type(value) for value in values} == {
        model.TwoArmDirectBranchRouteRealization,
        model.BranchFallthroughHelperRouteRealization,
        model.ClonedRouteCorridorRealization,
        model.ClonedSemanticPrefix,
        model.ClonedSemanticInstructionOrigin,
    }
    for value in values:
        encoded = ids.canonical_bytes(value)
        assert encoded == ids.canonical_bytes(value)
        with pytest.raises(ValueError):
            ids.canonical_decode(encoded)
        wire = json.loads(encoded)
        assert wire["t"] == "record" and wire["n"] == type(value).__name__
        assert tuple(name for name, _ in wire["v"]) == tuple(value.__dataclass_fields__)
        reversed_wire = dict(wire, v=list(reversed(wire["v"])))
        unknown_wire = dict(wire, n="UnknownAuthorityRecord")
        with pytest.raises((ValueError, UnicodeDecodeError)):
            ids.canonical_decode(json.dumps(reversed_wire, separators=(",", ":")).encode())
        with pytest.raises((ValueError, UnicodeDecodeError)):
            ids.canonical_decode(json.dumps(unknown_wire, separators=(",", ":")).encode())
        forged = object.__new__(type(value))
        for name in value.__dataclass_fields__:
            object.__setattr__(forged, name, getattr(value, name))
        identity_name = next(
            name for name in ("relation_id", "prefix_id", "origin_id")
            if name in value.__dataclass_fields__
        )
        object.__setattr__(forged, identity_name, authority_id("forged-route-id"))
        with pytest.raises(ValueError):
            forged.__post_init__()
        with pytest.raises((TypeError, ValueError)):
            ids.canonical_bytes(forged)
        subclass = type("ForgedRouteRecord", (type(value),), {})
        forged_subclass = object.__new__(subclass)
        for name in value.__dataclass_fields__:
            object.__setattr__(forged_subclass, name, getattr(value, name))
        with pytest.raises((TypeError, ValueError)):
            ids.canonical_bytes(forged_subclass)


def test_3b3_corridor_relation_id_commits_ordered_prefix_objects() -> None:
    from d810.transforms.unflatten_authority.ids import (
        cloned_semantic_instruction_origin_id,
        cloned_semantic_prefix_id,
        route_realization_id,
    )
    from tests.unit.transforms.unflatten_authority.test_bind import _compiler_split_case
    from d810.transforms.unflatten_authority import bind
    authority, plan, source, projected, facts, attempt, _ = _compiler_split_case(
        corridor_length=2, corridor=True, extra_prefix_origin=True,
    )
    result = realize_projected_routes_for_test(
        source_authority=authority, plan=plan, source_inventory=source,
        projected_inventory=projected, patch_step_facts=facts, attempt_id=attempt,
    )
    relation = result.realization.rows[0].relation
    assert type(relation) is model.ClonedRouteCorridorRealization
    prefix_objects = tuple(relation.semantic_prefixes)
    def relation_preimage(prefixes, creation_rows):
        return (
            "cloned_route_corridor", relation.predecessor, relation.proof_source,
            relation.descriptor_old_target, relation.terminal_continuation,
            relation.source_corridor, relation.cloned_corridor,
            relation.semantic_target, tuple(prefixes), tuple(creation_rows),
        )

    # This is the production preimage, including ordered nested prefix objects.
    expected_preimage = relation_preimage(prefix_objects, relation.creation_spec_digests)
    assert relation.relation_id == route_realization_id(expected_preimage)
    assert route_realization_id(expected_preimage) != route_realization_id(
        relation_preimage(prefix_objects[::-1], relation.creation_spec_digests)
    )
    assert route_realization_id(expected_preimage) != route_realization_id(
        relation_preimage(prefix_objects, relation.creation_spec_digests[::-1])
    )

    origin = prefix_objects[0].instruction_origins[0]
    changed_digest = authority_id("reordered-origin-observation")
    forged_origin = object.__new__(type(origin))
    for name in origin.__dataclass_fields__:
        object.__setattr__(forged_origin, name, getattr(origin, name))
    object.__setattr__(forged_origin, "observation_digest", changed_digest)
    object.__setattr__(forged_origin, "origin_id", cloned_semantic_instruction_origin_id((
            "cloned_semantic_instruction_origin", origin.source_owner,
            origin.clone_owner, origin.source_ordinal, origin.projected_ordinal,
            origin.instruction_ea, changed_digest,
        )))
    forged_prefix = object.__new__(type(prefix_objects[0]))
    for name in prefix_objects[0].__dataclass_fields__:
        object.__setattr__(forged_prefix, name, getattr(prefix_objects[0], name))
    object.__setattr__(forged_prefix, "instruction_origins", (
        forged_origin, *prefix_objects[0].instruction_origins[1:],
    ))
    object.__setattr__(forged_prefix, "prefix_id", cloned_semantic_prefix_id((
            "cloned_semantic_prefix", forged_prefix.ordinal,
            forged_prefix.source_owner, forged_prefix.clone_owner,
            forged_prefix.source_start_ordinal,
            forged_prefix.source_end_ordinal_exclusive,
            forged_prefix.instruction_origins,
            forged_prefix.source_trailing_goto_ordinal,
            forged_prefix.projected_synthetic_goto_ordinal,
            forged_prefix.projected_successor, forged_prefix.creation_spec_row,
        )))
    assert route_realization_id(expected_preimage) != route_realization_id(
        relation_preimage((forged_prefix, *prefix_objects[1:]), relation.creation_spec_digests)
    )
    assert relation.relation_id == route_realization_id((
        "cloned_route_corridor", relation.predecessor, relation.proof_source,
        relation.descriptor_old_target, relation.terminal_continuation,
        relation.source_corridor, relation.cloned_corridor, relation.semantic_target,
        relation.semantic_prefixes, relation.creation_spec_digests,
    ))

    def relation_with(**changes):
        values = {
            name: getattr(relation, name)
            for name in relation.__dataclass_fields__
        }
        values.update(changes)
        values["relation_id"] = route_realization_id(relation_preimage(
            values["semantic_prefixes"], values["creation_spec_digests"],
        ))
        candidate = object.__new__(type(relation))
        for name, value in values.items():
            object.__setattr__(candidate, name, value)
        return candidate

    # The compiler/SOURCE fixture itself provides the ordered two-origin
    # prefix.  Do not manufacture a second origin after production.
    expanded_prefix = prefix_objects[0]
    all_origins = tuple(
        origin
        for prefix in prefix_objects
        for origin in prefix.instruction_origins
    )
    assert len(expanded_prefix.instruction_origins) >= 2
    assert len(all_origins) >= 2

    reversed_origins = object.__new__(type(expanded_prefix))
    for name in expanded_prefix.__dataclass_fields__:
        object.__setattr__(reversed_origins, name, getattr(expanded_prefix, name))
    object.__setattr__(reversed_origins, "instruction_origins", tuple(reversed(expanded_prefix.instruction_origins)))
    object.__setattr__(reversed_origins, "prefix_id", cloned_semantic_prefix_id((
        "cloned_semantic_prefix", expanded_prefix.ordinal,
        expanded_prefix.source_owner, expanded_prefix.clone_owner,
        expanded_prefix.source_start_ordinal,
        expanded_prefix.source_end_ordinal_exclusive,
        tuple(reversed(expanded_prefix.instruction_origins)),
        expanded_prefix.source_trailing_goto_ordinal,
        expanded_prefix.projected_synthetic_goto_ordinal,
        expanded_prefix.projected_successor, expanded_prefix.creation_spec_row,
    )))
    with pytest.raises(ValueError, match="prefix origins"):
        reversed_origins.__post_init__()

    reordered_prefixes = relation_with(semantic_prefixes=prefix_objects[::-1])
    with pytest.raises(ValueError, match="corridor prefixes|creation_spec_digests"):
        reordered_prefixes.__post_init__()
    reordered_creation = relation_with(
        creation_spec_digests=relation.creation_spec_digests[::-1],
    )
    with pytest.raises(ValueError, match="creation spec rows|creation_spec_digests"):
        reordered_creation.__post_init__()

    # A nested observation substitution with a recomputed origin and prefix
    # identity is structurally valid, but it is not a binder-minted relation;
    # the public aggregate validator rejects it.
    changed_relation = relation_with(semantic_prefixes=(forged_prefix, *prefix_objects[1:]))
    changed_relation.__post_init__()
    assert changed_relation.relation_id != relation.relation_id
    original_prefixes = relation.semantic_prefixes
    try:
        object.__setattr__(relation, "semantic_prefixes", (forged_prefix, *prefix_objects[1:]))
        with pytest.raises(ValueError):
            bind.validate_projected_route_realization(result.realization)
    finally:
        object.__setattr__(relation, "semantic_prefixes", original_prefixes)
