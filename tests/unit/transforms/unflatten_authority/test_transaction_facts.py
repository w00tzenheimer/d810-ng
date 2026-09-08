"""Behavioral ownership and work bounds for the competing transaction path."""

from types import MappingProxyType

import pytest

from d810.transforms.unflatten_authority import ids
from d810.transforms.unflatten_authority.transaction_facts import TransactionFacts, fact_scope


def test_capture_detaches_transient_mapping_alias_and_reuses_fact_references():
    attributes = {"tag": ("original", 42)}
    external = (MappingProxyType(attributes),)
    owner = TransactionFacts()
    with fact_scope(owner):
        fact = owner.capture(external)
        before = ids.canonical_bytes(fact)
        attributes["tag"] = ("changed", 99)
        assert fact[0]["tag"] == ("original", 42)
        assert ids.canonical_bytes(fact) == before
        attributes["tag"] = ("original", 42)
        assert owner.capture(external) is fact
    assert dict(attributes) == {"tag": ("original", 42)}


def test_shared_children_are_captured_once_and_owned_encoding_has_no_guard(monkeypatch):
    owner = TransactionFacts()
    shared = tuple(range(32))
    with fact_scope(owner):
        root = owner.capture(tuple(shared for _ in range(100)))
        assert owner.metrics["captures"] == 2
        assert all(child is root[0] for child in root)

        def forbidden(*args, **kwargs):
            raise AssertionError("owned identity must not recursively guard")

        monkeypatch.setattr(ids, "_occurrence_guard", forbidden)
        first = ids.canonical_bytes(root)
        assert ids.canonical_bytes(root) == first
        assert owner.metrics["encoding_hits"] == 1


def test_snapshot_capture_scales_with_edges_and_never_recaptures_shared_descendants():
    def measure(size):
        owner = TransactionFacts()
        child = tuple(range(64))
        with fact_scope(owner):
            root = owner.capture(tuple((index, child) for index in range(size)))
            before = owner.metrics["capture_visits"]
            for item in root:
                assert owner.capture(item) is item
            assert owner.metrics["capture_visits"] - before == size
        return owner.metrics

    small, large = measure(100), measure(1000)
    assert large["captures"] - small["captures"] == 900
    assert large["capture_visits"] - small["capture_visits"] == 3600
    assert large["allocations"] - small["allocations"] == 900


def test_closed_and_foreign_owners_do_not_issue_validity():
    projected = TransactionFacts()
    foreign = TransactionFacts()
    registry = {}
    fact = projected.issue(registry, ("fact", 1))
    observed = TransactionFacts(parent=projected)
    assert observed.contains(fact)
    assert not foreign.registered(registry, fact)
    observed_fact = observed.issue(registry, ("observed", 2))
    assert not projected.contains(observed_fact)
    projected.close()
    with pytest.raises(ValueError, match="closed"):
        observed.contains(fact)


def test_unknown_schema_and_mutable_collection_are_rejected_without_issuance():
    owner = TransactionFacts()
    for value in ([1], {"a": 1}, object()):
        with pytest.raises(TypeError):
            owner.capture(value)
        assert not owner.contains(value)


def _run_transaction(local_alias, *, owned=True, on_preparation=None):
    from .test_transaction_api import _c1_direct_preparation_case
    from d810.transforms.cfg_transaction import CfgProjection, TransactionAttemptId
    from d810.transforms.unflatten_authority import model, transaction_api
    from d810.transforms.unflatten_authority.structural_transaction import (
        StructuralTransactionContext, StructuralTransactionCoordinates,
    )

    _fixture, source, plan, projected, gates = _c1_direct_preparation_case(local_alias=local_alias)
    attempt = TransactionAttemptId.new(plan.plan_id, "fact-experiment", 1)
    context = StructuralTransactionContext(
        attempt, plan.unflatten_proposal.source_identity_catalog.native_key,
        StructuralTransactionCoordinates(plan.snapshot_id, 4, 1, None, 1),
    )
    if on_preparation is not None:
        on_preparation()
    result = transaction_api.prepare_unflatten_authority(
        source=source, projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
        plan=plan, attempt_id=attempt, generic_gates=gates, structural_context=context if owned else None,
    )
    assert type(result) is model.UnflattenAuthorityPreparationAccepted, result
    assert result.prepared.projected_loss_ledger.case is result.prepared.projected_case
    assert result.prepared.source_inputs.source_inventory is result.prepared.source_inventory
    if owned:
        assert context.facts.metrics["registry_issues"] > 0
    from d810.ir.maturity import MaturityEnvelope, IRMaturity, SnapshotForm
    from d810.transforms.patch_binding import BoundPatchPlan, iter_refs, observed_patch_binding

    maturity = MaturityEnvelope(IRMaturity.GLOBAL_OPTIMIZED, SnapshotForm.OPTIMIZED_IR,
                                "hexrays", 6, "MMAT_GLBOPT2")
    refs = tuple(dict.fromkeys(iter_refs((plan.steps, plan.new_blocks, plan.relocation_map))))
    serials = dict(plan.source_coordinates)
    patch_binding = BoundPatchPlan(plan, attempt, attempt.session_id, attempt.generation,
                                  maturity, tuple((ref, serials[ref]) for ref in refs))
    binding = transaction_api.bind_prepared_unflatten_authority(
        prepared=result.prepared, patch_binding=patch_binding, structural_context=context if owned else None,
    )
    assert type(binding) is model.UnflattenAuthorityBindingAccepted, binding
    context.begin_observation(attempt, plan.unflatten_proposal.source_identity_catalog.native_key,
                              StructuralTransactionCoordinates(plan.snapshot_id, 4, 1, None, 1))
    verdict = transaction_api.revalidate_observed_unflatten_authority(
        authority=binding.authority, observed=projected, observed_generation=1,
        generic_gates=gates, observed_patch_binding=observed_patch_binding(patch_binding, ()),
        structural_context=context if owned else None,
    )
    if verdict.accepted:
        transaction_api.validate_observed_commit_authority(
            binding.authority, verdict, verdict.observed_acceptance,
            structural_context=context if owned else None,
        )
    assert verdict.safety_case.candidate_inventory is not result.prepared.source_inputs.candidate_inventory
    return result, binding, verdict, context


@pytest.mark.parametrize("local_alias", [False, True])
def test_owned_preparation_runs_the_real_case_and_ledger(local_alias):
    preparation, _binding, verdict, context = _run_transaction(local_alias)
    baseline_preparation, _baseline_binding, baseline, _ = _run_transaction(local_alias, owned=False)
    assert verdict.accepted == baseline.accepted
    assert verdict.reason == baseline.reason
    assert tuple((item.key.dimension, item.state) for item in verdict.failed_obligations) == tuple(
        (item.key.dimension, item.state) for item in baseline.failed_obligations
    )
    if not local_alias:
        assert verdict.accepted
    source_authority = preparation.prepared.source_route_authority
    assert ids.canonical_bytes(source_authority) == ids.canonical_bytes(
        baseline_preparation.prepared.source_route_authority
    )
    assert ids.materialize_for_persistence(source_authority, type(source_authority)).record == source_authority
    assert context.observed_facts is not context.facts


def test_owned_vertical_has_no_registry_reconstruction_or_owned_root_guard(monkeypatch):
    from d810.transforms.unflatten_authority import bind
    from d810.transforms.unflatten_authority.transaction_facts import active_facts

    def no_registry_work(*args, **kwargs):
        if active_facts() is not None:
            raise AssertionError("internal path replayed registry identity")

    for name in ("_memoizable_digest", "_route_result_identity"):
        original = getattr(bind, name)

        def checked(*args, _original=original, **kwargs):
            no_registry_work()
            return _original(*args, **kwargs)

        monkeypatch.setattr(bind, name, checked)
    original_guard = ids._occurrence_guard

    def guard(session, value):
        owner = active_facts()
        assert owner is None, "internal transaction ran a recursive guard"
        return original_guard(session, value)

    monkeypatch.setattr(ids, "_occurrence_guard", guard)
    # model imported its local inventory-seal reference before the tripwire.
    from d810.transforms.unflatten_authority import model
    monkeypatch.setattr(model, "_occurrence_guard", guard)
    _run_transaction(False)


def test_external_decode_never_inherits_transaction_issuance():
    from .test_model import _valid_proposal
    from d810.transforms.unflatten_authority import model

    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    owner = TransactionFacts()
    with fact_scope(owner):
        admitted = owner.admit_external(proposal, model.ProposedUnflattenContract)
        decoded = ids.canonical_decode(ids.canonical_bytes(admitted))
        assert not owner.contains(decoded)
        assert decoded == admitted
        assert ids.materialize_for_persistence(admitted, type(admitted)).canonical_bytes == ids.canonical_bytes(proposal)


@pytest.mark.parametrize("corruption", ["enum", "native", "schema"])
def test_public_admission_rejects_forged_fields_without_root_issuance(corruption):
    from .test_model import _valid_proposal
    from d810.transforms.unflatten_authority import model

    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    if corruption == "enum":
        object.__setattr__(proposal.plan_inputs, "shape", proposal.plan_inputs.shape.value)
    elif corruption == "native":
        object.__setattr__(proposal.source_identity_catalog.native_key, "function_rva", True)
    else:
        proposal = object.__new__(model.ProposedUnflattenContract)
    owner = TransactionFacts()
    with fact_scope(owner), pytest.raises((TypeError, ValueError, AttributeError)):
        owner.admit_external(proposal, model.ProposedUnflattenContract)
    assert not owner.contains(proposal)


def test_forged_enum_occurrence_is_not_an_admissible_immutable_atom():
    from d810.transforms.unflatten_authority import model
    genuine = model.UnflattenAuthorityPhase.PRODUCER_FORECAST
    forged = str.__new__(type(genuine), genuine.value)
    object.__setattr__(forged, "_value_", genuine.value)
    object.__setattr__(forged, "_name_", genuine.name)
    owner = TransactionFacts()
    with pytest.raises(ValueError, match="enum"):
        owner.capture(forged)
    assert not owner.immutable(forged)


def test_closed_and_foreign_context_cannot_continue_a_prepared_transaction():
    from d810.transforms.unflatten_authority import transaction_api
    from d810.transforms.unflatten_authority.structural_transaction import (
        StructuralTransactionContext, StructuralTransactionCoordinates,
    )

    prepared, binding, _verdict, context = _run_transaction(False)
    authority = binding.authority
    foreign = StructuralTransactionContext(
        authority.attempt_id, prepared.prepared.proposal.source_identity_catalog.native_key,
        StructuralTransactionCoordinates(prepared.prepared.snapshot_id, 4, 1, None, 1),
    )
    with pytest.raises(ValueError, match="foreign"):
        transaction_api.bind_prepared_unflatten_authority(
            prepared=prepared.prepared, patch_binding=authority.patch_binding, structural_context=foreign,
        )
    context.close()
    with pytest.raises(ValueError, match="closed"):
        transaction_api.bind_prepared_unflatten_authority(
            prepared=prepared.prepared, patch_binding=authority.patch_binding, structural_context=context,
        )


def transaction_work_counts():
    """Deterministic work inventory; profiling time is deliberately omitted."""
    import cProfile
    import pstats

    names = {
        "_feed_occurrence", "_feed_occurrence_token", "_wire", "_wire_uncached",
        "_external_wire", "_validate_canonical_value", "_occurrence_stamp",
        "_memoizable_digest", "_route_result_identity", "_canonical_record_snapshot",
        "_detached_canonical_copy", "canonical_decode", "validate_canonical_roundtrip",
    }
    result = {}
    for owned in (False, True):
        profile = cProfile.Profile()
        _prepared, _bound, verdict, context = _run_transaction(
            False, owned=owned, on_preparation=profile.enable,
        )
        profile.disable()
        counts = {name: 0 for name in names}
        for (filename, _line, name), (primitive, total, _own, _cumulative, _callers) in pstats.Stats(profile).stats.items():
            if name in counts and "/unflatten_authority/" in filename:
                counts[name] += total
        result["owned" if owned else "strict"] = {
            "legacy": counts,
            "accepted": verdict.accepted,
            "projected": dict(context.facts.metrics) if owned else {},
            "observed": dict(context.observed_facts.metrics) if owned else {},
        }
    return result


def test_complete_path_work_inventory():
    import json
    result = transaction_work_counts()
    assert result["owned"]["accepted"] == result["strict"]["accepted"]
    assert result["owned"]["legacy"]["_memoizable_digest"] == 0
    assert result["owned"]["legacy"]["_route_result_identity"] == 0
    assert result["owned"]["legacy"]["validate_canonical_roundtrip"] == 1
    assert result["owned"]["legacy"]["_feed_occurrence"] < result["strict"]["legacy"]["_feed_occurrence"]
    print(json.dumps(result, sort_keys=True))
