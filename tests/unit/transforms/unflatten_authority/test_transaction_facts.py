"""Behavioral ownership and work bounds for the competing transaction path."""

from types import MappingProxyType

import pytest

from d810.transforms.unflatten_authority import ids
from d810.transforms.unflatten_authority.transaction_facts import (
    TransactionFacts,
    _exact_fact_graph_equal,
    fact_scope,
)


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


def test_observed_partition_reuses_exact_parent_canonical_entry():
    projected = TransactionFacts()
    observed = TransactionFacts(parent=projected)
    try:
        with fact_scope(projected):
            fact = projected.capture((("source", 1), ("target", 2)))
            expected_bytes = ids.canonical_bytes(fact)
        with fact_scope(observed):
            assert ids.canonical_bytes(fact) is expected_bytes
        assert observed.metrics["parent_encoding_hits"] == 1
    finally:
        observed.close()
        projected.close()


def test_observed_partition_does_not_reuse_equal_distinct_parent_fact():
    projected = TransactionFacts()
    observed = TransactionFacts(parent=projected)
    try:
        with fact_scope(projected):
            parent_fact = projected.capture((("source", 1),))
            parent_bytes = ids.canonical_bytes(parent_fact)
        with fact_scope(observed):
            child_fact = observed.capture((("source", 1),))
            assert child_fact == parent_fact
            assert child_fact is not parent_fact
            assert observed.cached_wire(child_fact) is None
            child_bytes = ids.canonical_bytes(child_fact)
        assert child_bytes == parent_bytes
        assert observed.metrics["parent_encoding_hits"] == 0
    finally:
        observed.close()
        projected.close()


def test_observed_partition_does_not_borrow_mutable_parent_wire_tree():
    projected = TransactionFacts()
    observed = TransactionFacts(parent=projected)
    sibling = TransactionFacts(parent=projected)
    try:
        with fact_scope(projected):
            fact = projected.capture((("source", 1), ("target", 2)))
            parent_wire = ids._wire(fact)
        with fact_scope(observed):
            child_wire = ids._wire(fact)
        assert child_wire == parent_wire
        assert child_wire is not parent_wire
        child_wire["t"] = "poisoned"
        assert parent_wire["t"] == "tuple"
        with fact_scope(sibling):
            sibling_wire = ids._wire(fact)
        assert sibling_wire == parent_wire
        assert sibling_wire is not parent_wire
    finally:
        sibling.close()
        observed.close()
        projected.close()


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


def test_external_admission_avoids_root_roundtrip_and_decode(monkeypatch):
    from .test_model import _valid_proposal
    from d810.transforms.unflatten_authority import model

    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    expected = ids.canonical_bytes(proposal)
    owner = TransactionFacts()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("external admission rebuilt canonical wire")

    with monkeypatch.context() as scoped:
        scoped.setattr(ids, "canonical_decode", forbidden)
        scoped.setattr(ids, "validate_canonical_roundtrip", forbidden)
        with fact_scope(owner):
            admitted = owner.admit_external(
                proposal, model.ProposedUnflattenContract,
            )

    assert admitted is not proposal
    assert ids.canonical_bytes(admitted) == expected


def test_exact_fact_graph_equality_distinguishes_canonical_type_tags():
    assert _exact_fact_graph_equal(
        MappingProxyType({"nested": (1, frozenset({2}))}),
        MappingProxyType({"nested": (1, frozenset({2}))}),
    )
    assert not _exact_fact_graph_equal(True, 1)
    assert not _exact_fact_graph_equal((1,), [1])
    assert not _exact_fact_graph_equal(frozenset({True}), frozenset({1}))
    assert not _exact_fact_graph_equal(-0.0, 0.0)


def test_external_admission_rejects_constructor_normalization_without_wire():
    from d810.ir.block_identity import NativeEaInterval, NativeEaIntervalSet

    earlier = NativeEaInterval(0x10, 0x20)
    later = NativeEaInterval(0x30, 0x40)
    forged = object.__new__(NativeEaIntervalSet)
    object.__setattr__(forged, "intervals", (later, earlier))
    owner = TransactionFacts()

    with fact_scope(owner), pytest.raises(
        ValueError, match="changed .* value",
    ):
        owner.admit_external(forged, NativeEaIntervalSet)
    assert not owner.contains(forged)


@pytest.mark.parametrize("target", ["claim", "subject"])
def test_external_admission_rejects_forged_nested_lazy_identity(target):
    from .test_model import _valid_proposal
    from d810.transforms.unflatten_authority import model

    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    claim = proposal.claims[0]
    record, field = (
        (claim, "claim_id")
        if target == "claim"
        else (claim.source_subject, "subject_id")
    )
    object.__setattr__(record, field, "sha256:" + "f" * 64)
    owner = TransactionFacts()
    tables = (
        owner._values, owner._copies, owner._registry, owner._canonical,
        owner._digests, owner._wire, owner._external, owner._links,
    )
    before = tuple(dict(table) for table in tables)

    with fact_scope(owner), pytest.raises(
        ValueError, match="capture changed canonical value",
    ):
        owner.admit_external(proposal, model.ProposedUnflattenContract)
    assert not owner.contains(proposal)
    assert tuple(dict(table) for table in tables) == before
    assert id(proposal) not in owner._copies


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
        "_exact_fact_graph_equal",
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
    assert result["owned"]["legacy"]["validate_canonical_roundtrip"] == 0
    assert result["owned"]["legacy"]["_exact_fact_graph_equal"] > 0
    assert result["owned"]["legacy"]["_feed_occurrence"] < result["strict"]["legacy"]["_feed_occurrence"]
    print(json.dumps(result, sort_keys=True))


def test_owned_retirement_issuance_survives_fact_capture():
    """Binder-issued retirement must survive case/input ownership capture."""
    from d810.transforms.unflatten_authority import bind, model
    from tests.unit.transforms.unflatten_authority.test_transaction_api import _full_corridor_inputs

    *_, inputs = _full_corridor_inputs()
    owner = TransactionFacts()
    try:
        with fact_scope(owner):
            result = bind.bind_retired_dispatcher_infrastructure_claim(
                claim=next(claim for claim in inputs.proposal.claims
                           if type(claim) is model.RetiredDispatcherInfrastructureClaim),
                proposal=inputs.proposal,
                source_inventory=inputs.source_inventory,
                projected_inventory=inputs.candidate_inventory,
            )
            issued = result.phase_result
            assert issued is not None
            bind.validate_retirement_phase_result(issued)
            snapshot = owner.capture(issued)
            bind.validate_retirement_phase_result(snapshot)
            assert snapshot is issued
            # Merely owning a schema-valid copy must not confer issuance.
            from d810.transforms.unflatten_authority import ids
            from dataclasses import fields
            reminted = object.__new__(type(issued))
            for field in fields(issued):
                ids.stage_unpublished_field(reminted, field.name, getattr(issued, field.name))
            forged = owner.capture(reminted)
            with pytest.raises(ValueError, match="not minted"):
                bind.validate_retirement_phase_result(forged)
        foreign = TransactionFacts()
        try:
            with fact_scope(foreign):
                with pytest.raises(ValueError, match="not minted"):
                    bind.validate_retirement_phase_result(issued)
                copied = foreign.capture(issued)
                with pytest.raises(ValueError, match="not minted"):
                    bind.validate_retirement_phase_result(copied)
        finally:
            foreign.close()
        observed = TransactionFacts(parent=owner)
        try:
            with fact_scope(observed):
                bind.validate_retirement_phase_result(issued)
                assert observed.capture(issued) is issued
        finally:
            observed.close()
        with pytest.raises(ValueError, match="not minted"):
            bind.validate_retirement_phase_result(issued)
    finally:
        owner.close()
    with pytest.raises(ValueError, match="closed"):
        with fact_scope(owner):
            bind.validate_retirement_phase_result(issued)


def test_capture_does_not_adopt_external_retirement_issuance():
    """A captured external/legacy phase is data, not an owner-issued authority."""
    from d810.transforms.unflatten_authority import bind
    from tests.unit.transforms.unflatten_authority.test_transaction_api import _full_corridor_inputs

    *_, inputs = _full_corridor_inputs()
    original = inputs.retirement_phase_result
    bind.validate_retirement_phase_result(original)
    owner = TransactionFacts()
    try:
        with fact_scope(owner):
            copied = owner.capture(original)
            with pytest.raises(ValueError, match="not minted"):
                bind.validate_retirement_phase_result(copied)
    finally:
        owner.close()


@pytest.mark.parametrize("kind", ("logical_endpoint", "route_topology", "lowered_conditional_topology"))
def test_owned_observed_occurrence_requires_exact_namespace_issuance(kind):
    """Observed validators must consume owner issuance, never adopt copies."""
    from dataclasses import replace
    from d810.transforms.cfg_transaction import LogicalBlockRef
    from d810.transforms.unflatten_authority import bind, model

    refs = tuple(LogicalBlockRef("observed-session", name, 1)
                 for name in ("source", "false", "true"))
    fact = model.PatchStepEvidencePayload(
        ids.authority_id("plan"), 0, "PatchRedirectEdge", refs[0],
        ids.authority_id("step"), 0x401000, None, None,
    )
    pairs = (model.TopologyEdgeRelation(
        next(iter(model.SemanticEdgeRole)), ids.authority_id("source-subject"),
        ids.authority_id("target-subject"), 0x401000,
    ),)
    if kind == "logical_endpoint":
        mint = bind._mint_observed_logical_endpoint_occurrence
        validate = bind._validate_observed_logical_endpoint_occurrence
        values = dict(logical_ref=refs[1], projected_serial=4, observed_serial=5,
                      owner_ref=refs[0], predecessor_refs=(refs[0],))
    elif kind == "route_topology":
        mint = bind.mint_observed_route_topology_occurrence
        validate = bind.validate_observed_route_topology_occurrence
        values = dict(relation_id=ids.authority_id("relation"), row_id=ids.authority_id("row"),
                      patch_fact=fact, normalized_pairs=pairs)
    else:
        mint = bind.mint_observed_lowered_conditional_topology_occurrence
        validate = bind.validate_observed_lowered_conditional_topology_occurrence
        values = dict(patch_fact=fact, source_ref=refs[0], false_target_ref=refs[1],
                      true_target_ref=refs[2], normalized_pairs=pairs)
    projected = TransactionFacts()
    observed = TransactionFacts(parent=projected)
    try:
        with fact_scope(observed):
            issued = mint(**values)
            validate(issued)
            validate(observed.capture(issued))
            with pytest.raises(ValueError, match="not minted"):
                validate(observed.capture(replace(issued)))
        with fact_scope(projected):
            with pytest.raises(ValueError, match="not minted"):
                validate(issued)
        with pytest.raises(ValueError, match="not minted"):
            validate(issued)
    finally:
        observed.close()
        projected.close()


def _bind_owned_phase_result(kind):
    from d810.transforms.unflatten_authority import bind, model
    from . import test_bind

    if kind == "terminal":
        proposal, claim, fixture, source, candidate, _ = test_bind._terminal_cycle_inventory_fixture()
        result = bind.bind_terminal_cycle_break_claim(
            claim=claim, proposal=proposal, source_inventory=source,
            candidate_inventory=candidate, phase=fixture.phase_build_metrics.phase,
        )
        return result.phase_result, bind.validate_terminal_cycle_phase_result
    if kind in {"detached_source", "detached_phase"}:
        claim, source, candidate, corridor = test_bind._detached_binding_fixture()
        result = bind.bind_detached_dead_handler_component_claim(
            claim=claim, source_inventory=source, candidate_inventory=candidate,
            corridor_result=corridor, phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        )
        if kind == "detached_source":
            return result.source_result, bind.validate_detached_source_result
        return result.phase_result, bind.validate_detached_phase_result
    assert kind == "default_gap"
    proposal, source, candidate, authority = test_bind._default_gap_bound_projected_case()
    result = bind.bind_default_gap_infeasibility_forecast(
        proposal=authority.proposal, source_inventory=source, candidate_inventory=candidate,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, source_authority=authority,
    )
    assert result is not None
    return result, bind.validate_default_gap_infeasibility_phase_result


@pytest.mark.parametrize("kind", ["terminal", "detached_source", "detached_phase", "default_gap"])
def test_binder_phase_issuance_survives_owned_capture(kind):
    """Real private issuers must publish the final owned occurrence, not its precursor."""
    owner = TransactionFacts()
    try:
        with fact_scope(owner):
            issued, validate = _bind_owned_phase_result(kind)
            validate(issued)
            captured = owner.capture(issued)
            assert captured == issued
            validate(captured)
            assert captured is issued
    finally:
        owner.close()


@pytest.mark.parametrize("kind", ["terminal", "detached_source", "detached_phase", "default_gap"])
def test_owned_phase_issuance_rejects_clones_foreign_closed_and_reverse_partition(kind):
    from dataclasses import replace

    projected = TransactionFacts()
    observed = TransactionFacts(parent=projected)
    foreign = TransactionFacts()
    try:
        with fact_scope(observed):
            issued, validate = _bind_owned_phase_result(kind)
            validate(issued)
            with pytest.raises(ValueError, match="not minted"):
                validate(observed.capture(replace(issued)))
        for other in (projected, foreign):
            with fact_scope(other):
                with pytest.raises(ValueError, match="not minted"):
                    validate(issued)
                with pytest.raises(ValueError, match="not minted"):
                    validate(other.capture(issued))
        with pytest.raises(ValueError, match="not minted"):
            validate(issued)
        observed.close()
        with pytest.raises(ValueError, match="closed"):
            with fact_scope(observed):
                validate(issued)
    finally:
        observed.close()
        projected.close()
        foreign.close()


@pytest.mark.parametrize("kind", ["terminal", "detached_source", "detached_phase", "default_gap"])
def test_capture_does_not_adopt_external_phase_issuance(kind):
    issued, validate = _bind_owned_phase_result(kind)
    validate(issued)
    owner = TransactionFacts()
    try:
        with fact_scope(owner):
            copied = owner.capture(issued)
            assert copied is not issued
            with pytest.raises(ValueError, match="not minted"):
                validate(copied)
    finally:
        owner.close()


@pytest.mark.parametrize("kind", ["terminal", "detached", "default_gap"])
def test_owned_binder_observation_preserves_parent_and_issues_fresh_child(kind):
    from dataclasses import replace
    from d810.transforms.unflatten_authority import bind, model
    from . import test_bind

    parent = TransactionFacts()
    child = TransactionFacts(parent=parent)
    projected_phase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    observed_phase = model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY
    try:
        with fact_scope(parent):
            if kind == "terminal":
                proposal, claim, _, source, candidate, _ = test_bind._terminal_cycle_inventory_fixture()
                proposal, claim, source, candidate = parent.capture((proposal, claim, source, candidate))
                projected = bind.bind_terminal_cycle_break_claim(
                    claim=claim, proposal=proposal, source_inventory=source,
                    candidate_inventory=candidate, phase=projected_phase,
                ).phase_result
                observe = bind.revalidate_observed_terminal_cycle_break
                validate = bind.validate_terminal_cycle_phase_result
                values = dict(claim=claim, proposal=proposal, source_inventory=source)
            elif kind == "detached":
                claim, source, candidate, corridor = parent.capture(test_bind._detached_binding_fixture())
                projected_binding = bind.bind_detached_dead_handler_component_claim(
                    claim=claim, source_inventory=source, candidate_inventory=candidate,
                    corridor_result=corridor, phase=projected_phase,
                )
                projected = projected_binding.phase_result
                validate = bind.validate_detached_phase_result
                values = dict(claim=claim, source_inventory=source)
            else:
                _, source, candidate, authority = test_bind._default_gap_bound_projected_case()
                proposal = authority.proposal
                projected = bind.bind_default_gap_infeasibility_forecast(
                    proposal=proposal, source_inventory=source, candidate_inventory=candidate,
                    phase=projected_phase, source_authority=authority,
                )
                observe = bind.revalidate_observed_default_gap_infeasibility
                validate = bind.validate_default_gap_infeasibility_phase_result
                values = dict(proposal=proposal, source_inventory=source, source_authority=authority)
        with fact_scope(child):
            validate(projected)
            assert child.capture(projected) is projected
            if kind == "detached":
                _, _, observed_inventory, observed_corridor = test_bind._detached_binding_fixture(
                    candidate_phase=observed_phase,
                    candidate_fingerprint=ids.authority_id("owned-detached-observed"),
                    candidate_generation=5,
                )
                observed_binding = bind.bind_detached_dead_handler_component_claim(
                    **values, candidate_inventory=observed_inventory,
                    corridor_result=observed_corridor, phase=observed_phase,
                    source_result=projected_binding.source_result,
                )
                assert observed_binding.source_result is projected_binding.source_result
                observed = observed_binding.phase_result
            else:
                observed_inventory = test_bind._inventory_rephase(
                    candidate, phase=observed_phase,
                    fingerprint=ids.authority_id("owned-observed-" + kind),
                    generation=candidate.generation,
                )
                with pytest.raises(ValueError, match="not minted"):
                    observe(**values, projected_result=replace(projected), observed_inventory=observed_inventory)
                observed = observe(**values, projected_result=projected, observed_inventory=observed_inventory)
            assert observed.phase is observed_phase
            validate(observed)
            assert child.capture(observed) is observed
        with fact_scope(parent):
            validate(projected)
            with pytest.raises(ValueError, match="not minted"):
                validate(observed)
    finally:
        child.close()
        parent.close()
