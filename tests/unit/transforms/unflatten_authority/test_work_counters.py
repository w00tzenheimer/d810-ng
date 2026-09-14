"""Authority work counters must stay opt-in, bounded, and phase-exact."""

from importlib import import_module


def _work_counters():
    return import_module("d810.transforms.unflatten_authority.work_counters")


def test_disabled_scope_records_nothing() -> None:
    counters = _work_counters()

    with counters.authority_work_scope(enabled=False) as recorder:
        counters.record_authority_work(
            counters.AuthorityWorkKind.BUILD_SEMANTIC_CASE,
            counters.AuthorityWorkPhase.OBSERVED,
            counters.AuthorityInputOrigin.OBSERVED_GRAPH,
        )

    assert recorder.snapshot().rows == ()


def test_recorder_preserves_kind_phase_and_origin() -> None:
    counters = _work_counters()

    with counters.authority_work_scope(enabled=True) as recorder:
        counters.record_authority_work(
            counters.AuthorityWorkKind.DERIVE_TRANSACTION_FACTS,
            counters.AuthorityWorkPhase.PROJECTED,
            counters.AuthorityInputOrigin.PREPARED_SOURCE,
        )

    snapshot = recorder.snapshot()
    assert snapshot.count(
        kind=counters.AuthorityWorkKind.DERIVE_TRANSACTION_FACTS,
        phase=counters.AuthorityWorkPhase.PROJECTED,
        input_origin=counters.AuthorityInputOrigin.PREPARED_SOURCE,
    ) == 1
    assert snapshot.total == 1


def test_nested_scope_restores_outer_recorder() -> None:
    counters = _work_counters()

    with counters.authority_work_scope(enabled=True) as outer:
        counters.record_authority_work(
            counters.AuthorityWorkKind.DERIVE_INPUTS,
            counters.AuthorityWorkPhase.PROJECTED,
            counters.AuthorityInputOrigin.PROJECTED_GRAPH,
        )
        with counters.authority_work_scope(enabled=True) as inner:
            counters.record_authority_work(
                counters.AuthorityWorkKind.DERIVE_INPUTS,
                counters.AuthorityWorkPhase.OBSERVED,
                counters.AuthorityInputOrigin.OBSERVED_GRAPH,
            )
        counters.record_authority_work(
            counters.AuthorityWorkKind.DERIVE_INPUTS,
            counters.AuthorityWorkPhase.PROJECTED,
            counters.AuthorityInputOrigin.PROJECTED_GRAPH,
        )

    assert outer.snapshot().total == 2
    assert inner.snapshot().total == 1


def test_projected_and_observed_work_is_attributed_to_its_real_input() -> None:
    counters = _work_counters()
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.hexrays.mutation.patch_binding import bind_patch_plan
    from d810.transforms.cfg_transaction import CfgProjection
    from d810.transforms.unflatten_authority import transaction_api
    from .helpers import observed_patch_binding_for_test
    from .test_transaction_api import _c1_direct_preparation_case

    fixture, source, plan, projected, gates = _c1_direct_preparation_case()
    attempt = fixture.attempt_id
    with counters.authority_work_scope(enabled=True) as recorder:
        preparation = transaction_api.prepare_unflatten_authority(
            source=source,
            projection=CfgProjection(plan.plan_id, plan.snapshot_id, projected),
            plan=plan,
            attempt_id=attempt,
            generic_gates=gates,
        )
        prepared = preparation.prepared
        assert prepared is not None
        refs = tuple(plan.source_coordinates)
        index = MbaBlockIdentityIndex.from_bindings(
            generation=attempt.generation,
            maturity=None,
            native_key=refs[0][0].identity.native_key,
            snapshot_id=plan.snapshot_id,
            session_id=attempt.session_id,
            bindings=tuple((ref.identity, serial) for ref, serial in refs),
        )
        index.begin_transaction(attempt, quantity=len(source.blocks))
        binding = transaction_api.bind_prepared_unflatten_authority(
            prepared=prepared,
            patch_binding=bind_patch_plan(plan, index, attempt).bound_plan,
        )
        assert binding.authority is not None
        verdict = transaction_api.revalidate_observed_unflatten_authority(
            authority=binding.authority,
            observed=projected,
            observed_generation=attempt.generation,
            generic_gates=gates,
            observed_patch_binding=observed_patch_binding_for_test(
                binding.authority
            ),
        )
        assert verdict.accepted

    snapshot = recorder.snapshot()
    assert snapshot.count(
        kind=counters.AuthorityWorkKind.DERIVE_TRANSACTION_FACTS,
        phase=counters.AuthorityWorkPhase.PROJECTED,
        input_origin=counters.AuthorityInputOrigin.PREPARED_SOURCE,
    ) == 1
    assert snapshot.count(
        kind=counters.AuthorityWorkKind.BUILD_SEMANTIC_CASE,
        phase=counters.AuthorityWorkPhase.PROJECTED,
        input_origin=counters.AuthorityInputOrigin.PROJECTED_GRAPH,
    ) == 1
    assert snapshot.count(
        kind=counters.AuthorityWorkKind.BUILD_SEMANTIC_CASE,
        phase=counters.AuthorityWorkPhase.OBSERVED,
        input_origin=counters.AuthorityInputOrigin.OBSERVED_GRAPH,
    ) == 1
    assert snapshot.count(
        kind=counters.AuthorityWorkKind.BUILD_INVENTORY,
        phase=counters.AuthorityWorkPhase.OBSERVED,
        input_origin=counters.AuthorityInputOrigin.OBSERVED_GRAPH,
    ) == 1
