from __future__ import annotations

import pytest
from types import SimpleNamespace

from d810.ir.flowgraph import BlockKind, BlockSnapshot, InsnKind, InsnSnapshot, MopSnapshot
from d810.ir.semantics import ControlTransferKind
from d810.transforms.unflatten_authority.model import EffectSiteKind, TerminalKind
from d810.transforms.unflatten_authority import producer_api as producer_module
from d810.transforms.unflatten_authority.model import (
    InventoryInstructionObservation,
    resolve_inventory_block_sites,
)
from d810.transforms.unflatten_authority.producer_api import (
    classify_block_effects_and_terminals,
    validate_exact_effect_claim_semantics,
)


def _block(*instructions: InsnSnapshot, kind: BlockKind = BlockKind.UNKNOWN, succs: tuple[int, ...] = ()) -> BlockSnapshot:
    return BlockSnapshot(1, 0, succs, (), 0, 0x1000, instructions, kind=kind)


@pytest.mark.parametrize(
    ("insn_kind", "effect_kind", "terminal_kind"),
    [
        (InsnKind.STORE, EffectSiteKind.STORE, None),
        (InsnKind.TRAP, EffectSiteKind.TRAP, TerminalKind.TRAP),
        (InsnKind.RET, EffectSiteKind.RETURN, TerminalKind.RETURN),
        (InsnKind.CALL, EffectSiteKind.CALL, TerminalKind.NORETURN_CALL),
    ],
)
def test_classifier_emits_exact_effect_and_terminal_rows(
    insn_kind: InsnKind, effect_kind: EffectSiteKind, terminal_kind: TerminalKind | None,
) -> None:
    insn = InsnSnapshot(0x42, 0x1000, (), kind=insn_kind, l=MopSnapshot(size=2), r=MopSnapshot(size=4))
    effects, terminals = classify_block_effects_and_terminals(_block(insn), owner_ref=None, owner_anchor_ea=0x1000)
    assert len(effects) == 1
    assert effects[0].effect_kind is effect_kind
    assert effects[0].opcode == 0x42
    assert effects[0].width == 4
    if terminal_kind is None:
        assert terminals == ()
    else:
        assert terminals[0].terminal_kind is terminal_kind


def test_classifier_emits_call_terminal_and_synthesized_stop() -> None:
    call = InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.CALL)
    effects, terminals = classify_block_effects_and_terminals(
        _block(call, kind=BlockKind.STOP), owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert effects[0].effect_kind is EffectSiteKind.CALL
    assert {item.terminal_kind for item in terminals} == {TerminalKind.NORETURN_CALL}

    effects, terminals = classify_block_effects_and_terminals(
        _block(kind=BlockKind.STOP), owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert effects == ()
    assert terminals[0].terminal_kind is TerminalKind.STOP
    assert terminals[0].instruction_ordinal is None


def test_inventory_adapter_retains_generated_candidate_control_transfer_without_ea() -> None:
    generated = BlockSnapshot(
        7, 0, (8,), (), 0, 0xFFFFFFFFFFFFFFFF,
        (InsnSnapshot(
            0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.GOTO,
            control_transfer_kind=ControlTransferKind.GOTO,
        ),),
        kind=BlockKind.UNKNOWN,
    )
    observed = producer_module.observe_inventory_block(
        generated, owner_ref=None, owner_anchor_ea=None,
    )
    assert observed.successor_serials == (8,)
    assert observed.transfer_ea is None
    assert observed.instruction_observations[0].instruction_ea is None
    assert observed.instruction_observations[0].control_transfer_kind is ControlTransferKind.GOTO


def test_classifier_uses_return_transfer_and_rejects_overlap_or_missing_ea() -> None:
    with pytest.raises(TypeError):
        classify_block_effects_and_terminals(
            _block(SimpleNamespace(kind=InsnKind.STORE, native_ea=0x1000, ea=0x1000, opcode=1)),
            owner_ref=None, owner_anchor_ea=0x1000,
        )
    effects, terminals = classify_block_effects_and_terminals(
        _block(InsnSnapshot(0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.NOP)),
        owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert effects == () and terminals == ()
    returned = InsnSnapshot(0x42, 0x1000, (), control_transfer_kind=ControlTransferKind.RETURN)
    effects, terminals = classify_block_effects_and_terminals(_block(returned), owner_ref=None, owner_anchor_ea=0x1000)
    assert effects[0].effect_kind is EffectSiteKind.RETURN
    assert terminals[0].terminal_kind is TerminalKind.RETURN

    with pytest.raises(ValueError, match="overlap"):
        classify_block_effects_and_terminals(
            _block(InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.STORE, is_call=True)),
            owner_ref=None, owner_anchor_ea=0x1000,
        )
    with pytest.raises(ValueError, match="native"):
        classify_block_effects_and_terminals(
            _block(InsnSnapshot(0x42, 0xFFFFFFFFFFFFFFFF, (), kind=InsnKind.STORE)),
            owner_ref=None, owner_anchor_ea=0x1000,
        )

    with pytest.raises(ValueError, match="duplicate"):
        classify_block_effects_and_terminals(
            _block(
                InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.STORE),
                InsnSnapshot(0x43, 0x1000, (), kind=InsnKind.STORE),
            ),
            owner_ref=None, owner_anchor_ea=0x1000,
        )


def test_classifier_revalidates_corrupted_empty_block_scalars() -> None:
    block = _block()
    object.__setattr__(block, "serial", -1)
    with pytest.raises(ValueError):
        classify_block_effects_and_terminals(block, owner_ref=None, owner_anchor_ea=0x1000)


def test_producer_classifier_delegates_to_one_neutral_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []
    original = producer_module.resolve_inventory_block_sites

    def spy(**kwargs: object) -> object:
        calls.append(tuple(kwargs["instruction_observations"]))
        return original(**kwargs)

    monkeypatch.setattr(producer_module, "resolve_inventory_block_sites", spy)
    block = _block(InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.STORE))
    effects, terminals = classify_block_effects_and_terminals(
        block, owner_ref=None, owner_anchor_ea=0x1000,
    )
    assert len(calls) == 1
    rows = calls[0]
    assert all(type(row) is InventoryInstructionObservation for row in rows)
    expected = resolve_inventory_block_sites(
        serial=block.serial, owner_ref=None, owner_anchor_ea=0x1000,
        block_kind=block.kind, successor_serials=block.succs,
        instruction_observations=rows,
    )
    assert (effects, terminals) == expected


def test_classifier_rejects_non_tail_control_transfer() -> None:
    block = _block(
        InsnSnapshot(0x42, 0x1000, (), kind=InsnKind.GOTO),
        InsnSnapshot(0x43, 0x1004, (), kind=InsnKind.NOP),
        succs=(2,),
    )
    with pytest.raises(ValueError, match="tail"):
        classify_block_effects_and_terminals(block, owner_ref=None, owner_anchor_ea=0x1000)


@pytest.mark.parametrize("kind", (InsnKind.RET, InsnKind.GOTO))
def test_classifier_rejects_post_init_erased_raw_transfer_marker(kind: InsnKind) -> None:
    instruction = InsnSnapshot(0x42, 0x1000, (), kind=kind)
    object.__setattr__(instruction, "control_transfer_kind", None)
    with pytest.raises(ValueError, match="requires control transfer"):
        classify_block_effects_and_terminals(
            _block(instruction, succs=(2,) if kind is InsnKind.GOTO else ()),
            owner_ref=None,
            owner_anchor_ea=0x1000,
        )


@pytest.mark.parametrize("kind", (InsnKind.NOP, InsnKind.STORE, InsnKind.CALL))
def test_classifier_rejects_foreign_transfer_marker(kind: InsnKind) -> None:
    instruction = InsnSnapshot(
        0x42, 0x1000, (), kind=kind, control_transfer_kind=ControlTransferKind.GOTO,
    )
    with pytest.raises(ValueError, match="must not carry control transfer"):
        classify_block_effects_and_terminals(
            _block(instruction), owner_ref=None, owner_anchor_ea=0x1000,
        )


@pytest.mark.parametrize("transfer", (ControlTransferKind.GOTO, ControlTransferKind.RETURN))
def test_classifier_accepts_unknown_kind_recovered_transfer(transfer: ControlTransferKind) -> None:
    instruction = InsnSnapshot(0x42, 0x1000, (), control_transfer_kind=transfer)
    classify_block_effects_and_terminals(
        _block(instruction), owner_ref=None, owner_anchor_ea=0x1000,
    )


def test_exact_claim_semantics_rejects_state_and_storage_forgery() -> None:
    from dataclasses import replace

    from tests.unit.transforms.unflatten_authority.test_bind import _exact_fixture

    _source, proposal, _exclusion, refs = _exact_fixture()
    claim = next(item for item in proposal.claims if item.kind.value == "exact_infeasible_effect")
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    assert validate_exact_effect_claim_semantics(
        proposal=proposal, claim=claim, source_serial_by_ref=serial_by_ref,
    ) is not None

    object.__setattr__(claim, "normalized_state", claim.normalized_state + 1)
    assert validate_exact_effect_claim_semantics(
        proposal=proposal, claim=claim, source_serial_by_ref=serial_by_ref,
    ) is None
    object.__setattr__(claim, "normalized_state", 7)
    object.__setattr__(claim, "state_identity", replace(claim.state_identity, offset=8))
    assert validate_exact_effect_claim_semantics(
        proposal=proposal, claim=claim, source_serial_by_ref=serial_by_ref,
    ) is None


def test_build_proposal_requires_explicit_route_selection_and_preserves_mixed_claims() -> None:
    """A canonical route present in the evidence is not an implicit allowance."""

    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture
    from d810.transforms.unflatten_authority import producer_api

    source, proposal, exclusion, refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    common = dict(
        plan_id=proposal.plan_id,
        source=source,
        block_refs_by_serial=refs,
        source_generation=proposal.source_identity_catalog.generation,
        canonical_route_evidence=proposal.route_evidence,
        dispatcher_entry_serial=1,
        dispatcher_member_serials=(0, 1),
        authoritative_handler_serials=(2,),
        state_identity=proposal.plan_inputs.state_identity,
        use_def_witness=proposal.use_def_witness,
    )
    with pytest.raises(ValueError, match="semantic route or exact effect"):
        producer_api.build_proposal(**common, exact_state_effect_exclusions=())

    route_only = producer_api.build_proposal(
        **common,
        selected_route_proof_ids=(proof.proof_id,),
        exact_state_effect_exclusions=(),
    )
    assert tuple(item.route_proof_ids for item in route_only.claims) == ((proof.proof_id,),)

    mixed = producer_api.build_proposal(
        **common,
        selected_route_proof_ids=(proof.proof_id,),
        exact_state_effect_exclusions=(exclusion,),
    )
    assert {item.kind.value for item in mixed.claims} == {
        "equivalent_semantic_route", "exact_infeasible_effect",
    }
    assert sum(bool(getattr(item, "route_proof_ids", ())) for item in mixed.claims) == 2


def test_route_adapters_select_one_canonical_proof_and_reject_ambiguity() -> None:
    """Emitter DTOs are selectors over sealed evidence, never new evidence."""

    from dataclasses import replace

    from d810.analyses.control_flow.minimal_state_recovery import (
        StateWriteTransition, TransitionProof,
    )
    from d810.analyses.control_flow.native_preanalysis_session import (
        BootstrapRouteEvidence, BootstrapRouteProofKind,
    )
    from d810.analyses.control_flow.semantic_transition import NativeBoundTransitionRoute
    from d810.transforms.minimal_unflatten_emit import (
        BootstrapEntryRouteProof, ConcreteStateEntryRouteProof,
        ConditionalEntryBridgeProof,
    )
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    kwargs = dict(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=proposal.route_evidence,
    )
    concrete_evidence = replace(
        proposal.route_evidence,
        route_proofs=(replace(
            proposal.route_evidence.route_proofs[0],
            diagnostic_provenance=proposal.route_evidence.route_proofs[0].diagnostic_provenance
            + (("source_kinds", "concrete"),),
        ),),
    )
    concrete = ConcreteStateEntryRouteProof(7, 2, ("concrete",))
    assert producer_api.adapt_concrete_entry_route(
        concrete, **{**kwargs, "canonical_evidence": concrete_evidence},
    ) is concrete_evidence.route_proofs[0]
    with pytest.raises(ValueError, match="zero"):
        producer_api.adapt_concrete_entry_route(
            replace(concrete, target_handler=3),
            **{**kwargs, "canonical_evidence": concrete_evidence},
        )

    with pytest.raises(ValueError, match="outside"):
        BootstrapRouteEvidence(
            refs[0].identity, 0xDEAD, 7, refs[2].identity, 0x3000,
            BootstrapRouteProofKind.STATIC_NATIVE,
        )

    bootstrap_row = BootstrapEntryRouteProof(0, 2, 7, 0x1000, 0x3000)
    # A conditional canonical proof must not be reinterpreted as a bootstrap row.
    with pytest.raises(ValueError, match="zero"):
        producer_api.adapt_bootstrap_entry_route_proof(bootstrap_row, **kwargs)

    conditional = ConditionalEntryBridgeProof(1, 0x2001, 3, 2, True)
    assert producer_api.adapt_conditional_entry_route(conditional, **kwargs) is proposal.route_evidence.route_proofs[0]
    with pytest.raises(ValueError, match="zero"):
        producer_api.adapt_conditional_entry_route(
            replace(conditional, predicate_ea=0xDEAD), **kwargs,
        )

    native = NativeBoundTransitionRoute("fact", 0x1000, 0, 7, 2)
    native_proof = replace(
        proposal.route_evidence.route_proofs[0],
        diagnostic_provenance=(
            *proposal.route_evidence.route_proofs[0].diagnostic_provenance,
            ("fact_id", "fact"),
        ),
    )
    native_evidence = replace(proposal.route_evidence, route_proofs=(native_proof,))
    assert producer_api.adapt_native_bound_transition_route(
        native, **{**kwargs, "canonical_evidence": native_evidence},
    ) is native_proof
    transition = StateWriteTransition(
        0, 7, 2, False, None,
        proof=TransitionProof("test", "test", True),
    )
    assert producer_api.adapt_state_transition_route(
        transition, state_identity=proposal.plan_inputs.state_identity, **kwargs,
    ) is proposal.route_evidence.route_proofs[0]

    assert not hasattr(producer_api, "adapt_interval_route")

    duplicate = replace(proposal.route_evidence.route_proofs[0], proof_id="sha256:" + "2" * 64)
    evidence = replace(proposal.route_evidence, route_proofs=(proposal.route_evidence.route_proofs[0], duplicate))
    with pytest.raises(ValueError, match="multiple"):
        producer_api.adapt_conditional_entry_route(conditional, **{**kwargs, "canonical_evidence": evidence})


def test_route_adapters_reject_semantic_field_drift_beyond_endpoint_coincidence() -> None:
    """Selectors must bind the whole proof, not merely one matching endpoint."""

    from dataclasses import replace

    from d810.analyses.control_flow.minimal_state_recovery import (
        StateWriteTransition, TransitionProof,
    )
    from d810.analyses.control_flow.semantic_route_evidence import (
        SemanticEdgeRole, SemanticRouteProofKind, SemanticRouteShape,
    )
    from d810.analyses.control_flow.semantic_transition import NativeBoundTransitionRoute
    from d810.transforms.minimal_unflatten_emit import (
        ConcreteStateEntryRouteProof, ConditionalEntryBridgeProof,
    )
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    proof = proposal.route_evidence.route_proofs[0]
    kwargs = dict(source=source, source_catalog=proposal.source_identity_catalog,
                  block_refs_by_serial=refs, canonical_evidence=proposal.route_evidence)
    conditional = ConditionalEntryBridgeProof(1, 0x2001, 3, 2, True)
    native = NativeBoundTransitionRoute("fact", 0x1000, 0, 7, 2)
    transition = StateWriteTransition(
        0, 7, 2, False, None,
        proof=TransitionProof("test", "test", True),
    )

    unbound_drift: list[str] = []

    def proof_drift(field: str, value: object, invoke) -> None:
        original = getattr(proof, field)
        object.__setattr__(proof, field, value)
        try:
            try:
                invoke()
            except (TypeError, ValueError):
                return
            unbound_drift.append(field)
        finally:
            object.__setattr__(proof, field, original)

    proof_drift("proof_kind", SemanticRouteProofKind.BOOTSTRAP,
                lambda: producer_api.adapt_conditional_entry_route(conditional, **kwargs))
    proof_drift("shape", SemanticRouteShape.DIRECT,
                lambda: producer_api.adapt_conditional_entry_route(conditional, **kwargs))
    proof_drift("source_identity", refs[0].identity,
                lambda: producer_api.adapt_conditional_entry_route(conditional, **kwargs))
    proof_drift("source_anchor_ea", 0xDEAD,
                lambda: producer_api.adapt_conditional_entry_route(conditional, **kwargs))
    destination = proof.destinations[0]
    old_destination = (destination.target_identity, destination.target_anchor_ea, destination.role, destination.state_constant)
    for field, value in (("target_identity", refs[0].identity), ("target_anchor_ea", 0xDEAD),
                         ("role", SemanticEdgeRole.DIRECT), ("state_constant", 0x100000007)):
        index = ("target_identity", "target_anchor_ea", "role", "state_constant").index(field)
        object.__setattr__(destination, field, value)
        try:
            try:
                producer_api.adapt_conditional_entry_route(conditional, **kwargs)
            except (TypeError, ValueError):
                pass
            else:
                unbound_drift.append(f"destination.{field}")
        finally:
            object.__setattr__(destination, field, old_destination[index])

    state_write = proof.state_write
    assert state_write is not None
    old_write = (state_write.identity, state_write.state_constant, state_write.width, state_write.instruction_ea)
    for field, value in (("identity", refs[2].identity), ("state_constant", 8),
                         ("width", 8), ("instruction_ea", 0xDEAD)):
        index = ("identity", "state_constant", "width", "instruction_ea").index(field)
        object.__setattr__(state_write, field, value)
        try:
            try:
                producer_api.adapt_native_bound_transition_route(native, **kwargs)
            except (TypeError, ValueError):
                pass
            else:
                unbound_drift.append(f"state_write.{field}")
        finally:
            object.__setattr__(state_write, field, old_write[index])

    original_diag = proof.diagnostic_provenance
    object.__setattr__(proof, "diagnostic_provenance", original_diag + (("source_kinds", "concrete"), ("fact_id", "fact")))
    try:
        concrete = ConcreteStateEntryRouteProof(7, 2, ("concrete",))
        assert producer_api.adapt_concrete_entry_route(concrete, **kwargs) is proof
        try:
            producer_api.adapt_concrete_entry_route(ConcreteStateEntryRouteProof(7, 2, ("foreign",)), **kwargs)
        except (TypeError, ValueError):
            pass
        else:
            unbound_drift.append("provider.source_kinds")
        try:
            producer_api.adapt_native_bound_transition_route(replace(native, fact_id="foreign"), **kwargs)
        except (TypeError, ValueError):
            pass
        else:
            unbound_drift.append("provider.fact_id")
    finally:
        object.__setattr__(proof, "diagnostic_provenance", original_diag)

    try:
        producer_api.adapt_state_transition_route(
            replace(transition, next_state=0x100000007),
            state_identity=proposal.plan_inputs.state_identity,
            **kwargs,
        )
    except (TypeError, ValueError):
        pass
    else:
        unbound_drift.append("state_transition.next_state_width")
    with pytest.raises(ValueError, match="preservation relation"):
        producer_api.adapt_state_transition_route(
            replace(transition, via_block=1, preserve_via_block=True),
            state_identity=proposal.plan_inputs.state_identity,
            **kwargs,
        )
    for field, value in (
        ("proof", None), ("via_block", 0), ("branch_arm", 1),
        ("preserve_via_block", True), ("proof", object()),
        ("proof", replace(transition.proof, trusted=False)),
    ):
        try:
            producer_api.adapt_state_transition_route(
                replace(transition, **{field: value}),
                state_identity=proposal.plan_inputs.state_identity,
                **kwargs,
            )
        except (TypeError, ValueError):
            pass
        else:
            unbound_drift.append(f"state_transition.{field}")
    try:
        producer_api.adapt_state_transition_route(
            transition,
            state_identity=replace(
                proposal.plan_inputs.state_identity,
                offset=proposal.plan_inputs.state_identity.offset + 1,
            ),
            **kwargs,
        )
    except (TypeError, ValueError):
        pass
    else:
        unbound_drift.append("state_transition.state_identity")
    assert not unbound_drift, f"semantic drift accepted by adapters: {unbound_drift}"


def test_state_transition_preserve_via_block_requires_canonical_preservation_relation() -> None:
    """A producer-only clone flag must not reuse an otherwise identical route proof."""

    from dataclasses import replace
    from d810.analyses.control_flow.minimal_state_recovery import (
        StateWriteTransition, TransitionProof,
    )
    from d810.transforms.unflatten_authority import producer_api
    from tests.unit.transforms.unflatten_authority.helpers import exact_fixture

    source, proposal, _exclusion, refs = exact_fixture()
    kwargs = dict(
        source=source,
        source_catalog=proposal.source_identity_catalog,
        block_refs_by_serial=refs,
        canonical_evidence=proposal.route_evidence,
        state_identity=proposal.plan_inputs.state_identity,
    )
    transition = StateWriteTransition(
        0, 7, 2, False, None, via_block=1,
        proof=TransitionProof("test", "test", True),
    )
    assert producer_api.adapt_state_transition_route(transition, **kwargs) is proposal.route_evidence.route_proofs[0]
    with pytest.raises(ValueError, match="preservation relation"):
        producer_api.adapt_state_transition_route(
            replace(transition, preserve_via_block=True), **kwargs,
        )


def test_bootstrap_adapter_selects_canonical_proof_and_never_mints_authority() -> None:
    from d810.transforms.unflatten_authority import producer_api

    assert not hasattr(producer_api, "adapt_bootstrap_entry_route")
