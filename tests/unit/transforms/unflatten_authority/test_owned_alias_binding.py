"""The owned alias chain preserves guards at export and avoids replay capture."""

from dataclasses import replace

import pytest

from d810.core.runtime_identity import RuntimeAuthorityArena, RuntimeAuthorityScope
from d810.transforms.unflatten_authority import bind, inventory_alias_binding, inventory_inputs, model, transaction_api
from d810.transforms.unflatten_authority.ids import canonical_bytes, projected_authority_id
from d810.transforms.unflatten_authority.structural_transaction import StructuralTransactionContext, StructuralTransactionCoordinates
from d810.transforms.unflatten_authority.gates import GenericEffectfulGateFacts
from tests.unit.transforms.unflatten_authority.test_bind import _c_local_alias_fixture, _c_two_local_alias_draft_inputs, _c_two_local_alias_transaction_inputs, _compiler_direct_branch_case


def test_owned_alias_replay_uses_published_inputs_without_capture(monkeypatch):
    fixture = _c_local_alias_fixture()
    source = RuntimeAuthorityArena(RuntimeAuthorityScope("source"))
    projected = RuntimeAuthorityArena(RuntimeAuthorityScope("projected"))
    pair = inventory_alias_binding.publish_pair(source, projected, fixture["source_inventory"], fixture["projected_inventory"])
    draft = inventory_alias_binding.draft_alias(pair, fixture["claim"], fixture["patch_step_fact"], False)
    pair = inventory_alias_binding.release_occurrence_snapshots(pair)
    assert pair.source_occurrences is None and pair.projected_occurrences is None

    def forbidden(*args, **kwargs):
        raise AssertionError("replay must not capture or reconstruct")

    monkeypatch.setattr(inventory_inputs, "capture_inventory", forbidden)
    monkeypatch.setattr(inventory_inputs, "capture_inventory_reference", forbidden)
    monkeypatch.setattr(inventory_inputs, "materialize_inventory", forbidden)
    inventory_alias_binding.replay_alias(pair, draft, fixture["claim"], fixture["patch_step_fact"], False)


def test_owned_alias_export_rejects_current_public_row_replacement():
    fixture = _c_local_alias_fixture()
    source = RuntimeAuthorityArena(RuntimeAuthorityScope("source"))
    projected = RuntimeAuthorityArena(RuntimeAuthorityScope("projected"))
    pair = inventory_alias_binding.publish_pair(source, projected, fixture["source_inventory"], fixture["projected_inventory"])
    draft = inventory_alias_binding.draft_alias(pair, fixture["claim"], fixture["patch_step_fact"], False)
    public = fixture["source_inventory"]
    original = public.effects[0]
    # Exact content replacement preserves constructor invariants but must not
    # silently replace the selected original occurrence.
    object.__setattr__(public, "effects", (replace(original), *public.effects[1:]))
    with pytest.raises(ValueError, match="occurrence"):
        inventory_alias_binding.require_alias_export(pair, draft, public, fixture["projected_inventory"])


def test_private_site_draft_consumes_owned_aliases_without_legacy_guard(monkeypatch):
    values = _c_two_local_alias_draft_inputs()
    source = RuntimeAuthorityArena(RuntimeAuthorityScope("source"))
    projected = RuntimeAuthorityArena(RuntimeAuthorityScope("projected"))
    pair = inventory_alias_binding.publish_pair(source, projected, values.source_inventory, values.projected_inventory)

    def forbidden(*args, **kwargs):
        raise AssertionError("converted draft must not enter legacy inventory guard")

    monkeypatch.setattr(bind, "_draft_local_alias_binding", forbidden)
    draft = bind._draft_projected_site_closure(
        authority_id="owned-test", source_authority=values.source_authority,
        plan=values.plan, source_inventory=values.source_inventory,
        projected_inventory=values.projected_inventory, claims=values.claims,
        patch_step_facts=values.patch_step_facts, raw_effect_gate_fact=values.raw_effect_gate_fact,
        legacy_effective_gate_facts=None, attempt_id=values.attempt_id,
        drafts=values.drafts, owner_index=values.owner_index, _owned_pair=pair,
    )
    assert len(draft.local_binding_drafts) == 2
    assert all(type(item) is inventory_alias_binding.OwnedAliasDraft for item in draft.local_binding_drafts)
    assert tuple(item.patch_step_fact for item in draft.local_binding_drafts) == values.patch_step_facts


@pytest.mark.parametrize("context_mode", ("valid", "foreign-attempt", "foreign-native", "foreign-snapshot"))
def test_private_closure_replays_and_mints_owned_aliases_with_exact_output(monkeypatch, context_mode):
    authority, plan, source, projected, _facts, attempt = _compiler_direct_branch_case(helper=True, two_local_aliases=True)
    derived = transaction_api._derive_transaction_facts(source, plan)
    owners = frozenset(row.owner_serial for row in source.effects)
    legacy = GenericEffectfulGateFacts(True, owners, owners, frozenset(), "owned-alias-test")
    raw = bind.bind_raw_effect_gate_phase_fact(source_inventory=source, projected_inventory=projected, raw_gate_facts=legacy)
    identity = projected_authority_id(
        attempt_id=attempt, proposal_id=authority.proposal_id,
        source_authority_id=authority.source_authority_id, plan_id=plan.plan_id,
        claims=derived.claims, patch_step_facts=derived.patch_step_facts,
        source_inventory=source, projected_inventory=projected, raw_effect_gate_fact=raw,
    )
    values = dict(authority_id_value=identity, derived_claim_inventory=derived,
                  source_route_authority=authority, attempt_id=attempt,
                  projected_inventory=projected, raw_effect_gate_fact=raw,
                  legacy_effective_gate_facts=legacy)
    close = transaction_api.realize_projected_routes
    original = bind._draft_local_alias_binding
    calls = []

    def tracked(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(bind, "_draft_local_alias_binding", tracked)
    baseline = close(**values)
    assert type(baseline) is model.ProjectedRouteRealizationAccepted
    assert len(calls) == 4
    calls.clear()
    native = source.blocks[0].block_ref.identity.native_key
    context = StructuralTransactionContext(
        replace(attempt) if context_mode == "foreign-attempt" else attempt,
        replace(native, input_identity="foreign") if context_mode == "foreign-native" else native,
        StructuralTransactionCoordinates("foreign" if context_mode == "foreign-snapshot" else plan.snapshot_id,
                                         0, attempt.generation, None, 0),
    )
    result = close(**values, structural_context=context)
    if context_mode == "valid":
        assert type(result) is model.ProjectedRouteRealizationAccepted
        assert canonical_bytes(result) == canonical_bytes(baseline)
    else:
        assert type(result) is model.ProjectedRouteRealizationRejected
        assert len(context.source) == 0 and len(context.projected) == 0
    assert calls == []
    context.close()


@pytest.mark.parametrize("mutation", ("equal-source-row", "projected-display", "claim-token", "empty-origins"))
def test_owned_consumer_rejects_drift_before_mint(monkeypatch, mutation):
    authority, plan, source, projected, _facts, attempt = _compiler_direct_branch_case(helper=True, two_local_aliases=True)
    derived = transaction_api._derive_transaction_facts(source, plan)
    owners = frozenset(row.owner_serial for row in source.effects)
    legacy = GenericEffectfulGateFacts(True, owners, owners, frozenset(), "owned-alias-mutation")
    raw = bind.bind_raw_effect_gate_phase_fact(source_inventory=source, projected_inventory=projected, raw_gate_facts=legacy)
    identity = projected_authority_id(
        attempt_id=attempt, proposal_id=authority.proposal_id,
        source_authority_id=authority.source_authority_id, plan_id=plan.plan_id,
        claims=derived.claims, patch_step_facts=derived.patch_step_facts,
        source_inventory=source, projected_inventory=projected, raw_effect_gate_fact=raw,
    )
    context = StructuralTransactionContext(
        attempt, source.blocks[0].block_ref.identity.native_key,
        StructuralTransactionCoordinates(plan.snapshot_id, 0, attempt.generation, None, 0),
    )
    validate = bind._validate_projected_site_closure_draft
    minted = []
    mint = bind._site_mint

    def tracked_mint(*args, **kwargs):
        minted.append(args)
        return mint(*args, **kwargs)

    def mutate_then_validate(draft, **kwargs):
        item = draft.local_binding_drafts[0]
        effect, _, _, block, insn = item.rows.positions
        if mutation == "equal-source-row":
            rows = list(source.effects)
            rows[effect] = replace(rows[effect])
            object.__setattr__(source, "effects", tuple(rows))
        elif mutation == "projected-display":
            object.__setattr__(projected.blocks[block].instruction_observations[insn], "display_text", "changed = other")
        elif mutation == "claim-token":
            object.__setattr__(item.claim, "alias_token", "changed")
        else:
            object.__setattr__(draft, "local_binding_drafts", (item._replace(origins=()), *draft.local_binding_drafts[1:]))
        return validate(draft, **kwargs)

    monkeypatch.setattr(bind, "_validate_projected_site_closure_draft", mutate_then_validate)
    monkeypatch.setattr(bind, "_site_mint", tracked_mint)
    result = transaction_api.realize_projected_routes(
        authority_id_value=identity, derived_claim_inventory=derived,
        source_route_authority=authority, attempt_id=attempt,
        projected_inventory=projected, raw_effect_gate_fact=raw,
        legacy_effective_gate_facts=legacy, structural_context=context,
    )
    assert type(result) is model.ProjectedRouteRealizationRejected
    assert minted == []
    context.close()
