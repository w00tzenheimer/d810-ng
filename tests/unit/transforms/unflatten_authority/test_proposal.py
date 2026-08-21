"""Task 5 proposal-channel and plan-route contracts."""

from __future__ import annotations

import hashlib
import inspect

import pytest

from d810.transforms.plan import PatchPlan


def _proposal_and_plan_ids():
    from .helpers import import_authority_model
    from .test_model import _valid_proposal

    model = import_authority_model()
    proposal = model.ProposedUnflattenContract(**_valid_proposal(model))
    return proposal, proposal.plan_id


def _shadow(plan_id: str, snapshot_id: str = "snapshot-1"):
    from d810.transforms.unflatten_authority.ids import canonical_bytes
    from d810.transforms.unflatten_authority.model import (
        LegacyShadowEntry,
        LegacyUnflattenShadowEnvelope,
    )

    payload = canonical_bytes({"legacy": True})
    entry = LegacyShadowEntry(
        "dispatcher_corridor_coverage",
        payload,
        hashlib.sha256(payload).hexdigest(),
    )
    return LegacyUnflattenShadowEnvelope(
        1, plan_id, snapshot_id, 3, (entry,)
    )


def test_explicit_shadow_envelope_is_the_only_dual_channel_exception() -> None:
    """A typed plan may carry only the exact temporary shadow transport."""

    # This is the first RED assertion: the typed channel does not yet exist.
    assert "unflatten_proposal" in inspect.signature(PatchPlan).parameters
    assert "legacy_unflatten_shadow" in inspect.signature(PatchPlan).parameters
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    proposal, plan_id = _proposal_and_plan_ids()
    envelope = _shadow(plan_id)

    typed = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        unflatten_proposal=proposal,
        legacy_unflatten_shadow=envelope,
    )
    selected = select_plan_route(typed)
    from d810.transforms.unflatten_authority.model import (
        UnflattenAuthorityReason,
        UnflattenPlanRoute,
    )

    assert selected.route is UnflattenPlanRoute.TYPED_PROPOSAL

    dual = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        metadata=(("dispatcher_corridor_coverage", {"legacy": True}),),
        unflatten_proposal=proposal,
    )
    rejected = select_plan_route(dual)
    assert rejected.reason is UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL

    with pytest.raises(TypeError, match="shadow"):
        PatchPlan(
            plan_id=plan_id,
            snapshot_id="snapshot-1",
            source_generation=3,
            unflatten_proposal=proposal,
            legacy_unflatten_shadow={"schema_version": 1},
        )


def test_ordinary_and_legacy_only_plans_are_not_typed_authority() -> None:
    from d810.transforms.unflatten_authority.model import (
        UnflattenAuthorityNotApplicable,
        UnflattenAuthorityReason,
    )
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    ordinary = select_plan_route(PatchPlan(plan_id="ordinary", snapshot_id="snap"))
    assert isinstance(ordinary, UnflattenAuthorityNotApplicable)

    legacy_only = select_plan_route(
        PatchPlan(
            plan_id="legacy",
            snapshot_id="snap",
            metadata=(("dispatcher_corridor_coverage", {"legacy": True}),),
        )
    )
    assert legacy_only.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert legacy_only.detail_code == "legacy_metadata_requires_explicit_codec_adaptation"


def test_shadow_records_are_closed_sorted_and_digest_bound() -> None:
    from d810.transforms.unflatten_authority.ids import canonical_bytes
    from d810.transforms.unflatten_authority.model import (
        LegacyShadowEntry,
        LegacyUnflattenShadowEnvelope,
    )

    payload = canonical_bytes({"value": [1, 2]})
    digest = hashlib.sha256(payload).hexdigest()
    first = LegacyShadowEntry("dispatcher_corridor_coverage", payload, digest)
    second_payload = canonical_bytes({"value": 2})
    second = LegacyShadowEntry(
        "use_def_severance_audit",
        second_payload,
        hashlib.sha256(second_payload).hexdigest(),
    )
    envelope = LegacyUnflattenShadowEnvelope(
        1, "plan", "snapshot", 0, (first, second)
    )
    assert envelope.entries == (first, second)
    with pytest.raises(ValueError, match="sorted"):
        LegacyUnflattenShadowEnvelope(1, "plan", "snapshot", 0, (second, first))
    with pytest.raises(ValueError, match="digest"):
        LegacyShadowEntry(first.key, payload, "0" * 64)
    with pytest.raises(ValueError, match="reserved"):
        LegacyShadowEntry("not-authority", payload, digest)
    with pytest.raises(ValueError, match="empty"):
        LegacyUnflattenShadowEnvelope(1, "plan", "snapshot", 0, ())


def test_typed_plan_requires_exact_plan_snapshot_and_generation_correlation() -> None:
    proposal, plan_id = _proposal_and_plan_ids()
    with pytest.raises(ValueError, match="proposal authority"):
        PatchPlan(
            plan_id="different",
            snapshot_id="snapshot-1",
            source_generation=3,
            unflatten_proposal=proposal,
        )
    with pytest.raises(ValueError, match="shadow snapshot"):
        PatchPlan(
            plan_id=plan_id,
            snapshot_id="different-snapshot",
            source_generation=3,
            unflatten_proposal=proposal,
            legacy_unflatten_shadow=_shadow(plan_id),
        )


def test_mutated_proposal_is_revalidated_at_route_boundary() -> None:
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    plan = PatchPlan(
        plan_id=_proposal_and_plan_ids()[1],
        snapshot_id="snapshot-1",
        source_generation=3,
        unflatten_proposal=_proposal_and_plan_ids()[0],
    )
    object.__setattr__(plan.unflatten_proposal, "schema_version", 2)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "proposal_invariants_invalid"

    object.__setattr__(plan.unflatten_proposal, "schema_version", 1)
    object.__setattr__(plan.unflatten_proposal, "rule_set_version", 2)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "proposal_invariants_invalid"

    object.__setattr__(plan.unflatten_proposal, "rule_set_version", 1)
    object.__setattr__(plan.unflatten_proposal, "plan_id", "sha256:" + "0" * 64)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "proposal_plan_id_mismatch"


def test_mutated_shadow_is_revalidated_at_route_boundary() -> None:
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    proposal, plan_id = _proposal_and_plan_ids()
    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        unflatten_proposal=proposal,
        legacy_unflatten_shadow=_shadow(plan_id),
    )
    object.__setattr__(plan.legacy_unflatten_shadow, "schema_version", 2)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "shadow_invariants_invalid"

    object.__setattr__(plan.legacy_unflatten_shadow, "schema_version", 1)
    object.__setattr__(plan.legacy_unflatten_shadow.entries[0], "payload_sha256", "0" * 64)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "shadow_invariants_invalid"

    object.__setattr__(plan.legacy_unflatten_shadow.entries[0], "payload_sha256", hashlib.sha256(
        plan.legacy_unflatten_shadow.entries[0].canonical_payload
    ).hexdigest())
    from d810.transforms.unflatten_authority.ids import canonical_bytes
    from d810.transforms.unflatten_authority.model import LegacyShadowEntry

    payload = canonical_bytes({"legacy": 2})
    second = LegacyShadowEntry(
        "use_def_severance_audit", payload, hashlib.sha256(payload).hexdigest()
    )
    object.__setattr__(plan.legacy_unflatten_shadow, "entries", (second, plan.legacy_unflatten_shadow.entries[0]))
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "shadow_invariants_invalid"

    object.__setattr__(plan.legacy_unflatten_shadow, "entries", (plan.legacy_unflatten_shadow.entries[0],) * 2)
    result = select_plan_route(plan)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "shadow_invariants_invalid"


def test_reserved_metadata_shapes_fail_closed_and_cover_all_keys() -> None:
    from d810.transforms.unflatten_authority.proposal import LEGACY_UNFLATTEN_KEYS
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    for index, key in enumerate(sorted(LEGACY_UNFLATTEN_KEYS)):
        proposal, plan_id = _proposal_and_plan_ids()
        plan = PatchPlan(
            plan_id=plan_id,
            snapshot_id="snapshot-1",
            source_generation=3,
            unflatten_proposal=proposal,
            metadata=([key, index],),
        )
        result = select_plan_route(plan)
        assert result.reason is UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL
        assert result.key == key

    proposal, plan_id = _proposal_and_plan_ids()
    mapping_shape = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        unflatten_proposal=proposal,
        metadata={"use_def_severance_audit": True},
    )
    result = select_plan_route(mapping_shape)
    assert result.reason is UnflattenAuthorityReason.DUAL_AUTHORITY_CHANNEL

    malformed = PatchPlan(
        plan_id="ordinary",
        snapshot_id="snapshot-1",
    )
    object.__setattr__(malformed, "metadata", (("broken",),))
    result = select_plan_route(malformed)
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert result.detail_code == "metadata_shape_invalid"


def test_route_rejections_cannot_use_success_or_not_applicable_reasons() -> None:
    from d810.transforms.unflatten_authority.model import UnflattenAuthorityReason
    from d810.transforms.unflatten_authority.proposal import (
        ProposalRejected,
        RejectedPlanRoute,
    )

    for cls in (ProposalRejected, RejectedPlanRoute):
        with pytest.raises(ValueError, match="rejection reason"):
            cls(UnflattenAuthorityReason.ACCEPTED, "bad")
        with pytest.raises(ValueError, match="rejection reason"):
            cls(UnflattenAuthorityReason.NOT_APPLICABLE, "bad")


def test_metadata_generator_is_snapshotted_before_route_selection() -> None:
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route
    calls = []

    def metadata_generator():
        calls.append("iterated")
        yield ("ordinary", 1)

    plan = PatchPlan(
        plan_id="ordinary",
        snapshot_id="snapshot",
        metadata=metadata_generator(),
    )
    assert plan.metadata == (("ordinary", 1),)
    assert plan.metadata_dict() == {"ordinary": 1}
    assert select_plan_route(plan).route.value == "ordinary"
    assert plan.metadata_dict() == {"ordinary": 1}
    assert len(calls) == 1


def test_reserved_generator_remains_reserved_before_and_after_metadata_lookup() -> None:
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route
    proposal, plan_id = _proposal_and_plan_ids()
    calls = []

    def metadata_generator():
        calls.append("iterated")
        yield ("use_def_severance_audit", True)

    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        metadata=metadata_generator(),
        unflatten_proposal=proposal,
    )
    assert plan.metadata_dict()["use_def_severance_audit"] is True
    result = select_plan_route(plan)
    assert result.reason.value == "dual_authority_channel"
    assert select_plan_route(plan).reason.value == "dual_authority_channel"
    assert len(calls) == 1


class _ReservedAlias:
    def __hash__(self):
        return hash("use_def_severance_audit")

    def __eq__(self, other):
        return other == "use_def_severance_audit"


class _ExplodingHash:
    def __hash__(self):
        raise RuntimeError("hash exploded")


class _ExplodingPair:
    def __iter__(self):
        raise RuntimeError("pair exploded")


class _ExplodingMapping(dict):
    def items(self):
        raise RuntimeError("mapping exploded")


def test_reserved_scan_precedes_duplicate_collapse_and_aliases_fail_closed() -> None:
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route
    proposal, plan_id = _proposal_and_plan_ids()
    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        metadata=((_ReservedAlias(), 1), ("use_def_severance_audit", 2)),
        unflatten_proposal=proposal,
    )
    result = select_plan_route(plan)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_key_type_invalid"

    hostile = PatchPlan(plan_id="ordinary", snapshot_id="snapshot")
    object.__setattr__(hostile, "metadata", ((_ExplodingHash(), 1),))
    result = select_plan_route(hostile)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_key_type_invalid"

    hostile_pair = PatchPlan(plan_id="ordinary", snapshot_id="snapshot")
    object.__setattr__(hostile_pair, "metadata", (_ExplodingPair(),))
    result = select_plan_route(hostile_pair)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_shape_invalid"

    constructor_hostile = PatchPlan(
        plan_id="ordinary", snapshot_id="snapshot", metadata=_ExplodingMapping()
    )
    result = select_plan_route(constructor_hostile)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_shape_invalid"

    constructor_pair = PatchPlan(
        plan_id="ordinary", snapshot_id="snapshot", metadata=(_ExplodingPair(),)
    )
    result = select_plan_route(constructor_pair)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_shape_invalid"


class _LateAlias(str):
    def __hash__(self):
        return hash("use_def_severance_audit")

    def __eq__(self, other):
        return other == "use_def_severance_audit"


def test_str_subclass_metadata_key_is_not_authority_routing_input() -> None:
    from d810.transforms.unflatten_authority.transaction_api import select_plan_route

    proposal, plan_id = _proposal_and_plan_ids()
    plan = PatchPlan(
        plan_id=plan_id,
        snapshot_id="snapshot-1",
        source_generation=3,
        metadata=((_LateAlias("use_def_severance_audit"), True),),
        unflatten_proposal=proposal,
    )
    result = select_plan_route(plan)
    assert result.reason.value == "malformed_proposal"
    assert result.detail_code == "metadata_key_type_invalid"
