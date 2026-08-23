"""Validation helpers for the typed unflatten proposal channel.

This module validates the producer-owned value without evaluating it.  Route
selection belongs to :mod:`transaction_api`; the temporary legacy envelope is
transport only and is never converted into authority here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from d810.core.typing import Literal, TypeAlias
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef, PlanBlockRef
from d810.transforms.plan import (
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
    normalized_metadata_items,
)

from .model import (
    BlockSubjectLocator,
    CorridorSubjectLocator,
    LegacyUnflattenShadowEnvelope,
    ProposedUnflattenContract,
    RetirementMemberCatalogRow,
    RetiredDispatcherInfrastructureClaim,
    SemanticSubjectRole,
    UnflattenPlanShape,
    UnflattenAuthorityNotApplicable,
    UnflattenAuthorityReason,
    UnflattenPlanRoute,
)
from .producer_api import build_unflatten_plan_input_catalog
from . import producer_api
from .ids import content_id, validate_canonical_roundtrip
from .legacy_keys import LEGACY_UNFLATTEN_KEYS
from .legacy_keys import (
    DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    DISPATCHER_CORRIDOR_COVERAGE_METADATA,
)


@dataclass(frozen=True, slots=True)
class RedirectStepManifest:
    """Canonical, typed redirect steps owned by one finalized PatchPlan."""

    steps: tuple[dict[str, object], ...]
    owner_refs: tuple[NativeBlockRef | LogicalBlockRef, ...]
    digest: str


def retirement_member_catalog(
    proposal: ProposedUnflattenContract,
    claim: RetiredDispatcherInfrastructureClaim,
) -> tuple[RetirementMemberCatalogRow, ...]:
    """Validate and return all planned dispatcher members, retired or retained."""

    if type(proposal) is not ProposedUnflattenContract:
        raise TypeError("retirement catalog requires a closed proposal")
    if type(claim) is not RetiredDispatcherInfrastructureClaim:
        raise TypeError("retirement catalog requires a closed retirement claim")
    source_catalog = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }
    plan_refs = tuple(proposal.plan_inputs.dispatcher_member_refs)
    if not plan_refs:
        raise ValueError("retirement plan has no dispatcher members")
    if claim.source_generation != proposal.source_identity_catalog.generation:
        raise ValueError("retirement claim generation differs from source catalog")
    if proposal.retirement_catalog is None or claim.retirement_catalog != proposal.retirement_catalog:
        raise ValueError("retirement claim is not bound to proposal catalog")
    catalog_rows = {item.block_ref: item for item in proposal.retirement_catalog.members}
    if claim.infrastructure_subject.block_ref != proposal.plan_inputs.dispatcher_entry_ref:
        raise ValueError("retirement infrastructure subject is not the dispatcher entry")
    corridor = claim.corridor_subject.locator
    if type(corridor) is not CorridorSubjectLocator:
        raise ValueError("retirement claim corridor locator is not closed")
    entry = source_catalog.get(proposal.plan_inputs.dispatcher_entry_ref)
    if entry is None:
        raise ValueError("dispatcher entry is absent from source catalog")
    catalog_order = tuple(item.block_ref for item in proposal.retirement_catalog.members)
    if (
        corridor.entry_ref != proposal.plan_inputs.dispatcher_entry_ref
        or corridor.entry_anchor_ea != entry.anchor_ea
        or tuple(corridor.member_refs) != catalog_order
        or tuple(corridor.member_anchor_eas)
        != tuple(source_catalog[ref].anchor_ea for ref in catalog_order)
    ):
        raise ValueError("retirement corridor is not the exact plan member catalog")
    retired_by_ref = {member.block_ref: member for member in claim.member_subjects}
    if len(retired_by_ref) != len(claim.member_subjects) or any(
        ref not in plan_refs for ref in retired_by_ref
    ):
        raise ValueError("retirement members must be an exact plan-member subset")
    rows: list[RetirementMemberCatalogRow] = []
    for ref in plan_refs:
        witness = source_catalog.get(ref)
        if witness is None:
            raise ValueError("dispatcher member is absent from source catalog")
        member = retired_by_ref.get(ref)
        exact_row = catalog_rows.get(ref)
        if exact_row is None:
            raise ValueError("retirement member is absent from exact catalog")
        if member is not None:
            if (
                member.role is not SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
                or type(member.locator) is not BlockSubjectLocator
                or member.anchor_ea != witness.anchor_ea
            ):
                raise ValueError("retirement member identity drifted from source catalog")
        if exact_row.anchor_ea != witness.anchor_ea or exact_row.native_instruction_eas != witness.native_instruction_eas:
            raise ValueError("retirement catalog native identity drifted")
        rows.append(exact_row)
    return tuple(rows)


def _redirect_owner_sort_key(
    ref: NativeBlockRef | LogicalBlockRef,
) -> tuple[object, ...]:
    if type(ref) is LogicalBlockRef:
        return ("logical", ref.session_id, ref.proxy_token, ref.version)
    identity = ref.identity
    return (
        "native",
        identity.native_key.to_json(),
        tuple(sorted(identity.exact_instruction_eas)),
        tuple((item.start_ea, item.end_ea) for item in identity.native_ranges.intervals),
    )


def _validate_redirect_ref(
    plan: PatchPlan, value: object, field_name: str, *, source_owner: bool = False,
) -> None:
    allowed = (NativeBlockRef, LogicalBlockRef, PlanBlockRef)
    if type(value) not in allowed:
        raise TypeError(f"redirect {field_name} must be an exact typed block reference")
    if source_owner and type(value) is PlanBlockRef:
        raise ValueError("redirect source owner must be a source block reference")
    if type(value) is PlanBlockRef and value.plan_id != plan.plan_id:
        raise ValueError("redirect plan-owned reference belongs to a foreign plan")


def _validate_redirect_step(plan: PatchPlan, step: object) -> None:
    if type(step) not in (PatchRedirectGoto, PatchRedirectBranch):
        if isinstance(step, PatchRedirectGoto):
            raise TypeError("redirect step subclasses are unsupported")
        return
    _validate_redirect_ref(plan, step.from_serial, "source owner", source_owner=True)
    _validate_redirect_ref(plan, step.old_target, "old target")
    _validate_redirect_ref(plan, step.new_target, "new target")
    if type(step) is PatchRedirectBranch:
        helper = step.fallthrough_helper_block_id
        if helper is not None and type(helper) is not PlanBlockRef:
            raise TypeError("branch fallthrough helper must be an exact PlanBlockRef")
        if helper is not None and helper.plan_id != plan.plan_id:
            raise ValueError("branch fallthrough helper belongs to a foreign plan")


def canonical_redirect_manifest(plan: PatchPlan) -> RedirectStepManifest:
    """Return the one canonical redirect manifest used by proposal validation.

    The manifest includes every redirect step in plan order and all of its
    typed fields.  Source owners are the typed ``from_serial`` references,
    never backend serials or plan-local helper references.
    """

    if type(plan) is not PatchPlan:
        raise TypeError("redirect manifest requires a PatchPlan")
    rows: list[dict[str, object]] = []
    owners: list[NativeBlockRef | LogicalBlockRef] = []
    for index, step in enumerate(plan.steps):
        _validate_redirect_step(plan, step)
        if type(step) not in (PatchRedirectGoto, PatchRedirectBranch):
            continue
        if type(step) is PatchRedirectBranch:
            row = {
                "index": index,
                "step_type": "PatchRedirectBranch",
                "from_ref": step.from_serial,
                "old_target": step.old_target,
                "new_target": step.new_target,
                "fallthrough_helper_block_id": step.fallthrough_helper_block_id,
            }
        elif type(step) is PatchRedirectGoto:
            row = {
                "index": index,
                "step_type": "PatchRedirectGoto",
                "from_ref": step.from_serial,
                "old_target": step.old_target,
                "new_target": step.new_target,
            }
        else:
            continue
        rows.append(row)
        owners.append(step.from_serial)
    if not rows:
        raise ValueError("typed proposal requires a non-empty redirect manifest")
    owner_refs = tuple(sorted(set(owners), key=_redirect_owner_sort_key))
    manifest_rows = tuple(rows)
    return RedirectStepManifest(
        steps=manifest_rows,
        owner_refs=owner_refs,
        digest=content_id(
            "unflatten.use-def.redirect-manifest.v1", manifest_rows
        ),
    )


# Public for the codec/router seam and tests.  It is assembled from the
# current owners above, so this backstop cannot drift by omission.


class MetadataKeyTypeError(ValueError):
    """A metadata key is not a closed, exact ``str`` routing input."""


def reserved_metadata_keys(plan: PatchPlan) -> tuple[str, ...]:
    """Return reserved top-level metadata keys in stable metadata order."""

    keys: list[str] = []
    try:
        raw_items = normalized_metadata_items(plan.metadata)
        # Validate the key domain before invoking dict/set hash or equality
        # semantics.  In particular, a str subclass or arbitrary alias must
        # not get an opportunity to impersonate a reserved key.
        for key, _value in raw_items:
            if type(key) is not str:
                raise MetadataKeyTypeError("metadata keys must be exact str")
        dict(raw_items)
        for key, _value in raw_items:
            if key in LEGACY_UNFLATTEN_KEYS:
                keys.append(key)
    except MetadataKeyTypeError:
        raise
    except Exception as exc:
        raise ValueError("metadata key inspection failed") from exc
    return tuple(keys)


@dataclass(frozen=True, slots=True)
class ProposalAccepted:
    """A validated typed proposal bound to one exact plan."""

    proposal: ProposedUnflattenContract

    def __post_init__(self) -> None:
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("proposal must be a ProposedUnflattenContract")


@dataclass(frozen=True, slots=True)
class ProposalRejected:
    """A typed proposal rejection with an exhaustive authority reason."""

    reason: UnflattenAuthorityReason
    detail_code: str
    key: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, UnflattenAuthorityReason):
            raise TypeError("reason must be an UnflattenAuthorityReason")
        if self.reason in (
            UnflattenAuthorityReason.ACCEPTED,
            UnflattenAuthorityReason.NOT_APPLICABLE,
        ):
            raise ValueError("rejection reason must describe rejection")
        if not isinstance(self.detail_code, str) or not self.detail_code.strip():
            raise ValueError("detail_code must not be blank")
        if self.key is not None and self.key not in LEGACY_UNFLATTEN_KEYS:
            raise ValueError("key must be a reserved unflatten metadata key")


ProposalValidationResult: TypeAlias = ProposalAccepted | ProposalRejected


def validate_proposal(
    plan: PatchPlan,
    proposal: object,
) -> ProposalValidationResult:
    """Validate exact proposal type and plan correlation without evaluation."""

    if type(proposal) is not ProposedUnflattenContract:
        return ProposalRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "proposal_type_is_not_closed",
        )
    if proposal.plan_id != plan.plan_id:
        return ProposalRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "proposal_plan_id_mismatch",
        )
    try:
        validate_canonical_roundtrip(proposal, ProposedUnflattenContract)
        ProposedUnflattenContract.__post_init__(proposal)
        _validate_use_def_locator(plan, proposal)
        for claim in proposal.claims:
            if type(claim) is RetiredDispatcherInfrastructureClaim:
                retirement_member_catalog(proposal, claim)
        source_blocks = proposal.source_identity_catalog.blocks
        if source_blocks and all(
            type(block.block_ref) is NativeBlockRef for block in source_blocks
        ):
            source_serial_by_ref = {
                block.block_ref: serial
                for serial, block in enumerate(source_blocks)
            }
            for claim in proposal.claims:
                if type(claim) is not producer_api.ExactInfeasibleEffectClaim:
                    continue
                if producer_api.validate_exact_effect_claim_semantics(
                    proposal=proposal,
                    claim=claim,
                    source_serial_by_ref=source_serial_by_ref,
                ) is None:
                    raise ValueError("exact effect claim semantic correlation is invalid")
    except Exception:
        return ProposalRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "proposal_invariants_invalid",
        )
    return ProposalAccepted(proposal)


def _validate_use_def_locator(
    plan: PatchPlan, proposal: ProposedUnflattenContract
) -> None:
    """Validate the fragment-wide locator against the source catalog.

    The value-flow subject is an aggregate, so it has no block serial or
    primary owner.  Its owner references must nevertheless be an exact,
    non-empty set of source-catalog references; otherwise a producer could
    omit or substitute redirect owners while retaining a superficially valid
    typed proposal.
    """

    if type(plan.source_generation) is not int:
        raise TypeError("typed proposal requires an exact integer source generation")
    catalog = proposal.source_identity_catalog
    if type(catalog.generation) is not int or plan.source_generation != catalog.generation:
        raise ValueError("proposal source generation does not match PatchPlan")
    manifest = canonical_redirect_manifest(plan)
    witness = proposal.use_def_witness
    if tuple(witness.redirect_owner_refs) != manifest.owner_refs:
        raise ValueError("use-def redirect owners do not match the redirect manifest")
    allowed_redirect_owners = set(proposal.plan_inputs.dispatcher_member_refs)
    if not set(witness.redirect_owner_refs) <= allowed_redirect_owners:
        raise ValueError("use-def redirect owners must be dispatcher members")
    if witness.redirect_digest != manifest.digest:
        raise ValueError("use-def redirect digest does not match the redirect manifest")
    catalog_refs = {item.block_ref for item in catalog.blocks}
    if not set(manifest.owner_refs) <= catalog_refs:
        raise ValueError("use-def redirect owner is outside the source catalog")


@dataclass(frozen=True, slots=True)
class TypedProposalRoute:
    """The sole accepted semantic route in this task."""

    route: Literal[UnflattenPlanRoute.TYPED_PROPOSAL]
    proposal: ProposedUnflattenContract

    def __post_init__(self) -> None:
        if self.route is not UnflattenPlanRoute.TYPED_PROPOSAL:
            raise ValueError("typed route must be TYPED_PROPOSAL")
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("typed route proposal must be closed")


@dataclass(frozen=True, slots=True)
class RejectedPlanRoute:
    """A total route-selection rejection."""

    reason: UnflattenAuthorityReason
    detail_code: str
    key: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.reason, UnflattenAuthorityReason):
            raise TypeError("reason must be an UnflattenAuthorityReason")
        if self.reason in (
            UnflattenAuthorityReason.ACCEPTED,
            UnflattenAuthorityReason.NOT_APPLICABLE,
        ):
            raise ValueError("rejection reason must describe rejection")
        if not isinstance(self.detail_code, str) or not self.detail_code.strip():
            raise ValueError("detail_code must not be blank")
        if self.key is not None and self.key not in LEGACY_UNFLATTEN_KEYS:
            raise ValueError("key must be a reserved unflatten metadata key")


PlanRouteResult: TypeAlias = (
    UnflattenAuthorityNotApplicable | TypedProposalRoute | RejectedPlanRoute
)


@dataclass(frozen=True, slots=True)
class ShadowValidationAccepted:
    """The exact shadow transport correlates with its owning plan."""


ShadowValidationResult: TypeAlias = ShadowValidationAccepted | RejectedPlanRoute


def validate_shadow_for_plan(
    plan: PatchPlan,
    shadow: object,
) -> ShadowValidationResult:
    """Return a typed rejection for malformed or stale shadow transport."""

    if type(plan) is not PatchPlan:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "plan_type_is_not_closed",
        )
    if (
        type(plan.plan_id) is not str
        or type(plan.snapshot_id) is not str
        or type(plan.source_generation) is not int
    ):
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_plan_identity_invalid",
        )
    if type(shadow) is not LegacyUnflattenShadowEnvelope:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_type_is_not_closed",
        )
    try:
        LegacyUnflattenShadowEnvelope.__post_init__(shadow)
        from .legacy_wire import decode_legacy_value, encode_legacy_value

        for entry in shadow.entries:
            decoded = decode_legacy_value(entry.canonical_payload)
            if encode_legacy_value(decoded) != entry.canonical_payload:
                raise ValueError("legacy shadow payload is not byte-canonical")
    except Exception:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_invariants_invalid",
        )
    if shadow.plan_id != plan.plan_id:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_plan_id_mismatch",
        )
    if shadow.snapshot_id != plan.snapshot_id:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_snapshot_id_mismatch",
        )
    if shadow.source_generation != plan.source_generation:
        return RejectedPlanRoute(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            "shadow_source_generation_mismatch",
        )
    return ShadowValidationAccepted()


def attach_typed_proposal(
    plan: PatchPlan,
    *,
    source,
    block_refs_by_serial,
    canonical_route_evidence,
    selected_route_proof_ids=None,
    exact_state_effect_exclusions,
    dispatcher_entry_serial,
    dispatcher_member_serials,
    authoritative_handler_serials,
    state_identity,
    use_def_witness,
) -> PatchPlan:
    """Attach one typed proposal and capture all legacy metadata exactly once."""

    if type(plan) is not PatchPlan:
        raise TypeError("typed proposal attachment requires a PatchPlan")
    if plan.unflatten_proposal is not None or plan.legacy_unflatten_shadow is not None:
        raise ValueError("typed proposal attachment may run only once")
    proposal = producer_api.build_proposal(
        plan_id=plan.plan_id,
        source=source,
        block_refs_by_serial=block_refs_by_serial,
        source_generation=plan.source_generation,
        canonical_route_evidence=canonical_route_evidence,
        selected_route_proof_ids=selected_route_proof_ids,
        exact_state_effect_exclusions=exact_state_effect_exclusions,
        dispatcher_entry_serial=dispatcher_entry_serial,
        dispatcher_member_serials=dispatcher_member_serials,
        authoritative_handler_serials=authoritative_handler_serials,
        state_identity=state_identity,
        use_def_witness=use_def_witness,
    )
    metadata_items = tuple(normalized_metadata_items(plan.metadata))
    corridor_rows = tuple(
        value for key, value in metadata_items
        if key == DISPATCHER_CORRIDOR_COVERAGE_METADATA
    )
    if len(corridor_rows) > 1:
        raise ValueError("legacy corridor coverage metadata occurs more than once")
    if corridor_rows:
        corridor_payload = corridor_rows[0]
        from .legacy_codec import corridor_coverage_forecast_from_legacy_metadata
        try:
            forecast = corridor_coverage_forecast_from_legacy_metadata(
                corridor_payload,
                proposal=proposal,
                block_refs_by_serial=block_refs_by_serial,
                source_function_ea=int(source.func_ea),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("legacy corridor coverage conversion failed") from exc
        proposal = replace(proposal, corridor_coverage_forecast=forecast)
    # Legacy retirement families are adapted once into the proposal-owned
    # exact catalog.  The claim remains partial when the proof covers only a
    # subset of planned members.
    retirement_payload = dict(metadata_items).get(
        DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA
    )
    retirement_family_keys = (
        "retired_infrastructure", "retired_state_plumbing", "retired_corridor",
    )
    retirement_present = tuple(
        key for key in retirement_family_keys
        if isinstance(retirement_payload, dict)
        and key in retirement_payload
    )
    if retirement_present:
        from .legacy_codec import retirement_claim_from_legacy_proof

        try:
            if len(retirement_present) != 1:
                raise ValueError("legacy retirement families are ambiguous")
            transport = {retirement_present[0]: retirement_payload[retirement_present[0]]}
            if "proof_ids" in retirement_payload:
                transport["proof_ids"] = retirement_payload["proof_ids"]
            claim = retirement_claim_from_legacy_proof(
                transport,
                proposal=proposal,
                block_refs_by_serial=block_refs_by_serial,
            )
            retired_refs = {member.block_ref for member in claim.member_subjects}
            member_refs = set(proposal.plan_inputs.dispatcher_member_refs)
            if retired_refs and retired_refs <= member_refs:
                shape = (
                    UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT
                    if retired_refs == member_refs
                    else UnflattenPlanShape.PARTIAL_REWRITE
                )
                proposal = replace(
                    proposal,
                    claims=tuple(sorted((*proposal.claims, claim), key=lambda item: item.claim_id)),
                    plan_inputs=replace(
                        proposal.plan_inputs,
                        shape=shape,
                    ),
                    retirement_catalog=claim.retirement_catalog,
                )
        except (TypeError, ValueError) as exc:
            # A supported retirement family is authority input once present;
            # malformed rows fail closed instead of silently becoming a shadow.
            raise ValueError("legacy retirement proof conversion failed") from exc
    if (
        proposal.retirement_catalog is not None
        or any(type(claim) is RetiredDispatcherInfrastructureClaim for claim in proposal.claims)
    ) and proposal.corridor_coverage_forecast is None:
        raise ValueError("corridor rewrite or retirement proposal requires coverage metadata")
    from .legacy_codec import capture_legacy_unflatten_shadow

    cleaned, shadow = capture_legacy_unflatten_shadow(
        plan_id=plan.plan_id,
        snapshot_id=plan.snapshot_id,
        source_generation=plan.source_generation,
        metadata=plan.metadata,
    )
    if shadow is None:
        raise ValueError("typed proposal attachment requires legacy shadow capture")
    return replace(
        plan,
        metadata=cleaned,
        unflatten_proposal=proposal,
        legacy_unflatten_shadow=shadow,
    )


__all__ = [
    "build_unflatten_plan_input_catalog",
    "RedirectStepManifest",
    "canonical_redirect_manifest",
    "LEGACY_UNFLATTEN_KEYS",
    "PlanRouteResult",
    "ProposalAccepted",
    "ProposalRejected",
    "ProposalValidationResult",
    "RejectedPlanRoute",
    "ShadowValidationAccepted",
    "ShadowValidationResult",
    "TypedProposalRoute",
    "reserved_metadata_keys",
    "retirement_member_catalog",
    "validate_proposal",
    "validate_shadow_for_plan",
    "attach_typed_proposal",
]
