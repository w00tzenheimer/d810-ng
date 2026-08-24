"""Validation helpers for the typed unflatten proposal channel.

This module validates the producer-owned value without evaluating it. Route
selection belongs to :mod:`transaction_api`; historical envelopes are decoded
only by the persistence codec and are never producer transport here.
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
from d810.transforms.dispatcher_corridor_coverage import (
    DispatcherCorridor,
    DispatcherCorridorCoverage,
    DispatcherRemovalPreflightProof,
    DispatcherRemovalPreflightValidation,
    TerminalSwitchCycleBreakProof,
)
from d810.analyses.control_flow.minimal_state_recovery import (
    CandidatePrefixAlternateCorridorProof,
)
from d810.ir.block_identity import StableBlockIdentity

from .model import (
    CorridorCoverageForecast,
    CorridorCoveragePath,
    CorridorCoveragePathNode,
    CorridorPathDisposition,
    CorridorSemanticExclusion,
    CorridorSubjectLocator,
    BlockSubjectLocator,
    HandlerSubjectLocator,
    ProposedUnflattenContract,
    RetirementAuthorityCatalog,
    RetirementProofContent,
    RetirementProofMember,
    RetirementProofFamily,
    RetirementProofRecord,
    RetirementMemberCatalogRow,
    RetiredDispatcherInfrastructureClaim,
    DetachedDeadHandlerComponentClaim,
    SemanticSubjectKind,
    SemanticSubjectRef,
    SemanticSubjectRole,
    EquivalentSemanticRouteClaim,
    TerminalCycleBreakClaim,
    TerminalKind,
    TerminalSubjectLocator,
    UnflattenClaimKind,
    UnflattenPlanShape,
    UnflattenAuthorityNotApplicable,
    UnflattenAuthorityReason,
    UnflattenPlanRoute,
)
from .producer_api import build_unflatten_plan_input_catalog
from . import producer_api
from .ids import (
    _claim_factory,
    _subject_factory,
    authority_id,
    canonical_bytes,
    content_id,
    validate_canonical_roundtrip,
)
from .legacy_keys import LEGACY_UNFLATTEN_KEYS


@dataclass(frozen=True, slots=True)
class RedirectStepManifest:
    """Canonical, typed redirect steps owned by one finalized PatchPlan."""

    steps: tuple[dict[str, object], ...]
    owner_refs: tuple[NativeBlockRef | LogicalBlockRef, ...]
    digest: str


def corridor_coverage_forecast_from_analysis(
    coverage: DispatcherCorridorCoverage,
    *,
    proposal: ProposedUnflattenContract,
    block_refs_by_serial: dict[int, NativeBlockRef | LogicalBlockRef],
) -> CorridorCoverageForecast:
    """Seal producer coverage directly into the typed proposal vocabulary.

    The emitter already owns the immutable corridor analysis.  This adapter
    only changes its identity representation; it deliberately does not emit
    a legacy payload and parse that payload back into authority objects.
    """

    if type(proposal) is not ProposedUnflattenContract:
        raise TypeError("coverage forecast requires a closed proposal")
    if type(coverage) is not DispatcherCorridorCoverage:
        raise TypeError("coverage analysis must be DispatcherCorridorCoverage")
    catalog = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }
    refs_by_serial = dict(block_refs_by_serial)

    def node_coords(serial: int, ea: int, label: str) -> CorridorCoveragePathNode:
        serial = int(serial)
        ea = int(ea)
        ref = refs_by_serial.get(serial)
        if ref is None or ref not in catalog or catalog[ref].anchor_ea != ea:
            raise ValueError(f"coverage {label} is foreign to source catalog")
        return CorridorCoveragePathNode(ref, ea)

    dispatcher_anchor = coverage.dispatcher
    if dispatcher_anchor is None:
        raise ValueError("coverage forecast requires a dispatcher anchor")
    dispatcher_node = node_coords(
        dispatcher_anchor.serial, dispatcher_anchor.ea, "dispatcher"
    )
    dispatcher_ref = dispatcher_node.block_ref
    if dispatcher_ref != proposal.plan_inputs.dispatcher_entry_ref:
        raise ValueError("coverage dispatcher differs from proposal entry")

    exclusions: list[CorridorSemanticExclusion] = []
    exclusion_suffixes: dict[str, tuple[tuple[int, int], ...]] = {}
    for raw in coverage.semantic_exclusions:
        if type(raw) is not CandidatePrefixAlternateCorridorProof:
            raise TypeError("coverage semantic exclusions must be canonical proofs")
        source = node_coords(
            raw.source_serial, raw.source_ea,
            "semantic exclusion source",
        )
        feeder = None
        if raw.feeder_serial is not None:
            feeder = node_coords(
                raw.feeder_serial, raw.feeder_ea,
                "semantic exclusion feeder",
            )
        prefix = node_coords(
            raw.prefix_serial, raw.prefix_ea,
            "semantic exclusion prefix",
        )
        root = node_coords(
            raw.root_serial, raw.root_ea,
            "semantic exclusion root",
        )
        typed = (
            "unflatten.corridor-semantic-exclusion.v1",
            int(raw.normalized_state) & 0xFFFFFFFF,
            raw.state_identity,
            source,
            feeder,
            prefix,
            root,
        )
        exclusion_id = authority_id(typed)
        exclusion = CorridorSemanticExclusion(
            exclusion_id,
            authority_id(("unflatten.corridor-semantic-exclusion-digest.v1", typed)),
            int(raw.normalized_state) & 0xFFFFFFFF,
            raw.state_identity,
            source,
            feeder,
            prefix,
            root,
        )
        exclusions.append(exclusion)
        suffix = [(int(raw.source_serial), int(raw.source_ea))]
        if feeder is not None:
            suffix.append((int(raw.feeder_serial), int(raw.feeder_ea)))
        suffix.extend(
            (
                (int(raw.prefix_serial), int(raw.prefix_ea)),
                (int(raw.root_serial), int(raw.root_ea)),
            )
        )
        exclusion_suffixes[exclusion_id] = tuple(suffix)

    def path_row(corridor: DispatcherCorridor, disposition: CorridorPathDisposition) -> CorridorCoveragePath:
        if type(corridor) is not DispatcherCorridor:
            raise TypeError("coverage paths must be canonical corridors")
        anchors = tuple(
            node_coords(anchor.serial, anchor.ea, "corridor path")
            for anchor in corridor.path
        )
        state_merge = (
            None
            if corridor.state_merge is None
            else node_coords(
                corridor.state_merge.serial,
                corridor.state_merge.ea,
                "corridor state merge",
            )
        )
        path_exclusions = tuple(
            exclusion_id
            for exclusion_id, suffix in exclusion_suffixes.items()
            if len(corridor.path) >= len(suffix)
            and tuple(
                (int(anchor.serial), int(anchor.ea))
                for anchor in corridor.path[-len(suffix):]
            ) == suffix
        )
        actual_disposition = (
            CorridorPathDisposition.SEMANTICALLY_EXCLUDED
            if path_exclusions
            else disposition
        )
        path_id = authority_id((
            "unflatten.corridor-coverage-path.v1", anchors, state_merge,
            actual_disposition, path_exclusions,
        ))
        return CorridorCoveragePath(
            path_id, anchors, state_merge, actual_disposition, path_exclusions,
        )

    covered = tuple(
        path_row(corridor, CorridorPathDisposition.STRUCTURALLY_COVERED)
        for corridor in coverage.covered_corridors
    )
    residual = tuple(
        path_row(corridor, CorridorPathDisposition.RESIDUAL)
        for corridor in coverage.residual_corridors
    )
    paths = tuple(sorted((*covered, *residual), key=lambda path: path.path_id))
    covered_ids = tuple(path.path_id for path in paths if path.disposition is not CorridorPathDisposition.RESIDUAL)
    residual_ids = tuple(path.path_id for path in paths if path.disposition is CorridorPathDisposition.RESIDUAL)
    exclusion_rows = tuple(sorted(exclusions, key=lambda item: item.exclusion_id))
    digest_rows = tuple((item.exclusion_id, item.digest) for item in exclusion_rows)
    linked_paths = tuple(
        (item.exclusion_id, tuple(path.path_id for path in paths if item.exclusion_id in path.semantic_exclusion_ids))
        for item in exclusion_rows
    )
    forecast_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", proposal.plan_id,
        int(coverage.function_ea), proposal.source_identity_catalog.native_key,
        proposal.source_identity_catalog.generation, dispatcher_ref,
        dispatcher_node.anchor_ea, paths, covered_ids, residual_ids,
        bool(coverage.enumeration_complete), digest_rows, exclusion_rows, linked_paths,
    ))
    return CorridorCoverageForecast(
        forecast_id, proposal.plan_id, int(coverage.function_ea),
        proposal.source_identity_catalog.native_key,
        proposal.source_identity_catalog.generation, dispatcher_ref,
        dispatcher_node.anchor_ea, paths, covered_ids, residual_ids,
        bool(coverage.enumeration_complete), digest_rows, exclusion_rows, linked_paths,
    )


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


def claims_from_dispatcher_removal_validation(
    validation: DispatcherRemovalPreflightValidation,
    *,
    proposal: ProposedUnflattenContract,
    block_refs_by_serial: dict[int, NativeBlockRef | LogicalBlockRef],
) -> tuple[RetiredDispatcherInfrastructureClaim | DetachedDeadHandlerComponentClaim | TerminalCycleBreakClaim, ...]:
    """Convert producer removal proof objects directly into typed claims."""

    if type(validation) is not DispatcherRemovalPreflightValidation:
        raise TypeError("dispatcher removal validation must be canonical")
    proof = validation.proof
    if proof is not None and type(proof) is not DispatcherRemovalPreflightProof:
        raise TypeError("dispatcher removal proof must be canonical")
    if proof is None:
        return ()
    terminal = validation.terminal_switch_cycle_break
    if terminal is not None and type(terminal) is not TerminalSwitchCycleBreakProof:
        raise TypeError("terminal switch proof must be canonical")
    catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
    refs_by_serial = dict(block_refs_by_serial)
    plan_refs = tuple(sorted(proposal.plan_inputs.dispatcher_member_refs, key=canonical_bytes))
    entry_ref = proposal.plan_inputs.dispatcher_entry_ref
    entry = catalog.get(entry_ref)
    if entry is None:
        raise ValueError("dispatcher entry is absent from source catalog")
    handler_inputs = {
        item.block_ref: item for item in proposal.plan_inputs.authoritative_handlers
    }

    def resolve(anchor: object, label: str):
        serial, ea = int(anchor.serial), int(anchor.ea)
        ref = refs_by_serial.get(serial)
        witness = catalog.get(ref)
        if ref is None or witness is None or witness.anchor_ea != ea:
            raise ValueError(f"dispatcher removal {label} is foreign to source catalog")
        return ref, ea

    if terminal is not None:
        if (
            not validation.passed
            or validation.reason != "terminal_switch_cycle_break"
            or proof.passed
            or proof.reason != "untyped_lost_block"
            or any(
                allowance is not None
                for allowance in (
                    validation.interval_state_normalizer_retirement,
                    validation.state_transition_plumbing_retirement,
                    validation.comparison_corridor_retirement,
                )
            )
        ):
            raise ValueError("terminal switch allowance envelope is not canonical")

        dispatcher_ref, dispatcher_ea = resolve(terminal.dispatcher, "terminal dispatcher")
        if dispatcher_ref != entry_ref:
            raise ValueError("terminal switch dispatcher differs from plan entry")
        source_ref, source_ea = resolve(terminal.terminal_source, "terminal source")
        merge_ref, merge_ea = resolve(terminal.shared_merge, "shared merge")
        target_ref, target_ea = resolve(terminal.terminal_target, "terminal target")
        stop_ref, stop_ea = resolve(terminal.terminal_stop, "terminal stop")
        residue_rows = tuple(
            resolve(anchor, "retired residue") for anchor in terminal.retired_residue
        )
        residue_refs = tuple(ref for ref, _ea in residue_rows)
        residue_anchors = tuple(ea for _ref, ea in residue_rows)
        if (
            not residue_refs
            or len(set(residue_refs)) != len(residue_refs)
            or entry_ref not in residue_refs
            or merge_ref not in residue_refs
            or not set(residue_refs) <= set(plan_refs)
        ):
            raise ValueError("terminal switch residue is not an exact plan subset")
        residue_serials = frozenset(
            int(anchor.serial) for anchor in terminal.retired_residue
        )
        if proof.lost_blocks != residue_serials:
            raise ValueError("terminal switch residue disagrees with lost blocks")
        if tuple(proof.lost_block_anchors) != tuple(terminal.retired_residue):
            raise ValueError("terminal switch residue disagrees with lost anchors")
        for retired in proof.retired_infrastructure:
            resolve(retired.anchor, "retired infrastructure")

        def stable_identity(ref, label: str):
            witness = catalog.get(ref)
            if witness is None:
                raise ValueError(f"terminal {label} is foreign to source catalog")
            if type(ref) is NativeBlockRef:
                return ref.identity
            return StableBlockIdentity.from_instruction_eas(
                witness.native_instruction_eas,
                native_key=proposal.source_identity_catalog.native_key,
            )

        source_identity = stable_identity(source_ref, "source")
        target_identity = stable_identity(target_ref, "target")
        matching_proofs = []
        for route_proof in proposal.route_evidence.route_proofs:
            terminal_destinations = tuple(
                destination
                for destination in route_proof.destinations
                if destination.terminal
            )
            if (
                route_proof.source_identity == source_identity
                and route_proof.source_anchor_ea == source_ea
                and len(terminal_destinations) == 1
                and terminal_destinations[0].target_identity == target_identity
                and terminal_destinations[0].target_anchor_ea == target_ea
            ):
                matching_proofs.append(route_proof)
        if len(matching_proofs) != 1:
            raise ValueError("terminal switch route proof is absent or ambiguous")
        route_proof = matching_proofs[0]
        selected_route_claims = tuple(
            claim
            for claim in proposal.claims
            if type(claim) is EquivalentSemanticRouteClaim
            and route_proof.proof_id in claim.route_proof_ids
        )
        if len(selected_route_claims) != 1:
            raise ValueError("terminal switch route proof is not selected")

        cycle = _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.CORRIDOR,
            role=SemanticSubjectRole.DISPATCHER_CORRIDOR,
            block_ref=dispatcher_ref,
            anchor_ea=dispatcher_ea,
            locator=CorridorSubjectLocator(
                authority_id(("unflatten.terminal-cycle.v1", proposal.plan_id, residue_refs)),
                dispatcher_ref,
                dispatcher_ea,
                residue_refs,
                residue_anchors,
            ),
        )
        cleanup = _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.BLOCK,
            role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
            block_ref=merge_ref,
            anchor_ea=merge_ea,
            locator=BlockSubjectLocator(merge_ref, merge_ea),
        )
        terminal_subject = _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.TERMINAL,
            role=SemanticSubjectRole.TERMINAL_SITE,
            block_ref=stop_ref,
            anchor_ea=stop_ea,
            locator=TerminalSubjectLocator(stop_ref, stop_ea, TerminalKind.STOP, stop_ea),
        )
        return (_claim_factory(
            TerminalCycleBreakClaim,
            kind=UnflattenClaimKind.TERMINAL_CYCLE_BREAK,
            cycle_subject=cycle,
            cleanup_source_subject=cleanup,
            terminal_subject=terminal_subject,
            terminal_route_proof_ids=(route_proof.proof_id,),
            source_generation=proposal.source_identity_catalog.generation,
        ),)

    detached = validation.detached_dead_handler_component
    if detached is not None:
        if (
            not validation.passed
            or validation.reason != "detached_dead_handler_component"
            or proof.passed
            or proof.reason != "untyped_lost_block"
        ):
            raise ValueError("detached component allowance envelope is not canonical")
        dispatcher_ref, dispatcher_ea = resolve(detached.dispatcher, "detached dispatcher")
        if dispatcher_ref != entry_ref:
            raise ValueError("detached dispatcher differs from plan entry")

        def handler_subject(anchor, label):
            ref, ea = resolve(anchor, label)
            handler_input = handler_inputs.get(ref)
            if handler_input is None or int(handler_input.anchor_ea) != ea:
                raise ValueError(f"detached {label} is not an authoritative source handler")
            return _subject_factory(
                SemanticSubjectRef, kind=SemanticSubjectKind.HANDLER,
                role=SemanticSubjectRole.AUTHORITATIVE_HANDLER,
                block_ref=ref, anchor_ea=ea,
                locator=HandlerSubjectLocator(ref, ea, handler_input.normalized_states),
            )

        def component_subject(anchor):
            ref, ea = resolve(anchor, "detached component")
            return _subject_factory(
                SemanticSubjectRef, kind=SemanticSubjectKind.BLOCK,
                role=SemanticSubjectRole.DETACHED_DEAD_HANDLER_COMPONENT,
                block_ref=ref, anchor_ea=ea, locator=BlockSubjectLocator(ref, ea),
            )

        dead = tuple(handler_subject(anchor, "dead handler") for anchor in detached.dead_handlers)
        retained = tuple(handler_subject(anchor, "retained handler") for anchor in detached.retained_handlers)
        component = tuple(component_subject(anchor) for anchor in detached.component)
        if not dead or not retained or not component:
            raise ValueError("detached component content is incomplete")
        if len({item.block_ref for item in dead}) != len(dead) or len({item.block_ref for item in retained}) != len(retained) or len({item.block_ref for item in component}) != len(component):
            raise ValueError("detached component anchors are duplicate")
        if {item.block_ref for item in dead} & {item.block_ref for item in retained}:
            raise ValueError("detached handler partitions overlap")
        if not {item.block_ref for item in dead} <= {item.block_ref for item in component}:
            raise ValueError("detached component omits a dead handler")
        dispatcher = _subject_factory(
            SemanticSubjectRef, kind=SemanticSubjectKind.BLOCK,
            role=SemanticSubjectRole.DISPATCHER_ENTRY,
            block_ref=dispatcher_ref, anchor_ea=dispatcher_ea,
            locator=BlockSubjectLocator(dispatcher_ref, dispatcher_ea),
        )
        return (_claim_factory(
            DetachedDeadHandlerComponentClaim,
            kind=UnflattenClaimKind.DETACHED_DEAD_HANDLER_COMPONENT,
            dispatcher_subject=dispatcher, dead_handler_subjects=dead,
            retained_handler_subjects=retained, component_subjects=component,
            source_generation=proposal.source_identity_catalog.generation,
        ),)

    if not validation.passed or not proof.passed:
        return ()

    retired_rows = tuple(proof.retired_infrastructure)
    retired_by_ref = {
        resolve(row.anchor, "retired member")[0]: str(row.role)
        for row in retired_rows
    }
    if any(ref not in plan_refs for ref in retired_by_ref):
        raise ValueError("dispatcher removal member is outside proposal catalog")
    claims: list[RetiredDispatcherInfrastructureClaim | TerminalCycleBreakClaim] = []
    if retired_by_ref:
        family = RetirementProofFamily.RETIRED_INFRASTRUCTURE
        member_rows = tuple(
            (
                ref,
                int(catalog[ref].anchor_ea),
                ref in retired_by_ref,
                retired_by_ref.get(ref, "comparison_dispatcher"),
            )
            for ref in plan_refs
        )
        content = RetirementProofContent(
            family,
            proposal.source_identity_catalog.generation,
            tuple(
                RetirementProofMember(ref, anchor, retired, role)
                for ref, anchor, retired, role in member_rows
            ),
        )
        record = RetirementProofRecord(
            authority_id(("unflatten.retirement-proof.v3", canonical_bytes(content))),
            content,
        )
        members = tuple(
            RetirementMemberCatalogRow(
                ref, int(catalog[ref].anchor_ea), catalog[ref].native_instruction_eas,
                proposal.source_identity_catalog.generation, ref in retired_by_ref,
                (record,) if ref in retired_by_ref else (),
            ) for ref in plan_refs
        )
        retirement_catalog = RetirementAuthorityCatalog(
            authority_id(("unflatten.retirement-catalog.v1",
                          proposal.source_identity_catalog.generation, members, (record,))),
            proposal.source_identity_catalog.generation, members, (record,),
        )
        member_subjects = tuple(
            _subject_factory(
                SemanticSubjectRef,
                kind=SemanticSubjectKind.BLOCK,
                role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=ref, anchor_ea=int(catalog[ref].anchor_ea),
                locator=BlockSubjectLocator(ref, int(catalog[ref].anchor_ea)),
            ) for ref in plan_refs if ref in retired_by_ref
        )
        corridor = _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.CORRIDOR,
            role=SemanticSubjectRole.DISPATCHER_CORRIDOR,
            block_ref=entry_ref, anchor_ea=int(entry.anchor_ea),
            locator=CorridorSubjectLocator(
                content_id("unflatten.corridor.v1", plan_refs), entry_ref,
                int(entry.anchor_ea), plan_refs,
                tuple(int(catalog[ref].anchor_ea) for ref in plan_refs),
            ),
        )
        infrastructure = next(
            (item for item in member_subjects if item.block_ref == entry_ref),
            _subject_factory(
                SemanticSubjectRef,
                kind=SemanticSubjectKind.BLOCK,
                role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=entry_ref, anchor_ea=int(entry.anchor_ea),
                locator=BlockSubjectLocator(entry_ref, int(entry.anchor_ea)),
            ),
        )
        claims.append(_claim_factory(
            RetiredDispatcherInfrastructureClaim,
            kind=UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
            infrastructure_subject=infrastructure, corridor_subject=corridor,
            member_subjects=member_subjects,
            retirement_proof_ids=(record.proof_id,),
            source_generation=proposal.source_identity_catalog.generation,
            retirement_catalog=retirement_catalog,
        ))
    return tuple(claims)


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
    corridor_coverage=None,
    dispatcher_removal_validation=None,
) -> PatchPlan:
    """Attach one typed proposal from producer-owned typed evidence."""

    if type(plan) is not PatchPlan:
        raise TypeError("typed proposal attachment requires a PatchPlan")
    if plan.unflatten_proposal is not None:
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
    if any(key in LEGACY_UNFLATTEN_KEYS for key, _value in metadata_items):
        raise ValueError("typed producer plans cannot carry reserved legacy metadata")
    if corridor_coverage is not None:
        proposal = replace(
            proposal,
            corridor_coverage_forecast=corridor_coverage_forecast_from_analysis(
                corridor_coverage,
                proposal=proposal,
                block_refs_by_serial=block_refs_by_serial,
            ),
        )
    if dispatcher_removal_validation is not None:
        claims = claims_from_dispatcher_removal_validation(
            dispatcher_removal_validation,
            proposal=proposal,
            block_refs_by_serial=block_refs_by_serial,
        )
        if claims:
            retired_refs = {
                member.block_ref
                for claim in claims
                if type(claim) is RetiredDispatcherInfrastructureClaim
                for member in claim.member_subjects
            }
            dispatcher_refs = set(proposal.plan_inputs.dispatcher_member_refs)
            proposal = replace(
                proposal,
                claims=tuple(sorted((*proposal.claims, *claims), key=lambda item: item.claim_id)),
                plan_inputs=replace(
                    proposal.plan_inputs,
                    shape=UnflattenPlanShape.FULL_DISPATCHER_RETIREMENT
                    if retired_refs == dispatcher_refs
                    else UnflattenPlanShape.PARTIAL_REWRITE,
                ),
                retirement_catalog=next(
                    (claim.retirement_catalog for claim in claims
                     if type(claim) is RetiredDispatcherInfrastructureClaim),
                    proposal.retirement_catalog,
                ),
            )
    if (
        proposal.retirement_catalog is not None
        or any(type(claim) is RetiredDispatcherInfrastructureClaim for claim in proposal.claims)
    ) and proposal.corridor_coverage_forecast is None:
        raise ValueError("corridor rewrite or retirement proposal requires coverage metadata")
    return replace(plan, metadata=metadata_items, unflatten_proposal=proposal)


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
    "TypedProposalRoute",
    "reserved_metadata_keys",
    "retirement_member_catalog",
    "validate_proposal",
    "attach_typed_proposal",
    "claims_from_dispatcher_removal_validation",
]
