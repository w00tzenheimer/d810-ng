"""Exact source/projected identity binding for typed unflatten subjects."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import weakref

from d810.analyses.control_flow.effect_branch_exclusion import (
    ExactStateBranchEffectExclusion,
    validate_exact_state_branch_effect_exclusion,
)
from d810.ir.flowgraph import FlowGraph
from d810.ir.block_identity import StableBlockIdentity
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef, PlanBlockRef
from . import model, producer_api
from .ids import (
    _subject_factory,
    canonical_bytes,
    semantic_graph_fingerprint,
    validate_canonical_roundtrip,
    authority_id,
)
from .proposal import retirement_member_catalog


def _canonical_digest(value: object, label: str) -> None:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ValueError(f"{label} must be a canonical sha256 ID")


def _validate_exact_result_authority(
    *,
    proposal: model.ProposedUnflattenContract,
    exclusion: ExactStateBranchEffectExclusion,
    claim: model.ExactInfeasibleEffectClaim,
    source_serial_by_ref: dict[object, int],
) -> None:
    producer_api.validate_exact_effect_semantics(
        proposal=proposal,
        exclusion=exclusion,
        claim=claim,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=proposal.route_evidence,
        source_serial_by_ref=source_serial_by_ref,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class RetiredInfrastructureBindingResult:
    """Bound retirement members, including exact retained-member rows."""

    claim: model.RetiredDispatcherInfrastructureClaim
    proposal: model.ProposedUnflattenContract
    source_inventory: model.SemanticGraphInventory
    projected_inventory: model.SemanticGraphInventory
    source_catalog: model.SourceIdentityCatalog
    member_catalog: tuple[model.RetirementMemberCatalogRow, ...]
    source_bindings: tuple[model.PhaseSubjectBinding, ...]
    projected_bindings: tuple[model.PhaseSubjectBinding, ...]
    generation: int
    _content_seal: str = field(init=False, repr=False, compare=False)

    def __new__(cls, *args: object, **kwargs: object):
        raise TypeError("RetiredInfrastructureBindingResult can only be minted by bind_retired_dispatcher_infrastructure_claim")

    @property
    def claim_id(self) -> str:
        return self.claim.claim_id

    def _validate_fields(self) -> None:
        if type(self.claim) is not model.RetiredDispatcherInfrastructureClaim:
            raise TypeError("claim must be a closed retirement claim")
        if type(self.proposal) is not model.ProposedUnflattenContract:
            raise TypeError("proposal must be a closed proposal")
        if type(self.source_inventory) is not model.SemanticGraphInventory:
            raise TypeError("source_inventory must be a closed semantic inventory")
        if type(self.projected_inventory) is not model.SemanticGraphInventory:
            raise TypeError("projected_inventory must be a closed semantic inventory")
        model.validate_semantic_graph_inventory(self.source_inventory)
        model.validate_semantic_graph_inventory(self.projected_inventory)
        if self.source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
            raise ValueError("retirement source inventory must be producer forecast")
        if self.projected_inventory.phase not in {
            model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        }:
            raise ValueError("retirement projected inventory phase is stale")
        if self.source_inventory.generation != self.generation:
            raise ValueError("retirement source inventory generation is stale")
        validate_canonical_roundtrip(self.claim, model.RetiredDispatcherInfrastructureClaim)
        validate_canonical_roundtrip(self.proposal, model.ProposedUnflattenContract)
        validate_canonical_roundtrip(self.source_catalog, model.SourceIdentityCatalog)
        if self.claim not in self.proposal.claims:
            raise ValueError("retirement claim is foreign to the proposal")
        if self.generation != self.source_catalog.generation:
            raise ValueError("retirement binding generation is stale")
        expected = retirement_member_catalog(self.proposal, self.claim)
        if tuple(self.member_catalog) != expected:
            raise ValueError("retirement member catalog drifted after bind")
        rows_by_ref = {row.block_ref: row for row in expected}
        expected_subjects = {
            item.block_ref: item for item in self.claim.member_subjects
        }
        expected_ids = {
            expected_subjects.get(ref, _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.BLOCK,
                role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=ref,
                anchor_ea=row.anchor_ea,
                locator=model.BlockSubjectLocator(ref, row.anchor_ea),
            )).subject_id
            for ref, row in rows_by_ref.items()
        }
        source_by_id = {item.subject.subject_id: item for item in self.source_bindings}
        projected_by_id = {item.subject.subject_id: item for item in self.projected_bindings}
        inventory_source_by_id = {
            item.subject.subject_id: item
            for item in self.source_inventory.bindings
            if item.subject.subject_id in expected_ids
        }
        inventory_projected_by_id = {
            item.subject.subject_id: item
            for item in self.projected_inventory.bindings
            if item.subject.subject_id in expected_ids
        }
        if source_by_id != inventory_source_by_id:
            raise ValueError("retirement source bindings are not carried by source inventory")
        if projected_by_id != inventory_projected_by_id:
            raise ValueError("retirement projected bindings are not carried by projected inventory")
        if set(source_by_id) != expected_ids or set(projected_by_id) != expected_ids:
            raise ValueError("retirement binding rows do not cover the exact member catalog")
        expected_order = tuple(sorted(expected_ids))
        if (
            tuple(item.subject.subject_id for item in self.source_bindings) != expected_order
            or tuple(item.subject.subject_id for item in self.projected_bindings) != expected_order
        ):
            raise ValueError("retirement binding rows must preserve canonical subject order")
        native_by_ref = (
            {member.block_ref: member.native_instruction_eas
             for member in self.proposal.retirement_catalog.members}
            if self.proposal.retirement_catalog is not None else {}
        )
        for ref, row in rows_by_ref.items():
            subject = expected_subjects.get(ref, _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.BLOCK,
                role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=ref,
                anchor_ea=row.anchor_ea,
                locator=model.BlockSubjectLocator(ref, row.anchor_ea),
            ))
            source = source_by_id[subject.subject_id]
            projected = projected_by_id[subject.subject_id]
            if (
                source.subject != subject
                or
                source.status is not model.SubjectBindingStatus.UNIQUE
                or source.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
                or source.block_ref != ref
                or source.anchor_ea != row.anchor_ea
                or tuple(source.native_instruction_eas) != tuple(native_by_ref.get(ref, row.native_instruction_eas))
                or source.generation != row.source_generation
            ):
                raise ValueError("retirement source binding is not catalog-bound")
            if (
                projected.subject != subject
                or projected.phase not in {
                    model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                    model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
                }
                or projected.generation != row.source_generation
            ):
                raise ValueError("projected retirement binding is not catalog-bound")
            if row.retired and projected.status is model.SubjectBindingStatus.MISSING:
                if (
                    projected.block_ref is not None
                    or projected.serial is not None
                    or projected.anchor_ea is not None
                    or projected.native_instruction_eas
                ):
                    raise ValueError("retired projected binding is not an authorized missing row")
                continue
            if projected.status is not model.SubjectBindingStatus.UNIQUE:
                raise ValueError("projected retirement binding is not uniquely catalog-bound")
            if (
                projected.block_ref != ref
                or projected.anchor_ea != row.anchor_ea
                or tuple(projected.native_instruction_eas) != tuple(native_by_ref[ref])
            ):
                raise ValueError("retained projected binding drifted from catalog")
            if projected.serial is None:
                raise ValueError("projected retirement binding has no serial")
            if row.retired:
                if projected.serial in self.projected_inventory.reachable_serials:
                    raise ValueError("retired projected binding remains reachable")
            elif projected.serial not in self.projected_inventory.reachable_serials:
                raise ValueError("retained projected binding is unreachable")


def _retirement_binding_seal(result: RetiredInfrastructureBindingResult) -> str:
    catalog_rows = tuple(
        (
            row.block_ref,
            row.anchor_ea,
            row.source_generation,
            tuple(proof.proof_id for proof in row.proofs),
        )
        for row in result.member_catalog
    )
    return "sha256:" + hashlib.sha256(canonical_bytes((
        result.claim, result.proposal, result.source_inventory,
        result.projected_inventory, result.source_catalog,
        catalog_rows, result.source_bindings,
        result.projected_bindings, result.projected_inventory.reachable_serials,
        result.generation,
    ))).hexdigest()


def terminal_cycle_binding_subjects(
    proposal: model.ProposedUnflattenContract,
    claim: model.TerminalCycleBreakClaim,
) -> tuple[model.SemanticSubjectRef, ...]:
    """Return the one closed subject set owned by a terminal-cycle claim."""

    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("terminal-cycle subjects require a closed proposal")
    if type(claim) is not model.TerminalCycleBreakClaim:
        raise TypeError("terminal-cycle subjects require a closed claim")
    if claim not in proposal.claims:
        raise ValueError("terminal-cycle claim is foreign to the proposal")
    cycle_locator = claim.cycle_subject.locator
    if type(cycle_locator) is not model.CorridorSubjectLocator:
        raise ValueError("terminal-cycle corridor binding is not closed")
    residue_refs = tuple(cycle_locator.member_refs)
    residue_anchors = tuple(cycle_locator.member_anchor_eas)
    if (
        not residue_refs
        or len(set(residue_refs)) != len(residue_refs)
        or len(residue_refs) != len(residue_anchors)
        or cycle_locator.entry_ref
        != proposal.plan_inputs.dispatcher_entry_ref
        or not set(residue_refs)
        <= set(proposal.plan_inputs.dispatcher_member_refs)
        or claim.cleanup_source_subject.block_ref not in set(residue_refs)
    ):
        raise ValueError("terminal-cycle residue is not an exact plan subset")
    catalog_by_ref = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }
    residue_subjects: list[model.SemanticSubjectRef] = []
    for ref, anchor in zip(residue_refs, residue_anchors):
        witness = catalog_by_ref.get(ref)
        if witness is None or witness.anchor_ea != anchor:
            raise ValueError(
                "terminal-cycle residue member is foreign to the source catalog"
            )
        residue_subjects.append(
            claim.cleanup_source_subject
            if ref == claim.cleanup_source_subject.block_ref
            else _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.BLOCK,
                role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=ref,
                anchor_ea=anchor,
                locator=model.BlockSubjectLocator(ref, anchor),
            )
        )
    cleanup = catalog_by_ref.get(claim.cleanup_source_subject.block_ref)
    terminal = catalog_by_ref.get(claim.terminal_subject.block_ref)
    if (
        cleanup is None
        or cleanup.anchor_ea != claim.cleanup_source_subject.anchor_ea
        or terminal is None
        or terminal.anchor_ea != claim.terminal_subject.anchor_ea
        or claim.terminal_subject.locator.instruction_ea
        not in terminal.native_instruction_eas
    ):
        raise ValueError("terminal-cycle endpoint is foreign to the source catalog")
    proof = next(
        (
            item
            for item in proposal.route_evidence.route_proofs
            if item.proof_id == claim.terminal_route_proof_ids[0]
        ),
        None,
    )
    if proof is None:
        raise ValueError("terminal-cycle route proof is absent from canonical evidence")
    terminal_destinations = tuple(
        destination for destination in proof.destinations if destination.terminal
    )
    if len(terminal_destinations) != 1:
        raise ValueError(
            "terminal-cycle route proof does not bind one terminal carrier"
        )
    destination = terminal_destinations[0]
    carrier_witnesses = tuple(
        witness for witness in proposal.source_identity_catalog.blocks
        if witness.anchor_ea == destination.target_anchor_ea
        and destination.target_anchor_ea in witness.native_instruction_eas
        and (
            type(witness.block_ref) is not NativeBlockRef
            or witness.block_ref.identity == destination.target_identity
        )
    )
    if len(carrier_witnesses) != 1:
        raise ValueError(
            "terminal-cycle route proof carrier is foreign or ambiguous"
        )
    carrier = carrier_witnesses[0]
    source_witnesses = tuple(
        witness for witness in proposal.source_identity_catalog.blocks
        if witness.anchor_ea == proof.source_anchor_ea
        and proof.source_anchor_ea in witness.native_instruction_eas
        and (
            type(witness.block_ref) is not NativeBlockRef
            or witness.block_ref.identity == proof.source_identity
        )
    )
    if len(source_witnesses) != 1:
        raise ValueError(
            "terminal-cycle route proof source is foreign or ambiguous"
        )
    route_source = source_witnesses[0]
    if route_source.block_ref == claim.cleanup_source_subject.block_ref:
        raise ValueError("terminal route source aliases the cleanup source")
    route_source_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=route_source.block_ref,
        anchor_ea=route_source.anchor_ea,
        locator=model.BlockSubjectLocator(
            route_source.block_ref, route_source.anchor_ea,
        ),
    )
    carrier_subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        block_ref=carrier.block_ref,
        anchor_ea=carrier.anchor_ea,
        locator=model.BlockSubjectLocator(carrier.block_ref, carrier.anchor_ea),
    )
    return tuple(
        sorted(
            {
                item.subject_id: item
                for item in (
                    claim.cycle_subject,
                    claim.cleanup_source_subject,
                    claim.terminal_subject,
                    route_source_subject,
                    carrier_subject,
                    *residue_subjects,
                )
            }.values(),
            key=lambda item: item.subject_id,
        )
    )


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class TerminalCycleBindingResult:
    """Exact source/projected binding for one terminal-cycle allowance."""

    claim: model.TerminalCycleBreakClaim
    proposal: model.ProposedUnflattenContract
    source_bindings: tuple[model.PhaseSubjectBinding, ...]
    projected_bindings: tuple[model.PhaseSubjectBinding, ...]
    residue_refs: tuple[object, ...]
    source_cycle_edges: tuple[tuple[object, object], ...]
    projected_cycle_edges: tuple[tuple[object, object], ...]
    terminal_route_refs: tuple[object, ...]
    generation: int
    projected_generation: int
    phase_result: model.TerminalCyclePhaseResult
    _content_seal: str = field(init=False, repr=False, compare=False)

    def __new__(cls, *args: object, **kwargs: object):
        raise TypeError("TerminalCycleBindingResult can only be minted by bind_terminal_cycle_break_claim")

    @property
    def claim_id(self) -> str:
        return self.claim.claim_id

    def _validate_fields(self) -> None:
        if type(self.claim) is not model.TerminalCycleBreakClaim:
            raise TypeError("claim must be a closed terminal-cycle claim")
        if type(self.proposal) is not model.ProposedUnflattenContract:
            raise TypeError("proposal must be a closed proposal")
        validate_canonical_roundtrip(self.claim, model.TerminalCycleBreakClaim)
        validate_canonical_roundtrip(self.proposal, model.ProposedUnflattenContract)
        if self.claim not in self.proposal.claims:
            raise ValueError("terminal-cycle claim is foreign to the proposal")
        if self.generation != self.proposal.source_identity_catalog.generation:
            raise ValueError("terminal-cycle binding generation is stale")
        if type(self.phase_result) is not model.TerminalCyclePhaseResult:
            raise TypeError("terminal-cycle binding must carry one closed phase result")
        self.phase_result.__post_init__()
        expected_subjects = terminal_cycle_binding_subjects(
            self.proposal, self.claim,
        )
        expected = {
            subject.subject_id: subject for subject in expected_subjects
        }
        cycle_locator = self.claim.cycle_subject.locator
        if tuple(self.residue_refs) != tuple(cycle_locator.member_refs):
            raise ValueError("terminal-cycle residue refs drifted from corridor locator")
        source = {item.subject.subject_id: item for item in self.source_bindings}
        projected = {item.subject.subject_id: item for item in self.projected_bindings}
        if set(source) != set(expected) or set(projected) != set(expected):
            raise ValueError("terminal-cycle bindings do not cover the exact claim subjects")
        expected_order = tuple(sorted(expected))
        if (
            tuple(item.subject.subject_id for item in self.source_bindings)
            != expected_order
            or tuple(item.subject.subject_id for item in self.projected_bindings)
            != expected_order
        ):
            raise ValueError("terminal-cycle bindings must preserve canonical subject order")
        catalog_by_ref = {
            item.block_ref: item
            for item in self.proposal.source_identity_catalog.blocks
        }
        for subject_id, subject in expected.items():
            witness = catalog_by_ref[subject.block_ref]
            source_row = source[subject_id]
            if (
                source_row.subject != subject
                or source_row.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
                or source_row.status is not model.SubjectBindingStatus.UNIQUE
                or source_row.generation != self.generation
                or source_row.block_ref != subject.block_ref
                or source_row.anchor_ea != subject.anchor_ea
                or tuple(source_row.native_instruction_eas)
                != tuple(witness.native_instruction_eas)
            ):
                raise ValueError("terminal-cycle source binding is not catalog-bound")
            projected_row = projected[subject_id]
            if (
                projected_row.subject != subject
                or projected_row.phase not in {
                    model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                    model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
                }
                or projected_row.generation != self.projected_generation
            ):
                raise ValueError("terminal-cycle projected binding is not phase-bound")
            if subject is self.claim.terminal_subject:
                if (
                    projected_row.status is not model.SubjectBindingStatus.UNIQUE
                    or projected_row.block_ref != subject.block_ref
                    or projected_row.anchor_ea != subject.anchor_ea
                    or tuple(projected_row.native_instruction_eas)
                    != tuple(witness.native_instruction_eas)
                ):
                    raise ValueError("terminal subject must remain projected-reachable by identity")
        if not _contains_directed_cycle(
            self.residue_refs, self.source_cycle_edges,
        ):
            raise ValueError("terminal-cycle source residue is not cyclic")
        if _contains_directed_cycle(
            self.residue_refs, self.projected_cycle_edges,
        ):
            raise ValueError("terminal-cycle residual cycle remains projected")
        carrier = next(
            subject for subject in expected_subjects
            if subject.role
            is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
        )
        if (
            not self.terminal_route_refs
            or self.terminal_route_refs[0] != carrier.block_ref
            or self.terminal_route_refs[-1]
            != self.claim.terminal_subject.block_ref
        ):
            raise ValueError(
                "terminal-cycle route does not join its carrier to its terminal"
            )
        phase_result = self.phase_result
        if (
            phase_result.claim_id != self.claim.claim_id
            or phase_result.terminal_route_proof_id
            != self.claim.terminal_route_proof_ids[0]
            or phase_result.source_bindings != self.source_bindings
            or phase_result.candidate_bindings != self.projected_bindings
            or phase_result.residue_refs != self.residue_refs
            or phase_result.source_cycle_edges != self.source_cycle_edges
            or phase_result.candidate_cycle_edges != self.projected_cycle_edges
            or phase_result.terminal_route_refs != self.terminal_route_refs
            or phase_result.source_generation != self.generation
            or phase_result.candidate_generation != self.projected_generation
        ):
            raise ValueError("terminal-cycle phase result drifted from binder facts")


def _terminal_cycle_binding_seal(result: TerminalCycleBindingResult) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes((
        result.claim, result.proposal, result.source_bindings,
        result.projected_bindings, result.residue_refs, result.generation,
        result.projected_generation, result.source_cycle_edges,
        result.projected_cycle_edges, result.terminal_route_refs,
        result.phase_result,
    ))).hexdigest()


def _contains_directed_cycle(
    member_refs: Sequence[object],
    edges: Sequence[tuple[object, object]],
) -> bool:
    members = set(member_refs)
    successors = {ref: set() for ref in members}
    for source_ref, target_ref in edges:
        if source_ref in members and target_ref in members:
            successors[source_ref].add(target_ref)
    active: set[object] = set()
    complete: set[object] = set()

    def visit(ref: object) -> bool:
        if ref in active:
            return True
        if ref in complete:
            return False
        active.add(ref)
        if any(visit(target) for target in successors[ref]):
            return True
        active.remove(ref)
        complete.add(ref)
        return False

    return any(visit(ref) for ref in tuple(members))


def _terminal_cycle_edges(
    inventory: model.SemanticGraphInventory,
    *,
    residue_subjects: Mapping[object, model.SemanticSubjectRef],
) -> tuple[tuple[object, object], ...]:
    bindings = {
        binding.subject.subject_id: binding for binding in inventory.bindings
    }
    ref_by_serial: dict[int, object] = {}
    for ref, subject in residue_subjects.items():
        binding = bindings.get(subject.subject_id)
        if (
            binding is not None
            and binding.status is model.SubjectBindingStatus.UNIQUE
        ):
            ref_by_serial[binding.serial] = ref
    edges = {
        (ref_by_serial[row.owner_serial], ref_by_serial[row.peer_serial])
        for row in inventory.topology
        if row.kind is model.TopologyIncidenceKind.SUCCESSOR
        and row.owner_serial in ref_by_serial
        and row.peer_serial in ref_by_serial
    }
    return tuple(
        sorted(
            edges,
            key=lambda edge: (
                model._structural_key(edge[0]),
                model._structural_key(edge[1]),
            ),
        )
    )


def _terminal_route_refs(
    inventory: model.SemanticGraphInventory,
    *,
    carrier_binding: model.PhaseSubjectBinding,
    terminal_binding: model.PhaseSubjectBinding,
) -> tuple[object, ...]:
    """Return one exact reachable one-way carrier-to-terminal corridor."""

    if (
        carrier_binding.status is not model.SubjectBindingStatus.UNIQUE
        or terminal_binding.status is not model.SubjectBindingStatus.UNIQUE
        or carrier_binding.serial is None
        or terminal_binding.serial is None
    ):
        raise ValueError("terminal carrier and terminal must bind uniquely")
    reachable = set(inventory.reachable_serials)
    if (
        carrier_binding.serial not in reachable
        or terminal_binding.serial not in reachable
    ):
        raise ValueError("terminal route endpoints must remain reachable")
    blocks = {block.serial: block for block in inventory.blocks}
    current = carrier_binding.serial
    terminal_serial = terminal_binding.serial
    seen: set[int] = set()
    route: list[object] = []
    while current not in seen:
        seen.add(current)
        block = blocks.get(current)
        if block is None or block.block_ref is None:
            raise ValueError("terminal route contains an unbound helper block")
        route.append(block.block_ref)
        successors = tuple(
            successor for successor in block.successor_serials
            if successor in reachable
        )
        if current == terminal_serial:
            if successors:
                raise ValueError("terminal route endpoint has a live successor")
            return tuple(route)
        if len(successors) != 1:
            raise ValueError("terminal route is not one exact one-way corridor")
        current = successors[0]
    raise ValueError("terminal route corridor is cyclic")


def bind_terminal_cycle_break_claim(
    *,
    claim: model.TerminalCycleBreakClaim,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase,
) -> TerminalCycleBindingResult:
    """Bind one exact reachable cycle break from canonical phase inventories."""

    subjects = terminal_cycle_binding_subjects(proposal, claim)
    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("terminal-cycle source inventory must be closed")
    if type(candidate_inventory) is not model.SemanticGraphInventory:
        raise TypeError("terminal-cycle candidate inventory must be closed")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(candidate_inventory)
    if (
        claim.source_generation != source_inventory.generation
        or source_inventory.generation
        != proposal.source_identity_catalog.generation
    ):
        raise ValueError("terminal-cycle claim and source catalog generations differ")
    if type(phase) is not model.UnflattenAuthorityPhase or phase not in {
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    }:
        raise ValueError("terminal-cycle binding phase must be projected or observed")
    if (
        source_inventory.phase
        is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST
        or candidate_inventory.phase is not phase
    ):
        raise ValueError("terminal-cycle inventories are bound to the wrong phase")
    cycle_locator = claim.cycle_subject.locator
    subject_ids = {subject.subject_id for subject in subjects}
    source_bindings = tuple(
        binding for binding in source_inventory.bindings
        if binding.subject.subject_id in subject_ids
    )
    projected_bindings = tuple(
        binding for binding in candidate_inventory.bindings
        if binding.subject.subject_id in subject_ids
    )
    residue_subjects = {
        subject.block_ref: subject
        for subject in subjects
        if subject.role is model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE
        and subject.block_ref in set(cycle_locator.member_refs)
    }
    if set(residue_subjects) != set(cycle_locator.member_refs):
        raise ValueError("terminal-cycle residue subjects are incomplete")
    source_cycle_edges = _terminal_cycle_edges(
        source_inventory, residue_subjects=residue_subjects,
    )
    projected_cycle_edges = _terminal_cycle_edges(
        candidate_inventory, residue_subjects=residue_subjects,
    )
    if _contains_directed_cycle(cycle_locator.member_refs, projected_cycle_edges):
        raise ValueError("terminal-cycle residual cycle remains projected")
    source_binding_by_id = {
        binding.subject.subject_id: binding for binding in source_bindings
    }
    source_entry_binding = source_binding_by_id[
        residue_subjects[cycle_locator.entry_ref].subject_id
    ]
    if (
        source_entry_binding.status is not model.SubjectBindingStatus.UNIQUE
        or source_entry_binding.serial
        not in set(source_inventory.reachable_serials)
    ):
        raise ValueError("terminal-cycle source residue is not source-reachable")
    terminal_binding = next(
        (
            binding for binding in projected_bindings
            if binding.subject == claim.terminal_subject
        ),
        None,
    )
    if (
        terminal_binding is None
        or terminal_binding.status is not model.SubjectBindingStatus.UNIQUE
        or terminal_binding.serial not in set(candidate_inventory.reachable_serials)
    ):
        raise ValueError("terminal subject is not candidate-reachable by identity")
    carrier_binding = next(
        (
            binding for binding in projected_bindings
            if binding.subject.role
            is model.SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION
        ),
        None,
    )
    if carrier_binding is None:
        raise ValueError("terminal route carrier binding is absent")
    route_source_binding = next(
        (
            binding for binding in projected_bindings
            if binding.subject.role
            is model.SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE
        ),
        None,
    )
    cleanup_binding = next(
        (
            binding for binding in projected_bindings
            if binding.subject == claim.cleanup_source_subject
        ),
        None,
    )
    if (
        route_source_binding is None
        or cleanup_binding is None
        or route_source_binding.status is not model.SubjectBindingStatus.UNIQUE
        or cleanup_binding.status is not model.SubjectBindingStatus.UNIQUE
        or carrier_binding.status is not model.SubjectBindingStatus.UNIQUE
        or route_source_binding.serial
        not in set(candidate_inventory.reachable_serials)
    ):
        raise ValueError(
            "terminal cycle redirects lack exact source, cleanup, or carrier bindings"
        )
    candidate_blocks = {
        block.serial: block for block in candidate_inventory.blocks
    }
    if (
        tuple(candidate_blocks[route_source_binding.serial].successor_serials)
        != (carrier_binding.serial,)
        or tuple(candidate_blocks[cleanup_binding.serial].successor_serials)
        != (carrier_binding.serial,)
    ):
        raise ValueError(
            "terminal source and cleanup do not converge on the exact carrier"
        )
    terminal_route_refs = _terminal_route_refs(
        candidate_inventory,
        carrier_binding=carrier_binding,
        terminal_binding=terminal_binding,
    )
    source_bindings = tuple(sorted(
        source_bindings, key=lambda item: item.subject.subject_id,
    ))
    projected_bindings = tuple(sorted(
        projected_bindings, key=lambda item: item.subject.subject_id,
    ))
    bound_subject_ids = tuple(
        binding.subject.subject_id for binding in source_bindings
    )
    phase_result_values = {
        "claim_id": claim.claim_id,
        "terminal_route_proof_id": claim.terminal_route_proof_ids[0],
        "phase": phase,
        "source_fingerprint": source_inventory.graph_fingerprint,
        "candidate_fingerprint": candidate_inventory.graph_fingerprint,
        "source_generation": source_inventory.generation,
        "candidate_generation": candidate_inventory.generation,
        "bound_subject_ids": bound_subject_ids,
        "source_binding_digest": authority_id(source_bindings),
        "candidate_binding_digest": authority_id(projected_bindings),
        "residue_refs": tuple(cycle_locator.member_refs),
        "source_cycle_edges": source_cycle_edges,
        "candidate_cycle_edges": projected_cycle_edges,
        "source_bindings": source_bindings,
        "candidate_bindings": projected_bindings,
        "terminal_source_ref": route_source_binding.block_ref,
        "cleanup_source_ref": cleanup_binding.block_ref,
        "terminal_carrier_ref": carrier_binding.block_ref,
        "terminal_route_refs": terminal_route_refs,
        "terminal_subject_id": claim.terminal_subject.subject_id,
        "terminal_subject_ref": terminal_binding.block_ref,
    }
    phase_result_id = authority_id((
        "unflatten.terminal-cycle-phase.v1",
        phase_result_values["claim_id"],
        phase_result_values["terminal_route_proof_id"],
        phase_result_values["phase"],
        phase_result_values["source_fingerprint"],
        phase_result_values["candidate_fingerprint"],
        phase_result_values["source_generation"],
        phase_result_values["candidate_generation"],
        phase_result_values["bound_subject_ids"],
        phase_result_values["source_binding_digest"],
        phase_result_values["candidate_binding_digest"],
        phase_result_values["residue_refs"],
        phase_result_values["source_cycle_edges"],
        phase_result_values["candidate_cycle_edges"],
        phase_result_values["terminal_source_ref"],
        phase_result_values["cleanup_source_ref"],
        phase_result_values["terminal_carrier_ref"],
        phase_result_values["terminal_route_refs"],
        phase_result_values["terminal_subject_id"],
        phase_result_values["terminal_subject_ref"],
    ))
    phase_result = model.TerminalCyclePhaseResult(
        result_id=phase_result_id, **phase_result_values,
    )
    result = object.__new__(TerminalCycleBindingResult)
    for name, value in {
        "claim": claim, "proposal": proposal,
        "source_bindings": source_bindings,
        "projected_bindings": projected_bindings,
        "residue_refs": tuple(cycle_locator.member_refs),
        "source_cycle_edges": source_cycle_edges,
        "projected_cycle_edges": projected_cycle_edges,
        "terminal_route_refs": terminal_route_refs,
        "generation": source_inventory.generation,
        "projected_generation": candidate_inventory.generation,
        "phase_result": phase_result,
    }.items():
        object.__setattr__(result, name, value)
    object.__setattr__(result, "_content_seal", _terminal_cycle_binding_seal(result))
    result._validate_fields()
    return result


def validate_terminal_cycle_binding_result(result: TerminalCycleBindingResult) -> None:
    if type(result) is not TerminalCycleBindingResult:
        raise TypeError("terminal-cycle result must be closed")
    if result._content_seal != _terminal_cycle_binding_seal(result):
        raise ValueError("terminal-cycle binding content seal does not match")
    result._validate_fields()


def bind_corridor_coverage_forecast(
    *,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase,
) -> model.CorridorCoveragePhaseResult | None:
    """Fold one sealed forecast against already-built inventory topology."""

    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("corridor forecast binding requires a closed proposal")
    forecast = proposal.corridor_coverage_forecast
    if forecast is None:
        return None
    if type(source_inventory) is not model.SemanticGraphInventory or type(candidate_inventory) is not model.SemanticGraphInventory:
        raise TypeError("corridor forecast binding requires closed inventories")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(candidate_inventory)
    if type(phase) is not model.UnflattenAuthorityPhase or candidate_inventory.phase is not phase:
        raise ValueError("corridor forecast phase differs from candidate inventory")
    if source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
        raise ValueError("corridor forecast source inventory must be producer forecast")

    source_blocks = {row.block_ref: row for row in source_inventory.blocks if row.block_ref is not None}
    candidate_blocks = {row.block_ref: row for row in candidate_inventory.blocks if row.block_ref is not None}
    candidate_edges = {
        (row.owner_serial, row.peer_serial)
        for row in candidate_inventory.topology
        if row.kind is model.TopologyIncidenceKind.SUCCESSOR
    }
    source_edges = {
        (row.owner_serial, row.peer_serial)
        for row in source_inventory.topology
        if row.kind is model.TopologyIncidenceKind.SUCCESSOR
    }
    source_predecessor_counts: dict[int, int] = {}
    for row in source_inventory.topology:
        if row.kind is model.TopologyIncidenceKind.PREDECESSOR:
            source_predecessor_counts[row.owner_serial] = source_predecessor_counts.get(row.owner_serial, 0) + 1
    source_fp = source_inventory.graph_fingerprint
    candidate_fp = candidate_inventory.graph_fingerprint
    if source_inventory.generation != forecast.source_generation:
        raise ValueError("corridor forecast source generation differs from source inventory")
    if forecast.function_ea != source_inventory.function_ea:
        raise ValueError("corridor forecast function EA differs from source inventory")
    if candidate_inventory.function_ea != source_inventory.function_ea:
        raise ValueError("candidate function EA differs from source inventory")
    dispatcher_bindings = tuple(
        binding for binding in source_inventory.bindings
        if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
        and binding.subject.block_ref == forecast.dispatcher_ref
        and binding.subject.anchor_ea == forecast.dispatcher_anchor_ea
    )
    if len(dispatcher_bindings) != 1:
        raise ValueError("corridor forecast dispatcher binding is missing or ambiguous")
    source_dispatcher = dispatcher_bindings[0]
    if (
        source_dispatcher.status is not model.SubjectBindingStatus.UNIQUE
        or source_dispatcher.serial not in source_inventory.reachable_serials
    ):
        raise ValueError("corridor forecast source dispatcher is not uniquely reachable")
    candidate_dispatcher_bindings = tuple(
        binding for binding in candidate_inventory.bindings
        if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
        and binding.subject.block_ref == forecast.dispatcher_ref
        and binding.subject.anchor_ea == forecast.dispatcher_anchor_ea
    )
    if len(candidate_dispatcher_bindings) != 1:
        raise ValueError("corridor forecast candidate dispatcher binding is missing or ambiguous")
    candidate_dispatcher = candidate_dispatcher_bindings[0]
    if candidate_dispatcher.status not in {
        model.SubjectBindingStatus.MISSING, model.SubjectBindingStatus.UNIQUE,
    }:
        raise ValueError("corridor forecast candidate dispatcher binding drifted")
    source_dispatcher_reachable = True
    candidate_dispatcher_reachable = (
        candidate_dispatcher.status is model.SubjectBindingStatus.UNIQUE
        and candidate_dispatcher.serial in candidate_inventory.reachable_serials
    )
    if source_dispatcher_reachable and not forecast.paths:
        raise ValueError("reachable source dispatcher requires a non-empty corridor forecast")
    forecast_path_ids = {path.path_id for path in forecast.paths}
    if set(forecast.covered_path_ids) | set(forecast.residual_path_ids) != forecast_path_ids:
        raise ValueError("corridor forecast partitions do not cover the path universe")
    if set(forecast.covered_path_ids) & set(forecast.residual_path_ids):
        raise ValueError("corridor forecast partitions overlap")
    covered: list[str] = []
    residual: list[str] = []
    drifted: list[str] = []
    matched_exclusions: list[str] = []
    correlation_specs: list[tuple[object, ...]] = []
    exclusions_by_id = {
        exclusion.exclusion_id: exclusion
        for exclusion in forecast.semantic_exclusions
    }
    route_proofs = {
        proof.proof_id: proof for proof in proposal.route_evidence.route_proofs
    }

    source_catalog_by_ref = {
        witness.block_ref: witness
        for witness in proposal.source_identity_catalog.blocks
    }

    def exact_native_identity(node: model.CorridorCoveragePathNode) -> StableBlockIdentity:
        witness = source_catalog_by_ref.get(node.block_ref)
        if witness is None or witness.anchor_ea != node.anchor_ea:
            raise ValueError("corridor semantic exclusion node is absent from source catalog")
        if type(witness.block_ref) is NativeBlockRef:
            expected = witness.block_ref.identity
        else:
            expected = StableBlockIdentity.from_instruction_eas(
                witness.native_instruction_eas,
                native_key=proposal.source_identity_catalog.native_key,
            )
        if expected.exact_instruction_eas != frozenset(witness.native_instruction_eas):
            raise ValueError("corridor semantic exclusion identity differs from source catalog")
        return expected

    def bind_semantic_exclusion(
        exclusion_id: str,
        path_id: str,
        ordered_prefix: tuple[model.CorridorCoveragePathNode, ...],
    ) -> None:
        exclusion = exclusions_by_id.get(exclusion_id)
        if exclusion is None:
            raise ValueError("corridor semantic exclusion is absent from forecast")
        exact_suffix = tuple(
            node for node in (
                exclusion.source, exclusion.feeder, exclusion.prefix, exclusion.root,
            )
            if node is not None
        )
        if (
            len(exact_suffix) > len(ordered_prefix)
            or ordered_prefix[-len(exact_suffix):] != exact_suffix
            or exclusion.root.block_ref != forecast.dispatcher_ref
            or exclusion.root.anchor_ea != forecast.dispatcher_anchor_ea
        ):
            raise ValueError("corridor semantic exclusion topology differs from forecast path")
        suffix_serials = tuple(source_inventory.serial_by_ref[node.block_ref] for node in exact_suffix)
        if any(edge not in source_edges for edge in zip(suffix_serials, suffix_serials[1:])):
            raise ValueError("corridor semantic exclusion suffix is absent from source topology")
        source_identity = exact_native_identity(exclusion.source)
        candidates = []
        for claim in proposal.claims:
            if type(claim) is not model.EquivalentSemanticRouteClaim:
                continue
            if len(claim.route_proof_ids) != 1:
                continue
            proof = route_proofs.get(claim.route_proof_ids[0])
            if proof is None:
                continue
            source_match = (
                proof.source_anchor_ea == exclusion.source.anchor_ea
                and proof.source_identity == source_identity
            )
            matching_destinations = tuple(
                destination
                for destination in proof.destinations
                if destination.state_constant == exclusion.normalized_state
            )
            state_route_match = (
                proof.state_write is not None
                and proof.state_write.state_variable == exclusion.state_identity
                and proof.state_write.state_constant == exclusion.normalized_state
                and len(matching_destinations) == 1
            )
            if source_match and state_route_match:
                destination = matching_destinations[0]
                destination_pairs = {
                    (subject.block_ref, subject.anchor_ea)
                    for subject in claim.destination_subjects
                }
                exact_destination_nodes = tuple(
                    model.CorridorCoveragePathNode(block_ref, anchor_ea)
                    for block_ref, anchor_ea in destination_pairs
                    if anchor_ea == destination.target_anchor_ea
                    and exact_native_identity(
                        model.CorridorCoveragePathNode(block_ref, anchor_ea)
                    ) == destination.target_identity
                )
                destination_match = (
                    len(exact_destination_nodes) == 1
                    and (
                        exact_destination_nodes[0].block_ref,
                        exact_destination_nodes[0].anchor_ea,
                    ) in destination_pairs
                )
            else:
                destination_match = False
            if source_match and state_route_match and destination_match:
                candidates.append(claim)
        if len(candidates) != 1:
            raise ValueError("corridor semantic exclusion has zero or multiple route links")
        matched_exclusions.append(exclusion_id)
        claim = candidates[0]
        correlation_specs.append((
            exclusion_id, exclusion.digest, path_id, claim.claim_id, claim.route_proof_ids[0],
            ordered_prefix, source_fp, candidate_fp,
            source_inventory.generation, candidate_inventory.generation,
        ))

    for path in forecast.paths:
        source_serials: list[int] = []
        candidate_serials: list[int] = []
        source_ok = True
        candidate_ok = True
        for node in path.nodes:
            source_row = source_blocks.get(node.block_ref)
            if source_row is None or source_row.anchor_ea != node.anchor_ea:
                source_ok = False
                candidate_ok = False
                break
            source_serials.append(source_row.serial)
            candidate_row = candidate_blocks.get(node.block_ref)
            if candidate_row is None or candidate_row.anchor_ea != node.anchor_ea:
                candidate_ok = False
            else:
                candidate_serials.append(candidate_row.serial)
        source_path_exists = source_ok and all(
            (left, right) in source_edges
            for left, right in zip(source_serials, source_serials[1:])
        )
        candidate_path_exists = candidate_ok and len(candidate_serials) == len(path.nodes) and all(
            (left, right) in candidate_edges
            for left, right in zip(candidate_serials, candidate_serials[1:])
        )
        candidate_state_ok = True
        candidate_state_hard_failure = False
        if source_path_exists and path.state_merge is not None:
            if path.state_merge != path.nodes[-3]:
                raise ValueError("corridor state merge is not the exact path[-3] node")
            merge_row = source_blocks.get(path.state_merge.block_ref)
            feeder_row = source_blocks.get(path.nodes[-2].block_ref)
            if (
                merge_row is None or feeder_row is None
                or source_predecessor_counts.get(merge_row.serial, 0) < 2
                or (merge_row.serial, feeder_row.serial) not in source_edges
                or {
                    peer for left, peer in source_edges if left == merge_row.serial
                } != {feeder_row.serial}
            ):
                raise ValueError("corridor state merge semantics drifted from source topology")
            candidate_merge = candidate_blocks.get(path.state_merge.block_ref)
            candidate_feeder = candidate_blocks.get(path.nodes[-2].block_ref)
            if candidate_merge is None or candidate_feeder is None:
                candidate_state_ok = False
                candidate_state_hard_failure = True
            else:
                candidate_merge_predecessors = sum(
                    1 for row in candidate_inventory.topology
                    if row.kind is model.TopologyIncidenceKind.PREDECESSOR
                    and row.owner_serial == candidate_merge.serial
                )
                candidate_state_ok = (
                    candidate_merge_predecessors >= 2
                    and (candidate_merge.serial, candidate_feeder.serial) in candidate_edges
                    and {
                        peer for left, peer in candidate_edges
                        if left == candidate_merge.serial
                    } == {candidate_feeder.serial}
                )
                candidate_state_hard_failure = candidate_merge_predecessors < 2

        if not source_path_exists:
            drifted.append(path.path_id)
        elif path.disposition is model.CorridorPathDisposition.SEMANTICALLY_EXCLUDED:
            if not path.semantic_exclusion_ids:
                raise ValueError("semantic exclusion path has no typed exclusion IDs")
            for exclusion_id in path.semantic_exclusion_ids:
                bind_semantic_exclusion(exclusion_id, path.path_id, tuple(path.nodes))
            covered.append(path.path_id)
        elif path.disposition is model.CorridorPathDisposition.RESIDUAL:
            if not candidate_path_exists or candidate_state_hard_failure:
                raise ValueError(
                    "residual corridor path classification lacks required candidate topology"
                )
            (residual if candidate_state_ok else drifted).append(path.path_id)
        elif candidate_path_exists:
            drifted.append(path.path_id)
        else:
            covered.append(path.path_id)
            if path.semantic_exclusion_ids:
                raise ValueError("structural corridor coverage cannot carry semantic exclusions")
    correlation_content = tuple(
        sorted(correlation_specs, key=lambda item: (item[0], item[2]))
    )
    # The forecast is the sole producer-owned comparison authority.  Preserve
    # its exact source nodes as sealed subject IDs for consumers that must
    # validate dispatcher-only ingress; do not rediscover a comparison region
    # from either transaction graph.
    comparison_region_subject_ids = tuple(sorted({
        binding.subject.subject_id
        for path in forecast.paths
        for node in path.nodes
        for binding in source_inventory.bindings
        if binding.subject.block_ref == node.block_ref
        and binding.subject.anchor_ea == node.anchor_ea
    }))
    if not comparison_region_subject_ids:
        raise ValueError("corridor forecast has no source comparison-region subjects")
    dispatcher_candidates = tuple(
        binding.subject.subject_id for binding in source_inventory.bindings
        if binding.subject.role is model.SemanticSubjectRole.DISPATCHER_ENTRY
        and binding.subject.block_ref == forecast.dispatcher_ref
        and binding.subject.anchor_ea == forecast.dispatcher_anchor_ea
        and binding.status is model.SubjectBindingStatus.UNIQUE
    )
    if len(dispatcher_candidates) != 1:
        raise ValueError("corridor forecast dispatcher has no exact unique source subject")
    dispatcher_subject_id = dispatcher_candidates[0]
    result_id = authority_id((
        "unflatten.corridor-coverage-phase.v1", forecast.forecast_id, phase,
        source_fp, candidate_fp, source_inventory.generation,
        candidate_inventory.generation, tuple(sorted(covered)),
        tuple(sorted(residual)), tuple(sorted(drifted)),
        forecast.enumeration_complete, tuple(sorted(set(matched_exclusions))),
        source_dispatcher_reachable, candidate_dispatcher_reachable,
        correlation_content, comparison_region_subject_ids, dispatcher_subject_id,
    ))
    expected_covered = set(forecast.covered_path_ids)
    if (
        (not candidate_dispatcher_reachable and set(covered) != expected_covered)
        or set(covered) & set(residual)
        or set(covered) | set(residual) | set(drifted) != forecast_path_ids
    ):
        raise ValueError("corridor phase classification disagrees with sealed forecast partition")
    correlations = tuple(
        model.CorridorSemanticExclusionCorrelation(*spec, phase_result_id=result_id)
        for spec in correlation_content
    )
    return model.CorridorCoveragePhaseResult(
        result_id, forecast.forecast_id, phase, source_fp, candidate_fp,
        source_inventory.generation, candidate_inventory.generation,
        tuple(sorted(covered)), tuple(sorted(residual)), tuple(sorted(drifted)),
        forecast.enumeration_complete, tuple(sorted(set(matched_exclusions))),
        source_dispatcher_reachable, candidate_dispatcher_reachable,
        correlations, comparison_region_subject_ids, dispatcher_subject_id,
    )


@dataclass(frozen=True, slots=True)
class DetachedDeadHandlerComponentBindingResult:
    """One transaction-minted detached source authority and phase verdict."""

    source_result: model.DetachedDeadHandlerComponentSourceResult
    phase_result: model.DetachedDeadHandlerComponentPhaseResult

    def __post_init__(self) -> None:
        if type(self.source_result) is not model.DetachedDeadHandlerComponentSourceResult:
            raise TypeError("detached binding requires a closed source result")
        if type(self.phase_result) is not model.DetachedDeadHandlerComponentPhaseResult:
            raise TypeError("detached binding requires a closed phase result")
        validate_detached_source_result(self.source_result)
        validate_detached_phase_result(self.phase_result)
        if self.phase_result.source_result_id != self.source_result.result_id:
            raise ValueError("detached phase result is foreign to its source authority")


def _ref_tuple(values: Sequence[object]) -> tuple[object, ...]:
    return tuple(sorted(set(values), key=canonical_bytes))


def _stable_terminal_keys(
    inventory: model.SemanticGraphInventory,
) -> tuple[tuple[object, int, model.TerminalKind], ...]:
    reachable = set(inventory.reachable_serials)
    rows = (
        (
            item.owner_ref
            if item.owner_ref is not None
            else ("generated", item.owner_serial, item.owner_anchor_ea),
            item.instruction_ea,
            item.terminal_kind,
        )
        for item in inventory.terminals
        if item.owner_serial in reachable
    )
    return tuple(sorted(rows, key=canonical_bytes))


def _stable_effect_keys(
    inventory: model.SemanticGraphInventory,
) -> tuple[tuple[object, int, model.EffectSiteKind], ...]:
    reachable = set(inventory.reachable_serials)
    rows = (
        (
            item.owner_ref
            if item.owner_ref is not None
            else ("generated", item.owner_serial, item.owner_anchor_ea),
            item.instruction_ea,
            item.effect_kind,
        )
        for item in inventory.effects
        if item.owner_serial in reachable
    )
    return tuple(sorted(rows, key=canonical_bytes))


def _candidate_reachable_refs(
    inventory: model.SemanticGraphInventory,
) -> frozenset[object]:
    reachable = set(inventory.reachable_serials)
    return frozenset(
        block.block_ref
        for block in inventory.blocks
        if block.serial in reachable and block.block_ref is not None
    )


def _source_block_maps(
    blocks: Sequence[model.InventoryBlockObservation],
) -> tuple[dict[int, model.InventoryBlockObservation], dict[object, model.InventoryBlockObservation]]:
    by_serial = {block.serial: block for block in blocks}
    by_ref = {
        block.block_ref: block for block in blocks if block.block_ref is not None
    }
    if len(by_serial) != len(tuple(blocks)) or len(by_ref) != len(tuple(blocks)):
        raise ValueError("detached source block facts are not exact by serial and ref")
    return by_serial, by_ref


def _derive_detached_component_refs(
    *,
    source_blocks: Sequence[model.InventoryBlockObservation],
    dead_handler_refs: frozenset[object],
    dispatcher_ref: object,
    candidate_reachable_refs: frozenset[object],
) -> frozenset[object]:
    by_serial, by_ref = _source_block_maps(source_blocks)
    source_refs = frozenset(by_ref)
    lost_refs = source_refs - candidate_reachable_refs
    component: set[object] = set()
    pending = list(dead_handler_refs)
    while pending:
        ref = pending.pop()
        if (
            ref in component
            or ref == dispatcher_ref
            or ref in candidate_reachable_refs
            or ref not in lost_refs
        ):
            continue
        block = by_ref.get(ref)
        if block is None:
            raise ValueError("detached handler is absent from sealed source blocks")
        component.add(ref)
        pending.extend(by_serial[target].block_ref for target in block.successor_serials)
    return frozenset(component)


def _validate_candidate_detached_partition(
    *,
    claim: model.DetachedDeadHandlerComponentClaim,
    candidate_inventory: model.SemanticGraphInventory,
    source_blocks: Sequence[model.InventoryBlockObservation],
    dispatcher_ref: object,
    comparison_refs: frozenset[object],
    expected_component_refs: frozenset[object],
    source_terminal_keys: tuple[tuple[object, int, model.TerminalKind], ...],
    source_effect_keys: tuple[tuple[object, int, model.EffectSiteKind], ...],
) -> tuple[frozenset[object], frozenset[object]]:
    bindings = {
        binding.subject.subject_id: binding
        for binding in candidate_inventory.bindings
    }
    reachable_serials = set(candidate_inventory.reachable_serials)
    reachable_refs = _candidate_reachable_refs(candidate_inventory)

    def binding_reachable(subject: model.SemanticSubjectRef) -> bool:
        binding = bindings.get(subject.subject_id)
        if binding is None or binding.status is model.SubjectBindingStatus.AMBIGUOUS:
            raise ValueError("detached candidate subject binding is absent or ambiguous")
        exact_reachable = (
            binding.status is model.SubjectBindingStatus.UNIQUE
            and binding.serial in reachable_serials
        )
        if exact_reachable != (subject.block_ref in reachable_refs):
            raise ValueError("detached candidate binding disagrees with stable-ref reachability")
        return exact_reachable

    if binding_reachable(claim.dispatcher_subject):
        raise ValueError("detached dispatcher remains candidate-reachable")
    if any(binding_reachable(subject) for subject in claim.dead_handler_subjects):
        raise ValueError("detached dead-handler partition remains candidate-reachable")
    if not all(binding_reachable(subject) for subject in claim.retained_handler_subjects):
        raise ValueError("detached retained-handler partition is not candidate-reachable")
    if any(binding_reachable(subject) for subject in claim.component_subjects):
        raise ValueError("detached component member remains candidate-reachable")

    dead_refs = frozenset(subject.block_ref for subject in claim.dead_handler_subjects)
    derived_component = _derive_detached_component_refs(
        source_blocks=source_blocks,
        dead_handler_refs=dead_refs,
        dispatcher_ref=dispatcher_ref,
        candidate_reachable_refs=reachable_refs,
    )
    if derived_component != expected_component_refs:
        raise ValueError("detached component differs from the exact source/candidate walk")
    if not dead_refs <= derived_component:
        raise ValueError("detached component does not cover every dead handler")

    by_serial, by_ref = _source_block_maps(source_blocks)
    source_refs = frozenset(by_ref)
    lost_refs = source_refs - reachable_refs
    for ref in dead_refs:
        block = by_ref[ref]
        reachable_preds = frozenset(
            by_serial[pred].block_ref
            for pred in block.predecessor_serials
            if pred in by_serial
        )
        if not reachable_preds or not reachable_preds <= comparison_refs:
            raise ValueError("detached dead handler has non-comparison ingress")
    for ref in derived_component:
        block = by_ref[ref]
        reachable_preds = frozenset(
            by_serial[pred].block_ref
            for pred in block.predecessor_serials
            if pred in by_serial
        )
        if not reachable_preds <= derived_component | comparison_refs:
            raise ValueError("detached component has external semantic ingress")
        if any(
            observation.is_call
            or observation.instruction_kind in {model.InsnKind.CALL, model.InsnKind.STORE}
            for observation in block.instruction_observations
        ):
            raise ValueError("detached component contains CALL or STORE")

    remainder = lost_refs - derived_component - comparison_refs
    retired_region = remainder | derived_component | comparison_refs
    for ref in remainder:
        block = by_ref[ref]
        if any(
            observation.is_call
            or observation.instruction_kind in {model.InsnKind.CALL, model.InsnKind.STORE}
            for observation in block.instruction_observations
        ):
            raise ValueError("detached remainder contains CALL or STORE")
        if not block.successor_serials:
            raise ValueError("detached remainder contains a terminal block")
        successor_refs = frozenset(by_serial[target].block_ref for target in block.successor_serials)
        if not successor_refs <= retired_region:
            raise ValueError("detached remainder escapes the retired region")

    if _stable_terminal_keys(candidate_inventory) != source_terminal_keys:
        raise ValueError("detached candidate terminal identity drifted")
    if _stable_effect_keys(candidate_inventory) != source_effect_keys:
        raise ValueError("detached candidate effect identity drifted")
    if len(derived_component) * 2 >= max(1, len(source_refs)):
        raise ValueError("detached component is not a strict minority island")
    return derived_component, frozenset(remainder)


def _detached_source_result_values(
    *,
    claim: model.DetachedDeadHandlerComponentClaim,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    corridor_result: model.CorridorCoveragePhaseResult,
) -> dict[str, object]:
    model.validate_semantic_graph_inventory(source_inventory)
    source_bindings = {
        binding.subject.subject_id: binding for binding in source_inventory.bindings
    }
    source_reachable = set(source_inventory.reachable_serials)
    required_subjects = (
        claim.dispatcher_subject,
        *claim.dead_handler_subjects,
        *claim.retained_handler_subjects,
        *claim.component_subjects,
    )
    for subject in required_subjects:
        binding = source_bindings.get(subject.subject_id)
        if (
            binding is None
            or binding.subject != subject
            or binding.status is not model.SubjectBindingStatus.UNIQUE
            or binding.serial not in source_reachable
        ):
            raise ValueError("detached source subject is not uniquely source-reachable")
    if corridor_result.dispatcher_subject_id != claim.dispatcher_subject.subject_id:
        raise ValueError("detached dispatcher differs from sealed corridor authority")
    comparison_bindings = tuple(
        source_bindings.get(subject_id)
        for subject_id in corridor_result.comparison_region_subject_ids
    )
    if any(
        binding is None
        or binding.status is not model.SubjectBindingStatus.UNIQUE
        or binding.serial not in source_reachable
        for binding in comparison_bindings
    ):
        raise ValueError("detached comparison region is not exactly source-bound")

    source_blocks = tuple(
        block for block in source_inventory.blocks if block.serial in source_reachable
    )
    _source_block_maps(source_blocks)
    source_refs = frozenset(block.block_ref for block in source_blocks)
    comparison_refs = frozenset(binding.block_ref for binding in comparison_bindings)
    dead_refs = frozenset(subject.block_ref for subject in claim.dead_handler_subjects)
    retained_refs = frozenset(subject.block_ref for subject in claim.retained_handler_subjects)
    claimed_component_refs = frozenset(
        subject.block_ref for subject in claim.component_subjects
    )
    terminal_keys = _stable_terminal_keys(source_inventory)
    effect_keys = _stable_effect_keys(source_inventory)
    component_refs, remainder_refs = _validate_candidate_detached_partition(
        claim=claim,
        candidate_inventory=candidate_inventory,
        source_blocks=source_blocks,
        dispatcher_ref=claim.dispatcher_subject.block_ref,
        comparison_refs=comparison_refs,
        expected_component_refs=claimed_component_refs,
        source_terminal_keys=terminal_keys,
        source_effect_keys=effect_keys,
    )
    reachable_subject_ids = tuple(sorted(
        subject_id
        for subject_id, binding in source_bindings.items()
        if binding.status is model.SubjectBindingStatus.UNIQUE
        and binding.serial in source_reachable
    ))
    values = (
        claim.claim_id,
        corridor_result.forecast_id,
        corridor_result.result_id,
        source_inventory.graph_fingerprint,
        source_inventory.generation,
        claim.dispatcher_subject.subject_id,
        claim.dispatcher_subject.block_ref,
        tuple(subject.subject_id for subject in claim.dead_handler_subjects),
        tuple(subject.subject_id for subject in claim.retained_handler_subjects),
        tuple(subject.subject_id for subject in claim.component_subjects),
        corridor_result.comparison_region_subject_ids,
        reachable_subject_ids,
        _ref_tuple(dead_refs),
        _ref_tuple(retained_refs),
        _ref_tuple(comparison_refs),
        authority_id(terminal_keys),
        authority_id(effect_keys),
        authority_id(source_blocks),
        _ref_tuple(source_refs),
        _ref_tuple(component_refs),
        _ref_tuple(remainder_refs),
        terminal_keys,
        effect_keys,
        source_blocks,
    )
    return {
        "result_id": authority_id((
            "unflatten.detached-dead-handler-component-source.v2", *values,
        )),
        "claim_id": values[0],
        "corridor_forecast_id": values[1],
        "corridor_coverage_result_id": values[2],
        "source_fingerprint": values[3],
        "source_generation": values[4],
        "dispatcher_subject_id": values[5],
        "dispatcher_block_ref": values[6],
        "dead_handler_subject_ids": values[7],
        "retained_handler_subject_ids": values[8],
        "component_subject_ids": values[9],
        "comparison_region_subject_ids": values[10],
        "source_reachable_subject_ids": values[11],
        "dead_handler_block_refs": values[12],
        "retained_handler_block_refs": values[13],
        "comparison_region_block_refs": values[14],
        "terminal_digest": values[15],
        "effect_digest": values[16],
        "topology_digest": values[17],
        "source_reachable_block_refs": values[18],
        "component_block_refs": values[19],
        "remainder_block_refs": values[20],
        "terminal_site_keys": values[21],
        "effect_site_keys": values[22],
        "source_blocks": values[23],
    }


def _graph_bind_detached_dead_handler_component_claim(
    *, claim: model.DetachedDeadHandlerComponentClaim,
    source_inventory: model.SemanticGraphInventory,
    candidate_inventory: model.SemanticGraphInventory,
    corridor_result: model.CorridorCoveragePhaseResult,
    phase: model.UnflattenAuthorityPhase,
    source_result: model.DetachedDeadHandlerComponentSourceResult | None = None,
    _mint_source_result: object | None = None,
    _mint_phase_result: object | None = None,
    _lifecycle_secret: object | None = None,
    _source_values_impl=_detached_source_result_values,
) -> DetachedDeadHandlerComponentBindingResult:
    """Mint projected authority once, then validate observed candidates against it."""

    if (
        _lifecycle_secret is None
        or not callable(_mint_source_result)
        or not callable(_mint_phase_result)
    ):
        raise TypeError("detached binding lifecycle is closed")
    if type(claim) is not model.DetachedDeadHandlerComponentClaim:
        raise TypeError("detached claim must be closed")
    claim.__post_init__()
    if phase not in {
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    }:
        raise ValueError("detached binding phase must be projected or observed")
    if (
        type(corridor_result) is not model.CorridorCoveragePhaseResult
        or corridor_result.phase is not phase
        or not corridor_result.full
    ):
        raise ValueError("detached bind requires exact full phase corridor authority")
    corridor_result.__post_init__()
    model.validate_semantic_graph_inventory(candidate_inventory)
    if candidate_inventory.phase is not phase:
        raise ValueError("detached candidate inventory is bound to the wrong phase")
    if (
        corridor_result.source_fingerprint != source_inventory.graph_fingerprint
        or corridor_result.candidate_fingerprint != candidate_inventory.graph_fingerprint
        or corridor_result.source_generation != source_inventory.generation
        or corridor_result.candidate_generation != candidate_inventory.generation
    ):
        raise ValueError("detached corridor result has foreign phase coordinates")

    if source_result is None:
        if phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT:
            raise ValueError("observed detached bind requires projected sealed source authority")
        source_result = _mint_source_result(**_source_values_impl(
            claim=claim,
            source_inventory=source_inventory,
            candidate_inventory=candidate_inventory,
            corridor_result=corridor_result,
        ))
    else:
        if phase is not model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY:
            raise ValueError("projected detached bind must mint its own source authority")
        if type(source_result) is not model.DetachedDeadHandlerComponentSourceResult:
            raise TypeError("detached source result must be closed")
        validate_detached_source_result(source_result)
        if (
            source_result.claim_id != claim.claim_id
            or source_result.corridor_forecast_id != corridor_result.forecast_id
            or source_result.source_fingerprint != source_inventory.graph_fingerprint
            or source_result.source_generation != source_inventory.generation
            or source_result.dispatcher_subject_id != claim.dispatcher_subject.subject_id
            or source_result.dispatcher_block_ref != claim.dispatcher_subject.block_ref
            or source_result.comparison_region_subject_ids
            != corridor_result.comparison_region_subject_ids
            or corridor_result.dispatcher_subject_id
            != source_result.dispatcher_subject_id
        ):
            raise ValueError("observed detached bind has foreign sealed source authority")
        if source_result.dead_handler_subject_ids != tuple(
            subject.subject_id for subject in claim.dead_handler_subjects
        ) or source_result.retained_handler_subject_ids != tuple(
            subject.subject_id for subject in claim.retained_handler_subjects
        ) or source_result.component_subject_ids != tuple(
            subject.subject_id for subject in claim.component_subjects
        ):
            raise ValueError("observed detached claim partition drifted from source authority")
        component_refs, _remainder_refs = _validate_candidate_detached_partition(
            claim=claim,
            candidate_inventory=candidate_inventory,
            source_blocks=source_result.source_blocks,
            dispatcher_ref=source_result.dispatcher_block_ref,
            comparison_refs=frozenset(source_result.comparison_region_block_refs),
            expected_component_refs=frozenset(source_result.component_block_refs),
            source_terminal_keys=source_result.terminal_site_keys,
            source_effect_keys=source_result.effect_site_keys,
        )
        if component_refs != frozenset(source_result.component_block_refs):
            raise ValueError("observed detached component drifted from source authority")

    values = (
        claim.claim_id,
        phase,
        corridor_result.result_id,
        source_inventory.graph_fingerprint,
        candidate_inventory.graph_fingerprint,
        source_inventory.generation,
        candidate_inventory.generation,
        True,
        source_result.result_id,
    )
    phase_result = _mint_phase_result(
        result_id=authority_id(("unflatten.detached-dead-handler-component-phase.v1", *values)),
        claim_id=claim.claim_id,
        phase=phase,
        corridor_coverage_result_id=corridor_result.result_id,
        source_fingerprint=source_inventory.graph_fingerprint,
        candidate_fingerprint=candidate_inventory.graph_fingerprint,
        source_generation=source_inventory.generation,
        candidate_generation=candidate_inventory.generation,
        accepted=True,
        source_result_id=source_result.result_id,
    )
    return DetachedDeadHandlerComponentBindingResult(source_result, phase_result)


def _make_detached_binding_entrypoint(
    graph_impl=_graph_bind_detached_dead_handler_component_claim,
):
    """Keep detached authority minting private to the graph-binding closure."""

    source_registry: dict[
        int,
        tuple[
            weakref.ReferenceType[model.DetachedDeadHandlerComponentSourceResult], str,
        ],
    ] = {}
    phase_registry: dict[
        int,
        tuple[
            weakref.ReferenceType[model.DetachedDeadHandlerComponentPhaseResult], str,
        ],
    ] = {}
    lifecycle_secret = object()

    def validate_source(result: model.DetachedDeadHandlerComponentSourceResult) -> None:
        if type(result) is not model.DetachedDeadHandlerComponentSourceResult:
            raise TypeError("detached source result must be closed")
        registered = source_registry.get(id(result))
        if registered is None or registered[0]() is not result:
            raise ValueError("detached source result was not minted by the transaction binder")
        result.__post_init__()
        if registered[1] != authority_id(("unflatten.detached-source-object-seal.v1", result)):
            raise ValueError("detached source result content changed after minting")

    def validate_phase(result: model.DetachedDeadHandlerComponentPhaseResult) -> None:
        if type(result) is not model.DetachedDeadHandlerComponentPhaseResult:
            raise TypeError("detached phase result must be closed")
        registered = phase_registry.get(id(result))
        if registered is None or registered[0]() is not result:
            raise ValueError("detached phase result was not minted by the transaction binder")
        result.__post_init__()
        if registered[1] != authority_id(("unflatten.detached-phase-object-seal.v1", result)):
            raise ValueError("detached phase result content changed after minting")

    def mint_source(**values: object) -> model.DetachedDeadHandlerComponentSourceResult:
        result = object.__new__(model.DetachedDeadHandlerComponentSourceResult)
        for name, value in values.items():
            object.__setattr__(result, name, value)
        result.__post_init__()
        identity = id(result)
        seal = authority_id(("unflatten.detached-source-object-seal.v1", result))

        def cleanup(
            reference: weakref.ReferenceType[model.DetachedDeadHandlerComponentSourceResult],
        ) -> None:
            registered = source_registry.get(identity)
            if registered is not None and registered[0] is reference:
                source_registry.pop(identity, None)

        source_registry[identity] = (weakref.ref(result, cleanup), seal)
        validate_source(result)
        return result

    def mint_phase(**values: object) -> model.DetachedDeadHandlerComponentPhaseResult:
        result = object.__new__(model.DetachedDeadHandlerComponentPhaseResult)
        for name, value in values.items():
            object.__setattr__(result, name, value)
        result.__post_init__()
        identity = id(result)
        seal = authority_id(("unflatten.detached-phase-object-seal.v1", result))

        def cleanup(
            reference: weakref.ReferenceType[model.DetachedDeadHandlerComponentPhaseResult],
        ) -> None:
            registered = phase_registry.get(identity)
            if registered is not None and registered[0] is reference:
                phase_registry.pop(identity, None)

        phase_registry[identity] = (weakref.ref(result, cleanup), seal)
        validate_phase(result)
        return result

    def entrypoint(**kwargs: object) -> DetachedDeadHandlerComponentBindingResult:
        return graph_impl(
            **kwargs,
            _mint_source_result=mint_source,
            _mint_phase_result=mint_phase,
            _lifecycle_secret=lifecycle_secret,
        )

    return entrypoint, validate_source, validate_phase


(
    bind_detached_dead_handler_component_claim,
    validate_detached_source_result,
    validate_detached_phase_result,
) = _make_detached_binding_entrypoint()
del _make_detached_binding_entrypoint
del _graph_bind_detached_dead_handler_component_claim
del _detached_source_result_values


def bind_retired_dispatcher_infrastructure_claim(
    *,
    claim: model.RetiredDispatcherInfrastructureClaim,
    proposal: model.ProposedUnflattenContract,
    source_inventory: model.SemanticGraphInventory,
    projected_inventory: model.SemanticGraphInventory,
    phase: model.UnflattenAuthorityPhase = model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
) -> RetiredInfrastructureBindingResult:
    """Bind every planned member and classify retirement by inventory reachability.

    A retired member may be physically missing or remain uniquely indexed while
    absent from the exact candidate reachable closure. Retained members must be
    unique and reachable. No raw serial is stored in the result's authority
    catalog; serials remain phase-local rows on the returned bindings.
    """

    if type(claim) is not model.RetiredDispatcherInfrastructureClaim:
        raise TypeError("retirement binding requires a closed retirement claim")
    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("retirement binding requires a closed proposal")
    if claim not in proposal.claims:
        raise ValueError("retirement claim is foreign to the proposal")
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("retirement binding phase must be an UnflattenAuthorityPhase")
    if phase not in {
        model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
    }:
        raise ValueError("retirement binding phase must be projected or observed")
    if type(source_inventory) is not model.SemanticGraphInventory:
        raise TypeError("retirement source_inventory must be a closed semantic inventory")
    if type(projected_inventory) is not model.SemanticGraphInventory:
        raise TypeError("retirement projected_inventory must be a closed semantic inventory")
    model.validate_semantic_graph_inventory(source_inventory)
    model.validate_semantic_graph_inventory(projected_inventory)
    if source_inventory.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST:
        raise ValueError("retirement source inventory must be producer forecast")
    if projected_inventory.phase is not phase:
        raise ValueError("retirement projected inventory phase differs from requested phase")
    generation = source_inventory.generation
    if projected_inventory.generation != generation:
        raise ValueError("retirement projected inventory generation differs from source authority")
    source_graph_fingerprint = source_inventory.graph_fingerprint
    projected_graph_fingerprint = projected_inventory.graph_fingerprint
    catalog_rows = retirement_member_catalog(proposal, claim)
    catalog = proposal.source_identity_catalog
    subjects_by_ref = {member.block_ref: member for member in claim.member_subjects}
    subjects = []
    for row in catalog_rows:
        subject = subjects_by_ref.get(row.block_ref)
        if subject is None:
            subject = _subject_factory(
                model.SemanticSubjectRef,
                kind=model.SemanticSubjectKind.BLOCK,
                role=model.SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
                block_ref=row.block_ref,
                anchor_ea=row.anchor_ea,
                locator=model.BlockSubjectLocator(row.block_ref, row.anchor_ea),
            )
        subjects.append(subject)
    expected_ids = {subject.subject_id for subject in subjects}
    source_bindings = tuple(sorted(
        (binding for binding in source_inventory.bindings if binding.subject.subject_id in expected_ids),
        key=lambda item: item.subject.subject_id,
    ))
    projected_bindings = tuple(sorted(
        (binding for binding in projected_inventory.bindings if binding.subject.subject_id in expected_ids),
        key=lambda item: item.subject.subject_id,
    ))
    if len(source_bindings) != len(expected_ids) or len(projected_bindings) != len(expected_ids):
        raise ValueError("retirement inventories lack the exact member binding rows")
    result = object.__new__(RetiredInfrastructureBindingResult)
    for name, value in {
        "claim": claim, "proposal": proposal,
        "source_inventory": source_inventory,
        "projected_inventory": projected_inventory,
        "source_catalog": catalog,
        "member_catalog": catalog_rows, "source_bindings": source_bindings,
        "projected_bindings": projected_bindings,
        "generation": generation,
    }.items():
        object.__setattr__(result, name, value)
    object.__setattr__(result, "_content_seal", _retirement_binding_seal(result))
    result._validate_fields()
    return result


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ExactEffectBindingResult:
    """The only binding output admitted for an exact-effect claim."""

    def __new__(cls, *args: object, **kwargs: object):
        raise TypeError("ExactEffectBindingResult can only be minted by bind_exact_effect_claim")

    claim: model.ExactInfeasibleEffectClaim
    proposal: model.ProposedUnflattenContract
    exclusion: ExactStateBranchEffectExclusion
    source_catalog: model.SourceIdentityCatalog
    source_serial_rows: tuple[tuple[object, int], ...]
    projected_serial_rows: tuple[tuple[object, int], ...]
    source_bindings: tuple[model.PhaseSubjectBinding, ...]
    projected_bindings: tuple[model.PhaseSubjectBinding, ...]
    source_graph_fingerprint: str
    projected_graph_fingerprint: str
    generation: int
    _content_seal: str = field(init=False, repr=False, compare=False)

    @property
    def claim_id(self) -> str:
        return self.claim.claim_id

    def _validate_fields(self) -> None:
        if type(self.claim) is not model.ExactInfeasibleEffectClaim:
            raise TypeError("claim must be the closed exact-effect claim")
        validate_canonical_roundtrip(self.claim, model.ExactInfeasibleEffectClaim)
        if type(self.proposal) is not model.ProposedUnflattenContract:
            raise TypeError("proposal must be the closed exact-effect proposal")
        if type(self.exclusion) is not ExactStateBranchEffectExclusion:
            raise TypeError("exclusion must be the closed exact-effect record")
        validate_canonical_roundtrip(self.proposal, model.ProposedUnflattenContract)
        self.exclusion.__post_init__()
        if type(self.source_catalog) is not model.SourceIdentityCatalog:
            raise TypeError("source_catalog must be the closed identity catalog")
        validate_canonical_roundtrip(self.source_catalog, model.SourceIdentityCatalog)
        if self.proposal.source_identity_catalog != self.source_catalog:
            raise ValueError("result catalog must equal proposal catalog")
        if (
            self.claim.source_generation != self.generation
            or self.source_catalog.generation != self.generation
        ):
            raise ValueError("exact-effect claim, catalog, and binding generation must match")
        catalog_refs = tuple(item.block_ref for item in self.source_catalog.blocks)
        catalog_ref_set = set(catalog_refs)
        claim_owned_refs = {
            subject.block_ref
            for subject in (
                self.claim.source_subject,
                self.claim.predicate_subject,
                self.claim.selected_target_subject,
                self.claim.discarded_effect_subject,
            )
        }
        if any(ref is None for ref in claim_owned_refs) or len(claim_owned_refs) != 4:
            raise ValueError("exact-effect claim must own four distinct block references")

        def validate_rows(
            rows: object,
            label: str,
        ) -> dict[object, int]:
            if type(rows) is not tuple:
                raise TypeError(f"{label} must be an exact tuple")
            parsed: list[tuple[object, int]] = []
            for row in rows:
                if type(row) is not tuple or len(row) != 2:
                    raise TypeError(f"{label} must contain (ref, serial) rows")
                ref, serial = row
                if type(ref) not in (NativeBlockRef, LogicalBlockRef):
                    raise TypeError(f"{label} contains a foreign ref")
                validate_canonical_roundtrip(ref, type(ref))
                if type(serial) is not int or serial < 0:
                    raise ValueError(f"{label} contains a non-canonical serial")
                parsed.append((ref, serial))
            refs = tuple(ref for ref, _serial in parsed)
            serials = tuple(serial for _ref, serial in parsed)
            if len(set(refs)) != len(refs) or len(set(serials)) != len(serials):
                raise ValueError(f"{label} contains duplicate rows")
            expected_order = tuple(
                item.block_ref
                for item in self.source_catalog.blocks
                if item.block_ref in claim_owned_refs
            )
            if refs != expected_order:
                raise ValueError(f"{label} must use canonical catalog order")
            if set(refs) != claim_owned_refs:
                raise ValueError(f"{label} must exactly cover the claim-owned references")
            if not set(refs) <= catalog_ref_set:
                raise ValueError(f"{label} contains a foreign catalog reference")
            return dict(parsed)

        source_serial_by_ref = validate_rows(self.source_serial_rows, "source serial rows")
        projected_serial_by_ref = validate_rows(self.projected_serial_rows, "projected serial rows")
        if type(self.source_bindings) is not tuple or type(self.projected_bindings) is not tuple:
            raise TypeError("exact-effect bindings must be exact tuples")
        if not self.source_bindings or not self.projected_bindings:
            raise ValueError("exact-effect bindings must not be empty")
        if any(type(item) is not model.PhaseSubjectBinding for item in self.source_bindings):
            raise TypeError("source_bindings must be closed phase bindings")
        if any(type(item) is not model.PhaseSubjectBinding for item in self.projected_bindings):
            raise TypeError("projected_bindings must be closed phase bindings")
        for item in (*self.source_bindings, *self.projected_bindings):
            validate_canonical_roundtrip(item, model.PhaseSubjectBinding)
        source_ids = tuple(item.subject.subject_id for item in self.source_bindings)
        projected_ids = tuple(item.subject.subject_id for item in self.projected_bindings)
        if source_ids != tuple(sorted(source_ids)) or projected_ids != tuple(sorted(projected_ids)):
            raise ValueError("exact-effect bindings must use canonical subject order")
        if len(set(source_ids)) != len(source_ids) or len(set(projected_ids)) != len(projected_ids):
            raise ValueError("exact-effect bindings must not duplicate subjects")
        if set(source_ids) != set(projected_ids):
            raise ValueError("source/projected exact-effect subjects must match")
        for item in (*self.source_bindings, *self.projected_bindings):
            if item.status is not model.SubjectBindingStatus.UNIQUE:
                raise ValueError("exact-effect binding result cannot contain missing subjects")
        if any(item.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST for item in self.source_bindings):
            raise ValueError("source exact-effect bindings have the wrong phase")
        if any(item.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT for item in self.projected_bindings):
            raise ValueError("projected exact-effect bindings have the wrong phase")
        projected_by_id = {item.subject.subject_id: item for item in self.projected_bindings}
        if any(item.role is not projected_by_id[item.subject.subject_id].role for item in self.source_bindings):
            raise ValueError("source/projected exact-effect roles must match")
        _canonical_digest(self.source_graph_fingerprint, "source graph fingerprint")
        _canonical_digest(self.projected_graph_fingerprint, "projected graph fingerprint")
        if type(self.generation) is not int or isinstance(self.generation, bool) or self.generation < 0:
            raise ValueError("binding generation must be an exact non-negative int")
        if any(item.generation != self.generation for item in (*self.source_bindings, *self.projected_bindings)):
            raise ValueError("exact-effect binding generations must be uniform")
        if any(item.graph_fingerprint != self.source_graph_fingerprint for item in self.source_bindings):
            raise ValueError("source binding fingerprints must be uniform")
        if any(item.graph_fingerprint != self.projected_graph_fingerprint for item in self.projected_bindings):
            raise ValueError("projected binding fingerprints must be uniform")
        expected_subjects = {
            subject.subject_id for subject in (
                self.claim.source_subject,
                self.claim.predicate_subject,
                self.claim.selected_target_subject,
                self.claim.discarded_effect_subject,
            )
        }
        if set(source_ids) != expected_subjects or set(projected_ids) != expected_subjects:
            raise ValueError("bindings are not cryptographically tied to the claim")
        source_binding_refs = {item.block_ref for item in self.source_bindings}
        projected_binding_refs = {item.block_ref for item in self.projected_bindings}
        if source_binding_refs != claim_owned_refs or projected_binding_refs != claim_owned_refs:
            raise ValueError("binding rows must exactly cover the claim-owned references")
        if self.claim.source_generation != self.generation:
            raise ValueError("claim generation does not match result generation")
        _validate_exact_result_authority(
            proposal=self.proposal,
            exclusion=self.exclusion,
            claim=self.claim,
            source_serial_by_ref=source_serial_by_ref,
        )
        witnesses = {item.block_ref: item for item in self.source_catalog.blocks}
        for item in self.source_bindings:
            witness = witnesses.get(item.block_ref)
            serial = source_serial_by_ref.get(item.block_ref)
            if witness is None or serial is None:
                raise ValueError("source binding refers to a foreign catalog row")
            if (
                item.serial != serial
                or item.anchor_ea != witness.anchor_ea
                or item.native_instruction_eas != witness.native_instruction_eas
                or item.generation != self.source_catalog.generation
            ):
                raise ValueError("source binding is not truthfully bound to its catalog row")
        for item in self.projected_bindings:
            witness = witnesses.get(item.block_ref)
            serial = projected_serial_by_ref.get(item.block_ref)
            if witness is None or serial is None:
                raise ValueError("projected binding refers to a foreign catalog row")
            if (
                item.serial != serial
                or item.anchor_ea != witness.anchor_ea
                or item.native_instruction_eas != witness.native_instruction_eas
                or item.generation != self.source_catalog.generation
            ):
                raise ValueError("projected binding is not truthfully bound to its catalog row")


def _binding_content_seal(result: ExactEffectBindingResult) -> str:
    exclusion = result.exclusion
    exclusion_payload = (
        exclusion.normalized_state,
        exclusion.source_serial,
        exclusion.source_ea,
        exclusion.source_write_ea,
        exclusion.predicate_serial,
        exclusion.predicate_ea,
        exclusion.predicate_branch_ea,
        exclusion.selected_target_serial,
        exclusion.selected_target_ea,
        exclusion.discarded_effect_serial,
        exclusion.discarded_effect_ea,
        exclusion.state_identity,
    )
    payload = (
        result.claim,
        result.proposal,
        exclusion_payload,
        result.source_catalog,
        result.source_serial_rows,
        result.projected_serial_rows,
        result.source_bindings,
        result.projected_bindings,
        result.source_graph_fingerprint,
        result.projected_graph_fingerprint,
        result.generation,
    )
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _locator_refs(subject: model.SemanticSubjectRef) -> tuple[object, ...]:
    locator = subject.locator
    if type(locator) is model.BlockSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is model.EdgeSubjectLocator:
        return (locator.source_ref, locator.target_ref)
    if type(locator) is model.RouteSubjectLocator:
        return (locator.source_ref, *locator.destination_refs)
    if type(locator) is model.EffectSubjectLocator:
        return (locator.owner_ref,)
    if type(locator) is model.HandlerSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is model.TerminalSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is model.ValueFlowSubjectLocator:
        return tuple(locator.redirect_owner_refs)
    if type(locator) is model.CorridorSubjectLocator:
        return (locator.entry_ref, *locator.member_refs)
    raise TypeError("subject locator is not closed")


def bind_subjects(
    subjects: Sequence[model.SemanticSubjectRef],
    *,
    catalog: model.SourceIdentityCatalog,
    phase: model.UnflattenAuthorityPhase,
    graph_fingerprint: str,
    generation: int,
    serial_by_ref: Mapping[object, int],
    native_instruction_eas_by_ref: Mapping[object, Sequence[int]] | None = None,
) -> tuple[model.PhaseSubjectBinding, ...]:
    """Bind every subject against one immutable catalog and exact generation.

    The binding operation deliberately accepts no serial fallback and no
    nearest-anchor matching.  A missing, duplicate, foreign, stale, or
    partially matching row is a rejection rather than an ambiguous binding.
    """

    if type(catalog) is not model.SourceIdentityCatalog:
        raise TypeError("catalog must be a SourceIdentityCatalog")
    validate_canonical_roundtrip(catalog, model.SourceIdentityCatalog)
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("phase must be an UnflattenAuthorityPhase")
    if type(graph_fingerprint) is not str or not graph_fingerprint.startswith("sha256:"):
        raise ValueError("graph_fingerprint must be a canonical ID")
    if type(generation) is not int or isinstance(generation, bool) or generation != catalog.generation:
        raise ValueError("binding generation does not match source catalog")
    witnesses = {item.block_ref: item for item in catalog.blocks}
    if len(witnesses) != len(catalog.blocks):
        raise ValueError("source catalog contains duplicate block references")
    if set(serial_by_ref) != set(witnesses):
        raise ValueError("serial binding must exactly cover the source catalog")
    serials = tuple(serial_by_ref.values())
    if any(type(serial) is not int or serial < 0 for serial in serials):
        raise ValueError("serial bindings must be exact non-negative integers")
    if len(set(serials)) != len(serials):
        raise ValueError("serial bindings must be unique")
    origins = (
        {
            ref: witness.native_instruction_eas for ref, witness in witnesses.items()
        }
        if native_instruction_eas_by_ref is None
        else native_instruction_eas_by_ref
    )
    if set(origins) != set(witnesses):
        raise ValueError("native-origin binding must exactly cover the source catalog")

    result: list[model.PhaseSubjectBinding] = []
    seen_subjects: set[str] = set()
    for subject in subjects:
        if type(subject) is not model.SemanticSubjectRef:
            raise TypeError("subjects must contain SemanticSubjectRef values")
        validate_canonical_roundtrip(subject, model.SemanticSubjectRef)
        if subject.subject_id in seen_subjects:
            raise ValueError("subject bindings contain duplicate subjects")
        seen_subjects.add(subject.subject_id)
        refs = _locator_refs(subject)
        if any(ref not in witnesses for ref in refs):
            raise ValueError("subject contains a foreign or missing source reference")
        for ref in refs:
            expected = tuple(witnesses[ref].native_instruction_eas)
            supplied = tuple(origins[ref])
            if supplied != expected:
                raise ValueError("native instruction origins do not exactly match catalog")
        if subject.kind is model.SemanticSubjectKind.VALUE_FLOW:
            result.append(model.PhaseSubjectBinding(
                subject=subject,
                phase=phase,
                block_ref=None,
                graph_fingerprint=graph_fingerprint,
                generation=generation,
                status=model.SubjectBindingStatus.MISSING,
                serial=None,
                anchor_ea=None,
                native_instruction_eas=(),
                role=subject.role,
            ))
            continue
        owner = subject.block_ref
        if owner not in witnesses or subject.anchor_ea is None:
            raise ValueError("subject has no exact owner anchor")
        witness = witnesses[owner]
        if subject.anchor_ea != witness.anchor_ea or subject.anchor_ea not in witness.native_instruction_eas:
            raise ValueError("subject anchor is a near-match for its source witness")
        result.append(model.PhaseSubjectBinding(
            subject=subject,
            phase=phase,
            block_ref=owner,
            graph_fingerprint=graph_fingerprint,
            generation=generation,
            status=model.SubjectBindingStatus.UNIQUE,
            serial=serial_by_ref[owner],
            anchor_ea=subject.anchor_ea,
            native_instruction_eas=witness.native_instruction_eas,
            role=subject.role,
        ))
    return tuple(sorted(result, key=lambda item: item.subject.subject_id))


bind_source_subjects = bind_subjects


def bind_projected_subjects(
    subjects: Sequence[model.SemanticSubjectRef],
    *,
    catalog: model.SourceIdentityCatalog,
    phase: model.UnflattenAuthorityPhase,
    graph_fingerprint: str,
    generation: int,
    serial_by_ref: Mapping[object, int],
    native_instruction_eas_by_ref: Mapping[object, Sequence[int]] | None = None,
) -> tuple[model.PhaseSubjectBinding, ...]:
    """Bind source subjects against a possibly lossy projected graph.

    The projected map is intentionally allowed to omit source references.  A
    subject whose exact owner is absent is represented as ``MISSING``; it is
    not rebound by serial, anchor proximity, or a fabricated projected ref.
    """

    if type(catalog) is not model.SourceIdentityCatalog:
        raise TypeError("catalog must be a SourceIdentityCatalog")
    validate_canonical_roundtrip(catalog, model.SourceIdentityCatalog)
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("phase must be an UnflattenAuthorityPhase")
    if type(graph_fingerprint) is not str or not graph_fingerprint.startswith("sha256:"):
        raise ValueError("graph_fingerprint must be a canonical ID")
    if type(generation) is not int or isinstance(generation, bool) or generation != catalog.generation:
        raise ValueError("binding generation does not match source catalog")
    witnesses = {item.block_ref: item for item in catalog.blocks}
    if len(witnesses) != len(catalog.blocks):
        raise ValueError("source catalog contains duplicate block references")
    extra_refs = {
        ref for ref in serial_by_ref
        if ref not in witnesses
    }
    if any(type(ref) is not PlanBlockRef for ref in extra_refs):
        raise ValueError("projected serial binding contains a foreign source reference")
    serials = tuple(serial_by_ref.values())
    if any(type(serial) is not int or serial < 0 for serial in serials):
        raise ValueError("serial bindings must be exact non-negative integers")
    if len(set(serials)) != len(serials):
        raise ValueError("serial bindings must be unique")
    origins = (
        {
            ref: witness.native_instruction_eas
            for ref, witness in witnesses.items()
            if ref in serial_by_ref
        }
        if native_instruction_eas_by_ref is None
        else native_instruction_eas_by_ref
    )
    if native_instruction_eas_by_ref is not None and set(origins) != set(serial_by_ref):
        raise ValueError("projected native-origin binding must cover every projected reference")
    if any(ref not in serial_by_ref for ref in origins):
        raise ValueError("projected native-origin binding contains a foreign reference")
    for ref, supplied in origins.items():
        if ref in witnesses:
            expected_origins = tuple(witnesses[ref].native_instruction_eas)
            supplied_origins = tuple(supplied)
            if supplied_origins != expected_origins and not (
                ref in extra_refs
                and type(ref) is PlanBlockRef
                and
                supplied_origins
                and set(supplied_origins) < set(expected_origins)
                and witnesses[ref].anchor_ea in supplied_origins
            ):
                raise ValueError("native instruction origins do not exactly match catalog")
        if ref in extra_refs and (
            type(supplied) is not tuple
            or not supplied
            or any(type(ea) is not int or ea < 0 for ea in supplied)
            or len(set(supplied)) != len(supplied)
        ):
            raise ValueError("plan helper origins must be exact and nonempty")

    result: list[model.PhaseSubjectBinding] = []
    seen_subjects: set[str] = set()
    for subject in subjects:
        if type(subject) is not model.SemanticSubjectRef:
            raise TypeError("subjects must contain SemanticSubjectRef values")
        validate_canonical_roundtrip(subject, model.SemanticSubjectRef)
        if subject.subject_id in seen_subjects:
            raise ValueError("subject bindings contain duplicate subjects")
        seen_subjects.add(subject.subject_id)
        refs = _locator_refs(subject)
        if any(ref not in witnesses and ref not in extra_refs for ref in refs):
            raise ValueError("subject contains a foreign or missing source reference")
        owner = subject.block_ref
        if subject.kind is model.SemanticSubjectKind.VALUE_FLOW:
            owner_present = False
        else:
            if owner is None:
                raise ValueError("projected subject has no exact owner")
            owner_present = owner in serial_by_ref
        complete = all(ref in serial_by_ref for ref in refs)
        if not owner_present or not complete:
            result.append(model.PhaseSubjectBinding(
                subject=subject,
                phase=phase,
                block_ref=None,
                graph_fingerprint=graph_fingerprint,
                generation=generation,
                status=model.SubjectBindingStatus.MISSING,
                serial=None,
                anchor_ea=None,
                native_instruction_eas=(),
                role=subject.role,
            ))
            continue
        if owner in witnesses:
            witness_anchor = witnesses[owner].anchor_ea
            witness_origins = tuple(origins[owner])
        else:
            witness_anchor = subject.anchor_ea
            witness_origins = tuple(origins.get(owner, ()))
        if subject.anchor_ea is None or subject.anchor_ea != witness_anchor:
            raise ValueError("subject anchor is a near-match for its source witness")
        if subject.anchor_ea not in witness_origins:
            raise ValueError("projected subject origin does not exactly match catalog")
        result.append(model.PhaseSubjectBinding(
            subject=subject,
            phase=phase,
            block_ref=owner,
            graph_fingerprint=graph_fingerprint,
            generation=generation,
            status=model.SubjectBindingStatus.UNIQUE,
            serial=serial_by_ref[owner],
            anchor_ea=subject.anchor_ea,
            native_instruction_eas=witness_origins,
            role=subject.role,
        ))
    return tuple(sorted(result, key=lambda item: item.subject.subject_id))


def bind_inventory_subjects(
    subjects: Sequence[model.SemanticSubjectRef],
    *,
    catalog: model.SourceIdentityCatalog,
    phase: model.UnflattenAuthorityPhase,
    graph_fingerprint: str,
    generation: int,
    serial_by_ref: Mapping[object, int],
    effects: Sequence[model.InventoryEffectSite],
    terminals: Sequence[model.InventoryTerminalSite],
    reachable_serials: Sequence[int],
    native_instruction_eas_by_ref: Mapping[object, Sequence[int]] | None = None,
) -> tuple[model.PhaseSubjectBinding, ...]:
    """Bind an inventory using the inventory's exact reachable site rows.

    Block ownership is not sufficient evidence for an effect or terminal
    subject.  This is the canonical site-level binding operation used by the
    projected and observed inventory builders; every downstream gate consumes
    the resulting binding status rather than reconstructing site presence.
    """
    if type(subjects) is not tuple:
        raise TypeError("subjects must be an exact tuple")
    if type(effects) is not tuple:
        raise TypeError("effects must be an exact tuple")
    if type(terminals) is not tuple:
        raise TypeError("terminals must be an exact tuple")
    if any(type(row) is not model.InventoryEffectSite for row in effects):
        raise TypeError("effects must contain exact InventoryEffectSite rows")
    if any(type(row) is not model.InventoryTerminalSite for row in terminals):
        raise TypeError("terminals must contain exact InventoryTerminalSite rows")
    if type(reachable_serials) is not tuple:
        raise TypeError("reachable_serials must be an exact tuple")
    if reachable_serials != tuple(sorted(set(reachable_serials))) or any(
        type(serial) is not int or serial < 0 for serial in reachable_serials
    ):
        raise ValueError("reachable_serials must be sorted exact non-negative integers")
    # Validate all closed row inputs before binding any subject.  The model
    # resolver is the shared owner of site identity and status semantics.
    for row in (*effects, *terminals):
        row.__post_init__()
        if row.owner_serial not in reachable_serials:
            raise ValueError("inventory site row is outside reachable_serials")
    base = bind_projected_subjects(
        subjects,
        catalog=catalog,
        phase=phase,
        graph_fingerprint=graph_fingerprint,
        generation=generation,
        serial_by_ref=serial_by_ref,
        native_instruction_eas_by_ref=native_instruction_eas_by_ref,
    )
    rebound: list[model.PhaseSubjectBinding] = []
    for binding in base:
        if binding.subject.role in (
            model.SemanticSubjectRole.EFFECT_SITE,
            model.SemanticSubjectRole.TERMINAL_SITE,
        ) and type(binding.subject.locator) in (
            model.EffectSubjectLocator,
            model.TerminalSubjectLocator,
        ):
            rebound.append(model.resolve_inventory_site_binding(
                binding.subject,
                binding,
                effects=effects,
                terminals=terminals,
                reachable_serials=reachable_serials,
                serial_by_ref=dict(serial_by_ref),
            ))
        else:
            rebound.append(binding)
    return tuple(sorted(rebound, key=lambda item: item.subject.subject_id))


def _graph_bind_exact_effect_claim(
    *,
    source: FlowGraph,
    projected: FlowGraph,
    source_block_refs_by_serial: Mapping[int, object],
    projected_serial_by_ref: Mapping[object, int],
    exclusion: ExactStateBranchEffectExclusion,
    claim: model.ExactInfeasibleEffectClaim,
    proposal: model.ProposedUnflattenContract,
    generation: int,
    _mint_result: object,
    _lifecycle_secret: object,
) -> ExactEffectBindingResult:
    """Replay exact source/projected topology before emitting bindings.

    This facade is intentionally narrower than the generic binders. It accepts
    only the exact-effect claim, replays the immutable source/projected proof,
    correlates every claim locator to the source catalog, and returns source
    and projected phase bindings. Any changed topology, identity, generation,
    or claim/exclusion field rejects the complete fragment.
    """

    if type(source) is not FlowGraph or type(projected) is not FlowGraph:
        raise TypeError("exact-effect binding requires exact FlowGraph values")
    if type(exclusion) is not ExactStateBranchEffectExclusion:
        raise TypeError("exact-effect binding requires the closed exclusion type")
    if type(claim) is not model.ExactInfeasibleEffectClaim:
        raise TypeError("exact-effect binding requires the closed claim type")
    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("exact-effect binding requires the closed proposal type")
    validate_canonical_roundtrip(proposal, model.ProposedUnflattenContract)
    validate_canonical_roundtrip(claim, model.ExactInfeasibleEffectClaim)
    if claim not in proposal.claims or claim.source_generation != generation:
        raise ValueError("exact-effect claim is foreign to the proposal generation")
    if proposal.source_identity_catalog.generation != generation:
        raise ValueError("exact-effect proposal generation is stale")
    if not validate_exact_state_branch_effect_exclusion(source, projected, exclusion):
        raise ValueError("exact-effect source/projected topology is not exact")

    if type(source_block_refs_by_serial) is not dict:
        raise TypeError("source serial map must be an exact dict")
    source_rows = tuple(source_block_refs_by_serial.items())
    if any(
        type(serial) is not int or serial < 0
        or type(ref) not in (NativeBlockRef, LogicalBlockRef)
        for serial, ref in source_rows
    ):
        raise ValueError("source serial map contains a non-canonical row")
    for _serial, ref in source_rows:
        validate_canonical_roundtrip(ref, type(ref))
    by_serial = dict(source_rows)
    catalog_by_ref = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }
    if set(by_serial.values()) != set(catalog_by_ref):
        raise ValueError("source serial map does not exactly cover the proposal catalog")
    for serial, ref in by_serial.items():
        block = source.get_block(serial)
        anchor = None if block is None else block.native_start_ea
        if anchor is None and block is not None:
            anchor = block.start_ea
        if block is None or type(anchor) is not int or anchor != catalog_by_ref[ref].anchor_ea:
            raise ValueError("source block identity does not match the proposal catalog")
    if type(projected_serial_by_ref) is not dict:
        raise TypeError("projected serial map must be an exact dict")
    projected_rows = tuple(projected_serial_by_ref.items())
    if any(
        type(ref) not in (NativeBlockRef, LogicalBlockRef)
        or type(serial) is not int or serial < 0
        for ref, serial in projected_rows
    ):
        raise ValueError("projected serial map contains a non-canonical row")
    for ref, _serial in projected_rows:
        validate_canonical_roundtrip(ref, type(ref))
    projected_rows_map = dict(projected_rows)
    if len(projected_rows_map) != len(projected_rows) or len({serial for _ref, serial in projected_rows}) != len(projected_rows):
        raise ValueError("projected serial map contains duplicate identity rows")
    for ref, serial in projected_rows:
        block = projected.get_block(serial)
        anchor = None if block is None else block.native_start_ea
        if anchor is None and block is not None:
            anchor = block.start_ea
        if ref not in catalog_by_ref or block is None or type(anchor) is not int or anchor != catalog_by_ref[ref].anchor_ea:
            raise ValueError("projected block identity is foreign or missing")
    exclusion_refs = {}
    for name in (
        "source_serial", "predicate_serial", "selected_target_serial",
        "discarded_effect_serial",
    ):
        serial = getattr(exclusion, name)
        if serial not in by_serial:
            raise ValueError("exact-effect exclusion refers to an unknown source serial")
        exclusion_refs[name] = by_serial[serial]
    if claim.state_identity != exclusion.state_identity:
        raise ValueError("exact-effect claim state identity is not exclusion-bound")
    if claim.normalized_state != exclusion.normalized_state:
        raise ValueError("exact-effect claim state value is not exclusion-bound")
    if claim.source_write_ea != exclusion.source_write_ea:
        raise ValueError("exact-effect claim source write is not exclusion-bound")
    if claim.predicate_branch_ea != exclusion.predicate_branch_ea:
        raise ValueError("exact-effect claim predicate branch is not exclusion-bound")
    discarded_witness = catalog_by_ref[exclusion_refs["discarded_effect_serial"]]
    if claim.discarded_effect_subject.anchor_ea != discarded_witness.anchor_ea:
        raise ValueError("exact-effect claim discarded block anchor is foreign")
    if claim.discarded_effect_subject.locator.instruction_ea != claim.discarded_effect_ea:
        raise ValueError("exact-effect claim discarded effect EA is not locator-bound")
    expected_claim = producer_api.build_exact_effect_claim(
        exclusion=exclusion,
        source=source,
        source_catalog=proposal.source_identity_catalog,
        block_refs_by_serial=by_serial,
        canonical_route_evidence=proposal.route_evidence,
        state_identity=proposal.plan_inputs.state_identity,
    )
    if claim != expected_claim or claim.claim_id != expected_claim.claim_id:
        raise ValueError("exact-effect claim does not match canonical producer reconstruction")
    if claim.source_subject.block_ref != exclusion_refs["source_serial"]:
        raise ValueError("exact-effect claim source identity is foreign")
    if claim.predicate_subject.block_ref != exclusion_refs["predicate_serial"]:
        raise ValueError("exact-effect claim predicate identity is foreign")
    if claim.selected_target_subject.block_ref != exclusion_refs["selected_target_serial"]:
        raise ValueError("exact-effect claim selected identity is foreign")
    if claim.discarded_effect_subject.block_ref != exclusion_refs["discarded_effect_serial"]:
        raise ValueError("exact-effect claim discarded identity is foreign")
    source_origins = {
        ref: witness.native_instruction_eas
        for ref, witness in catalog_by_ref.items()
    }
    exact_subjects = tuple({
        item.subject_id: item for item in (
            claim.effect_subject, claim.source_subject, claim.predicate_subject,
            claim.selected_target_subject, claim.discarded_effect_subject,
        )
    }.values())
    source_bindings = bind_source_subjects(
        exact_subjects,
        catalog=proposal.source_identity_catalog,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        graph_fingerprint=semantic_graph_fingerprint(source),
        generation=generation,
        serial_by_ref={ref: serial for serial, ref in by_serial.items()},
        native_instruction_eas_by_ref=source_origins,
    )
    projected_bindings = bind_projected_subjects(
        exact_subjects,
        catalog=proposal.source_identity_catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=semantic_graph_fingerprint(projected),
        generation=generation,
        serial_by_ref=projected_rows_map,
    )
    if any(item.status is not model.SubjectBindingStatus.UNIQUE for item in projected_bindings):
        raise ValueError("exact-effect projected bindings must be unique")
    expected_serials = {
        by_serial[getattr(exclusion, field)]: getattr(exclusion, field)
        for field in (
            "source_serial", "predicate_serial", "selected_target_serial",
            "discarded_effect_serial",
        )
    }
    if any(projected_rows_map.get(ref) != serial for ref, serial in expected_serials.items()):
        raise ValueError("projected exact-effect serials do not match the exclusion")
    source_fingerprint = semantic_graph_fingerprint(source)
    projected_fingerprint = semantic_graph_fingerprint(projected)
    if any(item.graph_fingerprint != source_fingerprint for item in source_bindings):
        raise ValueError("source bindings do not contain the measured graph fingerprint")
    if any(item.graph_fingerprint != projected_fingerprint for item in projected_bindings):
        raise ValueError("projected bindings do not contain the measured graph fingerprint")
    source_rows = tuple(
        (item.block_ref, {ref: serial for serial, ref in by_serial.items()}[item.block_ref])
        for item in proposal.source_identity_catalog.blocks
        if item.block_ref in {
            subject.block_ref
            for subject in (
                claim.source_subject,
                claim.predicate_subject,
                claim.selected_target_subject,
                claim.discarded_effect_subject,
            )
        }
    )
    projected_rows = tuple(
        (item.block_ref, projected_rows_map[item.block_ref])
        for item in proposal.source_identity_catalog.blocks
        if item.block_ref in projected_rows_map
        and item.block_ref in {
            subject.block_ref
            for subject in (
                claim.source_subject,
                claim.predicate_subject,
                claim.selected_target_subject,
                claim.discarded_effect_subject,
            )
        }
    )
    if _lifecycle_secret is None:
        raise TypeError("exact-effect binding lifecycle is closed")
    return _mint_result(
        claim=claim,
        proposal=proposal,
        exclusion=exclusion,
        source_catalog=proposal.source_identity_catalog,
        source_serial_rows=source_rows,
        projected_serial_rows=projected_rows,
        source_bindings=source_bindings,
        projected_bindings=projected_bindings,
        source_graph_fingerprint=source_fingerprint,
        projected_graph_fingerprint=projected_fingerprint,
        generation=generation,
    )


def _make_binding_entrypoint(graph_impl=_graph_bind_exact_effect_claim):
    registry: dict[int, tuple[weakref.ReferenceType[ExactEffectBindingResult], str]] = {}
    lifecycle_secret = object()

    def validate(result: ExactEffectBindingResult) -> None:
        if type(result) is not ExactEffectBindingResult:
            raise TypeError("exact-effect result must be closed")
        registered = registry.get(id(result))
        if registered is None or registered[0]() is not result:
            raise ValueError("exact-effect result was not minted by the graph binder")
        if result._content_seal != registered[1] or registered[1] != _binding_content_seal(result):
            raise ValueError("exact-effect binding content seal does not match")
        result._validate_fields()

    def mint(**values: object) -> ExactEffectBindingResult:
        result = object.__new__(ExactEffectBindingResult)
        for name, value in values.items():
            object.__setattr__(result, name, value)
        object.__setattr__(result, "_content_seal", _binding_content_seal(result))
        identity = id(result)
        def cleanup(reference: weakref.ReferenceType[ExactEffectBindingResult]) -> None:
            registered = registry.get(identity)
            if registered is not None and registered[0] is reference:
                registry.pop(identity, None)
        reference = weakref.ref(result, cleanup)
        registry[identity] = (reference, result._content_seal)
        validate(result)
        return result

    def entrypoint(**kwargs: object) -> ExactEffectBindingResult:
        return graph_impl(
            **kwargs, _mint_result=mint, _lifecycle_secret=lifecycle_secret,
        )

    return entrypoint, validate


bind_exact_effect_claim, validate_exact_effect_binding_result = _make_binding_entrypoint()


def validate_retired_infrastructure_binding_result(
    result: RetiredInfrastructureBindingResult,
) -> None:
    """Reject a retirement binding mutated after it was sealed."""

    if type(result) is not RetiredInfrastructureBindingResult:
        raise TypeError("retirement result must be closed")
    if result._content_seal != _retirement_binding_seal(result):
        raise ValueError("retirement binding content seal does not match")
    result._validate_fields()
del _make_binding_entrypoint
del _graph_bind_exact_effect_claim


__all__ = [
    "ExactEffectBindingResult",
    "RetiredInfrastructureBindingResult",
    "TerminalCycleBindingResult",
    "bind_detached_dead_handler_component_claim",
    "bind_retired_dispatcher_infrastructure_claim",
    "bind_terminal_cycle_break_claim",
    "terminal_cycle_binding_subjects",
    "validate_exact_effect_binding_result",
    "validate_detached_source_result",
    "validate_detached_phase_result",
    "validate_retired_infrastructure_binding_result",
    "validate_terminal_cycle_binding_result",
    "bind_subjects",
    "bind_source_subjects",
    "bind_projected_subjects",
    "bind_exact_effect_claim",
]
