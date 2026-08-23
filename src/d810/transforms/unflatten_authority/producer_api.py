"""Producer-side, serial-free inputs for unflatten authority.

The producer is deliberately a small adapter layer.  It consumes the complete
portable source graph, the exact identity-index export for that graph, and one
canonical route-evidence object.  It does not inspect metadata, attach a
proposal, or invoke transaction code.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib

from d810.analyses.control_flow.semantic_route_evidence import (
    bind_canonical_semantic_evidence,
    CanonicalSemanticEvidence,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteShape,
    SemanticStateWriteDeliveryKind,
)
from d810.analyses.control_flow.effect_branch_exclusion import (
    ExactStateBranchEffectExclusion,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity
from d810.ir.block_identity import StableBlockIdentity
from d810.transforms.cfg_transaction import CfgBlockRef, LogicalBlockRef, NativeBlockRef, PlanBlockRef
from d810.transforms.use_def_redirect_filter import UseDefSeveranceAudit

from .model import (
    AuthoritativeHandlerInput,
    EffectSiteKind,
    EffectSubjectLocator,
    EquivalentSemanticRouteClaim,
    SourceBlockIdentityWitness,
    SourceIdentityCatalog,
    TerminalKind,
    TerminalSubjectLocator,
    UnflattenPlanInputCatalog,
    UnflattenPlanShape,
    UseDefFragmentWitness,
    BlockSubjectLocator,
    ExactInfeasibleEffectClaim,
    ProposedUnflattenContract,
    ProviderConsensusMode,
    ProviderConsensusWitness,
    SemanticSubjectKind,
    SemanticSubjectRef,
    SemanticSubjectRole,
    RouteSubjectLocator,
    UnflattenClaimKind,
    InventoryEffectSite,
    InventoryInstructionObservation,
    validate_inventory_control_transfer,
    InventoryTerminalSite,
    resolve_inventory_block_sites,
)
from . import model
from .ids import (
    _claim_factory,
    _subject_factory,
    validate_canonical_roundtrip,
)


_BADADDR = 0xFFFFFFFFFFFFFFFF
AuthorityBlockRef = NativeBlockRef | LogicalBlockRef


def _validate_classifier_operand(operand: object, label: str) -> None:
    if operand is None:
        return
    if type(operand) is not MopSnapshot:
        raise TypeError(f"{label} must be an exact MopSnapshot")
    if type(operand.t) is not int or type(operand.size) is not int or operand.size < 0:
        raise TypeError(f"{label} scalar fields must be exact ints")
    if type(operand.kind) is not OperandKind:
        raise TypeError(f"{label}.kind must be OperandKind")
    if type(operand.args) is not tuple:
        raise TypeError(f"{label}.args must be an exact tuple")
    for index, child in enumerate(operand.args):
        _validate_classifier_operand(child, f"{label}.args[{index}]")
    _validate_classifier_operand(operand.sub_l, f"{label}.sub_l")
    _validate_classifier_operand(operand.sub_r, f"{label}.sub_r")


def _validate_classifier_instruction(insn: object) -> None:
    if type(insn) is not InsnSnapshot:
        raise TypeError("block instructions must be exact InsnSnapshot values")
    if type(insn.opcode) is not int or type(insn.ea) is not int:
        raise TypeError("instruction opcode and EA must be exact ints")
    if type(insn.operands) is not tuple or type(insn.operand_slots) is not tuple:
        raise TypeError("instruction operand collections must be exact tuples")
    if type(insn.kind) is not InsnKind:
        raise TypeError("instruction kind must be exact InsnKind")
    for name, value, enum_type in (
        ("value_op_kind", insn.value_op_kind, ValueOpKind),
        ("control_transfer_kind", insn.control_transfer_kind, ControlTransferKind),
        ("call_kind", insn.call_kind, CallKind),
        ("predicate_kind", insn.predicate_kind, PredicateKind),
        ("branch_predicate", insn.branch_predicate, PredicateKind),
    ):
        if value is not None and type(value) is not enum_type:
            raise TypeError(f"instruction {name} must be exact {enum_type.__name__}")
    validate_inventory_control_transfer(insn.kind, insn.control_transfer_kind)
    for name, value in (
        ("is_conditional_jump", insn.is_conditional_jump),
        ("is_unconditional_jump", insn.is_unconditional_jump),
        ("is_call", insn.is_call),
    ):
        if type(value) is not bool:
            raise TypeError(f"instruction {name} must be an exact bool")
    for name, value in (
        ("raw_opcode", insn.raw_opcode),
        ("compare_width", insn.compare_width),
        ("native_ea", insn.native_ea),
    ):
        if value is not None and type(value) is not int:
            raise TypeError(f"instruction {name} must be an exact int or None")
    if type(insn.display_text) is not str or not isinstance(insn.opcode_attrs, Mapping):
        raise TypeError("instruction text and opcode attributes are malformed")
    _validate_classifier_operand(insn.l, "instruction.l")
    _validate_classifier_operand(insn.r, "instruction.r")
    _validate_classifier_operand(insn.d, "instruction.d")


def _classifier_ea(value: object) -> bool:
    return type(value) is int and 0 <= value < _BADADDR


def _graph_start_ea(value: object) -> bool:
    return type(value) is int and 0 <= value <= _BADADDR


def _validate_classifier_block(block: BlockSnapshot) -> None:
    if type(block) is not BlockSnapshot:
        raise TypeError("block must be an exact BlockSnapshot")
    if type(block.serial) is not int or type(block.insn_snapshots) is not tuple:
        raise TypeError("block serial and instructions must be exact")
    if block.serial < 0:
        raise ValueError("block serial must be nonnegative")
    if type(block.block_type) is not int or block.block_type < 0 or type(block.flags) is not int or block.flags < 0 or not _graph_start_ea(block.start_ea):
        raise TypeError("block scalar fields must be exact ints")
    if block.native_start_ea is not None and not _classifier_ea(block.native_start_ea):
        raise TypeError("block native_start_ea must be an exact int or None")
    if block.tail_opcode is not None and type(block.tail_opcode) is not int:
        raise TypeError("block tail_opcode must be an exact int or None")
    if block.raw_block_type is not None and type(block.raw_block_type) is not int:
        raise TypeError("block raw_block_type must be an exact int or None")
    if block.raw_tail_opcode is not None and type(block.raw_tail_opcode) is not int:
        raise TypeError("block raw_tail_opcode must be an exact int or None")
    if block.tail_kind is not None and type(block.tail_kind) is not InsnKind:
        raise TypeError("block tail_kind must be exact InsnKind or None")
    if type(block.kind) is not BlockKind:
        raise TypeError("block kind must be exact BlockKind")
    if type(block.succs) is not tuple or type(block.preds) is not tuple:
        raise TypeError("block topology collections must be exact tuples")
    if any(type(serial) is not int or serial < 0 for serial in (*block.succs, *block.preds)):
        raise TypeError("block topology serials must be exact nonnegative ints")
    for instruction in block.insn_snapshots:
        _validate_classifier_instruction(instruction)


def _inventory_instruction_rows(
    block: BlockSnapshot,
) -> tuple[InventoryInstructionObservation, ...]:
    _validate_classifier_block(block)
    rows: list[InventoryInstructionObservation] = []
    for ordinal, insn in enumerate(block.insn_snapshots):
        raw_native_ea = insn.native_ea if _classifier_ea(insn.native_ea) else insn.ea
        instruction_ea = int(raw_native_ea) if _classifier_ea(raw_native_ea) else None
        if type(insn.opcode) is not int:
            raise TypeError("opcode must be an exact int")
        sizes: list[int] = []
        for name, operand in (("l", insn.l), ("r", insn.r), ("d", insn.d)):
            if operand is None:
                continue
            if type(operand) is not MopSnapshot:
                raise TypeError(f"{name} must be an exact MopSnapshot")
            if type(operand.size) is not int or isinstance(operand.size, bool) or operand.size < 0:
                raise ValueError("operand size must be a nonnegative exact int")
            sizes.append(operand.size)
        rows.append(InventoryInstructionObservation(
            ordinal, instruction_ea, insn.opcode, max(sizes, default=0),
            insn.kind, insn.control_transfer_kind, insn.is_call, insn.call_kind,
            insn.display_text,
        ))
    return tuple(rows)


def observe_inventory_block(
    block: BlockSnapshot,
    *,
    owner_ref: CfgBlockRef | None,
    owner_anchor_ea: int | None,
) -> model.InventoryBlockObservation:
    """Adapt one exact block snapshot into the closed inventory vocabulary."""

    rows = _inventory_instruction_rows(block)
    if owner_ref is not None and type(owner_ref) not in (NativeBlockRef, LogicalBlockRef, PlanBlockRef):
        raise TypeError("owner_ref must be a CfgBlockRef or None")
    if owner_anchor_ea is not None and not _classifier_ea(owner_anchor_ea):
        raise ValueError("owner_anchor_ea must be a valid native EA or None")
    anchor_ea = owner_anchor_ea
    if anchor_ea is None:
        if _classifier_ea(block.native_start_ea):
            anchor_ea = block.native_start_ea
        elif _classifier_ea(block.start_ea):
            anchor_ea = block.start_ea
    transfer_ea = None
    if rows and rows[-1].control_transfer_kind is not None:
        transfer_ea = rows[-1].instruction_ea
    return model.InventoryBlockObservation(
        serial=block.serial,
        block_ref=owner_ref,
        anchor_ea=anchor_ea,
        native_instruction_eas=tuple(sorted({
            row.instruction_ea for row in rows if row.instruction_ea is not None
        })),
        predecessor_serials=tuple(sorted(block.preds)),
        successor_serials=tuple(sorted(block.succs)),
        transfer_ea=transfer_ea,
        instruction_observations=rows,
        block_kind=block.kind,
        graph_start_ea=block.start_ea,
    )


def classify_block_effects_and_terminals(
    block: BlockSnapshot,
    *,
    owner_ref: CfgBlockRef | None,
    owner_anchor_ea: int,
) -> tuple[tuple[InventoryEffectSite, ...], tuple[InventoryTerminalSite, ...]]:
    """Classify one immutable block through the closed inventory adapter."""

    observed = observe_inventory_block(
        block, owner_ref=owner_ref, owner_anchor_ea=owner_anchor_ea,
    )
    return resolve_inventory_block_sites(
        serial=observed.serial,
        owner_ref=observed.block_ref,
        owner_anchor_ea=observed.anchor_ea if observed.anchor_ea is not None else 0,
        block_kind=observed.block_kind,
        successor_serials=observed.successor_serials,
        instruction_observations=observed.instruction_observations,
    )


@dataclass(frozen=True, slots=True)
class DiscoveredEffect:
    """One reachable effect site with its exact serial-free locator."""

    locator: EffectSubjectLocator

    @property
    def effect_kind(self) -> EffectSiteKind:
        return self.locator.effect_kind


@dataclass(frozen=True, slots=True)
class DiscoveredTerminal:
    """One reachable terminal site with its exact serial-free locator."""

    locator: TerminalSubjectLocator

    @property
    def terminal_kind(self) -> TerminalKind:
        return self.locator.terminal_kind


@dataclass(frozen=True, slots=True)
class SourceEffectTerminalCatalog:
    """The disjoint reachable effect and terminal discovery result."""

    effects: tuple[DiscoveredEffect, ...]
    terminals: tuple[DiscoveredTerminal, ...]

    def __iter__(self):
        yield self.effects
        yield self.terminals


@dataclass(frozen=True, slots=True)
class _ExactEffectSemanticCorrelation:
    """The producer-owned portable correlation for one exact effect claim."""

    proof: SemanticRouteProof
    selected_destination: SemanticRouteDestination
    discarded_destination: SemanticRouteDestination
    exclusion: ExactStateBranchEffectExclusion
    effect_locator: EffectSubjectLocator
    normalized_state: int
    state_identity: StorageIdentity
    source_write_ea: int
    predicate_branch_ea: int
    discarded_effect_ea: int
    source_identity: StableBlockIdentity
    predicate_identity: StableBlockIdentity
    selected_identity: StableBlockIdentity
    discarded_identity: StableBlockIdentity
    width: int

    def __post_init__(self) -> None:
        if type(self.proof) is not SemanticRouteProof:
            raise TypeError("correlation proof must be SemanticRouteProof")
        if type(self.selected_destination) is not SemanticRouteDestination or type(self.discarded_destination) is not SemanticRouteDestination:
            raise TypeError("correlation destinations must be SemanticRouteDestination")
        if type(self.exclusion) is not ExactStateBranchEffectExclusion:
            raise TypeError("correlation exclusion must be ExactStateBranchEffectExclusion")
        if type(self.effect_locator) is not EffectSubjectLocator:
            raise TypeError("correlation effect locator must be EffectSubjectLocator")
        if type(self.effect_locator.owner_ref) is not NativeBlockRef:
            raise TypeError("correlation effect locator must use NativeBlockRef")
        self.exclusion.__post_init__()
        self.effect_locator.__post_init__()
        if type(self.state_identity) is not StorageIdentity:
            raise TypeError("correlation state identity must be StorageIdentity")
        for value, label in (
            (self.normalized_state, "normalized_state"),
            (self.source_write_ea, "source_write_ea"),
            (self.predicate_branch_ea, "predicate_branch_ea"),
            (self.discarded_effect_ea, "discarded_effect_ea"),
            (self.width, "width"),
        ):
            if type(value) is not int:
                raise TypeError(f"correlation {label} must be a built-in int")
        if not 0 <= self.normalized_state <= 0xFFFFFFFF or not 1 <= self.width <= 8:
            raise ValueError("correlation scalar is outside its canonical range")
        if any(value <= 0 or value >= _BADADDR for value in (self.source_write_ea, self.predicate_branch_ea, self.discarded_effect_ea)):
            raise ValueError("correlation EA is not a native address")
        if (
            self.normalized_state != self.exclusion.normalized_state
            or self.state_identity != self.exclusion.state_identity
            or self.source_write_ea != self.exclusion.source_write_ea
            or self.predicate_branch_ea != self.exclusion.predicate_branch_ea
            or self.discarded_effect_ea != self.exclusion.discarded_effect_ea
            or self.effect_locator.instruction_ea != self.discarded_effect_ea
            or self.effect_locator.effect_kind not in {EffectSiteKind.CALL, EffectSiteKind.STORE}
        ):
            raise ValueError("correlation scalar disagrees with canonical exclusion/effect locator")
        if not all(type(identity) is StableBlockIdentity for identity in (self.source_identity, self.predicate_identity, self.selected_identity, self.discarded_identity)):
            raise TypeError("correlation identities must be StableBlockIdentity")
        if self.proof.proof_kind is not SemanticRouteProofKind.STATE_CHOICE or self.proof.state_write is None or self.proof.predicate is None:
            raise ValueError("correlation proof is not a complete state choice")
        if self.proof.native_key != self.selected_destination.target_identity.native_key:
            raise ValueError("correlation proof and destination keys disagree")
        write = self.proof.state_write
        predicate = self.proof.predicate
        if (
            self.proof.source_identity != self.predicate_identity
            or self.proof.predicate.origin.identity != self.predicate_identity
            or self.proof.predicate.consumer.identity != self.proof.source_identity
            or write.identity != self.source_identity
            or write.state_variable != self.state_identity
            or write.width != self.width
            or write.state_constant != self.normalized_state
            or write.instruction_ea != self.source_write_ea
            or predicate.origin.anchor_ea != self.predicate_branch_ea
            or predicate.storage_identity != self.state_identity
            or predicate.width != self.width
        ):
            raise ValueError("correlation proof fields disagree")
        if self.selected_destination not in self.proof.destinations or self.discarded_destination not in self.proof.destinations:
            raise ValueError("correlation destinations are not proof-owned")
        if self.selected_destination.target_identity != self.selected_identity or self.discarded_destination.target_identity != self.discarded_identity:
            raise ValueError("correlation destination identities disagree")
        if self.selected_destination.state_constant != self.normalized_state:
            raise ValueError("correlation selected state disagrees")
        if self.discarded_destination.state_constant == self.selected_destination.state_constant:
            raise ValueError("correlation destinations must represent distinct state arms")
        if (
            self.effect_locator.owner_ref.identity != self.discarded_identity
            or self.effect_locator.owner_anchor_ea != self.discarded_destination.target_anchor_ea
            or self.effect_locator.owner_ref.identity.native_key != self.proof.native_key
        ):
            raise ValueError("correlation effect locator does not match discarded route destination")
        if self.selected_destination.role is self.discarded_destination.role:
            raise ValueError("correlation destination roles must differ")


def _resolve_exact_effect_semantics(
    *,
    exclusion: ExactStateBranchEffectExclusion,
    source_catalog: SourceIdentityCatalog,
    route_evidence: CanonicalSemanticEvidence,
    state_identity: StorageIdentity,
    source_locator: BlockSubjectLocator,
    predicate_locator: BlockSubjectLocator,
    selected_locator: BlockSubjectLocator,
    effect_locator: EffectSubjectLocator,
    source_serial_by_ref: dict[object, int],
    expected_route_proof_id: str | None = None,
    expected_selected_edge_role: SemanticEdgeRole | None = None,
    expected_width: int | None = None,
) -> _ExactEffectSemanticCorrelation:
    """Resolve the sole canonical route proof and all exact-effect fields."""

    if type(exclusion) is not ExactStateBranchEffectExclusion or type(source_catalog) is not SourceIdentityCatalog or type(route_evidence) is not CanonicalSemanticEvidence:
        raise TypeError("exact semantic inputs are not closed")
    if type(state_identity) is not StorageIdentity or any(type(locator) is not BlockSubjectLocator for locator in (source_locator, predicate_locator, selected_locator)) or type(effect_locator) is not EffectSubjectLocator:
        raise TypeError("exact semantic locators are not closed")
    if any(type(locator.block_ref) is not NativeBlockRef for locator in (source_locator, predicate_locator, selected_locator)) or type(effect_locator.owner_ref) is not NativeBlockRef:
        raise ValueError("exact semantic locators require native identities")
    if exclusion.state_identity != state_identity or source_locator.anchor_ea != exclusion.source_ea or predicate_locator.anchor_ea != exclusion.predicate_ea or selected_locator.anchor_ea != exclusion.selected_target_ea or effect_locator.instruction_ea != exclusion.discarded_effect_ea:
        raise ValueError("exact semantic locator fields disagree with exclusion")
    subjects = (
        (exclusion.source_serial, source_locator.block_ref),
        (exclusion.predicate_serial, predicate_locator.block_ref),
        (exclusion.selected_target_serial, selected_locator.block_ref),
        (exclusion.discarded_effect_serial, effect_locator.owner_ref),
    )
    if any(source_serial_by_ref.get(ref) != serial for serial, ref in subjects):
        raise ValueError("exact semantic serials do not resolve to locators")
    if expected_route_proof_id is not None and type(expected_route_proof_id) is not str:
        raise TypeError("expected route proof id must be a string")
    if expected_selected_edge_role is not None and type(expected_selected_edge_role) is not SemanticEdgeRole:
        raise TypeError("expected selected edge role must be SemanticEdgeRole")
    if expected_width is not None and (type(expected_width) is not int or expected_width <= 0):
        raise ValueError("expected width must be a positive built-in int")
    matches = []
    for proof in route_evidence.route_proofs:
        if proof.native_key != route_evidence.native_key or proof.proof_kind is not SemanticRouteProofKind.STATE_CHOICE or proof.state_write is None or proof.predicate is None:
            continue
        destinations = tuple(destination for destination in proof.destinations if destination.target_identity == selected_locator.block_ref.identity and destination.target_anchor_ea == selected_locator.anchor_ea and destination.state_constant == exclusion.normalized_state)
        if len(destinations) != 1 or len(proof.destinations) != 2:
            continue
        if expected_route_proof_id is not None and proof.proof_id != expected_route_proof_id:
            continue
        destination = destinations[0]
        if expected_selected_edge_role is not None and destination.role is not expected_selected_edge_role:
            continue
        if proof.source_identity != predicate_locator.block_ref.identity or proof.source_anchor_ea != predicate_locator.anchor_ea:
            continue
        if proof.source_owner_identity is not None and proof.source_owner_identity != source_locator.block_ref.identity:
            continue
        if proof.source_owner_anchor_ea is not None and proof.source_owner_anchor_ea != source_locator.anchor_ea:
            continue
        if (
            proof.predicate.origin.identity != predicate_locator.block_ref.identity
            or proof.predicate.origin.anchor_ea != exclusion.predicate_branch_ea
            or proof.predicate.consumer.identity != proof.source_identity
            or proof.predicate.consumer.anchor_ea != exclusion.predicate_branch_ea
        ):
            continue
        write = proof.state_write
        predicate = proof.predicate
        if write.identity != source_locator.block_ref.identity or write.state_variable != state_identity or write.instruction_ea != exclusion.source_write_ea or write.state_constant != exclusion.normalized_state or predicate.storage_identity != state_identity or predicate.width != write.width or write.width <= 0 or (expected_width is not None and write.width != expected_width):
            continue
        opposite = tuple(item for item in proof.destinations if item is not destination)
        if len(opposite) != 1 or opposite[0].target_identity != effect_locator.owner_ref.identity or opposite[0].target_anchor_ea != effect_locator.owner_anchor_ea or opposite[0].role is destination.role:
            continue
        matches.append((proof, destination, opposite[0], write.width))
    if len(matches) != 1:
        raise ValueError("exact semantic route proof is missing or ambiguous")
    proof, selected_destination, discarded_destination, width = matches[0]
    return _ExactEffectSemanticCorrelation(
        proof, selected_destination, discarded_destination,
        exclusion, effect_locator, exclusion.normalized_state, state_identity, exclusion.source_write_ea,
        exclusion.predicate_branch_ea, exclusion.discarded_effect_ea,
        source_locator.block_ref.identity, predicate_locator.block_ref.identity,
        selected_locator.block_ref.identity, effect_locator.owner_ref.identity,
        width,
    )


def validate_exact_effect_semantics(
    *,
    proposal: ProposedUnflattenContract | None,
    exclusion: ExactStateBranchEffectExclusion,
    claim: ExactInfeasibleEffectClaim,
    source_catalog: SourceIdentityCatalog,
    route_evidence: CanonicalSemanticEvidence,
    source_serial_by_ref: dict[object, int],
) -> _ExactEffectSemanticCorrelation:
    """Validate the one shared portable proposal/exclusion/claim relationship."""

    if type(exclusion) is not ExactStateBranchEffectExclusion:
        raise TypeError("exact effect exclusion must be closed")
    if type(claim) is not ExactInfeasibleEffectClaim:
        raise TypeError("exact effect claim must be closed")
    if type(source_catalog) is not SourceIdentityCatalog:
        raise TypeError("exact effect source catalog must be closed")
    if type(route_evidence) is not CanonicalSemanticEvidence:
        raise TypeError("exact effect route evidence must be canonical")
    if proposal is not None:
        if type(proposal) is not ProposedUnflattenContract:
            raise TypeError("exact effect proposal must be closed")
        validate_canonical_roundtrip(proposal, ProposedUnflattenContract)
        if proposal.source_identity_catalog != source_catalog:
            raise ValueError("proposal and correlation catalogs disagree")
        if proposal.route_evidence != route_evidence:
            raise ValueError("proposal and correlation route evidence disagree")
        matching_claims = tuple(item for item in proposal.claims if item.claim_id == claim.claim_id)
        if len(matching_claims) != 1 or matching_claims[0] != claim:
            raise ValueError("claim is not the exact proposal claim")
    exclusion.__post_init__()
    claim.__post_init__()
    if claim.effect_subject != claim.discarded_effect_subject:
        raise ValueError("exact claim effect subjects disagree")
    if (
        claim.state_identity != exclusion.state_identity
        or claim.normalized_state != exclusion.normalized_state
        or claim.source_write_ea != exclusion.source_write_ea
        or claim.predicate_branch_ea != exclusion.predicate_branch_ea
        or claim.discarded_effect_ea != exclusion.discarded_effect_ea
    ):
        raise ValueError("exact claim scalar is not exclusion-bound")
    subjects = {
        "source_serial": claim.source_subject,
        "predicate_serial": claim.predicate_subject,
        "selected_target_serial": claim.selected_target_subject,
        "discarded_effect_serial": claim.discarded_effect_subject,
    }
    if any(type(subject.locator) is not BlockSubjectLocator for name, subject in subjects.items() if name != "discarded_effect_serial"):
        raise ValueError("exact claim block locators are not canonical")
    if type(claim.discarded_effect_subject.locator) is not EffectSubjectLocator:
        raise ValueError("exact claim effect locator is not canonical")
    effect_locator = claim.discarded_effect_subject.locator
    if effect_locator.instruction_ea != claim.discarded_effect_ea:
        raise ValueError("claim effect locator EA disagrees with claim")
    for name, subject in subjects.items():
        if source_serial_by_ref.get(subject.block_ref) != getattr(exclusion, name):
            raise ValueError("exclusion serial does not resolve to the claim reference")
    source_locator = claim.source_subject.locator
    predicate_locator = claim.predicate_subject.locator
    selected_locator = claim.selected_target_subject.locator
    if not all(type(locator.block_ref) is NativeBlockRef for locator in (source_locator, predicate_locator, selected_locator)) or type(effect_locator.owner_ref) is not NativeBlockRef:
        raise ValueError("exact claim route refs are not native identities")
    return _resolve_exact_effect_semantics(
        exclusion=exclusion,
        source_catalog=source_catalog,
        route_evidence=route_evidence,
        state_identity=claim.state_identity,
        source_locator=source_locator,
        predicate_locator=predicate_locator,
        selected_locator=selected_locator,
        effect_locator=effect_locator,
        source_serial_by_ref=source_serial_by_ref,
        expected_route_proof_id=claim.route_proof_ids[0],
        expected_selected_edge_role=claim.selected_edge_role,
        expected_width=claim.width,
    )


def validate_exact_effect_claim_semantics(
    *,
    proposal: ProposedUnflattenContract,
    claim: ExactInfeasibleEffectClaim,
    source_serial_by_ref: dict[object, int],
) -> _ExactEffectSemanticCorrelation | None:
    """Validate one proposal claim through the producer-owned proof matcher.

    The typed claim does not persist the legacy exclusion record, so rebuild
    that closed record from its canonical locators and scalar fields before
    delegating to ``validate_exact_effect_semantics``.  All state/storage,
    route, width, source-write, branch, role, and proof correlation remains in
    the one existing matcher.
    """

    if type(proposal) is not ProposedUnflattenContract:
        raise TypeError("proposal must be a ProposedUnflattenContract")
    if type(claim) is not ExactInfeasibleEffectClaim:
        raise TypeError("claim must be an ExactInfeasibleEffectClaim")
    source_locator = claim.source_subject.locator
    predicate_locator = claim.predicate_subject.locator
    selected_locator = claim.selected_target_subject.locator
    effect_locator = claim.discarded_effect_subject.locator
    if not all(
        type(locator) is BlockSubjectLocator
        for locator in (source_locator, predicate_locator, selected_locator)
    ) or type(effect_locator) is not EffectSubjectLocator:
        return None
    serials = {
        "source_serial": source_serial_by_ref.get(source_locator.block_ref),
        "predicate_serial": source_serial_by_ref.get(predicate_locator.block_ref),
        "selected_target_serial": source_serial_by_ref.get(selected_locator.block_ref),
        "discarded_effect_serial": source_serial_by_ref.get(effect_locator.owner_ref),
    }
    if any(type(value) is not int for value in serials.values()):
        return None
    exclusion = ExactStateBranchEffectExclusion(
        normalized_state=claim.normalized_state,
        source_serial=serials["source_serial"],
        source_ea=source_locator.anchor_ea,
        source_write_ea=claim.source_write_ea,
        predicate_serial=serials["predicate_serial"],
        predicate_ea=predicate_locator.anchor_ea,
        predicate_branch_ea=claim.predicate_branch_ea,
        selected_target_serial=serials["selected_target_serial"],
        selected_target_ea=selected_locator.anchor_ea,
        discarded_effect_serial=serials["discarded_effect_serial"],
        discarded_effect_ea=claim.discarded_effect_ea,
        state_identity=claim.state_identity,
    )
    try:
        return validate_exact_effect_semantics(
            proposal=proposal,
            exclusion=exclusion,
            claim=claim,
            source_catalog=proposal.source_identity_catalog,
            route_evidence=proposal.route_evidence,
            source_serial_by_ref=source_serial_by_ref,
        )
    except (TypeError, ValueError):
        return None


def _valid_ea(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < _BADADDR


def _as_serial(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative serial")
    return int(value)


def _native_instruction_origins(block: object) -> tuple[int, ...]:
    instructions = tuple(getattr(block, "insn_snapshots", ()))
    origins: list[int] = []
    for instruction in instructions:
        native_ea = getattr(instruction, "native_ea", None)
        ea = native_ea if _valid_ea(native_ea) else getattr(instruction, "ea", None)
        if not _valid_ea(ea):
            raise ValueError("source instruction has no valid native origin")
        origins.append(int(ea))
    if not origins:
        raise ValueError("source block has empty native origins")
    if len(set(origins)) != len(origins):
        raise ValueError("source block has duplicate native origins")
    return tuple(sorted(origins))


def _block_anchor(block: object, origins: tuple[int, ...]) -> int:
    anchor = getattr(block, "native_start_ea", None)
    if not _valid_ea(anchor):
        anchor = getattr(block, "start_ea", None)
    if not _valid_ea(anchor) or int(anchor) not in origins:
        raise ValueError("source block anchor is invalid or outside native origins")
    return int(anchor)


def _require_ref(ref: object, label: str = "block_ref") -> AuthorityBlockRef:
    if type(ref) not in (NativeBlockRef, LogicalBlockRef):
        raise TypeError(f"{label} must be a NativeBlockRef or LogicalBlockRef")
    return ref  # type: ignore[return-value]


def _catalog_ref_by_serial(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
) -> dict[int, SourceBlockIdentityWitness]:
    expected = {_as_serial(serial, "source serial") for serial in source.blocks}
    actual = {_as_serial(serial, "source serial") for serial in block_refs_by_serial}
    if actual != expected:
        raise ValueError("block_refs_by_serial must exactly cover the source graph")
    witnesses = tuple(source_catalog.blocks)
    refs = tuple(block_refs_by_serial[serial] for serial in sorted(expected))
    if any(source.blocks[serial].serial != serial for serial in sorted(expected)):
        raise ValueError("source block serial does not match mapping key")
    if any(type(ref) not in (NativeBlockRef, LogicalBlockRef) for ref in refs):
        raise TypeError("block_refs_by_serial contains an invalid block reference")
    by_ref = {witness.block_ref: witness for witness in witnesses}
    if len(by_ref) != len(witnesses) or set(by_ref) != set(refs):
        raise ValueError("source catalog does not exactly cover block references")
    return {serial: by_ref[block_refs_by_serial[serial]] for serial in sorted(expected)}


def build_source_identity_catalog(
    source: FlowGraph,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    *,
    native_key: NativePreanalysisKey | None = None,
    source_generation: int | None = None,
    canonical_route_evidence: CanonicalSemanticEvidence | None = None,
) -> SourceIdentityCatalog:
    """Build one complete source catalog without exposing graph serials."""

    if type(source) is not FlowGraph:
        raise TypeError("source must be a FlowGraph")
    if canonical_route_evidence is not None:
        if type(canonical_route_evidence) is not CanonicalSemanticEvidence:
            raise TypeError("canonical_route_evidence must be CanonicalSemanticEvidence")
        if native_key is not None and native_key != canonical_route_evidence.native_key:
            raise ValueError("source native key disagrees with canonical route evidence")
        native_key = canonical_route_evidence.native_key
        if source_generation is not None and source_generation != canonical_route_evidence.generation:
            raise ValueError("source generation is stale relative to canonical route evidence")
        source_generation = canonical_route_evidence.generation
    if type(native_key) is not NativePreanalysisKey:
        raise TypeError("native_key is required for source identity catalog")
    if source_generation is None or isinstance(source_generation, bool) or not isinstance(source_generation, int) or source_generation < 0:
        raise ValueError("source_generation must be a non-negative integer")

    if not source.blocks:
        raise ValueError("source graph must contain at least one block")
    serials = {_as_serial(serial, "source serial") for serial in source.blocks}
    ref_serials = {_as_serial(serial, "source serial") for serial in block_refs_by_serial}
    if serials != ref_serials:
        raise ValueError("block_refs_by_serial must exactly cover the source graph")
    refs = tuple(_require_ref(block_refs_by_serial[serial]) for serial in sorted(serials))
    if len(set(refs)) != len(refs):
        raise ValueError("source block references must be unique")

    witnesses: list[SourceBlockIdentityWitness] = []
    all_origins: set[int] = set()
    anchors: set[int] = set()
    for serial in sorted(serials):
        block = source.blocks[serial]
        if block.serial != serial:
            raise ValueError("source block serial does not match mapping key")
        origins = _native_instruction_origins(block)
        anchor = _block_anchor(block, origins)
        if anchor in anchors:
            raise ValueError("source block anchors must be unique")
        if all_origins.intersection(origins):
            raise ValueError("source native instruction origins must be unique")
        ref = refs[sorted(serials).index(serial)]
        if type(ref) is NativeBlockRef:
            if ref.identity.native_key != native_key:
                raise ValueError("native source reference key does not match catalog key")
            if set(ref.identity.exact_instruction_eas) != set(origins):
                raise ValueError("native source reference origins do not match source block")
            if not ref.identity.native_ranges.contains(anchor):
                raise ValueError("source anchor is outside native reference range")
        witnesses.append(
            SourceBlockIdentityWitness(
                block_ref=ref,
                anchor_ea=anchor,
                native_instruction_eas=origins,
            )
        )
        anchors.add(anchor)
        all_origins.update(origins)
    return SourceIdentityCatalog(native_key=native_key, generation=source_generation, blocks=tuple(witnesses))


def _witness_for_serial(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: object,
) -> SourceBlockIdentityWitness:
    serial_int = _as_serial(serial, "block serial")
    if serial_int not in source.blocks or serial_int not in block_refs_by_serial:
        raise ValueError("block serial is absent from source catalog")
    by_ref = {item.block_ref: item for item in source_catalog.blocks}
    try:
        return by_ref[block_refs_by_serial[serial_int]]
    except KeyError as exc:
        raise ValueError("block serial reference is absent from source catalog") from exc


def resolve_block_locator(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: int,
    anchor_ea: int,
) -> BlockSubjectLocator:
    """Resolve an exact serial/EA pair; never invent a logical reference."""

    witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
    if not _valid_ea(anchor_ea) or int(anchor_ea) not in witness.native_instruction_eas:
        raise ValueError("block anchor is absent from source native origins")
    return BlockSubjectLocator(witness.block_ref, int(anchor_ea))


def resolve_effect_locator(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: int,
    instruction_ea: int,
    effect_kind: EffectSiteKind,
) -> EffectSubjectLocator:
    witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
    if not _valid_ea(instruction_ea) or int(instruction_ea) not in witness.native_instruction_eas:
        raise ValueError("effect instruction anchor is absent from source native origins")
    return EffectSubjectLocator(witness.block_ref, witness.anchor_ea, int(instruction_ea), effect_kind)


def resolve_terminal_locator(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: int,
    instruction_ea: int,
    terminal_kind: TerminalKind,
) -> TerminalSubjectLocator:
    witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
    if not _valid_ea(instruction_ea) or int(instruction_ea) not in witness.native_instruction_eas:
        raise ValueError("terminal instruction anchor is absent from source native origins")
    return TerminalSubjectLocator(witness.block_ref, witness.anchor_ea, terminal_kind, int(instruction_ea))


def _destination_matches_witness(destination: object, witness: SourceBlockIdentityWitness, native_key: NativePreanalysisKey) -> bool:
    target_identity = getattr(destination, "target_identity", None)
    target_anchor = getattr(destination, "target_anchor_ea", None)
    if target_identity is None or target_identity.native_key != native_key:
        return False
    if target_anchor not in witness.native_instruction_eas:
        return False
    if type(witness.block_ref) is NativeBlockRef:
        return target_identity == witness.block_ref.identity
    return True


def build_unflatten_plan_input_catalog(
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef] | None = None,
    canonical_route_evidence: CanonicalSemanticEvidence | None,
    source_entry_serial: int,
    dispatcher_entry_serial: int,
    dispatcher_member_serials: Iterable[int],
    authoritative_handler_serials: Iterable[int],
    state_identity: StorageIdentity,
    shape: UnflattenPlanShape | str,
) -> UnflattenPlanInputCatalog:
    """Lift only the explicit plan serial inputs into typed refs."""

    if type(source) is not FlowGraph or type(source_catalog) is not SourceIdentityCatalog:
        raise TypeError("source and source_catalog are required")
    if type(canonical_route_evidence) is not CanonicalSemanticEvidence:
        raise ValueError("canonical route evidence is required")
    if source_catalog.native_key != canonical_route_evidence.native_key or source_catalog.generation != canonical_route_evidence.generation:
        raise ValueError("source catalog is stale relative to canonical route evidence")
    if type(state_identity) is not StorageIdentity:
        raise TypeError("state_identity must be a StorageIdentity")
    if block_refs_by_serial is None:
        raise ValueError("block_refs_by_serial is required")
    _catalog_ref_by_serial(source, source_catalog, block_refs_by_serial)
    shape_value = shape if isinstance(shape, UnflattenPlanShape) else UnflattenPlanShape(shape)
    raw_members = tuple(_as_serial(serial, "dispatcher member serial") for serial in dispatcher_member_serials)
    if len(set(raw_members)) != len(raw_members):
        raise ValueError("dispatcher_member_serials must not contain duplicates")
    members = tuple(sorted(raw_members))
    raw_handlers = tuple(_as_serial(serial, "authoritative_handler_serials item") for serial in authoritative_handler_serials)
    if len(set(raw_handlers)) != len(raw_handlers):
        raise ValueError("authoritative_handler_serials must not contain duplicates")
    handlers = tuple(sorted(raw_handlers))
    dispatcher_entry = _as_serial(dispatcher_entry_serial, "dispatcher entry serial")
    source_entry = _as_serial(source_entry_serial, "source entry serial")
    if source_entry != int(source.entry_serial):
        raise ValueError("source_entry_serial must equal FlowGraph.entry_serial")
    if dispatcher_entry not in members:
        raise ValueError("dispatcher_member_serials must include dispatcher entry")
    source_entry_witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, source_entry)
    dispatcher_witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, dispatcher_entry)
    member_refs = tuple(_witness_for_serial(source, source_catalog, block_refs_by_serial, serial).block_ref for serial in members)

    authoritative_inputs: list[AuthoritativeHandlerInput] = []
    for serial in handlers:
        try:
            witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
        except ValueError as exc:
            raise ValueError("authoritative_handler_serials contains an unknown serial") from exc
        state_to_anchors: dict[int, set[int]] = {}
        for proof in canonical_route_evidence.route_proofs:
            for destination in proof.destinations:
                if _destination_matches_witness(destination, witness, canonical_route_evidence.native_key):
                    proof_state_identities = tuple(
                        identity
                        for identity in (
                            getattr(getattr(proof, "state_write", None), "state_variable", None),
                            getattr(getattr(proof, "predicate", None), "storage_identity", None),
                        )
                        if identity is not None
                    )
                    if any(identity != state_identity for identity in proof_state_identities):
                        raise ValueError("canonical route state identity disagrees with plan input")
                    state_to_anchors.setdefault(int(destination.state_constant), set()).add(int(destination.target_anchor_ea))
        if not state_to_anchors:
            raise ValueError("authoritative handler has no canonical route destination")
        if any(len(anchors) != 1 for anchors in state_to_anchors.values()):
            raise ValueError("authoritative handler route state is ambiguous")
        authoritative_inputs.append(
            AuthoritativeHandlerInput(
                block_ref=witness.block_ref,
                anchor_ea=witness.anchor_ea,
                normalized_states=tuple(sorted(state_to_anchors)),
            )
        )

    return UnflattenPlanInputCatalog(
        shape=shape_value,
        source_entry_ref=source_entry_witness.block_ref,
        dispatcher_entry_ref=dispatcher_witness.block_ref,
        dispatcher_member_refs=member_refs,
        authoritative_handlers=tuple(authoritative_inputs),
        state_identity=state_identity,
    )


def discover_reachable_effects_and_terminals(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
) -> SourceEffectTerminalCatalog:
    """Discover the exact, disjoint Section 15.3 effect/terminal inventory."""

    _catalog_ref_by_serial(source, source_catalog, block_refs_by_serial)
    reachable: list[int] = []
    pending = deque([int(source.entry_serial)])
    seen: set[int] = set()
    while pending:
        serial = pending.popleft()
        if serial in seen:
            continue
        if serial not in source.blocks:
            raise ValueError("reachable source successor is absent from source graph")
        seen.add(serial)
        reachable.append(serial)
        pending.extend(sorted(int(succ) for succ in source.blocks[serial].succs))

    effects: list[DiscoveredEffect] = []
    terminals: list[DiscoveredTerminal] = []
    effect_keys: set[tuple[AuthorityBlockRef, int, EffectSiteKind]] = set()
    terminal_keys: set[tuple[AuthorityBlockRef, int, TerminalKind]] = set()
    for serial in reachable:
        block = source.blocks[serial]
        witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
        pure_effects, pure_terminals = classify_block_effects_and_terminals(
            block, owner_ref=witness.block_ref, owner_anchor_ea=witness.anchor_ea,
        )
        for site in pure_effects:
            effect_key = (witness.block_ref, site.instruction_ea, site.effect_kind)
            if effect_key in effect_keys:
                raise ValueError("duplicate reachable effect site")
            effect_keys.add(effect_key)
            effects.append(DiscoveredEffect(resolve_effect_locator(
                source, source_catalog, block_refs_by_serial, serial,
                site.instruction_ea, site.effect_kind,
            )))
        for site in pure_terminals:
            terminal_key = (witness.block_ref, site.instruction_ea, site.terminal_kind)
            if terminal_key in terminal_keys:
                raise ValueError("duplicate reachable terminal site")
            terminal_keys.add(terminal_key)
            terminals.append(DiscoveredTerminal(resolve_terminal_locator(
                source, source_catalog, block_refs_by_serial, serial,
                site.instruction_ea, site.terminal_kind,
            )))
    return SourceEffectTerminalCatalog(tuple(effects), tuple(terminals))


def build_use_def_fragment_witness(
    audit: UseDefSeveranceAudit,
    *,
    fragment_id: str,
    state_identity: StorageIdentity,
    redirect_owner_refs: Iterable[object] = (),
    redirect_digest: str | None = None,
) -> UseDefFragmentWitness | None:
    """Convert only a clean executed audit into authoritative witness input."""

    if type(audit) is not UseDefSeveranceAudit or not audit.clean:
        return None
    refs = tuple(redirect_owner_refs)
    if redirect_digest is None:
        payload = repr(tuple(refs)).encode("utf-8")
        redirect_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if audit.violations:
        return None
    violations: tuple[str, ...] = ()
    return UseDefFragmentWitness(
        fragment_id=fragment_id,
        state_identity=state_identity,
        redirect_owner_refs=refs,
        redirect_digest=redirect_digest,
        executed=True,
        fragment_atomic=True,
        actionable_non_state_severance_count=0,
        violation_ids=violations,
    )


def _subject(kind, role, locator):
    return _subject_factory(
        SemanticSubjectRef,
        kind=kind,
        role=role,
        block_ref=getattr(locator, "block_ref", getattr(locator, "owner_ref", None)),
        anchor_ea=getattr(locator, "anchor_ea", getattr(locator, "owner_anchor_ea", None)),
        locator=locator,
    )


def _exact_effect_claim(
    *,
    exclusion: object,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    canonical_route_evidence: CanonicalSemanticEvidence,
    state_identity: StorageIdentity,
) -> ExactInfeasibleEffectClaim:
    """Adapt one legacy exclusion only through canonical source identities."""

    if type(exclusion) is not ExactStateBranchEffectExclusion:
        raise TypeError("exact effect exclusions must be closed producer records")
    if exclusion.state_identity != state_identity:
        raise ValueError("exact effect exclusion state identity is stale")
    try:
        discarded_block = source.blocks[exclusion.discarded_effect_serial]
    except (KeyError, TypeError) as exc:
        raise ValueError("discarded effect serial is absent from source catalog") from exc
    witness = _witness_for_serial(
        source, source_catalog, block_refs_by_serial,
        exclusion.discarded_effect_serial,
    )
    discarded_effects, _ = classify_block_effects_and_terminals(
        discarded_block,
        owner_ref=witness.block_ref,
        owner_anchor_ea=witness.anchor_ea,
    )
    discarded_sites = tuple(
        site for site in discarded_effects
        if site.effect_kind in {EffectSiteKind.STORE, EffectSiteKind.CALL}
    )
    if len(discarded_sites) != 1 or discarded_sites[0].instruction_ea != exclusion.discarded_effect_ea:
        raise ValueError("discarded effect EA does not resolve to one effect kind")
    discarded_effect_ea = discarded_sites[0].instruction_ea
    discarded_kind = discarded_sites[0].effect_kind
    discarded = resolve_effect_locator(
        source, source_catalog, block_refs_by_serial,
        exclusion.discarded_effect_serial, discarded_effect_ea,
        discarded_kind,
    )
    source_locator = resolve_block_locator(
        source, source_catalog, block_refs_by_serial,
        exclusion.source_serial, exclusion.source_ea,
    )
    predicate_locator = resolve_block_locator(
        source, source_catalog, block_refs_by_serial,
        exclusion.predicate_serial, exclusion.predicate_ea,
    )
    selected_locator = resolve_block_locator(
        source, source_catalog, block_refs_by_serial,
        exclusion.selected_target_serial, exclusion.selected_target_ea,
    )
    correlation = _resolve_exact_effect_semantics(
        exclusion=exclusion,
        source_catalog=source_catalog,
        route_evidence=canonical_route_evidence,
        state_identity=state_identity,
        source_locator=source_locator,
        predicate_locator=predicate_locator,
        selected_locator=selected_locator,
        effect_locator=discarded,
        source_serial_by_ref={ref: serial for serial, ref in block_refs_by_serial.items()},
    )
    proof = correlation.proof
    destination = correlation.selected_destination
    source_subject = _subject(
        SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        source_locator,
    )
    predicate_subject = _subject(
        SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        predicate_locator,
    )
    selected_subject = _subject(
        SemanticSubjectKind.BLOCK, SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
        selected_locator,
    )
    discarded_subject = _subject(
        SemanticSubjectKind.EFFECT, SemanticSubjectRole.EFFECT_SITE, discarded,
    )
    claim = _claim_factory(
        ExactInfeasibleEffectClaim,
        kind=UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT,
        effect_subject=discarded_subject,
        source_subject=source_subject,
        predicate_subject=predicate_subject,
        selected_target_subject=selected_subject,
        discarded_effect_subject=discarded_subject,
        normalized_state=correlation.normalized_state,
        state_identity=correlation.state_identity,
        width=correlation.width,
        source_write_ea=correlation.source_write_ea,
        predicate_branch_ea=correlation.predicate_branch_ea,
        discarded_effect_ea=correlation.discarded_effect_ea,
        selected_edge_role=destination.role,
        route_proof_ids=(proof.proof_id,),
        consensus=ProviderConsensusWitness(ProviderConsensusMode.NOT_APPLICABLE, ()),
        source_generation=source_catalog.generation,
    )
    return claim


def _route_witness(
    source_catalog: SourceIdentityCatalog,
    identity: StableBlockIdentity,
    anchor_ea: int,
) -> SourceBlockIdentityWitness:
    """Resolve one proof endpoint against the closed source identity catalog."""

    matches = tuple(
        witness
        for witness in source_catalog.blocks
        if type(witness.block_ref) is NativeBlockRef
        and witness.block_ref.identity == identity
        and int(anchor_ea) in witness.native_instruction_eas
    )
    if len(matches) != 1:
        raise ValueError("canonical route endpoint is missing or ambiguous")
    return matches[0]


def _select_route_proof(
    evidence: CanonicalSemanticEvidence,
    matcher: object,
    family: str,
) -> SemanticRouteProof:
    """Select exactly one proof; legacy/provider rows remain non-authoritative."""

    if type(evidence) is not CanonicalSemanticEvidence:
        raise TypeError(f"{family} adapter requires canonical semantic evidence")
    # Frozen dataclasses are an API boundary, not a substitute for binding.
    # Re-run the canonical invariants here so a deserialized, monkey-patched,
    # or otherwise corrupted proof cannot be selected by endpoint coincidence.
    for proof in evidence.route_proofs:
        for destination in proof.destinations:
            SemanticRouteDestination.__post_init__(destination)
        if proof.state_write is not None:
            type(proof.state_write).__post_init__(proof.state_write)
        if proof.predicate is not None:
            type(proof.predicate).__post_init__(proof.predicate)
        for carrier in proof.carriers:
            type(carrier).__post_init__(carrier)
        SemanticRouteProof.__post_init__(proof)
    CanonicalSemanticEvidence.__post_init__(evidence)
    if not callable(matcher):
        raise TypeError("route adapter matcher must be callable")
    matches = tuple(proof for proof in evidence.route_proofs if matcher(proof))
    if len(matches) != 1:
        raise ValueError(f"{family} route has zero or multiple canonical matches")
    return matches[0]


def _target_identity(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: int,
) -> StableBlockIdentity:
    witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
    if type(witness.block_ref) is not NativeBlockRef:
        raise ValueError("route adapter target must be a native block identity")
    return witness.block_ref.identity


def _diagnostic_values(proof: SemanticRouteProof, key: str) -> tuple[str, ...]:
    return tuple(value for name, value in proof.diagnostic_provenance if name == key)


def adapt_concrete_entry_route(
    route: object,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    canonical_evidence: CanonicalSemanticEvidence,
) -> SemanticRouteProof:
    """Adapt concrete-entry metadata by exact selection from canonical proofs."""

    from d810.transforms.minimal_unflatten_emit import ConcreteStateEntryRouteProof

    if type(route) is not ConcreteStateEntryRouteProof:
        raise TypeError("concrete entry adapter requires ConcreteStateEntryRouteProof")
    target_identity = _target_identity(
        source, source_catalog, block_refs_by_serial, route.target_handler,
    )
    state = int(route.normalized_state)
    source_kinds = tuple(route.source_kinds)
    return _select_route_proof(
        canonical_evidence,
        lambda proof: any(
            (
                int(destination.state_constant) == state
                and destination.target_identity == target_identity
                and proof.source_owner_identity is not None
                and proof.source_owner_anchor_ea is not None
                and (
                    _diagnostic_values(proof, "source_kinds")
                    == ("|".join(source_kinds),)
                )
            )
            for destination in proof.destinations
        ),
        "concrete entry",
    )


def adapt_bootstrap_entry_route_proof(
    route: object,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    canonical_evidence: CanonicalSemanticEvidence,
) -> SemanticRouteProof:
    """Select a bootstrap emitter row against stable canonical endpoints."""

    from d810.transforms.minimal_unflatten_emit import BootstrapEntryRouteProof

    if type(route) is not BootstrapEntryRouteProof:
        raise TypeError("bootstrap entry adapter requires BootstrapEntryRouteProof")
    source_identity = _target_identity(
        source, source_catalog, block_refs_by_serial, route.source_serial,
    )
    target_identity = _target_identity(
        source, source_catalog, block_refs_by_serial, route.handler_serial,
    )
    return _select_route_proof(
        canonical_evidence,
        lambda proof: (
            proof.proof_kind is SemanticRouteProofKind.BOOTSTRAP
            and proof.shape is SemanticRouteShape.DIRECT
            and proof.source_identity == source_identity
            and proof.source_anchor_ea == route.source_anchor_ea
            and any(
                destination.state_constant == route.state
                and destination.target_identity == target_identity
                and destination.target_anchor_ea == route.handler_anchor_ea
                for destination in proof.destinations
            )
        ),
        "bootstrap entry",
    )


def adapt_conditional_entry_route(
    route: object,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    canonical_evidence: CanonicalSemanticEvidence,
) -> SemanticRouteProof:
    """Select a complete conditional proof; sparse forests cannot mint one."""

    from d810.transforms.minimal_unflatten_emit import ConditionalEntryBridgeProof

    if type(route) is not ConditionalEntryBridgeProof:
        raise TypeError("conditional entry adapter requires ConditionalEntryBridgeProof")
    source_witness = _witness_for_serial(
        source, source_catalog, block_refs_by_serial, route.source_serial,
    )
    false_identity = _target_identity(
        source, source_catalog, block_refs_by_serial, route.false_target_serial,
    )
    true_identity = _target_identity(
        source, source_catalog, block_refs_by_serial, route.true_target_serial,
    )

    def matches(proof: SemanticRouteProof) -> bool:
        if (
            proof.proof_kind is not SemanticRouteProofKind.STATE_CHOICE
            or proof.shape is not SemanticRouteShape.CONDITIONAL
            or proof.predicate is None
        ):
            return False
        if proof.source_identity != getattr(source_witness.block_ref, "identity", None):
            return False
        if (
            proof.predicate.origin.anchor_ea != route.predicate_ea
            or proof.predicate.consumer.anchor_ea != route.predicate_ea
        ):
            return False
        by_role = {destination.role: destination for destination in proof.destinations}
        taken = by_role.get(SemanticEdgeRole.CONDITIONAL_TAKEN)
        fallthrough = by_role.get(SemanticEdgeRole.CONDITIONAL_FALLTHROUGH)
        expected_taken = true_identity if route.true_is_taken else false_identity
        expected_fallthrough = false_identity if route.true_is_taken else true_identity
        return (
            taken is not None and fallthrough is not None
            and taken.target_identity == expected_taken
            and fallthrough.target_identity == expected_fallthrough
        )

    return _select_route_proof(canonical_evidence, matches, "conditional entry")


def adapt_native_bound_transition_route(
    route: object,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    canonical_evidence: CanonicalSemanticEvidence,
) -> SemanticRouteProof:
    """Select one canonical proof for a native-bound transition receipt."""

    from d810.analyses.control_flow.semantic_transition import NativeBoundTransitionRoute

    if type(route) is not NativeBoundTransitionRoute:
        raise TypeError("native-bound adapter requires NativeBoundTransitionRoute")
    source_identity = _target_identity(
        source, source_catalog, block_refs_by_serial, route.source_block_serial,
    )
    target_identity = _target_identity(
        source, source_catalog, block_refs_by_serial, route.target_handler_serial,
    )
    return _select_route_proof(
        canonical_evidence,
        lambda proof: (
            proof.state_write is not None
            and proof.state_write.identity == source_identity
            and proof.state_write.state_constant == route.state_constant
            and proof.state_write.width == 4
            and proof.state_write.instruction_ea == route.source_instruction_ea
            and _diagnostic_values(proof, "fact_id") == (route.fact_id,)
            and any(
                destination.state_constant == route.state_constant
                and destination.target_identity == target_identity
                for destination in proof.destinations
            )
        ),
        "native-bound transition",
    )


def adapt_state_transition_route(
    route: object,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    canonical_evidence: CanonicalSemanticEvidence,
    state_identity: StorageIdentity | None = None,
) -> SemanticRouteProof:
    """Select one non-return state transition; retirement remains separate."""

    from d810.analyses.control_flow.minimal_state_recovery import StateWriteTransition
    if type(route) is StateWriteTransition:
        from d810.analyses.control_flow.minimal_state_recovery import TransitionProof

        if route.is_return or route.next_state is None or route.target_handler is None:
            raise ValueError("unresolved or return state transition cannot be a route")
        if type(route.proof) is not TransitionProof or not route.proof.trusted:
            raise ValueError("state transition route requires typed trusted provenance")
        if not isinstance(state_identity, StorageIdentity):
            raise TypeError("state transition route requires the exact state identity")
        if not 0 <= int(route.next_state) <= 0xFFFFFFFF:
            raise ValueError("state transition route state must be exact U32")
        writer_identity = _target_identity(
            source, source_catalog, block_refs_by_serial, route.write_block,
        )
        writer_witness = _witness_for_serial(
            source, source_catalog, block_refs_by_serial, route.write_block,
        )
        target_identity = _target_identity(
            source, source_catalog, block_refs_by_serial, route.target_handler,
        )
        target_witness = _witness_for_serial(
            source, source_catalog, block_refs_by_serial, route.target_handler,
        )

        via_identity = (
            None
            if route.via_block is None
            else _target_identity(
                source, source_catalog, block_refs_by_serial, route.via_block,
            )
        )
        via_witness = (
            None
            if route.via_block is None
            else _witness_for_serial(
                source, source_catalog, block_refs_by_serial, route.via_block,
            )
        )
        writer_block = source.get_block(int(route.write_block))
        if writer_block is None:
            raise ValueError("state transition writer is absent from source graph")
        writer_successors = tuple(int(item) for item in writer_block.succs)
        if route.via_block is not None and int(route.via_block) not in writer_successors:
            raise ValueError("state transition via block is not a writer successor")
        if route.branch_arm is not None:
            if (
                type(route.branch_arm) is not int
                or route.branch_arm not in (0, 1)
                or len(writer_successors) != 2
                or route.via_block is None
                or writer_successors[route.branch_arm] != int(route.via_block)
            ):
                raise ValueError("state transition branch arm is not exact source topology")
        if route.preserve_via_block and route.via_block is None:
            raise ValueError("state transition preservation requires an exact via block")
        if route.preserve_via_block:
            # ``SemanticRouteProof`` carries route topology, state-write, and
            # carrier corridors, but no proof field asserting the backend-only
            # feeder-clone policy.  Matching the otherwise identical route
            # would launder that policy from ``StateWriteTransition``.
            raise ValueError(
                "state transition has no canonical preservation relation"
            )

        def matches_transition(proof: SemanticRouteProof) -> bool:
            write = proof.state_write
            if write is None:
                return False
            via_matches = via_identity is None or (
                via_witness is not None
                and (
                    (
                        proof.source_identity == via_identity
                        and proof.source_anchor_ea == via_witness.anchor_ea
                    )
                    or via_witness.anchor_ea in write.corridor_instruction_eas
                )
            )
            branch_matches = route.branch_arm is None or (
                proof.shape is SemanticRouteShape.CONDITIONAL
                and write.delivery_kind is SemanticStateWriteDeliveryKind.CONDITIONAL
            )
            declared_sources = tuple(route.proof.route_source_kinds)
            canonical_sources = _diagnostic_values(proof, "source_kinds")
            provenance_matches = (
                not canonical_sources
                or canonical_sources == ("|".join(declared_sources),)
            )
            return (
                write.identity == writer_identity
                and write.instruction_ea in writer_witness.native_instruction_eas
                and write.state_variable == state_identity
                and write.state_constant == route.next_state
                and write.width == 4
                and via_matches
                and branch_matches
                and provenance_matches
                and any(
                    destination.state_constant == route.next_state
                    and destination.target_identity == target_identity
                    and destination.target_anchor_ea == target_witness.anchor_ea
                    for destination in proof.destinations
                )
            )

        return _select_route_proof(
            canonical_evidence, matches_transition, "state transition",
        )
    raise TypeError("state transition adapter requires a typed route row")


def _equivalent_route_claim(
    *,
    source_catalog: SourceIdentityCatalog,
    route_evidence: CanonicalSemanticEvidence,
    proof: SemanticRouteProof,
) -> EquivalentSemanticRouteClaim:
    """Adapt one selected canonical proof into a closed route claim."""

    if proof.native_key != source_catalog.native_key:
        raise ValueError("canonical route proof has a foreign native key")
    if not proof.atomic_group_id:
        raise ValueError("canonical route proof has an invalid atomic group")
    source_witness = _route_witness(
        source_catalog, proof.source_identity, proof.source_anchor_ea,
    )
    destination_witnesses = tuple(
        _route_witness(source_catalog, destination.target_identity, destination.target_anchor_ea)
        for destination in proof.destinations
    )
    source_locator = BlockSubjectLocator(
        source_witness.block_ref, source_witness.anchor_ea,
    )
    destination_subjects = tuple(
        _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.BLOCK,
            role=SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
            block_ref=witness.block_ref,
            anchor_ea=witness.anchor_ea,
            locator=BlockSubjectLocator(witness.block_ref, witness.anchor_ea),
        )
        for witness in destination_witnesses
    )
    source_subject = _subject_factory(
        SemanticSubjectRef,
        kind=SemanticSubjectKind.BLOCK,
        role=SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=source_witness.block_ref,
        anchor_ea=source_witness.anchor_ea,
        locator=source_locator,
    )
    destination_pairs = tuple(
        (subject.block_ref, subject.anchor_ea) for subject in destination_subjects
    )
    retired_locator = RouteSubjectLocator(
        proof.proof_id,
        proof.atomic_group_id,
        source_witness.block_ref,
        source_witness.anchor_ea,
        tuple(ref for ref, _anchor in destination_pairs),
        tuple(anchor for _ref, anchor in destination_pairs),
    )
    retired_subject = _subject_factory(
        SemanticSubjectRef,
        kind=SemanticSubjectKind.ROUTE,
        role=SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=source_witness.block_ref,
        anchor_ea=source_witness.anchor_ea,
        locator=retired_locator,
    )
    # The model's retired/replacement names describe source and candidate
    # phases.  They intentionally point to the same selected route identity;
    # phase equivalence is proved by the closed assessments, not a second ID.
    replacement_subject = retired_subject
    return _claim_factory(
        EquivalentSemanticRouteClaim,
        kind=UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
        retired_route_subject=retired_subject,
        replacement_route_subject=replacement_subject,
        source_subject=source_subject,
        destination_subjects=destination_subjects,
        route_proof_ids=(proof.proof_id,),
        atomic_group_id=proof.atomic_group_id,
        source_generation=route_evidence.generation,
    )


def build_equivalent_route_claims(
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    route_evidence: CanonicalSemanticEvidence,
    selected_proof_ids: Iterable[str] | None = None,
) -> tuple[EquivalentSemanticRouteClaim, ...]:
    """Mint claims only for explicitly selected canonical route proofs."""

    if type(source) is not FlowGraph or type(source_catalog) is not SourceIdentityCatalog:
        raise TypeError("route claim inputs must be closed")
    if type(route_evidence) is not CanonicalSemanticEvidence:
        raise TypeError("route evidence must be canonical")
    if route_evidence.generation != source_catalog.generation:
        raise ValueError("canonical route evidence generation is stale")
    if route_evidence.native_key != source_catalog.native_key:
        raise ValueError("canonical route evidence has a foreign native key")
    if selected_proof_ids is None:
        return ()
    selected = tuple(selected_proof_ids)
    if not selected:
        return ()
    bound = bind_canonical_semantic_evidence(source, route_evidence)
    if (
        bound is None
        or len(bound.routes) != len(route_evidence.route_proofs)
    ):
        raise ValueError("canonical route topology is missing or nonreciprocal")
    known = {proof.proof_id: proof for proof in route_evidence.route_proofs}
    if any(type(item) is not str or not item for item in selected):
        raise TypeError("selected_proof_ids must contain exact proof IDs")
    if len(set(selected)) != len(selected):
        raise ValueError("selected_proof_ids must not contain duplicates")
    if any(item not in known for item in selected):
        raise ValueError("selected route proof is foreign to canonical evidence")
    claims = []
    for proof_id in sorted(selected):
        proof = known[proof_id]
        claims.append(
            _equivalent_route_claim(
                source_catalog=source_catalog,
                route_evidence=route_evidence,
                proof=proof,
            )
        )
    return tuple(claims)


def resolve_equivalent_route_claim(
    *,
    source: FlowGraph,
    proposal: ProposedUnflattenContract,
    claim: EquivalentSemanticRouteClaim,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
) -> EquivalentSemanticRouteClaim:
    """Revalidate one route claim against the sealed proposal and live graph."""

    if type(proposal) is not ProposedUnflattenContract or type(claim) is not EquivalentSemanticRouteClaim:
        raise TypeError("route claim resolution requires closed proposal and claim")
    if type(block_refs_by_serial) is not dict:
        raise TypeError("route claim block references must be an exact mapping")
    if set(block_refs_by_serial.values()) != {
        item.block_ref for item in proposal.source_identity_catalog.blocks
    }:
        raise ValueError("route claim block references are foreign or incomplete")
    if set(block_refs_by_serial) != set(source.blocks):
        raise ValueError("route claim block serials do not cover the source graph")
    matches = tuple(item for item in proposal.claims if item is claim)
    if len(matches) != 1:
        raise ValueError("route claim is not uniquely owned by proposal")
    source_catalog = proposal.source_identity_catalog
    if proposal.route_evidence.generation != source_catalog.generation:
        raise ValueError("route claim generation is stale")
    rebuilt = build_equivalent_route_claims(
        source=source,
        source_catalog=source_catalog,
        route_evidence=proposal.route_evidence,
        selected_proof_ids=claim.route_proof_ids,
    )
    selected = tuple(item for item in rebuilt if item.claim_id == claim.claim_id)
    if len(selected) != 1 or selected[0] != claim:
        raise ValueError("route claim is stale or ambiguous")
    return claim


def build_proposal(
    *,
    plan_id: str,
    source: FlowGraph,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    source_generation: int,
    canonical_route_evidence: CanonicalSemanticEvidence,
    selected_route_proof_ids: Iterable[str] | None = None,
    exact_state_effect_exclusions: Iterable[object],
    dispatcher_entry_serial: int,
    dispatcher_member_serials: Iterable[int],
    authoritative_handler_serials: Iterable[int],
    state_identity: StorageIdentity,
    use_def_witness: UseDefFragmentWitness,
) -> ProposedUnflattenContract:
    """Build the complete typed producer proposal, including exact effects."""

    source_catalog = build_source_identity_catalog(
        source, block_refs_by_serial,
        source_generation=source_generation,
        canonical_route_evidence=canonical_route_evidence,
    )
    exclusions = tuple(exact_state_effect_exclusions)
    route_claims = build_equivalent_route_claims(
        source=source,
        source_catalog=source_catalog,
        route_evidence=canonical_route_evidence,
        selected_proof_ids=selected_route_proof_ids,
    )
    exact_claims = tuple(
        _exact_effect_claim(
            exclusion=item, source=source, source_catalog=source_catalog,
            block_refs_by_serial=block_refs_by_serial,
            canonical_route_evidence=canonical_route_evidence,
            state_identity=state_identity,
        )
        for item in exclusions
    )
    if not route_claims and not exact_claims:
        raise ValueError("typed proposal requires a semantic route or exact effect claim")
    claims = tuple(sorted((*exact_claims, *route_claims), key=lambda item: item.claim_id))
    plan_inputs = build_unflatten_plan_input_catalog(
        source=source,
        source_catalog=source_catalog,
        block_refs_by_serial=block_refs_by_serial,
        canonical_route_evidence=canonical_route_evidence,
        source_entry_serial=source.entry_serial,
        dispatcher_entry_serial=dispatcher_entry_serial,
        dispatcher_member_serials=dispatcher_member_serials,
        authoritative_handler_serials=authoritative_handler_serials,
        state_identity=state_identity,
        shape=(
            UnflattenPlanShape.PARTIAL_REWRITE
            if route_claims
            else UnflattenPlanShape.EXACT_EFFECT_ONLY
        ),
    )
    return ProposedUnflattenContract(
        schema_version=1,
        rule_set_version=1,
        plan_id=plan_id,
        route_evidence=canonical_route_evidence,
        source_identity_catalog=source_catalog,
        use_def_witness=use_def_witness,
        claims=claims,
        plan_inputs=plan_inputs,
    )


def build_exact_effect_claim(
    *,
    exclusion: ExactStateBranchEffectExclusion,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    canonical_route_evidence: CanonicalSemanticEvidence,
    state_identity: StorageIdentity,
) -> ExactInfeasibleEffectClaim:
    """Recompute one exact claim for binding-time semantic correlation."""

    return _exact_effect_claim(
        exclusion=exclusion,
        source=source,
        source_catalog=source_catalog,
        block_refs_by_serial=block_refs_by_serial,
        canonical_route_evidence=canonical_route_evidence,
        state_identity=state_identity,
    )


__all__ = [
    "DiscoveredEffect",
    "DiscoveredTerminal",
    "SourceEffectTerminalCatalog",
    "classify_block_effects_and_terminals",
    "build_source_identity_catalog",
    "build_unflatten_plan_input_catalog",
    "build_use_def_fragment_witness",
    "discover_reachable_effects_and_terminals",
    "resolve_block_locator",
    "resolve_effect_locator",
    "resolve_terminal_locator",
    "build_proposal",
    "build_exact_effect_claim",
    "build_equivalent_route_claims",
    "resolve_equivalent_route_claim",
    "adapt_concrete_entry_route",
    "adapt_bootstrap_entry_route_proof",
    "adapt_conditional_entry_route",
    "adapt_native_bound_transition_route",
    "adapt_state_transition_route",
    "validate_exact_effect_semantics",
    "validate_exact_effect_claim_semantics",
]
