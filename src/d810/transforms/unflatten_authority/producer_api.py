"""Producer-side, serial-free inputs for unflatten authority.

The producer is deliberately a small adapter layer.  It consumes the complete
portable source graph, the exact identity-index export for that graph, and one
canonical route-evidence object.  It does not inspect metadata, attach a
proposal, or invoke transaction code.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping, MutableMapping
from dataclasses import dataclass, replace

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
    RouteAuthorityBinding,
    RouteClaimAuthorityRefs,
    route_join_binding,
    SemanticRouteDestination,
    SemanticRouteProof,
    SemanticRouteProofKind,
    SemanticRouteFact,
    SemanticRouteFactKind,
    semantic_route_proof_kind_for_fact,
    SemanticRouteShape,
    SemanticStateWriteDeliveryKind,
    SemanticCorridorPoint,
    SemanticDagEndpoint,
    SemanticDagEndpointKind,
    SemanticLogicalDagEndpoint,
    DecisionDagRouteWitness,
    SemanticDecisionDagWitness,
    SemanticGuardedStateSelection,
    SemanticPhysicalGuardSelectionWitness,
    SemanticPhysicalStateWriteWitness,
    is_exact_logical_function_exit_shape,
)
from d810.analyses.control_flow.effect_branch_exclusion import (
    ExactStateBranchEffectExclusion,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.runtime_identity import RuntimeAuthorityRef, RuntimeJoinRejected
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.graph_fingerprint import instruction_projection_without_block_references
from d810.ir.insn_projection import project_instruction
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, storage_identity_from_mop_snapshot
from d810.ir.block_identity import StableBlockIdentity
from d810.ir.block_identity import stable_block_identity_semantic_anchor
from d810.transforms.cfg_transaction import CfgBlockRef, LogicalBlockRef, NativeBlockRef, PlanBlockRef
from d810.transforms.graph_modification import RedirectBranch, RedirectGoto
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
    LogicalFunctionExitSubjectLocator,
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
    InventoryTerminalSite,
    canonical_model_order,
    resolve_inventory_block_sites,
    validate_inventory_control_transfer,
)
from . import model
from .ids import (
    _claim_factory,
    _subject_factory,
    content_id,
    validate_canonical_roundtrip,
)


_BADADDR = 0xFFFFFFFFFFFFFFFF
AuthorityBlockRef = NativeBlockRef | LogicalBlockRef


@dataclass(frozen=True, slots=True)
class ConcreteEntryRouteForecast:
    """Producer selection forecast for one concrete scalar entry route."""

    normalized_state: int
    target_handler: int
    source_kinds: tuple[str, ...]
    physical_fact_id: str
    canonical_proof_id: str
    source_identity: StableBlockIdentity
    source_anchor_ea: int
    target_identity: StableBlockIdentity
    state_identity: StorageIdentity
    proof_owner_identity: str

    def __post_init__(self) -> None:
        if not isinstance(self.source_identity, StableBlockIdentity):
            raise TypeError("concrete entry route requires a stable source identity")
        if not isinstance(self.target_identity, StableBlockIdentity):
            raise TypeError("concrete entry route requires a stable target identity")
        if not isinstance(self.state_identity, StorageIdentity):
            raise TypeError("concrete entry route requires a typed state identity")
        fact_id = str(self.physical_fact_id).strip()
        owner = str(self.proof_owner_identity).strip()
        proof_id = str(self.canonical_proof_id).strip()
        if not fact_id or not proof_id or not owner:
            raise ValueError("concrete entry route requires physical fact and owner identities")
        source_anchor_ea = int(self.source_anchor_ea)
        if not 0 <= source_anchor_ea < _BADADDR:
            raise ValueError("concrete entry source anchor must be a valid native EA")
        if not self.source_identity.native_ranges.contains(source_anchor_ea):
            raise ValueError("concrete entry source anchor is outside its stable identity")
        object.__setattr__(self, "normalized_state", int(self.normalized_state) & 0xFFFFFFFF)
        object.__setattr__(self, "target_handler", int(self.target_handler))
        object.__setattr__(self, "source_kinds", tuple(str(kind) for kind in self.source_kinds))
        object.__setattr__(self, "physical_fact_id", fact_id)
        object.__setattr__(self, "canonical_proof_id", proof_id)
        object.__setattr__(self, "source_anchor_ea", source_anchor_ea)
        object.__setattr__(self, "proof_owner_identity", owner)


@dataclass(frozen=True, slots=True)
class TransitionRouteSelectionKey:
    """Stable route coordinates used by the selected-transition index."""

    state_constant: int
    target_identity: StableBlockIdentity
    target_anchor_ea: int

    def __post_init__(self) -> None:
        if type(self.target_identity) is not StableBlockIdentity:
            raise TypeError("transition route key requires stable target identity")
        object.__setattr__(self, "state_constant", int(self.state_constant) & 0xFFFFFFFF)
        object.__setattr__(self, "target_anchor_ea", int(self.target_anchor_ea))


def bundle_route_proof_refs(
    evidence: CanonicalSemanticEvidence,
    proofs: Iterable[SemanticRouteProof],
    *,
    rejection: str,
) -> tuple[RuntimeAuthorityRef, ...]:
    """Return the arena reference of every proof, proving bundle membership.

    This is the route-group -> proof join.  It replaces the pattern that built
    a ``{proof.proof_id: proof}`` index of the whole bundle and then compared
    each candidate to the indexed record: that asked whether some proof with
    the same content ID is present *and* compares equal, which is a content
    question answered by walking a record graph.  The authority question is
    whether this exact record is a proof of this exact bundle, and the arena
    answers it in constant time.

    A proof that is not the bundle's own record -- a forgery, a
    ``dataclasses.replace`` copy, a proof from a different bundle -- is
    refused.  So is an unbound bundle and one whose arena its owner has
    closed.  All four are translated into ``rejection`` here, at this
    boundary, so callers keep catching ``ValueError`` with the message this
    package already uses and the arena's exception type does not leak into it.

    Resolving the binding is *inside* the translation, not before it: an
    unbound or closed bundle is exactly the case a caller most needs
    translated, and leaving it outside would send the untranslated rejection
    past every ``except ValueError`` in the package.
    """

    try:
        binding = route_join_binding(evidence)
        return tuple(binding.ref_for(proof) for proof in proofs)
    except RuntimeJoinRejected as exc:
        raise ValueError(rejection) from exc


def route_claim_join_refs(
    claim: EquivalentSemanticRouteClaim,
) -> RouteClaimAuthorityRefs:
    """Return the join authority of one route claim, or refuse the join.

    The mirror of ``route_join_binding`` for the records minted *from* a
    bundle.  A claim that never carried a sidecar -- decoded from
    persistence, or built field by field -- has no authority for a join and is
    refused here rather than silently falling back to its content
    fingerprint, which would answer a different question ("is some claim with
    these bytes present") than the one a join asks ("is this claim about that
    route").  A claim whose arena its lifecycle owner has closed is refused
    for the same reason.

    ``RuntimeJoinRejected`` is a ``ValueError``, so a caller inside the
    emission's abstention contract declines the plan instead of aborting the
    decompilation.
    """

    if type(claim) is not EquivalentSemanticRouteClaim:
        raise TypeError("route claim join requires an equivalent route claim")
    refs = claim.runtime_refs
    if refs is None:
        raise RuntimeJoinRejected(
            "equivalent semantic route claim is not bound to a runtime "
            "authority arena; it carries a content fingerprint only"
        )
    if not refs.is_live:
        raise RuntimeJoinRejected(
            "the runtime authority arena of this route claim is closed"
        )
    return refs


@dataclass(frozen=True, slots=True)
class TransitionRouteSelectionIndex:
    """Immutable index of already-selected transition proof objects.

    This is intentionally proof-object based: callers cannot supply a naked
    proof-ID allowlist or use source catalogue coordinates as a substitute for
    a selected transition authority.
    """

    entries: tuple[tuple[TransitionRouteSelectionKey, SemanticRouteProof], ...]

    def __post_init__(self) -> None:
        entries = tuple(self.entries)
        if any(
            type(key) is not TransitionRouteSelectionKey
            or type(proof) is not SemanticRouteProof
            for key, proof in entries
        ):
            raise TypeError("transition route index requires typed proof entries")
        object.__setattr__(self, "entries", entries)

    @classmethod
    def from_proofs(
        cls,
        proofs: Iterable[SemanticRouteProof],
    ) -> "TransitionRouteSelectionIndex":
        by_key_and_proof: dict[tuple[TransitionRouteSelectionKey, str], SemanticRouteProof] = {}
        for proof in proofs:
            if type(proof) is not SemanticRouteProof:
                raise TypeError("transition route index requires canonical route proofs")
            for destination in proof.destinations:
                key = TransitionRouteSelectionKey(
                    int(destination.state_constant),
                    destination.target_identity,
                    int(destination.target_anchor_ea),
                )
                by_key_and_proof[(key, proof.proof_id)] = proof
        return cls(
            tuple((key, proof) for (key, _proof_id), proof in by_key_and_proof.items())
        )

    def candidates(
        self,
        key: TransitionRouteSelectionKey,
    ) -> tuple[SemanticRouteProof, ...]:
        matches = {
            proof.proof_id: proof
            for candidate_key, proof in self.entries
            if candidate_key == key
        }
        return tuple(matches[proof_id] for proof_id in sorted(matches))


@dataclass(frozen=True, slots=True)
class BootstrapEntryRouteForecast:
    """Producer selection forecast for one bound bootstrap entry route."""

    source_serial: int
    handler_serial: int
    state: int
    source_anchor_ea: int
    handler_anchor_ea: int


@dataclass(frozen=True, slots=True)
class ConditionalEntryBridgeForecast:
    """Producer selection forecast for one conditional entry bridge."""

    source_serial: int
    predicate_ea: int
    false_target_serial: int
    true_target_serial: int
    true_is_taken: bool = True


@dataclass(frozen=True, slots=True)
class ConditionalArmRouteForecast:
    """Exact producer evidence for one surviving conditional-arm redirect."""

    modification: RedirectGoto | RedirectBranch
    state_constant: int
    target_serial: int
    route_fact: SemanticRouteFact

    def __post_init__(self) -> None:
        if type(self.modification) not in (RedirectGoto, RedirectBranch):
            raise TypeError("conditional arm forecast requires an exact redirect")
        if not 0 <= int(self.state_constant) <= 0xFFFFFFFF:
            raise ValueError("conditional arm forecast state must be exact U32")
        if int(self.target_serial) < 0:
            raise ValueError("conditional arm forecast target must be non-negative")
        if type(self.route_fact) is not SemanticRouteFact:
            raise TypeError("conditional arm forecast requires a semantic route fact")
        if (
            self.route_fact.kind is not SemanticRouteFactKind.DECISION_DAG
            or self.route_fact.decision_dag_witness is None
            or int(self.route_fact.state_constant) != int(self.state_constant)
            or int(self.route_fact.target_serial) != int(self.target_serial)
            or int(self.modification.new_target) != int(self.target_serial)
        ):
            raise ValueError("conditional arm forecast does not bind one exact decision-DAG route")
        object.__setattr__(self, "state_constant", int(self.state_constant))
        object.__setattr__(self, "target_serial", int(self.target_serial))


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
        predicate_observation = None
        predicate_kind = insn.branch_predicate
        predicate_left, predicate_right = insn.l, insn.r
        # Hex-Rays materializes synthesized comparisons as ``jnz(setX(...))``.
        # Preserve the inner comparison as the semantic predicate while the
        # outer branch remains ordinary control-transfer evidence.
        nested_predicate = bool(
            insn.l is not None
            and insn.l.sub_predicate_kind is not None
            and insn.l.sub_l is not None
            and insn.l.sub_r is not None
        )
        if nested_predicate:
            predicate_kind = insn.l.sub_predicate_kind
            predicate_left, predicate_right = insn.l.sub_l, insn.l.sub_r
        if (
            insn.kind in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}
            and predicate_kind is not None
            and predicate_kind is not PredicateKind.TRUTHY
            and len(block.succs) == 2
            and insn.d is not None
            and insn.d.block_ref == block.succs[1]
        ):
            storage = storage_identity_from_mop_snapshot(predicate_left)
            if (
                predicate_left is not None
                and predicate_right is not None
                and predicate_right.kind is OperandKind.NUMBER
                and predicate_right.value is not None
                and insn.d.kind is OperandKind.BLOCK
                and insn.d.block_ref is not None
                and storage is not None
                and predicate_left.size > 0
                and (
                    nested_predicate
                    or predicate_left.kind is OperandKind.STACK
                )
            ):
                predicate_observation = model.InventoryPredicateObservation(
                    predicate_kind,
                    storage,
                    predicate_left.size,
                    predicate_right.value,
                    insn.d.block_ref,
                )
        semantic_width = (
            int(insn.d.size)
            if insn.kind is InsnKind.LOAD and insn.d is not None
            else int(insn.l.size)
            if (
                insn.kind is InsnKind.STORE
                and insn.l is not None
                and insn.d is not None
            )
            else max(sizes, default=0)
        )
        rows.append(InventoryInstructionObservation(
            ordinal, instruction_ea, insn.opcode, semantic_width,
            insn.kind, insn.control_transfer_kind, insn.is_call, insn.call_kind,
            insn.display_text, predicate_observation, insn.raw_opcode,
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
        tail = rows[-1]
        if (
            tail.instruction_ea is not None
            and sum(
                row.instruction_ea == tail.instruction_ea for row in rows
            ) != 1
        ):
            # A collapsed native EA cannot identify which normalized row is
            # the transfer tail.  Keep the native origin on the other row and
            # omit the ambiguous tail coordinate rather than minting a false
            # exact transfer identity.
            rows = (*rows[:-1], replace(tail, instruction_ea=None))
        transfer_ea = rows[-1].instruction_ea
    if rows and (block.tail_opcode is None or block.tail_kind is None):
        raise ValueError(
            "instruction-bearing backend blocks require independent tail metadata"
        )
    if rows and block.raw_tail_opcode != rows[-1].raw_opcode:
        raise ValueError("block raw tail provenance differs from its observed tail")
    if (
        rows
        and block.tail_opcode == -1
        and block.kind is BlockKind.ONE_WAY
        and block.tail_kind is InsnKind.GOTO
    ):
        # The only negative opcode admitted by the portable authority is the
        # synthetic helper GOTO.  Its backend snapshot must still carry the
        # complete closed transfer shape; do not let a normalized row hide a
        # stale conditional/call/predicate body.
        tail = block.insn_snapshots[-1]
        if (
            block.kind is not BlockKind.ONE_WAY
            or block.tail_kind is not InsnKind.GOTO
            or tail.kind is not InsnKind.GOTO
            or tail.control_transfer_kind is not ControlTransferKind.GOTO
            or not tail.is_unconditional_jump
            or tail.is_conditional_jump
            or tail.is_call
            or tail.call_kind is not None
            or tail.branch_predicate is not None
            or tail.predicate_kind is not None
            or tail.compare_width is not None
            or tail.d is None
            or tail.d.kind is not OperandKind.BLOCK
            or tail.d.block_ref not in block.succs
            or len(block.succs) != 1
        ):
            raise ValueError("synthetic helper GOTO body is not normalized")
    return model.InventoryBlockObservation(
        serial=block.serial,
        block_ref=owner_ref,
        anchor_ea=anchor_ea,
        native_instruction_eas=tuple(sorted({
            row.instruction_ea for row in rows if row.instruction_ea is not None
        })),
        predecessor_serials=tuple(sorted(block.preds)),
        successor_serials=tuple(block.succs),
        transfer_ea=transfer_ea,
        instruction_observations=rows,
        block_kind=block.kind,
        graph_start_ea=block.start_ea,
        # Block-tail metadata is an independent backend observation.  Never
        # reconstruct it from the normalized instruction row: stale block
        # metadata must remain visible to the authority digest/validator.
        tail_opcode=block.tail_opcode if rows else None,
        raw_tail_opcode=block.raw_tail_opcode if rows else None,
        tail_kind=block.tail_kind if rows else None,
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


def is_unowned_structural_logical_stop(
    block: object,
    block_ref: object,
) -> bool:
    """Recognize the graph's instructionless synthetic STOP row.

    This row is structural reachability bookkeeping, not a source identity:
    it has no native instruction, no physical anchor, and no successor.  It
    must never be converted into an empty logical witness.
    """

    return (
        type(block_ref) is LogicalBlockRef
        and getattr(block, "kind", None) is BlockKind.STOP
        and not tuple(getattr(block, "insn_snapshots", ()))
        and not tuple(getattr(block, "succs", ()))
        and not _valid_ea(getattr(block, "native_start_ea", None))
        and getattr(block, "start_ea", _BADADDR) == _BADADDR
    )


def is_exact_logical_function_exit(
    block: object,
    block_ref: object,
) -> bool:
    """Recognize the one owned logical endpoint admitted by a decision DAG."""

    return type(block_ref) is LogicalBlockRef and is_exact_logical_function_exit_shape(block)


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
        return ()
    # Multiple lowered microinstructions may legitimately retain the same
    # native origin.  Identity coordinates describe native instructions, not
    # the number of current-MBA projections, so canonicalize observations to
    # one ordered origin per native EA.
    return tuple(sorted(set(origins)))


def native_instruction_origins(block: object) -> tuple[int, ...]:
    """Return the canonical native-origin identity observed for one block."""

    return _native_instruction_origins(block)


def _block_anchor(
    block: object,
    origins: tuple[int, ...],
    *,
    block_ref: AuthorityBlockRef | None = None,
) -> int:
    anchor = getattr(block, "native_start_ea", None)
    if not _valid_ea(anchor):
        anchor = getattr(block, "start_ea", None)
    if type(block_ref) is NativeBlockRef:
        if _valid_ea(anchor):
            if not block_ref.identity.native_ranges.contains(int(anchor)):
                raise ValueError("source block anchor is outside native reference range")
            return int(anchor)
        if not origins:
            intervals = block_ref.identity.native_ranges.intervals
            if intervals:
                return int(intervals[0].start_ea)
            raise ValueError("empty native identity has no canonical range anchor")
    if not _valid_ea(anchor):
        if origins:
            return int(min(origins))
        raise ValueError(
            "source block anchor is invalid or outside native origins"
            f" serial={getattr(block, 'serial', None)}"
            f" ref_type={type(block_ref).__name__}"
            f" kind={getattr(block, 'kind', None)}"
            f" succs={tuple(getattr(block, 'succs', ()))}"
            f" start={getattr(block, 'start_ea', None)!r}"
            f" native_start={getattr(block, 'native_start_ea', None)!r}"
        )
    if int(anchor) in origins:
        return int(anchor)
    if origins:
        return int(min(origins))
    raise ValueError("source block anchor is invalid or outside native origins")


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
    catalog_refs = {
        ref for serial, ref in zip(sorted(expected), refs)
        if not (
            is_unowned_structural_logical_stop(source.blocks[serial], ref)
            or is_exact_logical_function_exit(source.blocks[serial], ref)
        )
    }
    if len(by_ref) != len(witnesses) or set(by_ref) != catalog_refs:
        raise ValueError("source catalog does not exactly cover block references")
    return {
        serial: by_ref[block_refs_by_serial[serial]]
        for serial in sorted(expected)
        if block_refs_by_serial[serial] in by_ref
    }


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
    anchor_keys: set[tuple[AuthorityBlockRef, int]] = set()
    for serial in sorted(serials):
        block = source.blocks[serial]
        if block.serial != serial:
            raise ValueError("source block serial does not match mapping key")
        ref = refs[sorted(serials).index(serial)]
        if (
            is_unowned_structural_logical_stop(block, ref)
            or is_exact_logical_function_exit(block, ref)
        ):
            continue
        origins = _native_instruction_origins(block)
        anchor = _block_anchor(block, origins, block_ref=ref)
        anchor_key = (ref, int(anchor))
        if anchor_key in anchor_keys:
            raise ValueError("source block reference and anchor must be unique")
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
        anchor_keys.add(anchor_key)
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
        block = source.blocks[serial_int]
        anchor = next(
            (int(insn.ea) for insn in block.insn_snapshots),
            int(source.func_ea),
        )
        raise ValueError(
            "block serial reference is absent from source catalog "
            f"(candidate=blk{serial_int}@0x{anchor:x}, "
            f"ref={type(block_refs_by_serial[serial_int]).__name__})"
        ) from exc


def resolve_block_locator(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: int,
    anchor_ea: int,
) -> BlockSubjectLocator:
    """Resolve an exact serial/EA pair; never invent a logical reference."""

    witness = _witness_for_serial(source, source_catalog, block_refs_by_serial, serial)
    if not _valid_ea(anchor_ea):
        raise ValueError("block anchor is absent from source native origins")
    if witness.native_instruction_eas:
        valid_anchor = int(anchor_ea) in witness.native_instruction_eas
    else:
        ref = witness.block_ref
        valid_anchor = (
            type(ref) is NativeBlockRef
            and not ref.identity.exact_instruction_eas
            and ref.identity.native_ranges.contains(int(anchor_ea))
        )
    if not valid_anchor:
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


def _canonical_handler_state_anchors(
    *,
    witness: SourceBlockIdentityWitness,
    canonical_route_evidence: CanonicalSemanticEvidence,
    state_identity: StorageIdentity,
) -> dict[int, set[int]]:
    """Return the one canonical destination catalogue for a handler witness."""

    state_to_anchors: dict[int, set[int]] = {}
    for proof in canonical_route_evidence.route_proofs:
        for destination in proof.destinations:
            if _destination_matches_witness(
                destination, witness, canonical_route_evidence.native_key,
            ):
                proof_state_identities = tuple(
                    identity
                    for identity in (
                        getattr(
                            getattr(proof, "state_write", None),
                            "state_variable", None,
                        ),
                        getattr(
                            getattr(proof, "predicate", None),
                            "storage_identity", None,
                        ),
                    )
                    if identity is not None
                )
                if any(identity != state_identity for identity in proof_state_identities):
                    raise ValueError(
                        "canonical route state identity disagrees with plan input"
                    )
                state_to_anchors.setdefault(
                    int(destination.state_constant), set(),
                ).add(int(destination.target_anchor_ea))
    return state_to_anchors


def derive_authoritative_handler_serials(
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    recovered_handler_serials: Iterable[int],
    caller_handler_serials: Iterable[int],
    canonical_route_evidence: CanonicalSemanticEvidence,
    state_identity: StorageIdentity,
    selected_route_proofs: Iterable[SemanticRouteProof] = (),
) -> tuple[int, ...]:
    """Promote recovered destinations and explicit handlers into authority.

    Condition-chain handlers are syntactic discovery candidates, not proof
    authority.  A recovered native candidate becomes an authoritative handler
    only when canonical route evidence selects it as a destination.  An
    explicit caller serial proposal remains a delivery-only obligation unless
    one selected canonical route already discharges the same stable native
    destination.  The exact logical function-exit sink may be discarded only
    from recovered discovery noise; explicit logical or unknown proposals
    always fail closed.
    """

    _catalog_ref_by_serial(source, source_catalog, block_refs_by_serial)
    if type(canonical_route_evidence) is not CanonicalSemanticEvidence:
        raise TypeError("canonical_route_evidence must be canonical")
    if canonical_route_evidence.native_key != source_catalog.native_key:
        raise ValueError("canonical route evidence has a foreign native key")
    if canonical_route_evidence.generation != source_catalog.generation:
        raise ValueError("canonical route evidence generation is stale")
    if type(state_identity) is not StorageIdentity:
        raise TypeError("state_identity must be a StorageIdentity")
    selected_proofs = tuple(selected_route_proofs)
    if any(type(proof) is not SemanticRouteProof for proof in selected_proofs):
        raise TypeError("selected_route_proofs must contain canonical route proofs")
    bundle_route_proof_refs(
        canonical_route_evidence,
        selected_proofs,
        rejection="selected route proof is foreign to canonical evidence",
    )
    # A selected route claim discharges only its retired source endpoint. Its
    # destination remains a physical delivery obligation unless independently
    # discharged by a selected route that retires that exact source identity.
    selected_retired_source_identities = frozenset(
        proof.source_identity for proof in selected_proofs
    )
    recovered = tuple(sorted({
        _as_serial(serial, "recovered handler serial")
        for serial in recovered_handler_serials
    }))
    caller = tuple(sorted({
        _as_serial(serial, "caller handler serial")
        for serial in caller_handler_serials
    }))

    def native_witness(
        serial: int, *, recovered_candidate: bool,
    ) -> SourceBlockIdentityWitness | None:
        candidate_ref = block_refs_by_serial.get(serial)
        candidate_block = source.get_block(serial)
        if (
            recovered_candidate
            and type(candidate_ref) is LogicalBlockRef
            and candidate_block is not None
            and (
                is_exact_logical_function_exit(candidate_block, candidate_ref)
                or is_unowned_structural_logical_stop(candidate_block, candidate_ref)
            )
        ):
            return None
        if candidate_block is None or candidate_ref is None:
            raise ValueError(
                f"handler candidate contains an unknown serial: {serial}"
            )
        if type(candidate_ref) is not NativeBlockRef:
            raise ValueError(
                f"handler candidate is not a native source block: {serial}"
            )
        try:
            witness = _witness_for_serial(
                source, source_catalog, block_refs_by_serial, serial,
            )
        except ValueError as exc:
            raise ValueError(
                f"handler candidate contains an unknown serial: {serial}"
            ) from exc
        return witness

    promoted: set[int] = set()
    for serial in recovered:
        witness = native_witness(serial, recovered_candidate=True)
        if witness is None:
            continue
        state_to_anchors = _canonical_handler_state_anchors(
            witness=witness,
            canonical_route_evidence=canonical_route_evidence,
            state_identity=state_identity,
        )
        if any(len(anchors) != 1 for anchors in state_to_anchors.values()):
            raise ValueError("recovered handler route state is ambiguous")
        if state_to_anchors:
            promoted.add(serial)
    for serial in caller:
        witness = native_witness(serial, recovered_candidate=False)
        if witness is None:
            raise ValueError("explicit caller handler must be native")
        if witness.block_ref.identity in selected_retired_source_identities:
            continue
        promoted.add(serial)
    return tuple(sorted(promoted))


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
        state_to_anchors = _canonical_handler_state_anchors(
            witness=witness,
            canonical_route_evidence=canonical_route_evidence,
            state_identity=state_identity,
        )
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
        ref = block_refs_by_serial[serial]
        if is_unowned_structural_logical_stop(block, ref):
            continue
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
    refs = model._canonical_cfg_ref_tuple(
        redirect_owner_refs, "redirect_owner_refs",
    )
    if redirect_digest is None:
        redirect_digest = content_id(
            "unflatten.use-def.redirect-owners.v1", refs,
        )
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
    matching_sites = tuple(
        site for site in discarded_sites
        if site.instruction_ea == exclusion.discarded_effect_ea
    )
    if (
        len(matching_sites) != 1
        or (len(discarded_sites) != 1 and not exclusion.site_specific)
    ):
        raise ValueError("discarded effect EA does not resolve to one effect kind")
    discarded_effect_ea = matching_sites[0].instruction_ea
    discarded_kind = matching_sites[0].effect_kind
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
        SemanticSubjectKind.BLOCK, SemanticSubjectRole.EXACT_EFFECT_SOURCE,
        source_locator,
    )
    predicate_subject = _subject(
        SemanticSubjectKind.BLOCK, SemanticSubjectRole.EXACT_EFFECT_PREDICATE,
        predicate_locator,
    )
    selected_subject = _subject(
        SemanticSubjectKind.BLOCK, SemanticSubjectRole.EXACT_EFFECT_SELECTED_TARGET,
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

    # Route endpoints use stable physical-entry coordinates.  The coordinate
    # may precede the first instruction origin, so identity/range containment
    # is the canonical check for both empty and instruction-backed blocks.
    matches = tuple(
        witness
        for witness in source_catalog.blocks
        if type(witness.block_ref) is NativeBlockRef
        and witness.block_ref.identity == identity
        and identity.native_ranges.contains(int(anchor_ea))
    )
    if len(matches) != 1:
        raise ValueError(
            "canonical route endpoint is missing or ambiguous"
            f" identity={identity.diagnostic_label()} anchor=0x{int(anchor_ea):X}"
        )
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
        raise ValueError(
            f"{family} route has zero or multiple canonical matches "
            f"candidate_ids={tuple(proof.proof_id for proof in matches)}"
        )
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


def concrete_entry_route_key(
    route: object,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
) -> tuple[int, StableBlockIdentity, int]:
    """Return the stable state/target/anchor key for entry correlation."""

    if type(route) is not ConcreteEntryRouteForecast:
        raise TypeError("concrete entry key requires ConcreteEntryRouteForecast")
    witness = _witness_for_serial(
        source, source_catalog, block_refs_by_serial, route.target_handler,
    )
    if type(witness.block_ref) is not NativeBlockRef:
        raise ValueError("concrete entry target must be a native block identity")
    return (
        int(route.normalized_state) & 0xFFFFFFFF,
        witness.block_ref.identity,
        int(witness.anchor_ea),
    )


def resolve_concrete_entry_route(
    route: object,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    canonical_evidence: CanonicalSemanticEvidence,
    selected_transitions: TransitionRouteSelectionIndex,
    proof_owners: MutableMapping[RuntimeAuthorityRef, str],
) -> SemanticRouteProof:
    """Select and own the exact canonical proof for one entry-prefix route."""

    if type(route) is not ConcreteEntryRouteForecast:
        raise TypeError("concrete entry resolution requires ConcreteEntryRouteForecast")
    if type(canonical_evidence) is not CanonicalSemanticEvidence:
        raise TypeError("concrete entry resolution requires canonical evidence")
    if type(selected_transitions) is not TransitionRouteSelectionIndex:
        raise TypeError("concrete entry resolution requires selected transition index")
    if not isinstance(proof_owners, MutableMapping):
        raise TypeError("concrete entry resolution requires mutable proof ownership")

    expected_target = _target_identity(
        source, source_catalog, block_refs_by_serial, route.target_handler,
    )
    if expected_target != route.target_identity:
        raise ValueError("concrete entry target stable identity mismatch")
    source_witness = _route_witness(
        source_catalog,
        route.source_identity,
        route.source_anchor_ea,
    )
    matches = tuple(
        proof for proof in canonical_evidence.route_proofs
        if proof.proof_id == route.canonical_proof_id
    )
    if len(matches) != 1:
        raise ValueError(
            "concrete entry route has zero or multiple canonical physical proofs "
            f"proof_id={route.canonical_proof_id!r} "
            f"candidate_ids={tuple(proof.proof_id for proof in matches)!r}"
        )
    proof = matches[0]
    try:
        for destination in proof.destinations:
            SemanticRouteDestination.__post_init__(destination)
        if proof.state_write is not None:
            type(proof.state_write).__post_init__(proof.state_write)
        if proof.state_carrier is not None:
            type(proof.state_carrier).__post_init__(proof.state_carrier)
        SemanticRouteProof.__post_init__(proof)
    except (TypeError, ValueError) as exc:
        raise ValueError("concrete entry source/state identity mismatch") from exc
    assignment_matches = bool(
        proof.state_write is not None
        and proof.state_write.identity == route.source_identity
        and proof.state_write.state_variable == route.state_identity
        and int(proof.state_write.state_constant) == int(route.normalized_state)
        # The concrete-entry forecast carries native receipt provenance; the
        # canonical state-write proof carries the separately rebound physical
        # state MOV coordinate.
        and int(proof.source_anchor_ea) == int(route.source_anchor_ea)
    )
    carrier = proof.state_carrier
    # A carrier seals two different coordinates on the same stable block:
    # the catalog's physical block-owner anchor and the receipt instruction
    # that produced the carrier value.  A stable identity's deterministic
    # semantic anchor is neither authoritative for the owner role nor
    # guaranteed to equal either of those coordinates.
    carrier_owner_anchor = source_witness.anchor_ea
    carrier_matches = bool(
        proof.proof_kind is SemanticRouteProofKind.STATE_CARRIER
        and proof.state_write is None
        and carrier is not None
        and proof.source_identity == route.source_identity
        and int(proof.source_anchor_ea) == int(route.source_anchor_ea)
        and proof.source_owner_identity is None
        and proof.source_owner_anchor_ea is None
        and carrier.owner_identity == route.source_identity
        and int(carrier.owner_anchor_ea) == int(carrier_owner_anchor)
        and carrier.source_identity == route.source_identity
        and int(carrier.source_anchor_ea) == int(route.source_anchor_ea)
        and carrier.state_identity == route.state_identity
        and int(carrier.state_constant) == int(route.normalized_state)
    )
    if not assignment_matches and not carrier_matches:
        raise ValueError("concrete entry source/state identity mismatch")
    destinations = tuple(
        destination
        for destination in proof.destinations
        if (
            int(destination.state_constant) == int(route.normalized_state)
            and destination.target_identity == route.target_identity
        )
    )
    if len(destinations) != 1:
        raise ValueError("concrete entry target/state proof mismatch")
    # Ownership is keyed on the bundle's arena reference, so "already owned"
    # is a statement about this exact canonical proof rather than about any
    # record that renders the same identifier.
    proof_ref = bundle_route_proof_refs(
        canonical_evidence,
        (proof,),
        rejection="concrete entry proof is foreign to canonical evidence",
    )[0]
    if proof_ref in proof_owners:
        raise ValueError("concrete entry proof is already owned")
    proof_owners[proof_ref] = route.proof_owner_identity
    return proof


def bootstrap_entry_route_key(
    route: object,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
 ) -> tuple[int, StableBlockIdentity, int]:
    """Return the stable key for a bootstrap entry view."""

    if type(route) is not BootstrapEntryRouteForecast:
        raise TypeError("bootstrap entry key requires BootstrapEntryRouteForecast")
    target_identity = _target_identity(
        source, source_catalog, block_refs_by_serial, route.handler_serial,
    )
    return (
        int(route.state) & 0xFFFFFFFF,
        target_identity,
        int(route.handler_anchor_ea),
    )


def resolve_bootstrap_entry_route(
    route: object,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    selected_transitions: TransitionRouteSelectionIndex,
) -> SemanticRouteProof:
    """Resolve a bootstrap entry forecast as a view over selected transitions."""

    if type(route) is not BootstrapEntryRouteForecast:
        raise TypeError("bootstrap entry resolution requires BootstrapEntryRouteForecast")
    if type(selected_transitions) is not TransitionRouteSelectionIndex:
        raise TypeError("bootstrap entry resolution requires selected transition index")
    key = TransitionRouteSelectionKey(
        *bootstrap_entry_route_key(
            route,
            source=source,
            source_catalog=source_catalog,
            block_refs_by_serial=block_refs_by_serial,
        )
    )
    source_identity = _target_identity(
        source, source_catalog, block_refs_by_serial, route.source_serial,
    )
    matches = tuple(
        proof
        for proof in selected_transitions.candidates(key)
        if proof.proof_kind is SemanticRouteProofKind.BOOTSTRAP
        and proof.shape is SemanticRouteShape.DIRECT
        and proof.bootstrap is not None
        and proof.bootstrap.source.identity == source_identity
        and proof.bootstrap.source.anchor_ea == int(route.source_anchor_ea)
    )
    if len(matches) != 1:
        raise ValueError(
            "bootstrap entry route has zero or multiple selected transition "
            f"proofs key={key!r} "
            f"candidate_ids={tuple(proof.proof_id for proof in matches)!r}"
        )
    return matches[0]


def adapt_conditional_entry_route(
    route: object,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    canonical_evidence: CanonicalSemanticEvidence,
) -> SemanticRouteProof:
    """Select one complete canonical proof from a conditional forecast."""

    if type(route) is not ConditionalEntryBridgeForecast:
        raise TypeError("conditional entry adapter requires ConditionalEntryBridgeForecast")
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
    semantic_route_fact: SemanticRouteFact | None = None,
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
    if (
        semantic_route_fact is not None
        and semantic_route_fact.kind is SemanticRouteFactKind.STATE_CARRIER
    ):
        fact = semantic_route_fact
        witness = fact.carrier_witness
        if (
            witness is None
            or fact.fact_id != route.fact_id
            or int(fact.owner_serial) != int(route.source_block_serial)
            or int(fact.source_serial) != int(route.source_block_serial)
            or int(fact.source_instruction_ea) != int(route.source_instruction_ea)
            or int(fact.state_constant) != int(route.state_constant)
            or int(fact.target_serial) != int(route.target_handler_serial)
            or int(witness.source_serial) != int(route.source_block_serial)
            or int(witness.source_instruction_ea) != int(route.source_instruction_ea)
            or int(witness.state) != int(route.state_constant)
        ):
            raise ValueError("native-bound carrier fact does not exactly match its receipt")
        feeder_identity = _target_identity(
            source,
            source_catalog,
            block_refs_by_serial,
            witness.feeder_serial,
        )
        comparison_identity = _target_identity(
            source,
            source_catalog,
            block_refs_by_serial,
            witness.comparison_entry_serial,
        )

        def matches_carrier(proof: SemanticRouteProof) -> bool:
            carrier = proof.state_carrier
            return bool(
                proof.proof_kind is SemanticRouteProofKind.STATE_CARRIER
                and carrier is not None
                and proof.source_identity == source_identity
                and int(proof.source_anchor_ea) == int(route.source_instruction_ea)
                and proof.source_owner_identity is None
                and carrier.owner_identity == source_identity
                and carrier.source_identity == source_identity
                and int(carrier.source_anchor_ea) == int(route.source_instruction_ea)
                and carrier.feeder_identity == feeder_identity
                and carrier.comparison_entry_identity == comparison_identity
                and carrier.carrier == witness.carrier
                and carrier.state_identity == witness.state_identity
                and int(carrier.state_constant) == int(route.state_constant)
                and bool(carrier.requires_feeder_clone)
                == bool(witness.requires_feeder_clone)
                and any(
                    int(destination.state_constant) == int(route.state_constant)
                    and destination.target_identity == target_identity
                    for destination in proof.destinations
                )
            )

        return _select_route_proof(
            canonical_evidence,
            matches_carrier,
            "native-bound carrier transition",
        )
    try:
        def matches_native_bound(proof: SemanticRouteProof) -> bool:
            return (
                # The native-bound receipt is the direct physical-entry view.
                # BOOTSTRAP has distinct ownership in resolve_bootstrap_entry_route;
                # STATE_CHOICE and every other proof kind remain distinct facts.
                proof.proof_kind is SemanticRouteProofKind.STATE_ASSIGNMENT
                and proof.state_write is not None
                and proof.state_write.identity == source_identity
                and proof.state_write.state_constant == route.state_constant
                and proof.state_write.width == 4
                # The route receipt is producer provenance.  A canonical
                # native proof may bind its separately witnessed physical
                # state MOV later in this same source block.
                and proof.source_anchor_ea == route.source_instruction_ea
                and any(
                    destination.state_constant == route.state_constant
                    and destination.target_identity == target_identity
                    for destination in proof.destinations
                )
            )

        return _select_route_proof(
            canonical_evidence,
            matches_native_bound,
            "native-bound transition",
        )
    except ValueError as exc:
        same_id = tuple(
            (
                proof.proof_id,
                proof.proof_kind.value,
                None if proof.state_write is None else proof.state_write.instruction_ea,
                None if proof.state_write is None else proof.state_write.state_constant,
            )
            for proof in canonical_evidence.route_proofs
        )
        raise ValueError(
            f"{exc}; route fact_id={route.fact_id!r} source_serial={route.source_block_serial} "
            f"source_ea=0x{route.source_instruction_ea:X} state=0x{route.state_constant:X} "
            f"target_serial={route.target_handler_serial} same_id={same_id}"
        ) from exc


def _raw_dag_endpoint(
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    serial: object,
) -> SemanticDagEndpoint:
    """Project one raw DAG successor into its exact typed endpoint."""

    serial_int = _as_serial(serial, "decision-DAG endpoint serial")
    block = source.blocks.get(serial_int)
    ref = block_refs_by_serial.get(serial_int)
    if block is None or ref is None:
        raise ValueError("decision-DAG endpoint is absent from source")
    if type(ref) is LogicalBlockRef:
        if not is_exact_logical_function_exit(block, ref):
            raise ValueError("logical decision-DAG endpoint is not an exact function exit")
        return SemanticLogicalDagEndpoint(
            SemanticDagEndpointKind.FUNCTION_EXIT,
            serial_int,
            ref.session_id,
            ref.proxy_token,
            ref.version,
        )
    identity = _target_identity(source, source_catalog, block_refs_by_serial, serial_int)
    return SemanticCorridorPoint(
        identity,
        stable_block_identity_semantic_anchor(identity),
    )


def _dag_endpoint_matches(
    raw: SemanticDagEndpoint,
    canonical: SemanticDagEndpoint,
) -> bool:
    """Compare native and logical DAG leaves without fabricating an EA."""

    if type(raw) is not type(canonical):
        return False
    if type(raw) is SemanticLogicalDagEndpoint:
        return raw == canonical
    if type(raw) is SemanticCorridorPoint:
        return raw.identity == canonical.identity and raw.anchor_ea == canonical.anchor_ea
    return False


def _matches_exact_decision_dag_witness(
    raw: DecisionDagRouteWitness,
    canonical: SemanticDecisionDagWitness,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
) -> bool:
    """Bind every typed raw DAG coordinate to its canonical witness."""

    if (
        raw.state_identity != canonical.state_identity
        or raw.state_constant != canonical.state_constant
        or raw.entry_anchor_ea != canonical.entry.anchor_ea
        or len(raw.path_serials) != len(canonical.path)
        or len(raw.comparisons) != len(canonical.comparisons)
        or len(raw.bridges) != len(canonical.bridges)
    ):
        return False
    try:
        if _target_identity(
            source, source_catalog, block_refs_by_serial, raw.entry_serial,
        ) != canonical.entry.identity:
            return False
        raw_path = tuple(
            (_target_identity(source, source_catalog, block_refs_by_serial, serial), int(anchor))
            for serial, anchor in zip(raw.path_serials, raw.path_anchors)
        )
        canonical_path = tuple((point.identity, point.anchor_ea) for point in canonical.path)
        raw_comparisons = tuple(
            (
                _target_identity(source, source_catalog, block_refs_by_serial, item.serial),
                dict(zip(raw.path_serials, raw.path_anchors)).get(
                    int(item.serial),
                    stable_block_identity_semantic_anchor(
                        _target_identity(
                            source, source_catalog, block_refs_by_serial, item.serial,
                        )
                    ),
                ),
                item.comparison.op,
                int(item.comparison.const) & 0xFFFFFFFF,
                item.state_identity,
                _raw_dag_endpoint(
                    source, source_catalog, block_refs_by_serial, item.comparison.true_target,
                ),
                _raw_dag_endpoint(
                    source, source_catalog, block_refs_by_serial, item.comparison.false_target,
                ),
            )
            for item in raw.comparisons
        )
        canonical_comparisons = tuple(
            (
                item.node.identity,
                item.node.anchor_ea,
                item.operation,
                item.constant,
                item.state_identity,
                item.true_target,
                item.false_target,
            )
            for item in canonical.comparisons
        )
        raw_aliases = tuple(
            (
                _target_identity(source, source_catalog, block_refs_by_serial, left),
                stable_block_identity_semantic_anchor(
                    _target_identity(source, source_catalog, block_refs_by_serial, left),
                ),
                _target_identity(source, source_catalog, block_refs_by_serial, right),
                stable_block_identity_semantic_anchor(
                    _target_identity(source, source_catalog, block_refs_by_serial, right),
                ),
            )
            for left, right in raw.aliases
        )
        raw_bridges = tuple(
            (
                _target_identity(source, source_catalog, block_refs_by_serial, item.node_serial),
                item.node_anchor_ea,
                item.instruction_ea,
                item.source_identity,
                item.result_identity,
                item.source_width,
                item.result_width,
            )
            for item in raw.bridges
        )
    except (KeyError, TypeError, ValueError):
        return False
    return (
        raw_path == canonical_path
        and all(
            raw_item[:5] == canonical_item[:5]
            and _dag_endpoint_matches(raw_item[5], canonical_item[5])
            and _dag_endpoint_matches(raw_item[6], canonical_item[6])
            for raw_item, canonical_item in zip(raw_comparisons, canonical_comparisons)
        )
        and raw_aliases == tuple(
            (left.identity, left.anchor_ea, right.identity, right.anchor_ea)
            for left, right in canonical.aliases
        )
        and raw_bridges == tuple(
            (
                item.node.identity,
                item.node.anchor_ea,
                item.instruction_ea,
                item.source_identity,
                item.result_identity,
                item.source_width,
                item.result_width,
            )
            for item in canonical.bridges
        )
    )


def _matches_complete_decision_dag_route(
    proof: SemanticRouteProof,
    *,
    fact: SemanticRouteFact,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    source_identity: StableBlockIdentity,
    owner_identity: StableBlockIdentity,
    target_identity: StableBlockIdentity,
    state_identity: StorageIdentity,
    require_direct_owner: bool = False,
) -> bool:
    """Bind an exact raw decision-DAG fact to its stable canonical proof."""

    raw = fact.decision_dag_witness
    dag = proof.state_dag
    state_write = proof.state_write
    physical = fact.physical_state_write
    physical_coordinates_match = False
    if isinstance(physical, SemanticPhysicalStateWriteWitness):
        physical_serial = physical.source_serial
        physical_ea = int(
            physical.source_instruction.native_ea
            or physical.source_instruction.ea
        )
        try:
            if type(physical_serial) is not int:
                raise ValueError("physical writer lacks an exact source serial")
            physical_identity = _target_identity(
                source, source_catalog, block_refs_by_serial, physical_serial,
            )
            physical_block = source.get_block(physical_serial)
            delivery_block = source.get_block(fact.source_serial)
            if physical.source_instruction.kind is InsnKind.MOV:
                physical_owner_identity = physical_identity
                physical_owner_anchor_ea = physical_ea
            elif (
                physical.source_instruction.kind is InsnKind.STORE
                and type(physical.alias_definition_serial) is int
                and physical.alias_definition_instruction is not None
            ):
                physical_owner_identity = _target_identity(
                    source,
                    source_catalog,
                    block_refs_by_serial,
                    physical.alias_definition_serial,
                )
                physical_owner_anchor_ea = int(
                    physical.alias_definition_instruction.native_ea
                    or physical.alias_definition_instruction.ea
                )
            else:
                raise ValueError("physical writer has no exact semantic owner")
        except (KeyError, TypeError, ValueError):
            return False
        split_delivery = int(physical_serial) != int(fact.source_serial)
        if (
            split_delivery
            or physical.source_instruction.kind is InsnKind.STORE
        ):
            expected_owner_identity = physical_owner_identity
            expected_owner_anchor_ea = physical_owner_anchor_ea
        elif owner_identity != source_identity:
            expected_owner_identity = owner_identity
            expected_owner_anchor_ea = int(
                fact.owner_anchor_ea
                or stable_block_identity_semantic_anchor(owner_identity)
            )
        else:
            expected_owner_identity = None
            expected_owner_anchor_ea = None
        delivery = None if state_write is None else state_write.physical_delivery
        delivery_succs = tuple(int(item) for item in delivery_block.succs)
        delivery_target_serial = (
            delivery_succs[0] if len(delivery_succs) == 1 else None
        )
        try:
            delivery_target_identity = (
                None
                if delivery_target_serial is None
                else _target_identity(
                    source,
                    source_catalog,
                    block_refs_by_serial,
                    delivery_target_serial,
                )
            )
            delivery_target_block = (
                None
                if delivery_target_serial is None
                else source.get_block(delivery_target_serial)
            )
        except (KeyError, TypeError, ValueError):
            return False
        delivery_target_matches = bool(
            delivery is not None
            and delivery_target_serial is not None
            and delivery_target_identity is not None
            and delivery_target_block is not None
            and delivery.target.identity == delivery_target_identity
            and delivery.target.anchor_ea
            == stable_block_identity_semantic_anchor(delivery_target_identity)
            and int(fact.source_serial)
            in tuple(int(item) for item in delivery_target_block.preds)
        )
        live_delivery = (
            ()
            if delivery is None
            else tuple(
                snapshot
                for snapshot in delivery_block.insn_snapshots
                if int(snapshot.native_ea or snapshot.ea)
                == int(delivery.delivery.anchor_ea)
            )
        )
        live_delivery_instruction = (
            None if len(live_delivery) != 1 else project_instruction(live_delivery[0])
        )
        exact_delivery_goto_matches = bool(
            delivery is not None
            and len(live_delivery) == 1
            and live_delivery[0].kind is InsnKind.GOTO
            and live_delivery_instruction is not None
            and live_delivery_instruction.control is not None
            and live_delivery_instruction.control.transfer
            is ControlTransferKind.GOTO
            and live_delivery_instruction.control.target == delivery_target_serial
            and instruction_projection_without_block_references(live_delivery[0])
            == delivery.delivery_instruction
        )
        matching_delivery_members = (
            ()
            if delivery is None
            else tuple(
                member
                for member in delivery.members
                if member.identity == physical_identity
                and member.instruction_ea == physical_ea
                and member.physical_state_write == physical
            )
        )
        physical_coordinates_match = bool(
            state_write is not None
            and physical.state_identity == state_identity
            and int(physical.width) == 4
            and int(physical.state_constant) == int(fact.state_constant)
            and state_write.identity == physical_identity
            and state_write.instruction_ea == physical_ea
            and state_write.state_variable == state_identity
            and int(state_write.width) == 4
            and int(state_write.state_constant) == int(fact.state_constant)
            and state_write.physical_state_write == physical
            and proof.source_owner_identity == expected_owner_identity
            and proof.source_owner_anchor_ea == expected_owner_anchor_ea
            and (
                not split_delivery
                and delivery is None
                or split_delivery
                and physical_block is not None
                and delivery_block is not None
                and tuple(int(item) for item in physical_block.succs)
                == (int(fact.source_serial),)
                and int(physical_serial)
                in tuple(int(item) for item in delivery_block.preds)
                and delivery is not None
                and delivery.delivery.identity == source_identity
                and delivery.delivery.anchor_ea == int(fact.source_instruction_ea)
                and exact_delivery_goto_matches
                and delivery_target_matches
                and delivery.target.identity == dag.witness.entry.identity
                and len(matching_delivery_members) == 1
            )
        )
    else:
        physical_coordinates_match = bool(
            state_write is not None
            and proof.source_owner_identity in (None, owner_identity)
            and state_write.identity == source_identity
            and state_write.instruction_ea == fact.source_instruction_ea
            and state_write.state_variable == state_identity
            and state_write.width == 4
            and state_write.state_constant == fact.state_constant
            and state_write.recovered_state_write == fact.recovered_state_write
        )
    if (
        raw is None or dag is None
        or proof.proof_kind is not SemanticRouteProofKind.STATE_DAG
        or proof.source_identity != source_identity
        or proof.source_anchor_ea != fact.source_instruction_ea
        or dag.source_identity != source_identity
        or dag.source_anchor_ea != fact.source_instruction_ea
        or dag.target_identity != target_identity
        or dag.target_anchor_ea != fact.target_anchor_ea
        or dag.witness.state_identity != state_identity
        or dag.witness.state_constant != fact.state_constant
        or dag.witness.entry.identity != _target_identity(source, source_catalog, block_refs_by_serial, raw.entry_serial)
        or dag.witness.entry.anchor_ea != raw.entry_anchor_ea
        or not physical_coordinates_match
        or len(proof.destinations) != 1
        or proof.destinations[0].state_constant != fact.state_constant
        or proof.destinations[0].target_identity != target_identity
        or proof.destinations[0].target_anchor_ea != fact.target_anchor_ea
        or len(raw.path_serials) != len(dag.witness.path)
        or len(raw.comparisons) != len(dag.witness.comparisons)
        or (require_direct_owner and (
            int(fact.owner_serial) != int(fact.source_serial)
            or owner_identity != source_identity
            or fact.owner_anchor_ea != _witness_for_serial(
                source, source_catalog, block_refs_by_serial, fact.owner_serial,
            ).anchor_ea
            or fact.source_instruction_ea not in _witness_for_serial(
                source, source_catalog, block_refs_by_serial, fact.source_serial,
            ).native_instruction_eas
        ))
    ):
        return False
    return _matches_exact_decision_dag_witness(
        raw, dag.witness, source=source, source_catalog=source_catalog,
        block_refs_by_serial=block_refs_by_serial,
    )


def _matches_exact_guarded_state_assignment(
    proof: SemanticRouteProof,
    *,
    fact: SemanticRouteFact,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    source_identity: StableBlockIdentity,
    owner_identity: StableBlockIdentity,
    target_identity: StableBlockIdentity,
    state_identity: StorageIdentity,
) -> bool:
    """Bind one typed physical STORE/guard fact to its stable assignment."""

    physical = fact.physical_state_write
    if not isinstance(physical, SemanticPhysicalStateWriteWitness):
        return False
    raw_guarded = physical.guarded_selection
    state_write = proof.state_write
    guarded = None if state_write is None else state_write.guarded_selection
    source_ea = int(
        physical.source_instruction.native_ea or physical.source_instruction.ea
    )
    comparison_ea = (
        -1
        if not isinstance(raw_guarded, SemanticPhysicalGuardSelectionWitness)
        else int(
            raw_guarded.comparison_instruction.native_ea
            or raw_guarded.comparison_instruction.ea
        )
    )
    if (
        fact.kind is not SemanticRouteFactKind.DECISION_DAG
        or fact.decision_dag_witness is not None
        or not isinstance(raw_guarded, SemanticPhysicalGuardSelectionWitness)
        or proof.proof_kind is not SemanticRouteProofKind.STATE_ASSIGNMENT
        or state_write is None
        or not isinstance(guarded, SemanticGuardedStateSelection)
        or physical.source_serial != int(fact.source_serial)
        or physical.alias_definition_serial != int(fact.owner_serial)
        or source_ea != int(fact.source_instruction_ea)
        or int(raw_guarded.guard_serial) != int(fact.source_serial)
        or int(raw_guarded.selected_target_serial) != int(fact.target_serial)
        or raw_guarded.state_identity != physical.state_identity
        or physical.state_identity != state_identity
        or int(physical.width) != 4
        or int(physical.state_constant) != (int(fact.state_constant) & 0xFFFFFFFF)
        or tuple(int(item) for item in fact.path_serials)
        != (int(fact.owner_serial), int(fact.source_serial))
        or tuple((int(left), int(right)) for left, right in fact.path_edges)
        != ((int(fact.owner_serial), int(fact.source_serial)),)
        or proof.source_identity != source_identity
        or proof.source_anchor_ea != int(fact.source_instruction_ea)
        or proof.source_owner_identity != owner_identity
        or proof.source_owner_anchor_ea != fact.owner_anchor_ea
        or len(proof.destinations) != 1
        or proof.destinations[0].state_constant != int(fact.state_constant)
        or proof.destinations[0].target_identity != target_identity
        or proof.destinations[0].target_anchor_ea != fact.target_anchor_ea
        or state_write.identity != source_identity
        or state_write.instruction_ea != int(fact.source_instruction_ea)
        or state_write.state_variable != state_identity
        or int(state_write.width) != 4
        or int(state_write.state_constant) != int(fact.state_constant)
        or state_write.physical_state_write
        != replace(physical, guarded_selection=None)
        or guarded.guard.identity != source_identity
        or guarded.guard.anchor_ea != comparison_ea
        or guarded.comparison_instruction != raw_guarded.comparison_instruction
        or guarded.state_identity != raw_guarded.state_identity
        or int(guarded.width) != int(raw_guarded.width)
        or int(guarded.constant) != int(raw_guarded.constant)
    ):
        return False
    try:
        raw_true = _raw_dag_endpoint(
            source,
            source_catalog,
            block_refs_by_serial,
            raw_guarded.true_target_serial,
        )
        raw_false = _raw_dag_endpoint(
            source,
            source_catalog,
            block_refs_by_serial,
            raw_guarded.false_target_serial,
        )
        raw_selected = _raw_dag_endpoint(
            source,
            source_catalog,
            block_refs_by_serial,
            raw_guarded.selected_target_serial,
        )
    except (KeyError, TypeError, ValueError):
        return False
    return bool(
        _dag_endpoint_matches(raw_true, guarded.true_target)
        and _dag_endpoint_matches(raw_false, guarded.false_target)
        and _dag_endpoint_matches(raw_selected, guarded.selected_target)
    )


def adapt_conditional_arm_route(
    forecast: ConditionalArmRouteForecast,
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef],
    canonical_evidence: CanonicalSemanticEvidence,
    state_identity: StorageIdentity,
) -> SemanticRouteProof:
    """Select the one complete canonical decision-DAG proof for an arm redirect."""

    if type(forecast) is not ConditionalArmRouteForecast:
        raise TypeError("conditional arm adapter requires an exact forecast")
    fact = forecast.route_fact
    modification = forecast.modification
    if (
        int(fact.owner_serial) != int(fact.source_serial)
        or int(modification.new_target) != int(forecast.target_serial)
    ):
        raise ValueError("conditional arm forecast owner/source or redirect drifted")
    source_identity = _target_identity(source, source_catalog, block_refs_by_serial, fact.source_serial)
    owner_identity = _target_identity(source, source_catalog, block_refs_by_serial, fact.owner_serial)
    target_identity = _target_identity(source, source_catalog, block_refs_by_serial, forecast.target_serial)
    return _select_route_proof(
        canonical_evidence,
        lambda proof: _matches_complete_decision_dag_route(
            proof, fact=fact, source=source, source_catalog=source_catalog,
            block_refs_by_serial=block_refs_by_serial, source_identity=source_identity,
            owner_identity=owner_identity, target_identity=target_identity,
            state_identity=state_identity,
        ),
        "conditional arm",
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
        if route.is_return or route.next_state is None or route.target_handler is None:
            raise ValueError("unresolved or return state transition cannot be a route")
        transform_fact = route.semantic_route_fact
        if not isinstance(transform_fact, SemanticRouteFact):
            raise ValueError("state transition route requires canonical typed fact")
        if not isinstance(state_identity, StorageIdentity):
            raise TypeError("state transition route requires the exact state identity")
        if not 0 <= int(route.next_state) <= 0xFFFFFFFF:
            raise ValueError("state transition route state must be exact U32")
        owner_identity = _target_identity(
            source, source_catalog, block_refs_by_serial, route.write_block,
        )
        source_identity = _target_identity(
            source, source_catalog, block_refs_by_serial, transform_fact.source_serial,
        )
        target_identity = _target_identity(
            source, source_catalog, block_refs_by_serial, route.target_handler,
        )
        target_witness = _witness_for_serial(
            source, source_catalog, block_refs_by_serial, route.target_handler,
        )
        guarded_physical_fact = bool(
            transform_fact.kind is SemanticRouteFactKind.DECISION_DAG
            and transform_fact.decision_dag_witness is None
            and isinstance(
                transform_fact.physical_state_write,
                SemanticPhysicalStateWriteWitness,
            )
            and isinstance(
                transform_fact.physical_state_write.guarded_selection,
                SemanticPhysicalGuardSelectionWitness,
            )
        )
        guarded_route_matches_fact = bool(
            guarded_physical_fact
            and int(transform_fact.owner_serial) == int(route.write_block)
            and route.via_block is not None
            and int(transform_fact.source_serial) == int(route.via_block)
            and int(transform_fact.state_constant) == int(route.next_state)
            and int(transform_fact.target_serial) == int(route.target_handler)
            and route.physical_state_write == transform_fact.physical_state_write
        )
        split_physical_dag_fact = bool(
            transform_fact.kind is SemanticRouteFactKind.DECISION_DAG
            and transform_fact.decision_dag_witness is not None
            and isinstance(
                transform_fact.physical_state_write,
                SemanticPhysicalStateWriteWitness,
            )
        )
        split_physical_dag_route_matches_fact = bool(
            split_physical_dag_fact
            and int(transform_fact.owner_serial) == int(route.write_block)
            and int(transform_fact.source_serial) == int(
                route.write_block if route.via_block is None else route.via_block
            )
            and int(transform_fact.state_constant) == int(route.next_state)
            and int(transform_fact.target_serial) == int(route.target_handler)
            and route.physical_state_write == transform_fact.physical_state_write
        )

        def matches(proof: SemanticRouteProof) -> bool:
            if not proof.destinations:
                return False
            if (
                proof.proof_kind
                is not semantic_route_proof_kind_for_fact(transform_fact)
            ):
                return False
            if transform_fact.kind is SemanticRouteFactKind.BOOTSTRAP:
                witness = transform_fact.bootstrap_witness
                bootstrap = proof.bootstrap
                if witness is None or bootstrap is None:
                    return False
                try:
                    source_witness = _witness_for_serial(
                        source, source_catalog, block_refs_by_serial,
                        witness.source_serial,
                    )
                    owner_witness = _witness_for_serial(
                        source, source_catalog, block_refs_by_serial,
                        witness.owner_serial,
                    )
                    dispatcher_witness = _witness_for_serial(
                        source, source_catalog, block_refs_by_serial,
                        witness.dispatcher_serial,
                    )
                    entry_witness = _witness_for_serial(
                        source, source_catalog, block_refs_by_serial,
                        witness.entry_serial,
                    )
                    corridor_witnesses = tuple(
                        _witness_for_serial(
                            source, source_catalog, block_refs_by_serial, serial,
                        )
                        for serial in witness.corridor_serials
                    )
                except (KeyError, TypeError, ValueError):
                    return False
                corridor = tuple(
                    (item.block_ref.identity, int(anchor))
                    for item, anchor in zip(corridor_witnesses, witness.corridor_anchors)
                )
                # Recovery's bootstrap owner is the physical corridor entry,
                # not necessarily the catalog's normalized first-instruction
                # anchor.  Bind that coordinate explicitly and require it to
                # belong to the owner's stable identity.
                if len(witness.corridor_anchors) < 2:
                    return False
                owner_anchor_ea = int(witness.corridor_anchors[-2])
                if not owner_witness.block_ref.identity.native_ranges.contains(owner_anchor_ea):
                    return False
                if len(proof.destinations) != 1:
                    return False
                canonical_target_anchor = int(proof.destinations[0].target_anchor_ea)
                if (
                    transform_fact.owner_serial != route.write_block
                    or transform_fact.target_serial != route.target_handler
                    or transform_fact.source_instruction_ea != witness.source_instruction_ea
                    or transform_fact.state_constant != int(route.next_state)
                    or witness.state_identity != state_identity
                    or witness.state_width != 4
                    or (
                        transform_fact.owner_anchor_ea is not None
                        and transform_fact.owner_anchor_ea != owner_anchor_ea
                    )
                    or (
                        transform_fact.target_anchor_ea is not None
                        and transform_fact.target_anchor_ea != canonical_target_anchor
                    )
                    or proof.source_identity != owner_witness.block_ref.identity
                    or proof.source_anchor_ea != owner_anchor_ea
                    or proof.source_owner_identity is not None
                    and proof.source_owner_identity != owner_witness.block_ref.identity
                    or bootstrap.entry.identity != entry_witness.block_ref.identity
                    or bootstrap.source.identity != source_witness.block_ref.identity
                    or bootstrap.source.anchor_ea != witness.source_instruction_ea
                    or bootstrap.owner.identity != owner_witness.block_ref.identity
                    or bootstrap.owner.anchor_ea != owner_anchor_ea
                    or bootstrap.dispatcher.identity != dispatcher_witness.block_ref.identity
                    or tuple((point.identity, point.anchor_ea) for point in bootstrap.corridor) != corridor
                    or bootstrap.state_write != proof.state_write
                    or proof.state_write is None
                    or proof.state_write.identity != source_witness.block_ref.identity
                    or proof.state_write.instruction_ea != witness.source_instruction_ea
                    or proof.state_write.state_variable != state_identity
                    or proof.state_write.width != 4
                    or proof.state_write.state_constant != int(route.next_state)
                    or bootstrap.state_dag != proof.state_dag
                    or proof.state_dag is None
                    or proof.state_dag.source_identity != owner_witness.block_ref.identity
                    or proof.state_dag.source_anchor_ea != owner_anchor_ea
                    or proof.state_dag.witness.state_identity != state_identity
                    or proof.state_dag.witness.state_constant != int(route.next_state)
                    or proof.state_dag.target_identity != target_identity
                    or proof.state_dag.target_anchor_ea != canonical_target_anchor
                    or tuple(bootstrap.preserved_effect_sites)
                    != tuple(witness.preserved_effect_sites)
                    or proof.destinations[0].state_constant != int(route.next_state)
                    or proof.destinations[0].target_identity != target_identity
                    or proof.destinations[0].target_anchor_ea != canonical_target_anchor
                ):
                    return False
                if not _matches_exact_decision_dag_witness(
                    witness.decision_dag_witness,
                    proof.state_dag.witness,
                    source=source,
                    source_catalog=source_catalog,
                    block_refs_by_serial=block_refs_by_serial,
                ):
                    return False
                return True
            if guarded_physical_fact:
                if not guarded_route_matches_fact:
                    return False
                return _matches_exact_guarded_state_assignment(
                    proof,
                    fact=transform_fact,
                    source=source,
                    source_catalog=source_catalog,
                    block_refs_by_serial=block_refs_by_serial,
                    source_identity=source_identity,
                    owner_identity=owner_identity,
                    target_identity=target_identity,
                    state_identity=state_identity,
                )
            if (
                transform_fact.kind is SemanticRouteFactKind.DECISION_DAG
                and transform_fact.decision_dag_witness is None
            ):
                return False
            if split_physical_dag_fact and not split_physical_dag_route_matches_fact:
                return False
            if (
                proof.source_identity != source_identity
                or proof.source_anchor_ea != transform_fact.source_instruction_ea
                or proof.destinations[0].state_constant != int(route.next_state)
                or proof.destinations[0].target_identity != target_identity
            ):
                return False
            if (
                not split_physical_dag_fact
                and proof.source_owner_identity is not None
                and proof.source_owner_identity != owner_identity
            ):
                return False
            if proof.state_write is not None and not split_physical_dag_fact:
                if (
                    proof.state_write.identity != source_identity
                    or proof.state_write.instruction_ea != transform_fact.source_instruction_ea
                    or proof.state_write.state_constant != int(route.next_state)
                ):
                    return False
            if proof.state_transform is not None:
                return (
                    transform_fact.kind is SemanticRouteFactKind.STATE_TRANSFORM
                    and proof.proof_kind is SemanticRouteProofKind.STATE_TRANSFORM
                    and proof.state_transform.source_identity == source_identity
                    and proof.state_transform.owner_identity == owner_identity
                    and proof.state_transform.state_identity == state_identity
                    and proof.state_transform.state_constant == int(route.next_state)
                )
            if proof.state_carrier is not None:
                return (
                    transform_fact.kind is SemanticRouteFactKind.STATE_CARRIER
                    and proof.proof_kind is SemanticRouteProofKind.STATE_CARRIER
                    and proof.state_carrier.source_identity == source_identity
                    and proof.state_carrier.owner_identity == owner_identity
                    and proof.state_carrier.state_identity == state_identity
                    and proof.state_carrier.state_constant == int(route.next_state)
                )
            if proof.state_partition is not None:
                return (
                    transform_fact.kind is SemanticRouteFactKind.STATE_PARTITION
                    and proof.proof_kind is SemanticRouteProofKind.STATE_PARTITION
                    and proof.state_partition.state_identity == state_identity
                    and proof.state_dag is not None
                    and transform_fact.decision_dag_witness is not None
                    and _matches_exact_decision_dag_witness(
                        transform_fact.decision_dag_witness,
                        proof.state_dag.witness,
                        source=source,
                        source_catalog=source_catalog,
                        block_refs_by_serial=block_refs_by_serial,
                    )
                    and any(
                        member.owner_identity == owner_identity
                        and member.state_constant == int(route.next_state)
                        for member in proof.state_partition.members
                    )
                )
            if proof.state_dag is not None:
                return transform_fact.kind is SemanticRouteFactKind.DECISION_DAG and _matches_complete_decision_dag_route(
                    proof,
                    fact=transform_fact,
                    source=source,
                    source_catalog=source_catalog,
                    block_refs_by_serial=block_refs_by_serial,
                    source_identity=source_identity,
                    owner_identity=owner_identity,
                    target_identity=target_identity,
                    state_identity=state_identity,
                )
            if transform_fact.kind in {
                SemanticRouteFactKind.DISPATCHER_MAP,
                SemanticRouteFactKind.NATIVE_BOUND,
            }:
                return (
                    proof.proof_kind is SemanticRouteProofKind.STATE_ASSIGNMENT
                    and proof.state_write is not None
                )
            return False

        return _select_route_proof(
            canonical_evidence, matches, "state transition",
        )

    raise TypeError("state transition adapter requires a typed route row")


def _equivalent_route_claim(
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    route_evidence: CanonicalSemanticEvidence,
    proof: SemanticRouteProof,
    binding: RouteAuthorityBinding,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef] | None,
) -> EquivalentSemanticRouteClaim:
    """Adapt one selected canonical proof into a closed route claim.

    ``binding`` is the bundle's own join authority, resolved once by the
    caller.  The claim is minted carrying the references it already holds for
    exactly this proof, so a later join asks the arena which route a claim is
    about instead of re-deriving it from a content ID.  ``binding.claim_refs``
    resolves the proof by object identity, so a proof that is not this
    bundle's record fails closed here rather than minting a claim whose
    authority names the wrong route.
    """

    if proof.native_key != source_catalog.native_key:
        raise ValueError("canonical route proof has a foreign native key")
    if not proof.atomic_group_id:
        raise ValueError("canonical route proof has an invalid atomic group")
    try:
        source_witness = _route_witness(
            source_catalog, proof.source_identity, proof.source_anchor_ea,
        )
    except ValueError as exc:
        raise ValueError(
            f"canonical route source endpoint proof_id={proof.proof_id}: {exc}"
        ) from exc
    destination_witnesses = []
    for index, destination in enumerate(proof.destinations):
        try:
            destination_witnesses.append(
                _route_witness(
                    source_catalog,
                    destination.target_identity,
                    destination.target_anchor_ea,
                )
            )
        except ValueError as exc:
            raise ValueError(
                "canonical route destination endpoint "
                f"proof_id={proof.proof_id} index={index} "
                f"role={destination.role.value}: {exc}"
            ) from exc
    destination_witnesses = tuple(destination_witnesses)
    # The source catalog proves identity/range membership; it does not own the
    # proof's semantic endpoint coordinate.  A native block start can precede
    # its first surviving instruction after partitioning, so reconstructing an
    # endpoint from ``witness.anchor_ea`` would create a second anchor
    # namespace and later make the claim unselectable by its own proof.
    source_anchor_ea = int(proof.source_anchor_ea)
    source_locator = BlockSubjectLocator(
        source_witness.block_ref, source_anchor_ea,
    )
    native_destination_subjects = tuple(
        _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.BLOCK,
            role=SemanticSubjectRole.SEMANTIC_ROUTE_DESTINATION,
            block_ref=witness.block_ref,
            anchor_ea=int(destination.target_anchor_ea),
            locator=BlockSubjectLocator(
                witness.block_ref, int(destination.target_anchor_ea),
            ),
        )
        for destination, witness in zip(
            proof.destinations, destination_witnesses, strict=True,
        )
    )
    destination_coordinates = tuple(
        (subject.block_ref, subject.anchor_ea)
        for subject in native_destination_subjects
    )
    if len(set(destination_coordinates)) != len(destination_coordinates):
        raise ValueError("canonical route proof has duplicate native destinations")
    logical_endpoints: dict[int, SemanticLogicalDagEndpoint] = {}
    if proof.state_dag is not None:
        for comparison in proof.state_dag.witness.comparisons:
            for endpoint in (comparison.true_target, comparison.false_target):
                if type(endpoint) is not SemanticLogicalDagEndpoint:
                    continue
                prior = logical_endpoints.setdefault(endpoint.serial, endpoint)
                if prior != endpoint:
                    raise ValueError("canonical logical route endpoint serial is ambiguous")
    if proof.terminal_delivery is not None:
        endpoint = proof.terminal_delivery.return_transport.logical_exit
        prior = logical_endpoints.setdefault(endpoint.serial, endpoint)
        if prior != endpoint:
            raise ValueError("canonical logical route endpoint serial is ambiguous")
    if logical_endpoints and block_refs_by_serial is None:
        raise ValueError("logical route endpoint requires exact source references")
    dag_endpoint_subjects = []
    for serial, endpoint in sorted(logical_endpoints.items()):
        ref = block_refs_by_serial.get(serial) if block_refs_by_serial is not None else None
        block = source.blocks.get(serial)
        if (
            type(ref) is not LogicalBlockRef
            or block is None
            or not is_exact_logical_function_exit(block, ref)
        ):
            raise ValueError("logical route endpoint differs from selected canonical proof")
        locator = LogicalFunctionExitSubjectLocator(ref, serial)
        dag_endpoint_subjects.append(_subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.BLOCK,
            role=SemanticSubjectRole.SEMANTIC_DAG_ENDPOINT,
            block_ref=ref,
            anchor_ea=None,
            locator=locator,
        ))
    destination_subjects = native_destination_subjects
    source_subject = _subject_factory(
        SemanticSubjectRef,
        kind=SemanticSubjectKind.BLOCK,
        role=SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=source_witness.block_ref,
        anchor_ea=source_anchor_ea,
        locator=source_locator,
    )
    destination_locators = tuple(subject.locator for subject in destination_subjects)
    dag_endpoint_locators = tuple(subject.locator for subject in dag_endpoint_subjects)
    retired_locator = RouteSubjectLocator(
        proof.proof_id,
        proof.atomic_group_id,
        source_witness.block_ref,
        source_anchor_ea,
        destination_locators,
        dag_endpoint_locators,
    )
    retired_subject = _subject_factory(
        SemanticSubjectRef,
        kind=SemanticSubjectKind.ROUTE,
        role=SemanticSubjectRole.SEMANTIC_ROUTE_SOURCE,
        block_ref=source_witness.block_ref,
        anchor_ea=source_anchor_ea,
        locator=retired_locator,
    )
    # The model's retired/replacement names describe source and candidate
    # phases.  They intentionally point to the same selected route identity;
    # phase equivalence is proved by the closed assessments, not a second ID.
    replacement_subject = retired_subject
    return _claim_factory(
        EquivalentSemanticRouteClaim,
        runtime_refs=binding.claim_refs(proof),
        kind=UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE,
        retired_route_subject=retired_subject,
        replacement_route_subject=replacement_subject,
        source_subject=source_subject,
        destination_subjects=canonical_model_order(
            destination_subjects, "destination_subjects",
        ),
        route_proof_ids=(proof.proof_id,),
        atomic_group_id=proof.atomic_group_id,
        source_generation=route_evidence.generation,
        dag_endpoint_subjects=canonical_model_order(
            dag_endpoint_subjects, "dag_endpoint_subjects",
        ),
    )


def build_equivalent_route_claims(
    *,
    source: FlowGraph,
    source_catalog: SourceIdentityCatalog,
    route_evidence: CanonicalSemanticEvidence,
    selected_proof_ids: Iterable[str] | None = None,
    block_refs_by_serial: Mapping[int, AuthorityBlockRef] | None = None,
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
    if any(type(item) is not str or not item for item in selected):
        raise TypeError("selected_proof_ids must contain exact proof IDs")
    if len(set(selected)) != len(selected):
        raise ValueError("selected_proof_ids must not contain duplicates")
    # ``selected_proof_ids`` is a *content* channel: it crosses into the
    # authority transaction as canonical identifiers and stays that way.  The
    # resolution below is therefore the one place the content ID is read, and
    # the claim order that comes out of it is the arena's mint order, not a
    # string sort -- mint order is the bundle's canonical proof order, so this
    # produces the identical sequence without ordering on a hash.
    binding = route_join_binding(route_evidence)
    wanted = frozenset(selected)
    ordered_proofs = tuple(
        binding.proof_for(ref)
        for ref in sorted(binding.proof_refs, key=binding.order_key)
    )
    resolved = tuple(
        proof for proof in ordered_proofs if proof.proof_id in wanted
    )
    if len(resolved) != len(selected):
        raise ValueError("selected route proof is foreign to canonical evidence")
    claims = []
    for proof in resolved:
        claims.append(
            _equivalent_route_claim(
                source_catalog=source_catalog,
                route_evidence=route_evidence,
                proof=proof,
                binding=binding,
                source=source,
                block_refs_by_serial=block_refs_by_serial,
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
        block_refs_by_serial=block_refs_by_serial,
    )
    # The claim -> claim correspondence is an authority question, so it keys
    # on the references the bundle minted, not on the content fingerprint.
    # ``rebuilt`` was minted from ``proposal.route_evidence`` a few lines
    # above, so a claim that belongs to this proposal names references from
    # that same arena; one that does not is refused instead of matching a
    # foreign claim that happens to encode to the same bytes.  ``claim_id``
    # remains the fingerprint, and full value equality still decides.
    try:
        wanted = route_claim_join_refs(claim)
        selected = tuple(
            item for item in rebuilt if route_claim_join_refs(item) == wanted
        )
    except RuntimeJoinRejected as exc:
        raise ValueError("route claim is stale or ambiguous") from exc
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
        block_refs_by_serial=block_refs_by_serial,
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
    claims = canonical_model_order((*exact_claims, *route_claims), "claims")
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
    "bundle_route_proof_refs",
    "ConcreteEntryRouteForecast",
    "TransitionRouteSelectionKey",
    "TransitionRouteSelectionIndex",
    "BootstrapEntryRouteForecast",
    "ConditionalEntryBridgeForecast",
    "DiscoveredEffect",
    "DiscoveredTerminal",
    "SourceEffectTerminalCatalog",
    "classify_block_effects_and_terminals",
    "build_source_identity_catalog",
    "derive_authoritative_handler_serials",
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
    "route_claim_join_refs",
    "concrete_entry_route_key",
    "resolve_concrete_entry_route",
    "bootstrap_entry_route_key",
    "resolve_bootstrap_entry_route",
    "adapt_conditional_entry_route",
    "adapt_native_bound_transition_route",
    "ConditionalArmRouteForecast",
    "adapt_conditional_arm_route",
    "adapt_state_transition_route",
    "validate_exact_effect_semantics",
    "validate_exact_effect_claim_semantics",
]
