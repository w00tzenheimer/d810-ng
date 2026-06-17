"""Execution-plan layer between planner GraphModification IR and backend apply.

Phase B introduces ``PatchPlan`` as the backend-facing execution IR. Planner code
continues to emit ``GraphModification`` objects. The compiler in this module
converts those modification intents into an ordered plan made of:

- concrete existing-block rewrites that backends can apply directly
- symbolic block specs for edits that create new blocks
- transitional legacy block-creation steps while one-shot materialization is
  still being built

This lets callers reason about block creation explicitly and reject fragile live
allocation paths before mutating the backend state.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum

from d810.core.algorithm_metadata import algorithm_metadata
from d810.core.typing import Union


class ExecutionPolicy(str, Enum):
    """Controls verification behaviour during plan lowering.

    STRICT: Default. Full verification, rollback on failure.
    NOP_CLEANUP_RELAXED: Only NOP-kind steps allowed. Tolerates transient
        verify failure (INTERR 50846) without rollback. Used exclusively by
        StateConstantReturnFixupStrategy for stale feeder cleanup.
    NOP_MERGE_BLOCKS_RELAXED: Only NOP-kind steps allowed. Runs the backend
        merge-block cleanup before native verify so tail-goto NOP cleanup can
        let Hex-Rays coalesce linear blocks.
    """

    STRICT = "strict"
    NOP_CLEANUP_RELAXED = "nop_cleanup_relaxed"
    NOP_MERGE_BLOCKS_RELAXED = "nop_merge_blocks_relaxed"

from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.transforms.graph_modification import (
    BypassDispatcherTrampoline,
    CanonicalizeJumpTableCaseOverlap,
    CloneConditionalAsGoto,
    CloneConditionalAsGotoFromBranchArm,
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    DuplicateReplayAndRedirect,
    DuplicateReplayEntry,
    EdgeRedirectViaPredSplit,
    GraphModification,
    InsertBlock,
    LowerConditionalStateTransition,
    NormalizeNWayDispatcherExit,
    NopInstructions,
    ZeroStateWrite,
    PhaseCycleLowering,
    PromoteOperandToScalar,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    DirectTerminalLoweringKind,
    DirectTerminalLoweringGroup,
    DirectTerminalLoweringSite,
    ReorderBlocks,
    RedirectBranch,
    RedirectGoto,
    RetargetOutputStore,
    RemoveEdge,
    ScalarizeLocalAliasAccess,
)
from d810.transforms.materialization_payload import CapturedBlockBody


@dataclass(frozen=True, order=True)
class VirtualBlockId:
    """Planner-visible symbolic identifier for a not-yet-materialized block."""

    namespace: str
    ordinal: int

    def __str__(self) -> str:
        return f"{self.namespace}:{self.ordinal}"


PatchBlockRef = Union[int, VirtualBlockId]


@dataclass(frozen=True)
class PatchEdgeRef:
    """Edge descriptor that can reference concrete or symbolic blocks."""

    source: PatchBlockRef
    target: PatchBlockRef


@dataclass(frozen=True)
class PatchBlockSpec:
    """Symbolic description of a block that must be materialized later."""

    block_id: VirtualBlockId
    kind: str
    template_block: int | None = None
    incoming_edge: PatchEdgeRef | None = None
    outgoing_edges: tuple[PatchEdgeRef, ...] = ()
    instructions: tuple[InsnSnapshot, ...] = ()
    captured_body: CapturedBlockBody | None = None


@dataclass(frozen=True)
class PatchRelocationMap:
    """Final serial assignments and block-reference rewrites."""

    assigned_serials: tuple[tuple[VirtualBlockId, int], ...] = ()
    stop_serial_before: int | None = None
    stop_serial_after: int | None = None
    rewritten_edges: tuple[tuple[PatchEdgeRef, PatchEdgeRef], ...] = ()

    def assigned_serial_for(self, block_id: VirtualBlockId) -> int | None:
        for candidate, serial in self.assigned_serials:
            if candidate == block_id:
                return serial
        return None

    def rewrite_serial(self, serial: int) -> int:
        if (
            self.stop_serial_before is not None
            and self.stop_serial_after is not None
            and serial == self.stop_serial_before
        ):
            return self.stop_serial_after
        return serial


@dataclass(frozen=True)
class PatchRedirectGoto:
    from_serial: int
    old_target: int
    new_target: int

    def to_graph_modification(self) -> RedirectGoto:
        return RedirectGoto(
            from_serial=self.from_serial,
            old_target=self.old_target,
            new_target=self.new_target,
        )


@dataclass(frozen=True)
class PatchRedirectBranch:
    from_serial: int
    old_target: int
    new_target: int

    def to_graph_modification(self) -> RedirectBranch:
        return RedirectBranch(
            from_serial=self.from_serial,
            old_target=self.old_target,
            new_target=self.new_target,
        )


@dataclass(frozen=True)
class PatchConvertToGoto:
    block_serial: int
    goto_target: int

    def to_graph_modification(self) -> ConvertToGoto:
        return ConvertToGoto(
            block_serial=self.block_serial,
            goto_target=self.goto_target,
        )


@dataclass(frozen=True)
class PatchRemoveEdge:
    from_serial: int
    to_serial: int

    def to_graph_modification(self) -> RemoveEdge:
        return RemoveEdge(from_serial=self.from_serial, to_serial=self.to_serial)


@dataclass(frozen=True)
class PatchNopInstructions:
    block_serial: int
    insn_eas: tuple[int, ...]

    def to_graph_modification(self) -> NopInstructions:
        return NopInstructions(block_serial=self.block_serial, insn_eas=self.insn_eas)


@dataclass(frozen=True)
class PatchZeroStateWrite:
    """Zero the source operand of a state variable write instruction."""
    block_serial: int
    insn_ea: int

    def to_graph_modification(self) -> ZeroStateWrite:
        return ZeroStateWrite(block_serial=self.block_serial, insn_ea=self.insn_ea)


@dataclass(frozen=True)
class PatchPromoteOperandToScalar:
    """Promote a fused sub-instruction operand into a fresh kreg standalone insn."""
    block_serial: int
    host_ea: int
    host_opcode: int
    operand_side: str  # "l" | "r"

    def to_graph_modification(self) -> PromoteOperandToScalar:
        return PromoteOperandToScalar(
            block_serial=self.block_serial,
            host_ea=self.host_ea,
            host_opcode=self.host_opcode,
            operand_side=self.operand_side,
        )


@dataclass(frozen=True)
class PatchLowerConditionalStateTransition:
    source_serial: int
    old_dispatcher_serial: int
    rewrite_from_ea: int
    condition_operand: object
    false_target_serial: int
    true_target_serial: int
    proof_id: str | None = None

    def to_graph_modification(self) -> LowerConditionalStateTransition:
        return LowerConditionalStateTransition(
            source_serial=self.source_serial,
            old_dispatcher_serial=self.old_dispatcher_serial,
            rewrite_from_ea=self.rewrite_from_ea,
            condition_operand=self.condition_operand,
            false_target_serial=self.false_target_serial,
            true_target_serial=self.true_target_serial,
            proof_id=self.proof_id,
        )


@dataclass(frozen=True)
class PatchNormalizeNWayDispatcherExit:
    block_serial: int
    dispatcher_entry_serial: int
    keep_target_serial: int | None = None

    def to_graph_modification(self) -> NormalizeNWayDispatcherExit:
        return NormalizeNWayDispatcherExit(
            block_serial=self.block_serial,
            dispatcher_entry_serial=self.dispatcher_entry_serial,
            keep_target_serial=self.keep_target_serial,
        )


@dataclass(frozen=True)
class PatchBypassDispatcherTrampoline:
    source_serial: int
    trampoline_serial: int
    target_serial: int

    def to_graph_modification(self) -> BypassDispatcherTrampoline:
        return BypassDispatcherTrampoline(
            source_serial=self.source_serial,
            trampoline_serial=self.trampoline_serial,
            target_serial=self.target_serial,
        )


@dataclass(frozen=True)
class PatchCanonicalizeJumpTableCaseOverlap:
    jtbl_serial: int
    retarget_map: tuple[tuple[int, int], ...]
    deduplicate: bool = False

    def to_graph_modification(self) -> CanonicalizeJumpTableCaseOverlap:
        return CanonicalizeJumpTableCaseOverlap(
            jtbl_serial=self.jtbl_serial,
            retarget_map=self.retarget_map,
            deduplicate=self.deduplicate,
        )


@dataclass(frozen=True)
class PatchScalarizeLocalAliasAccess:
    block_serial: int
    host_ea: int
    host_opcode: int
    alias_token: str
    base_token: str
    host_text_sha1: str | None = None
    value_size: int | None = None

    def to_graph_modification(self) -> ScalarizeLocalAliasAccess:
        return ScalarizeLocalAliasAccess(
            block_serial=self.block_serial,
            host_ea=self.host_ea,
            host_opcode=self.host_opcode,
            alias_token=self.alias_token,
            base_token=self.base_token,
            host_text_sha1=self.host_text_sha1,
            value_size=self.value_size,
        )


@dataclass(frozen=True)
class PatchRetargetOutputStore:
    block_serial: int
    host_ea: int
    host_opcode: int
    alias_token: str
    output_token: str
    host_text_sha1: str | None = None
    value_size: int | None = None

    def to_graph_modification(self) -> RetargetOutputStore:
        return RetargetOutputStore(
            block_serial=self.block_serial,
            host_ea=self.host_ea,
            host_opcode=self.host_opcode,
            alias_token=self.alias_token,
            output_token=self.output_token,
            host_text_sha1=self.host_text_sha1,
            value_size=self.value_size,
        )


@dataclass(frozen=True)
class PatchPhaseCycleLowering:
    header_entries: tuple[int, ...]
    header_target: int
    body_entries: tuple[int, ...]
    body_target: int
    next_phase_entries: tuple[int, ...]
    next_phase_target: int
    terminal_entries: tuple[int, ...] = ()
    terminal_target: int | None = None
    state_roles: tuple[tuple[str, int], ...] = ()
    reason: str = "dispatcher_phase_cycle"

    def to_graph_modification(self) -> PhaseCycleLowering:
        return PhaseCycleLowering(
            header_entries=self.header_entries,
            header_target=self.header_target,
            body_entries=self.body_entries,
            body_target=self.body_target,
            next_phase_entries=self.next_phase_entries,
            next_phase_target=self.next_phase_target,
            terminal_entries=self.terminal_entries,
            terminal_target=self.terminal_target,
            state_roles=self.state_roles,
            reason=self.reason,
        )


@dataclass(frozen=True)
class PatchEdgeSplitTrampoline:
    """Finalized edge-split trampoline materialization step."""

    block_id: VirtualBlockId
    assigned_serial: int
    source_serial: int
    via_pred: int
    old_target: int
    apply_old_target: int
    new_target: int
    template_block: int


@dataclass(frozen=True)
class PatchEdgeSplitCorridor:
    """Finalized strict 1-way corridor clone for an edge split."""

    clone_block_ids: tuple[VirtualBlockId, ...]
    clone_assigned_serials: tuple[int, ...]
    source_serial: int
    via_pred: int
    old_target: int
    new_target: int
    clone_until: int
    corridor_serials: tuple[int, ...]
    source_new_target: int | None = None
    rule_priority: int = 0

    def to_graph_modification(self) -> EdgeRedirectViaPredSplit:
        return EdgeRedirectViaPredSplit(
            src_block=self.source_serial,
            old_target=self.old_target,
            new_target=self.new_target,
            via_pred=self.via_pred,
            clone_until=self.clone_until,
            source_new_target=self.source_new_target,
            rule_priority=self.rule_priority,
        )


@dataclass(frozen=True)
class PatchConditionalRedirect:
    """Finalized materialization of a cloned conditional block plus NOP fallthrough."""

    block_id: VirtualBlockId
    assigned_serial: int
    fallthrough_block_id: VirtualBlockId
    fallthrough_serial: int
    source_serial: int
    ref_block: int
    conditional_target: int
    fallthrough_target: int
    old_target_serial: int | None = None
    instructions: tuple[InsnSnapshot, ...] = ()

    def to_graph_modification(self) -> CreateConditionalRedirect:
        return CreateConditionalRedirect(
            source_block=self.source_serial,
            ref_block=self.ref_block,
            conditional_target=self.conditional_target,
            fallthrough_target=self.fallthrough_target,
            old_target_serial=self.old_target_serial,
            instructions=self.instructions,
        )


@dataclass(frozen=True)
class PatchInsertBlock:
    """Finalized materialization of an inserted standalone block."""

    block_id: VirtualBlockId
    assigned_serial: int
    pred_serial: int
    succ_serial: int
    instructions: tuple[InsnSnapshot, ...]
    old_target_serial: int | None = None
    captured_body: CapturedBlockBody | None = None

    def to_graph_modification(self) -> InsertBlock:
        return InsertBlock(
            pred_serial=self.pred_serial,
            succ_serial=self.succ_serial,
            instructions=self.instructions,
            old_target_serial=self.old_target_serial,
            captured_body=self.captured_body,
        )


@dataclass(frozen=True)
class PatchDuplicateBlock:
    """Finalized materialization of a duplicated block plus predecessor redirect."""

    block_id: VirtualBlockId
    assigned_serial: int
    source_serial: int
    pred_serial: int | None
    pred_redirect_kind: str
    source_successors: tuple[int, ...]
    target_serial: int | None = None
    conditional_target: int | None = None
    fallthrough_target: int | None = None
    fallthrough_block_id: VirtualBlockId | None = None
    fallthrough_serial: int | None = None

    def to_graph_modification(self) -> DuplicateBlock:
        return DuplicateBlock(
            source_block=self.source_serial,
            target_block=self.target_serial,
            pred_serial=self.pred_serial,
            conditional_target=self.conditional_target,
            fallthrough_target=self.fallthrough_target,
        )


@dataclass(frozen=True)
class PatchDuplicateReplayEntry:
    """Finalized per-predecessor clone/replay route."""

    pred_serial: int
    target_serial: int
    replay_block_id: VirtualBlockId
    replay_serial: int
    captured_body: CapturedBlockBody
    clone_block_id: VirtualBlockId | None = None
    clone_serial: int | None = None


@dataclass(frozen=True)
class PatchDuplicateReplayAndRedirect:
    """Finalized duplicate-group replay materialization step."""

    source_serial: int
    dispatcher_entry: int
    per_pred_replays: tuple[PatchDuplicateReplayEntry, ...]

    def to_graph_modification(self) -> DuplicateReplayAndRedirect:
        return DuplicateReplayAndRedirect(
            source_serial=self.source_serial,
            dispatcher_entry=self.dispatcher_entry,
            per_pred_replays=tuple(
                DuplicateReplayEntry(
                    pred_serial=entry.pred_serial,
                    target_serial=entry.target_serial,
                    captured_body=entry.captured_body,
                )
                for entry in self.per_pred_replays
            ),
        )


@dataclass(frozen=True)
class PatchCloneConditionalAsGoto:
    """Finalized clone-conditional-as-goto materialization step."""

    block_id: VirtualBlockId
    assigned_serial: int
    source_serial: int
    pred_serial: int
    goto_target: int
    source_successors: tuple[int, int]
    conditional_target: int
    fallthrough_target: int
    reason: str = "fix_predecessor_clone_as_goto"

    def to_graph_modification(self) -> CloneConditionalAsGoto:
        return CloneConditionalAsGoto(
            source_block=self.source_serial,
            pred_serial=self.pred_serial,
            goto_target=self.goto_target,
            reason=self.reason,
        )


@dataclass(frozen=True)
class PatchCloneConditionalAsGotoFromBranchArm:
    """Finalized clone-conditional-as-goto-from-branch-arm materialization step.

    Sibling of :class:`PatchCloneConditionalAsGoto` for the case where the
    predecessor is itself a 2-way conditional whose ``pred_arm`` reaches the
    cloned source.  ``pred_arm == 1`` rewires the explicit conditional branch;
    ``pred_arm == 0`` materializes the implicit fallthrough through the
    mutation backend's adjacent helper-block path.
    """

    block_id: VirtualBlockId
    assigned_serial: int
    source_serial: int
    pred_serial: int
    pred_arm: int
    goto_target: int
    source_successors: tuple[int, int]
    pred_successors: tuple[int, int]
    pred_branch_target_serial: int
    pred_fallthrough_target_serial: int
    conditional_target: int
    fallthrough_target: int
    reason: str = "fix_predecessor_clone_as_goto_from_branch_arm"

    def to_graph_modification(self) -> CloneConditionalAsGotoFromBranchArm:
        return CloneConditionalAsGotoFromBranchArm(
            source_block=self.source_serial,
            pred_serial=self.pred_serial,
            pred_arm=self.pred_arm,
            goto_target=self.goto_target,
            reason=self.reason,
        )


@dataclass(frozen=True)
class PatchPrivateTerminalSuffix:
    """Finalized materialization of a private terminal suffix chain for one anchor.

    Clones each block in the shared suffix, wires the cloned chain in order,
    and redirects the anchor to the clone of shared_entry.

    Attributes:
        anchor_serial: Block whose edge to shared_entry gets rewired to clone chain.
        shared_entry_serial: First block in the shared suffix.
        return_block_serial: Terminal stop/return block (last in the suffix).
        suffix_serials: Ordered shared suffix serials (entry..return_block).
        clone_block_ids: Virtual block IDs for each clone (parallel to suffix_serials).
        clone_assigned_serials: Assigned concrete serials for each clone
            (parallel to suffix_serials). Populated after relocation.
    """

    anchor_serial: int
    shared_entry_serial: int
    return_block_serial: int
    suffix_serials: tuple[int, ...]
    clone_block_ids: tuple[VirtualBlockId, ...]
    clone_assigned_serials: tuple[int, ...]

    def to_graph_modification(self) -> PrivateTerminalSuffix:
        return PrivateTerminalSuffix(
            anchor_serial=self.anchor_serial,
            shared_entry_serial=self.shared_entry_serial,
            return_block_serial=self.return_block_serial,
            suffix_serials=self.suffix_serials,
        )


@dataclass(frozen=True)
class PatchPrivateTerminalSuffixGroup:
    """Grouped materialization of private terminal suffix chains for multiple anchors."""

    shared_entry_serial: int
    return_block_serial: int
    suffix_serials: tuple[int, ...]
    anchors: tuple[int, ...]
    # Parallel to anchors: per_anchor_clone_block_ids[i] are clone IDs for anchors[i]
    per_anchor_clone_block_ids: tuple[tuple[VirtualBlockId, ...], ...]
    per_anchor_clone_assigned_serials: tuple[tuple[int, ...], ...]

    def to_graph_modification(self) -> PrivateTerminalSuffixGroup:
        return PrivateTerminalSuffixGroup(
            anchors=self.anchors,
            shared_entry_serial=self.shared_entry_serial,
            return_block_serial=self.return_block_serial,
            suffix_serials=self.suffix_serials,
        )


@dataclass(frozen=True)
class PatchDirectTerminalLoweringGroup:
    """Grouped direct terminal lowering for multiple anchors sharing the same suffix."""

    shared_entry_serial: int
    return_block_serial: int
    suffix_serials: tuple[int, ...]
    sites: tuple[DirectTerminalLoweringSite, ...]
    per_site_clone_assigned_serials: dict[int, tuple[int, ...]]


@dataclass(frozen=True)
class PatchReorderBlocks:
    """Reorder handler blocks by copying them in DFS order to end of MBA."""

    dfs_block_order: tuple[int, ...]
    non_2way_serials: tuple[int, ...] = ()  # dfs_block_order minus BLT_2WAY blocks; for projector
    two_way_serials: tuple[int, ...] = ()
    # old_serial -> new_concrete_serial mapping, populated after relocation
    old_to_new: tuple[tuple[int, int], ...] = ()
    two_way_old_to_trampoline: tuple[tuple[int, int], ...] = ()

    def to_graph_modification(self) -> ReorderBlocks:
        return ReorderBlocks(
            dfs_block_order=self.dfs_block_order,
            non_2way_serials=self.non_2way_serials,
            two_way_serials=self.two_way_serials,
        )


BlockCreatingGraphModification = Union[
    EdgeRedirectViaPredSplit,
    CreateConditionalRedirect,
    DuplicateBlock,
    CloneConditionalAsGoto,
    CloneConditionalAsGotoFromBranchArm,
    DuplicateReplayAndRedirect,
    InsertBlock,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    DirectTerminalLoweringGroup,
]


@dataclass(frozen=True)
class LegacyBlockOperation:
    """Transitional fallback for block-creating edits.

    The plan already records symbolic block intent in ``new_blocks``. Until the
    backend can materialize those blocks transactionally from relocation data, we
    also retain the original planner edit so legacy lowering can be used when
    explicitly allowed.
    """

    modification: BlockCreatingGraphModification
    block_id: VirtualBlockId | None = None

    def to_graph_modification(self) -> GraphModification:
        return self.modification


PatchOperation = Union[
    PatchRedirectGoto,
    PatchRedirectBranch,
    PatchConvertToGoto,
    PatchRemoveEdge,
    PatchNopInstructions,
    PatchZeroStateWrite,
    PatchPromoteOperandToScalar,
    PatchLowerConditionalStateTransition,
    PatchNormalizeNWayDispatcherExit,
    PatchBypassDispatcherTrampoline,
    PatchCanonicalizeJumpTableCaseOverlap,
    PatchScalarizeLocalAliasAccess,
    PatchRetargetOutputStore,
    PatchPhaseCycleLowering,
    PatchEdgeSplitTrampoline,
    PatchEdgeSplitCorridor,
    PatchConditionalRedirect,
    PatchInsertBlock,
    PatchDuplicateBlock,
    PatchDuplicateReplayAndRedirect,
    PatchCloneConditionalAsGoto,
    PatchCloneConditionalAsGotoFromBranchArm,
    PatchPrivateTerminalSuffix,
    PatchPrivateTerminalSuffixGroup,
    PatchDirectTerminalLoweringGroup,
    PatchReorderBlocks,
]

PatchStep = Union[PatchOperation, LegacyBlockOperation]
LoweringInput = Union["PatchPlan", list[GraphModification]]


@dataclass(frozen=True)
class PatchPlan:
    """Ordered backend-facing execution plan."""

    steps: tuple[PatchStep, ...] = ()
    new_blocks: tuple[PatchBlockSpec, ...] = ()
    relocation_map: PatchRelocationMap = field(default_factory=PatchRelocationMap)
    planner_modifications: tuple[GraphModification, ...] = ()
    execution_policy: ExecutionPolicy = ExecutionPolicy.STRICT
    metadata: tuple[tuple[str, object], ...] = ()

    @property
    def concrete_operations(self) -> tuple[PatchOperation, ...]:
        return tuple(step for step in self.steps if not isinstance(step, LegacyBlockOperation))

    @property
    def legacy_block_operations(self) -> tuple[LegacyBlockOperation, ...]:
        return tuple(step for step in self.steps if isinstance(step, LegacyBlockOperation))

    @property
    def contains_block_creation(self) -> bool:
        has_reorder = any(isinstance(s, PatchReorderBlocks) for s in self.steps)
        return bool(self.new_blocks or self.legacy_block_operations or has_reorder)

    def as_graph_modifications(self) -> list[GraphModification]:
        """Reconstruct planner edits for compatibility tests and mock backends."""
        if self.planner_modifications:
            return list(self.planner_modifications)

        reconstructed: list[GraphModification] = []
        for step in self.steps:
            if isinstance(step, LegacyBlockOperation):
                reconstructed.append(step.to_graph_modification())
                continue
            if hasattr(step, "to_graph_modification"):
                reconstructed.append(step.to_graph_modification())
                continue
            raise TypeError(
                f"PatchPlan step {type(step).__name__} has no planner GraphModification equivalent"
            )
        return reconstructed

    def metadata_dict(self) -> dict[str, object]:
        """Return plan metadata as a dict for consumers that need keyed facts."""
        return dict(self.metadata)

    def metadata_value(self, key: str, default: object = None) -> object:
        """Return one metadata value without exposing the immutable pair storage."""
        return self.metadata_dict().get(key, default)

    def with_metadata(self, **entries: object) -> "PatchPlan":
        """Return a copy with metadata entries merged by key."""
        metadata = self.metadata_dict()
        metadata.update(entries)
        return replace(self, metadata=tuple(sorted(metadata.items())))


class _VirtualIdAllocator:
    """Allocate deterministic symbolic block identifiers per plan build."""

    def __init__(self) -> None:
        self._next_ordinal = 0

    def alloc(self, namespace: str) -> VirtualBlockId:
        block_id = VirtualBlockId(namespace=namespace, ordinal=self._next_ordinal)
        self._next_ordinal += 1
        return block_id


@dataclass(frozen=True)
class _PendingEdgeSplitTrampoline:
    modification: EdgeRedirectViaPredSplit
    block_id: VirtualBlockId


@dataclass(frozen=True)
class _PendingEdgeSplitCorridor:
    modification: EdgeRedirectViaPredSplit
    corridor_serials: tuple[int, ...]
    clone_block_ids: tuple[VirtualBlockId, ...]


@dataclass(frozen=True)
class _PendingConditionalRedirect:
    modification: CreateConditionalRedirect
    block_id: VirtualBlockId
    fallthrough_block_id: VirtualBlockId


@dataclass(frozen=True)
class _PendingInsertBlock:
    modification: InsertBlock
    block_id: VirtualBlockId


@dataclass(frozen=True)
class _PendingDuplicateBlock:
    modification: DuplicateBlock
    block_id: VirtualBlockId
    pred_redirect_kind: str
    source_successors: tuple[int, ...]
    conditional_target: int | None = None
    fallthrough_target: int | None = None
    fallthrough_block_id: VirtualBlockId | None = None


@dataclass(frozen=True)
class _PendingDuplicateReplayAndRedirect:
    modification: DuplicateReplayAndRedirect
    replay_block_ids: tuple[VirtualBlockId, ...]
    clone_block_ids: tuple[VirtualBlockId | None, ...]


@dataclass(frozen=True)
class _PendingCloneConditionalAsGoto:
    modification: CloneConditionalAsGoto
    block_id: VirtualBlockId
    source_successors: tuple[int, int]
    conditional_target: int
    fallthrough_target: int


@dataclass(frozen=True)
class _PendingCloneConditionalAsGotoFromBranchArm:
    modification: CloneConditionalAsGotoFromBranchArm
    block_id: VirtualBlockId
    source_successors: tuple[int, int]
    pred_successors: tuple[int, int]
    pred_branch_target_serial: int
    pred_fallthrough_target_serial: int
    conditional_target: int
    fallthrough_target: int


@dataclass(frozen=True)
class _PendingPrivateTerminalSuffix:
    modification: PrivateTerminalSuffix
    clone_block_ids: tuple[VirtualBlockId, ...]


@dataclass(frozen=True)
class _PendingPrivateTerminalSuffixGroup:
    modification: PrivateTerminalSuffixGroup
    per_anchor_clone_block_ids: tuple[tuple[VirtualBlockId, ...], ...]


@dataclass(frozen=True)
class _PendingDirectTerminalLoweringGroup:
    modification: DirectTerminalLoweringGroup
    per_site_clone_block_ids: dict[int, tuple[VirtualBlockId, ...]]


@dataclass(frozen=True)
class _PendingReorderBlocks:
    """Pre-resolution ReorderBlocks with virtual block IDs (not yet concrete serials)."""
    dfs_block_order: tuple[int, ...]
    non_2way_serials: tuple[int, ...]
    virtual_ids: tuple[VirtualBlockId, ...]  # one per block in non_2way_serials, in order
    two_way_serials: tuple[int, ...] = ()
    two_way_virtual_id_pairs: tuple[tuple[VirtualBlockId, VirtualBlockId], ...] = ()


def is_block_creating_modification(modification: GraphModification) -> bool:
    """Return True when the modification requires a new block."""
    return isinstance(
        modification,
        (
            EdgeRedirectViaPredSplit,
            CreateConditionalRedirect,
            DuplicateBlock,
            CloneConditionalAsGoto,
            CloneConditionalAsGotoFromBranchArm,
            DuplicateReplayAndRedirect,
            InsertBlock,
            PrivateTerminalSuffix,
            PrivateTerminalSuffixGroup,
            DirectTerminalLoweringGroup,
        ),
    )


def _rewrite_block_ref(block_ref: PatchBlockRef, relocation_map: PatchRelocationMap) -> PatchBlockRef:
    if isinstance(block_ref, VirtualBlockId):
        return block_ref
    return relocation_map.rewrite_serial(block_ref)


def _rewrite_edge_ref(edge: PatchEdgeRef, relocation_map: PatchRelocationMap) -> PatchEdgeRef:
    return PatchEdgeRef(
        source=_rewrite_block_ref(edge.source, relocation_map),
        target=_rewrite_block_ref(edge.target, relocation_map),
    )


def _rewrite_symbolic_spec(
    spec: PatchBlockSpec,
    relocation_map: PatchRelocationMap,
) -> PatchBlockSpec:
    incoming_edge = spec.incoming_edge
    if incoming_edge is not None:
        incoming_edge = _rewrite_edge_ref(incoming_edge, relocation_map)
    outgoing_edges = tuple(
        _rewrite_edge_ref(edge, relocation_map) for edge in spec.outgoing_edges
    )
    return replace(
        spec,
        incoming_edge=incoming_edge,
        outgoing_edges=outgoing_edges,
        instructions=_rewrite_instruction_snapshots(spec.instructions, relocation_map),
    )


def _rewrite_instruction_operand(
    operand: object,
    relocation_map: PatchRelocationMap,
) -> object:
    block_attr = "block_num"
    block_num = getattr(operand, block_attr, None)
    if not isinstance(block_num, int):
        block_attr = "block_ref"
        block_num = getattr(operand, block_attr, None)
    if not isinstance(block_num, int):
        return operand

    rewritten_block_num = relocation_map.rewrite_serial(block_num)
    if rewritten_block_num == block_num:
        return operand

    replace_kwargs = {block_attr: rewritten_block_num}
    if hasattr(operand, "owned_mop"):
        replace_kwargs["owned_mop"] = None
    try:
        return replace(operand, **replace_kwargs)
    except Exception:
        return operand


def _rewrite_instruction_snapshots(
    instructions: tuple[InsnSnapshot, ...],
    relocation_map: PatchRelocationMap,
) -> tuple[InsnSnapshot, ...]:
    rewritten_instructions: list[InsnSnapshot] = []
    for instruction in instructions:
        if instruction.operand_slots:
            rewritten_operand_slots = tuple(
                (slot_name, _rewrite_instruction_operand(operand, relocation_map))
                for slot_name, operand in instruction.operand_slots
            )
            rewritten_operands = tuple(
                operand for _, operand in rewritten_operand_slots
            )
        else:
            rewritten_operands = tuple(
                _rewrite_instruction_operand(operand, relocation_map)
                for operand in instruction.operands
            )
            rewritten_operand_slots = instruction.operand_slots
        rewritten_instructions.append(
            replace(
                instruction,
                operands=rewritten_operands,
                operand_slots=rewritten_operand_slots,
            )
        )
    return tuple(rewritten_instructions)


def _build_relocation_map(
    new_blocks: list[PatchBlockSpec],
    cfg: FlowGraph | None,
) -> PatchRelocationMap:
    if cfg is None or not new_blocks or not cfg.blocks:
        return PatchRelocationMap()

    stop_serial_before = max(cfg.blocks)
    assigned_serials = tuple(
        (spec.block_id, stop_serial_before + idx)
        for idx, spec in enumerate(new_blocks)
    )
    stop_serial_after = stop_serial_before + len(new_blocks)

    rewritten_edges: list[tuple[PatchEdgeRef, PatchEdgeRef]] = []
    for spec in new_blocks:
        if spec.incoming_edge is not None:
            rewritten_edges.append(
                (
                    spec.incoming_edge,
                    _rewrite_edge_ref(spec.incoming_edge, PatchRelocationMap(
                        assigned_serials=assigned_serials,
                        stop_serial_before=stop_serial_before,
                        stop_serial_after=stop_serial_after,
                    )),
                )
            )
        for edge in spec.outgoing_edges:
            rewritten_edges.append(
                (
                    edge,
                    _rewrite_edge_ref(edge, PatchRelocationMap(
                        assigned_serials=assigned_serials,
                        stop_serial_before=stop_serial_before,
                        stop_serial_after=stop_serial_after,
                    )),
                )
            )

    return PatchRelocationMap(
        assigned_serials=assigned_serials,
        stop_serial_before=stop_serial_before,
        stop_serial_after=stop_serial_after,
        rewritten_edges=tuple(rewritten_edges),
    )


def _infer_conditional_target(block: BlockSnapshot) -> int | None:
    if block.nsucc != 2 or not block.insn_snapshots:
        return None

    def _operand_block_ref(operand: object) -> int | None:
        for attr in ("block_num", "block_ref"):
            block_ref = getattr(operand, attr, None)
            if isinstance(block_ref, int):
                return block_ref
        return None

    tail = block.insn_snapshots[-1]
    for slot_name, operand in tail.operand_slots:
        if slot_name != "d":
            continue
        block_ref = _operand_block_ref(operand)
        if block_ref is not None:
            return block_ref

    if tail.d is not None:
        block_ref = _operand_block_ref(tail.d)
        if block_ref is not None:
            return block_ref

    for operand in tail.operands:
        block_ref = _operand_block_ref(operand)
        if block_ref is not None:
            return block_ref

    return None


def _infer_fallthrough_target(
    block: BlockSnapshot,
    *,
    conditional_target: int,
) -> int | None:
    if block.nsucc != 2:
        return None
    for succ in block.succs:
        if succ != conditional_target:
            return succ
    return None


def _classify_duplicate_pred_redirect(
    cfg: FlowGraph,
    *,
    pred_serial: int | None,
    source_serial: int,
) -> str:
    if pred_serial is None:
        return "missing"

    pred_block = cfg.get_block(pred_serial)
    if pred_block is None or source_serial not in pred_block.succs:
        return "missing"

    if pred_block.nsucc == 1:
        return "one_way"

    if pred_block.nsucc == 2:
        conditional_target = _infer_conditional_target(pred_block)
        if conditional_target is None:
            return "unknown"
        if conditional_target == source_serial:
            return "conditional"
        return "fallthrough"

    return "unsupported"


def _compile_clone_conditional_as_goto_step(
    modification: CloneConditionalAsGoto,
    cfg: FlowGraph,
    allocator: _VirtualIdAllocator,
) -> tuple[_PendingCloneConditionalAsGoto, PatchBlockSpec]:
    source_block = cfg.get_block(modification.source_block)
    pred_block = cfg.get_block(modification.pred_serial)
    target_block = cfg.get_block(modification.goto_target)
    if source_block is None:
        raise ValueError(
            f"CloneConditionalAsGoto source block {modification.source_block} not found"
        )
    if pred_block is None:
        raise ValueError(
            f"CloneConditionalAsGoto predecessor block {modification.pred_serial} not found"
        )
    if target_block is None:
        raise ValueError(
            f"CloneConditionalAsGoto goto target {modification.goto_target} not found"
        )
    if pred_block.nsucc != 1:
        raise ValueError(
            f"CloneConditionalAsGoto predecessor {modification.pred_serial} "
            f"has {pred_block.nsucc} successors; expected 1"
        )
    if pred_block.succs != (modification.source_block,):
        raise ValueError(
            f"CloneConditionalAsGoto predecessor {modification.pred_serial} "
            f"does not target source {modification.source_block}"
        )
    if source_block.nsucc != 2:
        raise ValueError(
            f"CloneConditionalAsGoto source {modification.source_block} "
            f"has {source_block.nsucc} successors; expected 2"
        )

    conditional_target = _infer_conditional_target(source_block)
    if conditional_target is None:
        raise ValueError(
            f"CloneConditionalAsGoto source {modification.source_block} "
            "has no explicit conditional target"
        )
    if conditional_target not in source_block.succs:
        raise ValueError(
            f"CloneConditionalAsGoto conditional target {conditional_target} "
            f"is not in source successors {source_block.succs}"
        )
    fallthrough_target = _infer_fallthrough_target(
        source_block,
        conditional_target=conditional_target,
    )
    if fallthrough_target is None:
        raise ValueError(
            f"CloneConditionalAsGoto source {modification.source_block} "
            f"has ambiguous fallthrough successors {source_block.succs}"
        )
    if modification.goto_target == modification.source_block:
        raise ValueError("CloneConditionalAsGoto target would self-loop to source")
    if modification.goto_target not in {conditional_target, fallthrough_target}:
        raise ValueError(
            f"CloneConditionalAsGoto target {modification.goto_target} is not "
            f"one of conditional arms {conditional_target}, {fallthrough_target}"
        )

    block_id = allocator.alloc("clone_conditional_as_goto")
    spec = PatchBlockSpec(
        block_id=block_id,
        kind="clone_conditional_as_goto",
        template_block=modification.source_block,
        incoming_edge=PatchEdgeRef(
            source=modification.pred_serial,
            target=modification.source_block,
        ),
        outgoing_edges=(
            PatchEdgeRef(source=block_id, target=modification.goto_target),
        ),
    )
    return (
        _PendingCloneConditionalAsGoto(
            modification=modification,
            block_id=block_id,
            source_successors=(
                int(source_block.succs[0]),
                int(source_block.succs[1]),
            ),
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
        ),
        spec,
    )


def _compile_clone_conditional_as_goto_from_branch_arm_step(
    modification: CloneConditionalAsGotoFromBranchArm,
    cfg: FlowGraph,
    allocator: _VirtualIdAllocator,
) -> tuple[_PendingCloneConditionalAsGotoFromBranchArm, PatchBlockSpec]:
    """Compile the 2-way-pred branch-arm clone-as-goto shape into PatchPlan IR.

    Mirrors :func:`_compile_clone_conditional_as_goto_step` but validates a
    2-way predecessor and threads ``pred_arm`` + pred-side arm targets so the
    backend translator can pick the explicit-branch or fallthrough-arm mutation
    path instead of ``change_1way_block_successor``.
    """
    source_block = cfg.get_block(modification.source_block)
    pred_block = cfg.get_block(modification.pred_serial)
    target_block = cfg.get_block(modification.goto_target)
    if source_block is None:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm source block {modification.source_block} not found"
        )
    if pred_block is None:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm predecessor block {modification.pred_serial} not found"
        )
    if target_block is None:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm goto target {modification.goto_target} not found"
        )
    if pred_block.nsucc != 2:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm predecessor {modification.pred_serial} "
            f"has {pred_block.nsucc} successors; expected 2"
        )
    if modification.source_block not in pred_block.succs:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm predecessor {modification.pred_serial} "
            f"successors {pred_block.succs} do not include source {modification.source_block}"
        )
    if modification.pred_arm not in (0, 1):
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm pred_arm must be 0 or 1, "
            f"got {modification.pred_arm}"
        )
    pred_branch_target = _infer_conditional_target(pred_block)
    if pred_branch_target is None:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm predecessor {modification.pred_serial} "
            "has no explicit branch arm"
        )
    pred_fallthrough_target = _infer_fallthrough_target(
        pred_block, conditional_target=pred_branch_target
    )
    if pred_fallthrough_target is None:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm predecessor {modification.pred_serial} "
            "arms collapse to a single target"
        )
    if modification.pred_arm == 1 and modification.source_block != pred_branch_target:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm pred_arm=1 but pred branch target is "
            f"{pred_branch_target}, not source {modification.source_block}"
        )
    if modification.pred_arm == 0 and modification.source_block != pred_fallthrough_target:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm pred_arm=0 but pred fallthrough is "
            f"{pred_fallthrough_target}, not source {modification.source_block}"
        )

    if source_block.nsucc != 2:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm source {modification.source_block} "
            f"has {source_block.nsucc} successors; expected 2"
        )
    conditional_target = _infer_conditional_target(source_block)
    if conditional_target is None:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm source {modification.source_block} "
            "has no explicit conditional target"
        )
    if conditional_target not in source_block.succs:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm conditional target {conditional_target} "
            f"is not in source successors {source_block.succs}"
        )
    fallthrough_target = _infer_fallthrough_target(
        source_block,
        conditional_target=conditional_target,
    )
    if fallthrough_target is None:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm source {modification.source_block} "
            f"has ambiguous fallthrough successors {source_block.succs}"
        )
    if modification.goto_target == modification.source_block:
        raise ValueError(
            "CloneConditionalAsGotoFromBranchArm target would self-loop to source"
        )
    if modification.goto_target not in {conditional_target, fallthrough_target}:
        raise ValueError(
            f"CloneConditionalAsGotoFromBranchArm target {modification.goto_target} is not "
            f"one of conditional arms {conditional_target}, {fallthrough_target}"
        )

    block_id = allocator.alloc("clone_conditional_as_goto_from_branch_arm")
    spec = PatchBlockSpec(
        block_id=block_id,
        kind="clone_conditional_as_goto_from_branch_arm",
        template_block=modification.source_block,
        incoming_edge=PatchEdgeRef(
            source=modification.pred_serial,
            target=modification.source_block,
        ),
        outgoing_edges=(
            PatchEdgeRef(source=block_id, target=modification.goto_target),
        ),
    )
    return (
        _PendingCloneConditionalAsGotoFromBranchArm(
            modification=modification,
            block_id=block_id,
            source_successors=(
                int(source_block.succs[0]),
                int(source_block.succs[1]),
            ),
            pred_successors=(
                int(pred_block.succs[0]),
                int(pred_block.succs[1]),
            ),
            pred_branch_target_serial=int(pred_branch_target),
            pred_fallthrough_target_serial=int(pred_fallthrough_target),
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
        ),
        spec,
    )


def _compile_legacy_block_step(
    modification: BlockCreatingGraphModification,
    allocator: _VirtualIdAllocator,
) -> tuple[LegacyBlockOperation, PatchBlockSpec]:
    match modification:
        case DuplicateBlock(source_block=src, target_block=target, pred_serial=pred):
            block_id = allocator.alloc("duplicate_block")
            outgoing_edges: tuple[PatchEdgeRef, ...] = ()
            if target is not None:
                outgoing_edges = (PatchEdgeRef(source=block_id, target=target),)
            incoming_edge = None
            if pred is not None:
                incoming_edge = PatchEdgeRef(source=pred, target=src)
            spec = PatchBlockSpec(
                block_id=block_id,
                kind="duplicate_block",
                template_block=src,
                incoming_edge=incoming_edge,
                outgoing_edges=outgoing_edges,
            )
            return LegacyBlockOperation(modification=modification, block_id=block_id), spec

        case InsertBlock(
            pred_serial=pred,
            succ_serial=succ,
            instructions=insns,
            old_target_serial=old_target,
            captured_body=captured_body,
        ):
            effective_old_target = succ if old_target is None else old_target
            block_id = allocator.alloc("insert_block")
            spec = PatchBlockSpec(
                block_id=block_id,
                kind="insert_block",
                incoming_edge=PatchEdgeRef(source=pred, target=effective_old_target),
                outgoing_edges=(PatchEdgeRef(source=block_id, target=succ),),
                instructions=insns,
                captured_body=captured_body,
            )
            return LegacyBlockOperation(modification=modification, block_id=block_id), spec

        case _:
            raise TypeError(f"Unsupported block-creating modification: {type(modification).__name__}")


def _compile_duplicate_block_step(
    modification: DuplicateBlock,
    cfg: FlowGraph,
    allocator: _VirtualIdAllocator,
) -> tuple[_PendingDuplicateBlock, tuple[PatchBlockSpec, ...]] | None:
    source_block = cfg.get_block(modification.source_block)
    if source_block is None:
        return None

    pred_redirect_kind = _classify_duplicate_pred_redirect(
        cfg,
        pred_serial=modification.pred_serial,
        source_serial=modification.source_block,
    )
    if pred_redirect_kind not in {"one_way", "conditional"}:
        return None

    if source_block.nsucc > 2:
        return None
    if source_block.nsucc == 2 and modification.target_block is not None:
        return None
    if source_block.nsucc != 2 and (
        modification.conditional_target is not None
        or modification.fallthrough_target is not None
    ):
        return None

    block_id = allocator.alloc("duplicate_block")
    incoming_edge = PatchEdgeRef(
        source=modification.pred_serial,
        target=modification.source_block,
    )
    clone_outgoing_edges: list[PatchEdgeRef] = []
    specs: list[PatchBlockSpec] = []
    conditional_target: int | None = None
    fallthrough_target: int | None = None
    fallthrough_block_id: VirtualBlockId | None = None

    if source_block.nsucc == 0:
        if modification.target_block is not None:
            clone_outgoing_edges.append(
                PatchEdgeRef(source=block_id, target=modification.target_block)
            )

    elif source_block.nsucc == 1:
        clone_target = (
            modification.target_block
            if modification.target_block is not None
            else source_block.succs[0]
        )
        clone_outgoing_edges.append(PatchEdgeRef(source=block_id, target=clone_target))

    elif source_block.nsucc == 2:
        source_conditional_target = _infer_conditional_target(source_block)
        if source_conditional_target is None:
            return None
        conditional_target = (
            modification.conditional_target
            if modification.conditional_target is not None
            else source_conditional_target
        )
        fallthrough_target = (
            modification.fallthrough_target
            if modification.fallthrough_target is not None
            else _infer_fallthrough_target(
                source_block,
                conditional_target=source_conditional_target,
            )
        )
        if fallthrough_target is None:
            return None
        if conditional_target == fallthrough_target:
            return None

        fallthrough_block_id = allocator.alloc("duplicate_block_fallthrough")
        clone_outgoing_edges.extend(
            (
                PatchEdgeRef(source=block_id, target=conditional_target),
                PatchEdgeRef(source=block_id, target=fallthrough_block_id),
            )
        )
        specs.append(
            PatchBlockSpec(
                block_id=fallthrough_block_id,
                kind="duplicate_block_fallthrough",
                template_block=modification.source_block,
                incoming_edge=PatchEdgeRef(source=block_id, target=fallthrough_block_id),
                outgoing_edges=(
                    PatchEdgeRef(source=fallthrough_block_id, target=fallthrough_target),
                ),
            )
        )

    specs.insert(
        0,
        PatchBlockSpec(
            block_id=block_id,
            kind="duplicate_block_clone",
            template_block=modification.source_block,
            incoming_edge=incoming_edge,
            outgoing_edges=tuple(clone_outgoing_edges),
        ),
    )
    return (
        _PendingDuplicateBlock(
            modification=modification,
            block_id=block_id,
            pred_redirect_kind=pred_redirect_kind,
            source_successors=source_block.succs,
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
            fallthrough_block_id=fallthrough_block_id,
        ),
        tuple(specs),
    )


def _compile_edge_split_corridor_step(
    modification: EdgeRedirectViaPredSplit,
    cfg: FlowGraph,
    allocator: _VirtualIdAllocator,
) -> tuple[_PendingEdgeSplitCorridor, tuple[PatchBlockSpec, ...]]:
    if modification.clone_until is None:
        raise ValueError("EdgeRedirectViaPredSplit corridor requires clone_until")

    pred_block = cfg.get_block(modification.via_pred)
    source_block = cfg.get_block(modification.src_block)
    if pred_block is None:
        raise ValueError(
            f"EdgeRedirectViaPredSplit via_pred {modification.via_pred} not found"
        )
    if source_block is None:
        raise ValueError(
            f"EdgeRedirectViaPredSplit source {modification.src_block} not found"
        )
    if pred_block.succs != (modification.src_block,):
        raise ValueError(
            f"EdgeRedirectViaPredSplit via_pred {modification.via_pred} "
            f"does not target source {modification.src_block}"
        )
    if source_block.succs != (modification.old_target,):
        raise ValueError(
            f"EdgeRedirectViaPredSplit source {modification.src_block} "
            f"does not start old_target {modification.old_target}"
        )

    corridor_serials: list[int] = [modification.src_block]
    seen = {modification.src_block}
    cursor = source_block
    while cursor.serial != modification.clone_until:
        if cursor.nsucc != 1:
            raise ValueError(
                f"EdgeRedirectViaPredSplit corridor block {cursor.serial} "
                f"has {cursor.nsucc} successors; expected 1"
            )
        next_serial = cursor.succs[0]
        if next_serial in seen:
            raise ValueError(
                f"EdgeRedirectViaPredSplit corridor cycle at {cursor.serial}->{next_serial}"
            )
        next_block = cfg.get_block(next_serial)
        if next_block is None:
            raise ValueError(
                f"EdgeRedirectViaPredSplit corridor missing block {next_serial}"
            )
        corridor_serials.append(next_serial)
        seen.add(next_serial)
        cursor = next_block

    if cursor.nsucc != 1:
        raise ValueError(
            f"EdgeRedirectViaPredSplit clone_until {cursor.serial} "
            f"has {cursor.nsucc} successors; expected 1"
        )
    if modification.new_target == cursor.serial:
        raise ValueError(
            "EdgeRedirectViaPredSplit corridor final target would self-loop"
        )
    if modification.source_new_target is not None:
        if modification.source_new_target == modification.src_block:
            raise ValueError(
                "EdgeRedirectViaPredSplit source target would self-loop"
            )
        if cfg.get_block(modification.source_new_target) is None:
            raise ValueError(
                f"EdgeRedirectViaPredSplit source target {modification.source_new_target} not found"
            )

    clone_ids = tuple(allocator.alloc("edge_split_corridor") for _ in corridor_serials)
    specs: list[PatchBlockSpec] = []
    for index, (source_serial, clone_id) in enumerate(zip(corridor_serials, clone_ids)):
        incoming_source: PatchBlockRef = (
            modification.via_pred if index == 0 else clone_ids[index - 1]
        )
        incoming_target = modification.src_block if index == 0 else source_serial
        outgoing_target: PatchBlockRef = (
            modification.new_target
            if index == len(clone_ids) - 1
            else clone_ids[index + 1]
        )
        specs.append(
            PatchBlockSpec(
                block_id=clone_id,
                kind="edge_split_corridor_clone",
                template_block=source_serial,
                incoming_edge=PatchEdgeRef(
                    source=incoming_source,
                    target=incoming_target,
                ),
                outgoing_edges=(PatchEdgeRef(source=clone_id, target=outgoing_target),),
            )
        )

    return (
        _PendingEdgeSplitCorridor(
            modification=modification,
            corridor_serials=tuple(corridor_serials),
            clone_block_ids=clone_ids,
        ),
        tuple(specs),
    )


def _compile_duplicate_replay_and_redirect_step(
    modification: DuplicateReplayAndRedirect,
    cfg: FlowGraph,
    allocator: _VirtualIdAllocator,
) -> tuple[_PendingDuplicateReplayAndRedirect, tuple[PatchBlockSpec, ...]]:
    source_block = cfg.get_block(modification.source_serial)
    dispatcher_block = cfg.get_block(modification.dispatcher_entry)
    if source_block is None:
        raise ValueError(
            f"DuplicateReplayAndRedirect source {modification.source_serial} not found"
        )
    if dispatcher_block is None:
        raise ValueError(
            f"DuplicateReplayAndRedirect dispatcher {modification.dispatcher_entry} not found"
        )
    if source_block.nsucc != 1 or source_block.succs[0] != modification.dispatcher_entry:
        raise ValueError(
            "DuplicateReplayAndRedirect requires source to be one-way to dispatcher"
        )
    if len(modification.per_pred_replays) < 2:
        raise ValueError("DuplicateReplayAndRedirect requires at least two predecessors")

    source_preds = set(source_block.preds)
    seen_preds: set[int] = set()
    replay_ids: list[VirtualBlockId] = []
    clone_ids: list[VirtualBlockId | None] = []
    for index, entry in enumerate(modification.per_pred_replays):
        if entry.pred_serial in seen_preds:
            raise ValueError(
                f"DuplicateReplayAndRedirect duplicate predecessor {entry.pred_serial}"
            )
        seen_preds.add(entry.pred_serial)

        pred_block = cfg.get_block(entry.pred_serial)
        target_block = cfg.get_block(entry.target_serial)
        if pred_block is None:
            raise ValueError(
                f"DuplicateReplayAndRedirect predecessor {entry.pred_serial} not found"
            )
        if target_block is None:
            raise ValueError(
                f"DuplicateReplayAndRedirect target {entry.target_serial} not found"
            )
        if pred_block.nsucc != 1 or pred_block.succs[0] != modification.source_serial:
            raise ValueError(
                "DuplicateReplayAndRedirect requires every predecessor to be one-way to source"
            )
        if entry.target_serial in {
            modification.source_serial,
            modification.dispatcher_entry,
        }:
            raise ValueError("DuplicateReplayAndRedirect target loops through cleanup source")
        if target_block.nsucc > 1:
            raise ValueError("DuplicateReplayAndRedirect target requires trampoline")
        if (
            entry.captured_body.instruction_count <= 0
            or entry.captured_body.summary.contains_call
        ):
            raise ValueError(
                "DuplicateReplayAndRedirect requires nonempty no-call replay bodies"
            )

        replay_ids.append(allocator.alloc("duplicate_replay_insert"))
        clone_ids.append(None if index == 0 else allocator.alloc("duplicate_replay_clone"))

    if seen_preds != source_preds:
        raise ValueError("DuplicateReplayAndRedirect must cover every source predecessor")

    specs: list[PatchBlockSpec] = []
    for entry, replay_id, clone_id in zip(
        modification.per_pred_replays,
        replay_ids,
        clone_ids,
    ):
        replay_source: PatchBlockRef = (
            modification.source_serial if clone_id is None else clone_id
        )
        specs.append(
            PatchBlockSpec(
                block_id=replay_id,
                kind="duplicate_replay_insert",
                incoming_edge=PatchEdgeRef(
                    source=replay_source,
                    target=modification.dispatcher_entry,
                ),
                outgoing_edges=(PatchEdgeRef(source=replay_id, target=entry.target_serial),),
                captured_body=entry.captured_body,
            )
        )

    for entry, replay_id, clone_id in zip(
        modification.per_pred_replays,
        replay_ids,
        clone_ids,
    ):
        if clone_id is None:
            continue
        specs.append(
            PatchBlockSpec(
                block_id=clone_id,
                kind="duplicate_replay_clone",
                template_block=modification.source_serial,
                incoming_edge=PatchEdgeRef(
                    source=entry.pred_serial,
                    target=modification.source_serial,
                ),
                outgoing_edges=(PatchEdgeRef(source=clone_id, target=replay_id),),
            )
        )

    return (
        _PendingDuplicateReplayAndRedirect(
            modification=modification,
            replay_block_ids=tuple(replay_ids),
            clone_block_ids=tuple(clone_ids),
        ),
        tuple(specs),
    )


def _finalize_step(
    step: PatchStep | _PendingEdgeSplitTrampoline | _PendingEdgeSplitCorridor | _PendingConditionalRedirect | _PendingInsertBlock | _PendingDuplicateBlock | _PendingDuplicateReplayAndRedirect | _PendingCloneConditionalAsGoto | _PendingCloneConditionalAsGotoFromBranchArm | _PendingPrivateTerminalSuffix | _PendingPrivateTerminalSuffixGroup | _PendingDirectTerminalLoweringGroup | _PendingReorderBlocks,
    relocation_map: PatchRelocationMap,
) -> PatchStep:
    match step:
        case PatchRedirectGoto(from_serial=src, old_target=old, new_target=new):
            return PatchRedirectGoto(
                from_serial=src,
                old_target=relocation_map.rewrite_serial(old),
                new_target=relocation_map.rewrite_serial(new),
            )

        case PatchRedirectBranch(from_serial=src, old_target=old, new_target=new):
            return PatchRedirectBranch(
                from_serial=src,
                old_target=relocation_map.rewrite_serial(old),
                new_target=relocation_map.rewrite_serial(new),
            )

        case PatchConvertToGoto(block_serial=serial, goto_target=target):
            return PatchConvertToGoto(
                block_serial=serial,
                goto_target=relocation_map.rewrite_serial(target),
            )

        case PatchRemoveEdge(from_serial=src, to_serial=dst):
            return PatchRemoveEdge(
                from_serial=src,
                to_serial=relocation_map.rewrite_serial(dst),
            )

        case PatchNopInstructions():
            return step

        case PatchZeroStateWrite():
            return step

        case PatchPromoteOperandToScalar():
            return step

        case (
            PatchLowerConditionalStateTransition()
            | PatchNormalizeNWayDispatcherExit()
            | PatchBypassDispatcherTrampoline()
            | PatchCanonicalizeJumpTableCaseOverlap()
            | PatchScalarizeLocalAliasAccess()
            | PatchRetargetOutputStore()
            | PatchPhaseCycleLowering()
        ):
            return step

        case _PendingEdgeSplitTrampoline(
            modification=EdgeRedirectViaPredSplit(
                src_block=src,
                old_target=old,
                new_target=new,
                via_pred=pred,
            ),
            block_id=block_id,
        ):
            assigned_serial = relocation_map.assigned_serial_for(block_id)
            if assigned_serial is None:
                raise ValueError(f"Missing assigned serial for {block_id}")
            return PatchEdgeSplitTrampoline(
                block_id=block_id,
                assigned_serial=assigned_serial,
                source_serial=src,
                via_pred=pred,
                old_target=old,
                apply_old_target=relocation_map.rewrite_serial(old),
                new_target=relocation_map.rewrite_serial(new),
                template_block=src,
            )

        case _PendingEdgeSplitCorridor(
            modification=EdgeRedirectViaPredSplit(
                src_block=src,
                old_target=old,
                new_target=new,
                via_pred=pred,
                clone_until=clone_until,
                rule_priority=rule_priority,
                source_new_target=source_new_target,
            ),
            corridor_serials=corridor_serials,
            clone_block_ids=clone_ids,
        ):
            if clone_until is None:
                raise ValueError("Missing clone_until for edge-split corridor")
            assigned: list[int] = []
            for clone_id in clone_ids:
                serial = relocation_map.assigned_serial_for(clone_id)
                if serial is None:
                    raise ValueError(f"Missing assigned serial for {clone_id}")
                assigned.append(serial)
            return PatchEdgeSplitCorridor(
                clone_block_ids=clone_ids,
                clone_assigned_serials=tuple(assigned),
                source_serial=src,
                via_pred=pred,
                old_target=old,
                new_target=new,
                clone_until=clone_until,
                corridor_serials=tuple(corridor_serials),
                source_new_target=source_new_target,
                rule_priority=rule_priority,
            )

        case _PendingConditionalRedirect(
            modification=CreateConditionalRedirect(
                source_block=src,
                ref_block=ref,
                conditional_target=conditional,
                fallthrough_target=fallthrough,
                old_target_serial=old_target,
                instructions=instructions,
            ),
            block_id=block_id,
            fallthrough_block_id=fallthrough_block_id,
        ):
            assigned_serial = relocation_map.assigned_serial_for(block_id)
            fallthrough_serial = relocation_map.assigned_serial_for(fallthrough_block_id)
            if assigned_serial is None:
                raise ValueError(f"Missing assigned serial for {block_id}")
            if fallthrough_serial is None:
                raise ValueError(f"Missing assigned serial for {fallthrough_block_id}")
            return PatchConditionalRedirect(
                block_id=block_id,
                assigned_serial=assigned_serial,
                fallthrough_block_id=fallthrough_block_id,
                fallthrough_serial=fallthrough_serial,
                source_serial=src,
                ref_block=relocation_map.rewrite_serial(ref),
                conditional_target=relocation_map.rewrite_serial(conditional),
                fallthrough_target=relocation_map.rewrite_serial(fallthrough),
                old_target_serial=(
                    None
                    if old_target is None
                    else relocation_map.rewrite_serial(old_target)
                ),
                instructions=_rewrite_instruction_snapshots(instructions, relocation_map),
            )

        case _PendingInsertBlock(
            modification=InsertBlock(
                pred_serial=pred,
                succ_serial=succ,
                instructions=insns,
                old_target_serial=old_target,
                captured_body=captured_body,
            ),
            block_id=block_id,
        ):
            assigned_serial = relocation_map.assigned_serial_for(block_id)
            if assigned_serial is None:
                raise ValueError(f"Missing assigned serial for {block_id}")
            return PatchInsertBlock(
                block_id=block_id,
                assigned_serial=assigned_serial,
                pred_serial=pred,
                succ_serial=relocation_map.rewrite_serial(succ),
                instructions=_rewrite_instruction_snapshots(insns, relocation_map),
                old_target_serial=(
                    None
                    if old_target is None
                    else relocation_map.rewrite_serial(old_target)
                ),
                captured_body=captured_body,
            )

        case _PendingDuplicateBlock(
            modification=DuplicateBlock(
                source_block=src,
                target_block=target,
                pred_serial=pred,
            ),
            block_id=block_id,
            pred_redirect_kind=pred_redirect_kind,
            source_successors=source_successors,
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
            fallthrough_block_id=fallthrough_block_id,
        ):
            assigned_serial = relocation_map.assigned_serial_for(block_id)
            if assigned_serial is None:
                raise ValueError(f"Missing assigned serial for {block_id}")
            fallthrough_serial = None
            if fallthrough_block_id is not None:
                fallthrough_serial = relocation_map.assigned_serial_for(fallthrough_block_id)
                if fallthrough_serial is None:
                    raise ValueError(f"Missing assigned serial for {fallthrough_block_id}")
            return PatchDuplicateBlock(
                block_id=block_id,
                assigned_serial=assigned_serial,
                source_serial=src,
                pred_serial=pred,
                pred_redirect_kind=pred_redirect_kind,
                source_successors=tuple(
                    relocation_map.rewrite_serial(serial) for serial in source_successors
                ),
                target_serial=(
                    relocation_map.rewrite_serial(target)
                    if target is not None
                    else None
                ),
                conditional_target=(
                    relocation_map.rewrite_serial(conditional_target)
                    if conditional_target is not None
                    else None
                ),
                fallthrough_target=(
                    relocation_map.rewrite_serial(fallthrough_target)
                    if fallthrough_target is not None
                    else None
                ),
                fallthrough_block_id=fallthrough_block_id,
                fallthrough_serial=fallthrough_serial,
            )

        case _PendingDuplicateReplayAndRedirect(
            modification=DuplicateReplayAndRedirect(
                source_serial=source,
                dispatcher_entry=dispatcher,
                per_pred_replays=per_pred_replays,
            ),
            replay_block_ids=replay_ids,
            clone_block_ids=clone_ids,
        ):
            finalized_replays: list[PatchDuplicateReplayEntry] = []
            for entry, replay_id, clone_id in zip(
                per_pred_replays,
                replay_ids,
                clone_ids,
            ):
                replay_serial = relocation_map.assigned_serial_for(replay_id)
                if replay_serial is None:
                    raise ValueError(f"Missing assigned serial for {replay_id}")
                clone_serial = None
                if clone_id is not None:
                    clone_serial = relocation_map.assigned_serial_for(clone_id)
                    if clone_serial is None:
                        raise ValueError(f"Missing assigned serial for {clone_id}")
                finalized_replays.append(
                    PatchDuplicateReplayEntry(
                        pred_serial=entry.pred_serial,
                        target_serial=relocation_map.rewrite_serial(entry.target_serial),
                        replay_block_id=replay_id,
                        replay_serial=replay_serial,
                        captured_body=entry.captured_body,
                        clone_block_id=clone_id,
                        clone_serial=clone_serial,
                    )
                )
            return PatchDuplicateReplayAndRedirect(
                source_serial=source,
                dispatcher_entry=dispatcher,
                per_pred_replays=tuple(finalized_replays),
            )

        case _PendingCloneConditionalAsGoto(
            modification=CloneConditionalAsGoto(
                source_block=src,
                pred_serial=pred,
                goto_target=target,
                reason=reason,
            ),
            block_id=block_id,
            source_successors=source_successors,
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
        ):
            assigned_serial = relocation_map.assigned_serial_for(block_id)
            if assigned_serial is None:
                raise ValueError(f"Missing assigned serial for {block_id}")
            return PatchCloneConditionalAsGoto(
                block_id=block_id,
                assigned_serial=assigned_serial,
                source_serial=src,
                pred_serial=pred,
                goto_target=relocation_map.rewrite_serial(target),
                source_successors=tuple(
                    relocation_map.rewrite_serial(serial)
                    for serial in source_successors
                ),
                conditional_target=relocation_map.rewrite_serial(conditional_target),
                fallthrough_target=relocation_map.rewrite_serial(fallthrough_target),
                reason=reason,
            )

        case _PendingCloneConditionalAsGotoFromBranchArm(
            modification=CloneConditionalAsGotoFromBranchArm(
                source_block=src,
                pred_serial=pred,
                pred_arm=pred_arm,
                goto_target=target,
                reason=reason,
            ),
            block_id=block_id,
            source_successors=source_successors,
            pred_successors=pred_successors,
            pred_branch_target_serial=pred_branch_target,
            pred_fallthrough_target_serial=pred_fallthrough_target,
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
        ):
            assigned_serial = relocation_map.assigned_serial_for(block_id)
            if assigned_serial is None:
                raise ValueError(f"Missing assigned serial for {block_id}")
            return PatchCloneConditionalAsGotoFromBranchArm(
                block_id=block_id,
                assigned_serial=assigned_serial,
                source_serial=src,
                pred_serial=pred,
                pred_arm=pred_arm,
                goto_target=relocation_map.rewrite_serial(target),
                source_successors=tuple(
                    relocation_map.rewrite_serial(serial)
                    for serial in source_successors
                ),
                pred_successors=tuple(
                    relocation_map.rewrite_serial(serial)
                    for serial in pred_successors
                ),
                pred_branch_target_serial=relocation_map.rewrite_serial(
                    pred_branch_target
                ),
                pred_fallthrough_target_serial=relocation_map.rewrite_serial(
                    pred_fallthrough_target
                ),
                conditional_target=relocation_map.rewrite_serial(conditional_target),
                fallthrough_target=relocation_map.rewrite_serial(fallthrough_target),
                reason=reason,
            )

        case _PendingPrivateTerminalSuffix(
            modification=PrivateTerminalSuffix(
                anchor_serial=anchor,
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
            ),
            clone_block_ids=clone_ids,
        ):
            assigned: list[int] = []
            for clone_id in clone_ids:
                serial = relocation_map.assigned_serial_for(clone_id)
                if serial is None:
                    raise ValueError(f"Missing assigned serial for {clone_id}")
                assigned.append(serial)
            return PatchPrivateTerminalSuffix(
                anchor_serial=anchor,
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                clone_block_ids=clone_ids,
                clone_assigned_serials=tuple(assigned),
            )

        case _PendingPrivateTerminalSuffixGroup(
            modification=PrivateTerminalSuffixGroup(
                anchors=anchors,
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
            ),
            per_anchor_clone_block_ids=per_anchor_ids,
        ):
            per_anchor_assigned: list[tuple[int, ...]] = []
            for anchor_clone_ids in per_anchor_ids:
                anchor_assigned: list[int] = []
                for clone_id in anchor_clone_ids:
                    serial = relocation_map.assigned_serial_for(clone_id)
                    if serial is None:
                        raise ValueError(f"Missing assigned serial for {clone_id}")
                    anchor_assigned.append(serial)
                per_anchor_assigned.append(tuple(anchor_assigned))
            return PatchPrivateTerminalSuffixGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                anchors=anchors,
                per_anchor_clone_block_ids=per_anchor_ids,
                per_anchor_clone_assigned_serials=tuple(per_anchor_assigned),
            )

        case _PendingDirectTerminalLoweringGroup(
            modification=DirectTerminalLoweringGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                sites=sites,
            ),
            per_site_clone_block_ids=per_site_ids,
        ):
            per_site_assigned: dict[int, tuple[int, ...]] = {}
            for anchor, clone_ids in per_site_ids.items():
                assigned: list[int] = []
                for clone_id in clone_ids:
                    serial = relocation_map.assigned_serial_for(clone_id)
                    if serial is None:
                        raise ValueError(f"Missing assigned serial for {clone_id}")
                    assigned.append(serial)
                per_site_assigned[int(anchor)] = tuple(assigned)
            return PatchDirectTerminalLoweringGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                sites=sites,
                per_site_clone_assigned_serials=per_site_assigned,
            )

        case _PendingReorderBlocks(
            dfs_block_order=order,
            non_2way_serials=non_2way,
            virtual_ids=vids,
            two_way_serials=two_way,
            two_way_virtual_id_pairs=two_way_pairs,
        ):
            old_to_new_pairs: list[tuple[int, int]] = []
            for old_serial, vid in zip(non_2way, vids):
                serial = relocation_map.assigned_serial_for(vid)
                if serial is None:
                    raise ValueError(f"Missing assigned serial for {vid}")
                old_to_new_pairs.append((old_serial, serial))

            two_way_old_to_trampoline: list[tuple[int, int]] = []
            for old_serial, (copy_vid, tramp_vid) in zip(two_way, two_way_pairs):
                copy_serial = relocation_map.assigned_serial_for(copy_vid)
                tramp_serial = relocation_map.assigned_serial_for(tramp_vid)
                if copy_serial is None:
                    raise ValueError(f"Missing copy serial for 2WAY {copy_vid}")
                if tramp_serial is None:
                    raise ValueError(f"Missing trampoline serial for 2WAY {tramp_vid}")
                old_to_new_pairs.append((old_serial, copy_serial))
                two_way_old_to_trampoline.append((old_serial, tramp_serial))

            _result = PatchReorderBlocks(
                dfs_block_order=order,
                non_2way_serials=non_2way,
                two_way_serials=two_way,
                old_to_new=tuple(old_to_new_pairs),
                two_way_old_to_trampoline=tuple(two_way_old_to_trampoline),
            )
            # DIAG: verify 2WAY serials match relocation map
            import logging as _diag_logging
            _diag_lg = _diag_logging.getLogger("D810.diag.plan")
            for _old, _new in old_to_new_pairs:
                if _old in set(two_way):
                    _diag_lg.warning(
                        "DIAG _finalize 2WAY old=%d copy_serial=%d stop_before=%s",
                        _old, _new, relocation_map.stop_serial_before,
                    )
            return _result

        case PatchReorderBlocks():
            return step

        case LegacyBlockOperation():
            return step

        case _:
            raise TypeError(f"Unsupported PatchPlan step: {type(step).__name__}")


@algorithm_metadata(
    algorithm_id="cfg.compile_patch_plan",
    family="tail_block_duplication_and_redirect",
    summary="Compiles abstract GraphModification intents into ordered PatchPlan steps.",
    use_cases=(
        "Materialize redirect, duplication, pred-split, and private-suffix edits into an execution-safe patch order.",
        "Simulate or validate CFG mutations before they hit the live MBA.",
    ),
    examples=(
        "Compile RedirectGoto/RedirectBranch edits into a patch plan preview inside the executor.",
        "Lower EdgeRedirectViaPredSplit into symbolic trampoline blocks when a shared suffix must split by predecessor.",
    ),
    tags=("cfg", "patch-plan", "redirect", "duplication", "simulation"),
    related_paths=(
        "src/d810/cfg/plan.py",
        "src/d810/cfg/modification_builder.py",
    ),
)
def compile_patch_plan(
    modifications: list[GraphModification],
    cfg: FlowGraph | None = None,
    execution_policy: ExecutionPolicy = ExecutionPolicy.STRICT,
) -> PatchPlan:
    """Compile planner modifications into ordered PatchPlan steps."""
    allocator = _VirtualIdAllocator()
    raw_steps: list[
        PatchStep
        | _PendingEdgeSplitTrampoline
        | _PendingEdgeSplitCorridor
        | _PendingConditionalRedirect
        | _PendingInsertBlock
        | _PendingDuplicateBlock
        | _PendingDuplicateReplayAndRedirect
        | _PendingCloneConditionalAsGoto
        | _PendingCloneConditionalAsGotoFromBranchArm
        | _PendingPrivateTerminalSuffix
        | _PendingPrivateTerminalSuffixGroup
        | _PendingDirectTerminalLoweringGroup
        | _PendingReorderBlocks
    ] = []
    new_blocks: list[PatchBlockSpec] = []

    for modification in modifications:
        match modification:
            case RedirectGoto(from_serial=src, old_target=old, new_target=new):
                raw_steps.append(
                    PatchRedirectGoto(
                        from_serial=src,
                        old_target=old,
                        new_target=new,
                    )
                )

            case RedirectBranch(from_serial=src, old_target=old, new_target=new):
                raw_steps.append(
                    PatchRedirectBranch(
                        from_serial=src,
                        old_target=old,
                        new_target=new,
                    )
                )

            case ConvertToGoto(block_serial=serial, goto_target=target):
                raw_steps.append(PatchConvertToGoto(block_serial=serial, goto_target=target))

            case RemoveEdge(from_serial=src, to_serial=dst):
                raw_steps.append(PatchRemoveEdge(from_serial=src, to_serial=dst))

            case NopInstructions(block_serial=serial, insn_eas=eas):
                raw_steps.append(PatchNopInstructions(block_serial=serial, insn_eas=eas))

            case ZeroStateWrite(block_serial=serial, insn_ea=ea):
                raw_steps.append(PatchZeroStateWrite(block_serial=serial, insn_ea=ea))

            case PromoteOperandToScalar(
                block_serial=serial,
                host_ea=host_ea,
                host_opcode=opcode,
                operand_side=side,
            ):
                raw_steps.append(PatchPromoteOperandToScalar(
                    block_serial=serial,
                    host_ea=host_ea,
                    host_opcode=opcode,
                    operand_side=side,
                ))

            case LowerConditionalStateTransition(
                source_serial=src,
                old_dispatcher_serial=dispatcher,
                rewrite_from_ea=ea,
                condition_operand=condition,
                false_target_serial=false_target,
                true_target_serial=true_target,
                proof_id=proof_id,
            ):
                raw_steps.append(PatchLowerConditionalStateTransition(
                    source_serial=src,
                    old_dispatcher_serial=dispatcher,
                    rewrite_from_ea=ea,
                    condition_operand=condition,
                    false_target_serial=false_target,
                    true_target_serial=true_target,
                    proof_id=proof_id,
                ))

            case NormalizeNWayDispatcherExit(
                block_serial=serial,
                dispatcher_entry_serial=dispatcher,
                keep_target_serial=keep,
            ):
                raw_steps.append(PatchNormalizeNWayDispatcherExit(
                    block_serial=serial,
                    dispatcher_entry_serial=dispatcher,
                    keep_target_serial=keep,
                ))

            case BypassDispatcherTrampoline(
                source_serial=src,
                trampoline_serial=trampoline,
                target_serial=target,
            ):
                raw_steps.append(PatchBypassDispatcherTrampoline(
                    source_serial=src,
                    trampoline_serial=trampoline,
                    target_serial=target,
                ))

            case CanonicalizeJumpTableCaseOverlap(
                jtbl_serial=serial,
                retarget_map=retarget_map,
                deduplicate=deduplicate,
            ):
                raw_steps.append(PatchCanonicalizeJumpTableCaseOverlap(
                    jtbl_serial=serial,
                    retarget_map=retarget_map,
                    deduplicate=deduplicate,
                ))

            case ScalarizeLocalAliasAccess(
                block_serial=serial,
                host_ea=host_ea,
                host_opcode=opcode,
                alias_token=alias,
                base_token=base,
                host_text_sha1=host_text_sha1,
                value_size=value_size,
            ):
                raw_steps.append(PatchScalarizeLocalAliasAccess(
                    block_serial=serial,
                    host_ea=host_ea,
                    host_opcode=opcode,
                    alias_token=alias,
                    base_token=base,
                    host_text_sha1=host_text_sha1,
                    value_size=value_size,
                ))

            case RetargetOutputStore(
                block_serial=serial,
                host_ea=host_ea,
                host_opcode=opcode,
                alias_token=alias,
                output_token=output,
                host_text_sha1=host_text_sha1,
                value_size=value_size,
            ):
                raw_steps.append(PatchRetargetOutputStore(
                    block_serial=serial,
                    host_ea=host_ea,
                    host_opcode=opcode,
                    alias_token=alias,
                    output_token=output,
                    host_text_sha1=host_text_sha1,
                    value_size=value_size,
                ))

            case PhaseCycleLowering(
                header_entries=header_entries,
                header_target=header_target,
                body_entries=body_entries,
                body_target=body_target,
                next_phase_entries=next_phase_entries,
                next_phase_target=next_phase_target,
                terminal_entries=terminal_entries,
                terminal_target=terminal_target,
                state_roles=state_roles,
                reason=reason,
            ):
                raw_steps.append(PatchPhaseCycleLowering(
                    header_entries=header_entries,
                    header_target=header_target,
                    body_entries=body_entries,
                    body_target=body_target,
                    next_phase_entries=next_phase_entries,
                    next_phase_target=next_phase_target,
                    terminal_entries=terminal_entries,
                    terminal_target=terminal_target,
                    state_roles=state_roles,
                    reason=reason,
                ))

            case EdgeRedirectViaPredSplit(
                src_block=src,
                old_target=old,
                new_target=new,
                via_pred=pred,
                clone_until=clone_until,
            ):
                if cfg is None:
                    raise ValueError(
                        "compile_patch_plan requires FlowGraph context for EdgeRedirectViaPredSplit"
                    )
                if clone_until is not None:
                    pending, specs = _compile_edge_split_corridor_step(
                        modification,
                        cfg,
                        allocator,
                    )
                    raw_steps.append(pending)
                    new_blocks.extend(specs)
                    continue
                block_id = allocator.alloc("edge_split")
                new_blocks.append(
                    PatchBlockSpec(
                        block_id=block_id,
                        kind="edge_split_trampoline",
                        template_block=src,
                        incoming_edge=PatchEdgeRef(source=pred, target=src),
                        outgoing_edges=(PatchEdgeRef(source=block_id, target=new),),
                    )
                )
                raw_steps.append(
                    _PendingEdgeSplitTrampoline(modification=modification, block_id=block_id)
                )

            case CreateConditionalRedirect(
                source_block=src,
                ref_block=ref,
                conditional_target=conditional,
                fallthrough_target=fallthrough,
                old_target_serial=_old_target,
            ):
                if cfg is None:
                    block_id = allocator.alloc("conditional_redirect")
                    outgoing_edges = [PatchEdgeRef(source=block_id, target=conditional)]
                    if fallthrough != conditional:
                        outgoing_edges.append(PatchEdgeRef(source=block_id, target=fallthrough))
                    raw_steps.append(
                        LegacyBlockOperation(modification=modification, block_id=block_id)
                    )
                    new_blocks.append(
                        PatchBlockSpec(
                            block_id=block_id,
                            kind="conditional_redirect_clone",
                            template_block=ref,
                            incoming_edge=PatchEdgeRef(source=src, target=ref),
                            outgoing_edges=tuple(outgoing_edges),
                        )
                    )
                else:
                    block_id = allocator.alloc("conditional_redirect")
                    fallthrough_block_id = allocator.alloc("conditional_redirect_fallthrough")
                    new_blocks.append(
                        PatchBlockSpec(
                            block_id=block_id,
                            kind="conditional_redirect_clone",
                            template_block=ref,
                            incoming_edge=PatchEdgeRef(source=src, target=ref),
                            outgoing_edges=(
                                PatchEdgeRef(source=block_id, target=conditional),
                                PatchEdgeRef(
                                    source=block_id,
                                    target=fallthrough_block_id,
                                ),
                            ),
                        )
                    )
                    new_blocks.append(
                        PatchBlockSpec(
                            block_id=fallthrough_block_id,
                            kind="conditional_redirect_fallthrough",
                            template_block=ref,
                            incoming_edge=PatchEdgeRef(
                                source=block_id,
                                target=fallthrough_block_id,
                            ),
                            outgoing_edges=(
                                PatchEdgeRef(
                                    source=fallthrough_block_id,
                                    target=fallthrough,
                                ),
                            ),
                        )
                    )
                    raw_steps.append(
                        _PendingConditionalRedirect(
                            modification=modification,
                            block_id=block_id,
                            fallthrough_block_id=fallthrough_block_id,
                        )
                    )

            case InsertBlock(
                pred_serial=pred,
                succ_serial=succ,
                instructions=insns,
                old_target_serial=old_target,
                captured_body=captured_body,
            ):
                effective_old_target = succ if old_target is None else old_target
                if cfg is None:
                    legacy_step, spec = _compile_legacy_block_step(modification, allocator)
                    raw_steps.append(legacy_step)
                    new_blocks.append(spec)
                else:
                    block_id = allocator.alloc("insert_block")
                    new_blocks.append(
                        PatchBlockSpec(
                            block_id=block_id,
                            kind="insert_block",
                            incoming_edge=PatchEdgeRef(
                                source=pred,
                                target=effective_old_target,
                            ),
                            outgoing_edges=(PatchEdgeRef(source=block_id, target=succ),),
                            instructions=insns,
                            captured_body=captured_body,
                        )
                    )
                    raw_steps.append(
                        _PendingInsertBlock(modification=modification, block_id=block_id)
                    )

            case DuplicateBlock():
                if cfg is None:
                    legacy_step, spec = _compile_legacy_block_step(modification, allocator)
                    raw_steps.append(legacy_step)
                    new_blocks.append(spec)
                else:
                    compiled_duplicate = _compile_duplicate_block_step(
                        modification,
                        cfg,
                        allocator,
                    )
                    if compiled_duplicate is None:
                        legacy_step, spec = _compile_legacy_block_step(modification, allocator)
                        raw_steps.append(legacy_step)
                        new_blocks.append(spec)
                    else:
                        pending_step, duplicate_specs = compiled_duplicate
                        raw_steps.append(pending_step)
                        new_blocks.extend(duplicate_specs)

            case DuplicateReplayAndRedirect():
                if cfg is None:
                    raise ValueError(
                        "compile_patch_plan requires FlowGraph context for "
                        "DuplicateReplayAndRedirect"
                    )
                pending_step, replay_specs = _compile_duplicate_replay_and_redirect_step(
                    modification,
                    cfg,
                    allocator,
                )
                raw_steps.append(pending_step)
                new_blocks.extend(replay_specs)

            case CloneConditionalAsGoto():
                if cfg is None:
                    raise ValueError(
                        "compile_patch_plan requires FlowGraph context for "
                        "CloneConditionalAsGoto"
                    )
                pending_step, clone_spec = _compile_clone_conditional_as_goto_step(
                    modification,
                    cfg,
                    allocator,
                )
                raw_steps.append(pending_step)
                new_blocks.append(clone_spec)

            case CloneConditionalAsGotoFromBranchArm():
                if cfg is None:
                    raise ValueError(
                        "compile_patch_plan requires FlowGraph context for "
                        "CloneConditionalAsGotoFromBranchArm"
                    )
                pending_step, clone_spec = (
                    _compile_clone_conditional_as_goto_from_branch_arm_step(
                        modification,
                        cfg,
                        allocator,
                    )
                )
                raw_steps.append(pending_step)
                new_blocks.append(clone_spec)

            case PrivateTerminalSuffix(
                anchor_serial=anchor,
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
            ):
                if not suffix:
                    raise ValueError("PrivateTerminalSuffix requires non-empty suffix_serials")
                clone_ids: list[VirtualBlockId] = []
                for idx, suffix_serial in enumerate(suffix):
                    clone_id = allocator.alloc(f"private_suffix_a{anchor}")
                    clone_ids.append(clone_id)
                    # Build edges: last clone has no outgoing (0-way terminal);
                    # others chain to next clone.
                    if idx < len(suffix) - 1:
                        next_clone_id = VirtualBlockId(
                            namespace=f"private_suffix_a{anchor}",
                            ordinal=clone_id.ordinal + 1,
                        )
                        outgoing = (PatchEdgeRef(source=clone_id, target=next_clone_id),)
                    else:
                        outgoing = ()
                    # First clone gets incoming from anchor
                    incoming = None
                    if idx == 0:
                        incoming = PatchEdgeRef(source=anchor, target=shared_entry)
                    new_blocks.append(
                        PatchBlockSpec(
                            block_id=clone_id,
                            kind="private_terminal_suffix_clone",
                            template_block=suffix_serial,
                            incoming_edge=incoming,
                            outgoing_edges=outgoing,
                        )
                    )
                raw_steps.append(
                    _PendingPrivateTerminalSuffix(
                        modification=modification,
                        clone_block_ids=tuple(clone_ids),
                    )
                )

            case PrivateTerminalSuffixGroup(
                anchors=anchors,
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
            ):
                if not suffix:
                    raise ValueError("PrivateTerminalSuffixGroup requires non-empty suffix_serials")
                per_anchor_clone_ids: list[tuple[VirtualBlockId, ...]] = []
                for anchor in anchors:
                    anchor_clone_ids: list[VirtualBlockId] = []
                    for idx, suffix_serial in enumerate(suffix):
                        clone_id = allocator.alloc(f"private_suffix_g_a{anchor}")
                        anchor_clone_ids.append(clone_id)
                        if idx < len(suffix) - 1:
                            next_clone_id = VirtualBlockId(
                                namespace=f"private_suffix_g_a{anchor}",
                                ordinal=clone_id.ordinal + 1,
                            )
                            outgoing = (PatchEdgeRef(source=clone_id, target=next_clone_id),)
                        else:
                            outgoing = ()
                        incoming = None
                        if idx == 0:
                            incoming = PatchEdgeRef(source=anchor, target=shared_entry)
                        new_blocks.append(
                            PatchBlockSpec(
                                block_id=clone_id,
                                kind="private_terminal_suffix_clone",
                                template_block=suffix_serial,
                                incoming_edge=incoming,
                                outgoing_edges=outgoing,
                            )
                        )
                    per_anchor_clone_ids.append(tuple(anchor_clone_ids))
                raw_steps.append(
                    _PendingPrivateTerminalSuffixGroup(
                        modification=modification,
                        per_anchor_clone_block_ids=tuple(per_anchor_clone_ids),
                    )
                )

            case DirectTerminalLoweringGroup(
                shared_entry_serial=shared_entry,
                suffix_serials=suffix,
                sites=sites,
            ):
                if not suffix:
                    raise ValueError(
                        "DirectTerminalLoweringGroup requires non-empty suffix_serials"
                    )
                per_site_clone_ids: dict[int, tuple[VirtualBlockId, ...]] = {}
                for site in sites:
                    if site.kind is DirectTerminalLoweringKind.RETURN_CONST:
                        per_site_clone_ids[int(site.anchor_serial)] = ()
                        continue
                    clone_sources = tuple(
                        int(serial) for serial in site.materializer_serials
                    )
                    if not clone_sources:
                        clone_sources = tuple(int(serial) for serial in suffix[:-1])
                    if not clone_sources:
                        raise ValueError(
                            "DirectTerminalLoweringGroup requires materializer "
                            "blocks or a non-terminal suffix"
                        )
                    site_clone_ids: list[VirtualBlockId] = []
                    for idx, source_serial in enumerate(clone_sources):
                        clone_id = allocator.alloc(
                            f"direct_terminal_a{site.anchor_serial}"
                        )
                        site_clone_ids.append(clone_id)
                        if idx < len(clone_sources) - 1:
                            next_clone_id = VirtualBlockId(
                                namespace=f"direct_terminal_a{site.anchor_serial}",
                                ordinal=clone_id.ordinal + 1,
                            )
                            outgoing = (
                                PatchEdgeRef(source=clone_id, target=next_clone_id),
                            )
                        else:
                            outgoing = ()
                        incoming = None
                        if idx == 0:
                            incoming = PatchEdgeRef(
                                source=int(site.anchor_serial),
                                target=int(shared_entry),
                            )
                        new_blocks.append(
                            PatchBlockSpec(
                                block_id=clone_id,
                                kind="direct_terminal_lowering_clone",
                                template_block=source_serial,
                                incoming_edge=incoming,
                                outgoing_edges=outgoing,
                            )
                        )
                    per_site_clone_ids[int(site.anchor_serial)] = tuple(site_clone_ids)
                raw_steps.append(
                    _PendingDirectTerminalLoweringGroup(
                        modification=modification,
                        per_site_clone_block_ids=per_site_clone_ids,
                    )
                )

            case ReorderBlocks(
                dfs_block_order=order,
                non_2way_serials=non_2way,
                two_way_serials=two_way,
            ):
                # Allocate one VirtualBlockId per non-2way block that will be copied
                virtual_ids = tuple(
                    allocator.alloc(f"reorder_copy_{old}")
                    for old in non_2way
                )
                # Register PatchBlockSpec entries so _build_relocation_map assigns concrete serials
                for vid, old_serial in zip(virtual_ids, non_2way):
                    new_blocks.append(PatchBlockSpec(
                        block_id=vid,
                        kind="reorder_block_copy",
                        template_block=old_serial,
                    ))

                two_way_pairs: list[tuple[VirtualBlockId, VirtualBlockId]] = []
                for old_serial in two_way:
                    copy_vid = allocator.alloc(f"reorder_2way_copy_{old_serial}")
                    tramp_vid = allocator.alloc(f"reorder_2way_tramp_{old_serial}")
                    new_blocks.append(PatchBlockSpec(
                        block_id=copy_vid,
                        kind="reorder_block_2way_copy",
                        template_block=old_serial,
                    ))
                    new_blocks.append(PatchBlockSpec(
                        block_id=tramp_vid,
                        kind="reorder_block_2way_trampoline",
                        template_block=old_serial,
                    ))
                    two_way_pairs.append((copy_vid, tramp_vid))

                raw_steps.append(_PendingReorderBlocks(
                    dfs_block_order=order,
                    non_2way_serials=non_2way,
                    virtual_ids=virtual_ids,
                    two_way_serials=two_way,
                    two_way_virtual_id_pairs=tuple(two_way_pairs),
                ))

            case _:
                raise TypeError(f"Unsupported GraphModification: {type(modification).__name__}")

    relocation_map = _build_relocation_map(new_blocks, cfg)
    steps = tuple(_finalize_step(step, relocation_map) for step in raw_steps)
    symbolic_specs = tuple(
        _rewrite_symbolic_spec(spec, relocation_map) for spec in new_blocks
    )
    return PatchPlan(
        steps=steps,
        new_blocks=symbolic_specs,
        relocation_map=relocation_map,
        planner_modifications=tuple(modifications),
        execution_policy=execution_policy,
    )


def ensure_patch_plan(lowering_input: LoweringInput) -> PatchPlan:
    """Return *lowering_input* as a PatchPlan, compiling when needed."""
    if isinstance(lowering_input, PatchPlan):
        return lowering_input
    return compile_patch_plan(list(lowering_input))


__all__ = [
    "ExecutionPolicy",
    "VirtualBlockId",
    "PatchBlockRef",
    "PatchEdgeRef",
    "PatchBlockSpec",
    "PatchRelocationMap",
    "PatchRedirectGoto",
    "PatchRedirectBranch",
    "PatchConvertToGoto",
    "PatchRemoveEdge",
    "PatchNopInstructions",
    "PatchZeroStateWrite",
    "PatchPromoteOperandToScalar",
    "PatchLowerConditionalStateTransition",
    "PatchNormalizeNWayDispatcherExit",
    "PatchBypassDispatcherTrampoline",
    "PatchCanonicalizeJumpTableCaseOverlap",
    "PatchScalarizeLocalAliasAccess",
    "PatchRetargetOutputStore",
    "PatchPhaseCycleLowering",
    "PatchEdgeSplitTrampoline",
    "PatchEdgeSplitCorridor",
    "PatchConditionalRedirect",
    "PatchInsertBlock",
    "PatchDuplicateBlock",
    "PatchDuplicateReplayEntry",
    "PatchDuplicateReplayAndRedirect",
    "PatchCloneConditionalAsGoto",
    "PatchPrivateTerminalSuffix",
    "PatchPrivateTerminalSuffixGroup",
    "PatchDirectTerminalLoweringGroup",
    "PatchReorderBlocks",
    "LegacyBlockOperation",
    "PatchOperation",
    "PatchStep",
    "PatchPlan",
    "BlockCreatingGraphModification",
    "LoweringInput",
    "is_block_creating_modification",
    "compile_patch_plan",
    "ensure_patch_plan",
]
