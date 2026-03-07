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

from d810.core.typing import Union

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    GraphModification,
    InsertBlock,
    NopInstructions,
    PrivateTerminalSuffix,
    RedirectBranch,
    RedirectGoto,
    RemoveEdge,
)


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

    def to_graph_modification(self) -> CreateConditionalRedirect:
        return CreateConditionalRedirect(
            source_block=self.source_serial,
            ref_block=self.ref_block,
            conditional_target=self.conditional_target,
            fallthrough_target=self.fallthrough_target,
        )


@dataclass(frozen=True)
class PatchInsertBlock:
    """Finalized materialization of an inserted standalone block."""

    block_id: VirtualBlockId
    assigned_serial: int
    pred_serial: int
    succ_serial: int
    instructions: tuple[InsnSnapshot, ...]

    def to_graph_modification(self) -> InsertBlock:
        return InsertBlock(
            pred_serial=self.pred_serial,
            succ_serial=self.succ_serial,
            instructions=self.instructions,
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


BlockCreatingGraphModification = Union[
    EdgeRedirectViaPredSplit,
    CreateConditionalRedirect,
    DuplicateBlock,
    InsertBlock,
    PrivateTerminalSuffix,
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
    PatchEdgeSplitTrampoline,
    PatchConditionalRedirect,
    PatchInsertBlock,
    PatchDuplicateBlock,
    PatchPrivateTerminalSuffix,
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

    @property
    def concrete_operations(self) -> tuple[PatchOperation, ...]:
        return tuple(step for step in self.steps if not isinstance(step, LegacyBlockOperation))

    @property
    def legacy_block_operations(self) -> tuple[LegacyBlockOperation, ...]:
        return tuple(step for step in self.steps if isinstance(step, LegacyBlockOperation))

    @property
    def contains_block_creation(self) -> bool:
        return bool(self.new_blocks or self.legacy_block_operations)

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
class _PendingPrivateTerminalSuffix:
    modification: PrivateTerminalSuffix
    clone_block_ids: tuple[VirtualBlockId, ...]


def is_block_creating_modification(modification: GraphModification) -> bool:
    """Return True when the modification requires a new block."""
    return isinstance(
        modification,
        (
            EdgeRedirectViaPredSplit,
            CreateConditionalRedirect,
            DuplicateBlock,
            InsertBlock,
            PrivateTerminalSuffix,
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
    block_num = getattr(operand, "block_num", None)
    if not isinstance(block_num, int):
        return operand

    rewritten_block_num = relocation_map.rewrite_serial(block_num)
    if rewritten_block_num == block_num:
        return operand

    replace_kwargs = {"block_num": rewritten_block_num}
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

    tail = block.insn_snapshots[-1]
    for slot_name, operand in tail.operand_slots:
        if slot_name != "d":
            continue
        block_num = getattr(operand, "block_num", None)
        if isinstance(block_num, int):
            return block_num

    for operand in tail.operands:
        block_num = getattr(operand, "block_num", None)
        if isinstance(block_num, int):
            return block_num

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

        case InsertBlock(pred_serial=pred, succ_serial=succ, instructions=insns):
            block_id = allocator.alloc("insert_block")
            spec = PatchBlockSpec(
                block_id=block_id,
                kind="insert_block",
                incoming_edge=PatchEdgeRef(source=pred, target=succ),
                outgoing_edges=(PatchEdgeRef(source=block_id, target=succ),),
                instructions=insns,
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
        conditional_target = _infer_conditional_target(source_block)
        if conditional_target is None:
            return None
        fallthrough_target = _infer_fallthrough_target(
            source_block,
            conditional_target=conditional_target,
        )
        if fallthrough_target is None:
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


def _finalize_step(
    step: PatchStep | _PendingEdgeSplitTrampoline | _PendingConditionalRedirect | _PendingInsertBlock | _PendingDuplicateBlock | _PendingPrivateTerminalSuffix,
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

        case _PendingConditionalRedirect(
            modification=CreateConditionalRedirect(
                source_block=src,
                ref_block=ref,
                conditional_target=conditional,
                fallthrough_target=fallthrough,
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
            )

        case _PendingInsertBlock(
            modification=InsertBlock(pred_serial=pred, succ_serial=succ, instructions=insns),
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

        case LegacyBlockOperation():
            return step

        case _:
            raise TypeError(f"Unsupported PatchPlan step: {type(step).__name__}")


def compile_patch_plan(
    modifications: list[GraphModification],
    cfg: FlowGraph | None = None,
) -> PatchPlan:
    """Compile planner modifications into ordered PatchPlan steps."""
    allocator = _VirtualIdAllocator()
    raw_steps: list[PatchStep | _PendingEdgeSplitTrampoline] = []
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

            case EdgeRedirectViaPredSplit(
                src_block=src,
                old_target=old,
                new_target=new,
                via_pred=pred,
            ):
                if cfg is None:
                    raise ValueError(
                        "compile_patch_plan requires FlowGraph context for EdgeRedirectViaPredSplit"
                    )
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

            case InsertBlock(pred_serial=pred, succ_serial=succ, instructions=insns):
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
                            incoming_edge=PatchEdgeRef(source=pred, target=succ),
                            outgoing_edges=(PatchEdgeRef(source=block_id, target=succ),),
                            instructions=insns,
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
    )


def ensure_patch_plan(lowering_input: LoweringInput) -> PatchPlan:
    """Return *lowering_input* as a PatchPlan, compiling when needed."""
    if isinstance(lowering_input, PatchPlan):
        return lowering_input
    return compile_patch_plan(list(lowering_input))


__all__ = [
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
    "PatchEdgeSplitTrampoline",
    "PatchConditionalRedirect",
    "PatchInsertBlock",
    "PatchDuplicateBlock",
    "PatchPrivateTerminalSuffix",
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
