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

from d810.cfg.flowgraph import FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    GraphModification,
    InsertBlock,
    NopInstructions,
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
    new_target: int
    template_block: int


BlockCreatingGraphModification = Union[
    EdgeRedirectViaPredSplit,
    CreateConditionalRedirect,
    DuplicateBlock,
    InsertBlock,
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


def is_block_creating_modification(modification: GraphModification) -> bool:
    """Return True when the modification requires a new block."""
    return isinstance(
        modification,
        (
            EdgeRedirectViaPredSplit,
            CreateConditionalRedirect,
            DuplicateBlock,
            InsertBlock,
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
    )


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


def _compile_symbolic_block_step(
    modification: BlockCreatingGraphModification,
    allocator: _VirtualIdAllocator,
) -> tuple[LegacyBlockOperation, PatchBlockSpec]:
    match modification:
        case CreateConditionalRedirect(
            source_block=src,
            ref_block=ref,
            conditional_target=conditional,
            fallthrough_target=fallthrough,
        ):
            block_id = allocator.alloc("conditional_redirect")
            outgoing_edges = [PatchEdgeRef(source=block_id, target=conditional)]
            if fallthrough != conditional:
                outgoing_edges.append(PatchEdgeRef(source=block_id, target=fallthrough))
            spec = PatchBlockSpec(
                block_id=block_id,
                kind="conditional_redirect_clone",
                template_block=ref,
                incoming_edge=PatchEdgeRef(source=src, target=ref),
                outgoing_edges=tuple(outgoing_edges),
            )
            return LegacyBlockOperation(modification=modification, block_id=block_id), spec

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


def _finalize_step(
    step: PatchStep | _PendingEdgeSplitTrampoline,
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
                old_target=relocation_map.rewrite_serial(old),
                new_target=relocation_map.rewrite_serial(new),
                template_block=src,
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

            case CreateConditionalRedirect() | DuplicateBlock() | InsertBlock():
                legacy_step, spec = _compile_symbolic_block_step(modification, allocator)
                raw_steps.append(legacy_step)
                new_blocks.append(spec)

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
