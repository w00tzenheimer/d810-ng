"""Execution-plan layer between planner GraphModification IR and backend apply.

``PatchPlan`` is the backend-facing execution IR. Planner code may emit
``GraphModification`` objects only while its exact source snapshot is live; the
compiler in this module lowers those intents once into an ordered plan made of:

- concrete existing-block rewrites that backends can apply directly
- symbolic block specs for edits that create new blocks
This lets callers reason about block creation explicitly and reject incomplete
source authority before mutating backend state.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields, replace
from contextvars import ContextVar
from enum import Enum
from uuid import uuid4

from d810.core.algorithm_metadata import algorithm_metadata
from d810.core.typing import ClassVar, Mapping, Protocol, TypeAlias, Union


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

from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.maturity import MaturityEnvelope
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
    ExitPathLoweringKind,
    ExitPathLoweringGroup,
    ExitPathLoweringSite,
    ReorderBlocks,
    RedirectBranch,
    RedirectGoto,
    RetargetOutputStore,
    RemoveEdge,
    ScalarizeLocalAliasAccess,
)
from d810.transforms.materialization_payload import CapturedBlockBody
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentOperation,
    FragmentPlan,
    FragmentReturnCarrier,
    FragmentTerminalReturn,
    FragmentTerminalRoute,
)
from d810.transforms.fragment_validation import (
    FragmentValidationPostcondition,
    FragmentValidationResult,
    ProjectedFragment,
)
from d810.transforms.cfg_transaction import CfgProjection
from d810.transforms.cfg_transaction import (
    CfgBlockRef,
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
)


PatchBlockRef: TypeAlias = CfgBlockRef


_PATCH_BLOCK_REF_TYPES = (NativeBlockRef, LogicalBlockRef, PlanBlockRef)
_COMPILER_BLOCK_REFS: ContextVar[Mapping[int, PatchBlockRef] | None] = ContextVar(
    "patch_plan_compiler_block_refs", default=None
)


def projected_source_coordinate(
    source_coordinates: tuple[tuple[NativeBlockRef | LogicalBlockRef, int], ...],
    ref: NativeBlockRef | LogicalBlockRef,
) -> int:
    """Resolve a projection coordinate from one explicit plan-owned mapping."""
    try:
        return dict(source_coordinates)[ref]
    except KeyError as exc:
        raise ValueError("typed reference has no projected source coordinate") from exc


def _require_patch_ref(value: object, field_name: str, *, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, _PATCH_BLOCK_REF_TYPES):
        raise TypeError(f"{field_name} must be a typed block reference")


def _coerce_compiler_ref(value: object) -> object:
    refs_by_serial = _COMPILER_BLOCK_REFS.get()
    if not isinstance(value, int) or isinstance(value, bool):
        return value
    if refs_by_serial is None:
        return value
    if value not in refs_by_serial:
        raise TypeError(f"block serial {value} has no typed source authority")
    return refs_by_serial[value]


class _PatchRefValidated:
    """Runtime guard preventing serial coordinates from entering immutable plans."""

    _REF_FIELDS: ClassVar[tuple[str, ...]] = ()
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = ()
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = ()

    def __post_init__(self) -> None:
        for field_name in self._REF_FIELDS:
            value = _coerce_compiler_ref(getattr(self, field_name))
            object.__setattr__(self, field_name, value)
            _require_patch_ref(value, field_name)
        for field_name in self._OPTIONAL_REF_FIELDS:
            value = _coerce_compiler_ref(getattr(self, field_name))
            object.__setattr__(self, field_name, value)
            _require_patch_ref(value, field_name, optional=True)
        for field_name in self._REF_TUPLE_FIELDS:
            values = getattr(self, field_name)
            if not isinstance(values, tuple):
                raise TypeError(f"{field_name} must be a tuple of typed block references")
            values = tuple(_coerce_compiler_ref(value) for value in values)
            object.__setattr__(self, field_name, values)
            for value in values:
                _require_patch_ref(value, field_name)


@dataclass(frozen=True)
class PatchEdgeRef(_PatchRefValidated):
    """Edge descriptor that can reference concrete or symbolic blocks."""

    source: PatchBlockRef
    target: PatchBlockRef
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("source", "target")


@dataclass(frozen=True)
class PatchBlockSpec(_PatchRefValidated):
    """Symbolic description of a block that must be materialized later."""

    block_id: PlanBlockRef
    kind: str
    template_block: PatchBlockRef | None = None
    incoming_edge: PatchEdgeRef | None = None
    outgoing_edges: tuple[PatchEdgeRef, ...] = ()
    instructions: tuple[InsnSnapshot, ...] = ()
    captured_body: CapturedBlockBody | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.block_id, PlanBlockRef):
            raise TypeError("block_id must be a PlanBlockRef")
        template_block = _coerce_compiler_ref(self.template_block)
        object.__setattr__(self, "template_block", template_block)
        _require_patch_ref(template_block, "template_block", optional=True)
        if self.incoming_edge is not None and not isinstance(
            self.incoming_edge, PatchEdgeRef
        ):
            raise TypeError("incoming_edge must be a PatchEdgeRef")
        if not isinstance(self.outgoing_edges, tuple) or any(
            not isinstance(edge, PatchEdgeRef) for edge in self.outgoing_edges
        ):
            raise TypeError("outgoing_edges must contain PatchEdgeRef values")


@dataclass(frozen=True)
class PatchRelocationMap:
    """Plan-reference lineage, never predicted live serial assignments."""

    planned_lineage: tuple[tuple[PlanBlockRef, PatchBlockRef | None], ...] = ()
    source_stop: PatchBlockRef | None = None
    rewritten_edges: tuple[tuple[PatchEdgeRef, PatchEdgeRef], ...] = ()

    def __post_init__(self) -> None:
        for plan_ref, parent_ref in self.planned_lineage:
            if not isinstance(plan_ref, PlanBlockRef):
                raise TypeError("relocation lineage requires PlanBlockRef keys")
            _require_patch_ref(parent_ref, "relocation parent", optional=True)
        source_stop = _coerce_compiler_ref(self.source_stop)
        object.__setattr__(self, "source_stop", source_stop)
        _require_patch_ref(source_stop, "relocation source_stop", optional=True)
        if not isinstance(self.rewritten_edges, tuple):
            raise TypeError("rewritten_edges must contain PatchEdgeRef pairs")
        for pair in self.rewritten_edges:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or not isinstance(pair[0], PatchEdgeRef)
                or not isinstance(pair[1], PatchEdgeRef)
            ):
                raise TypeError("rewritten_edges must contain PatchEdgeRef pairs")

    def rewrite_serial(self, block_ref: PatchBlockRef) -> PatchBlockRef:
        """Retain identity; transaction-local binding accounts for live shifts."""
        block_ref = _coerce_compiler_ref(block_ref)
        _require_patch_ref(block_ref, "block_ref")
        return block_ref


@dataclass(frozen=True)
class PatchRedirectGoto(_PatchRefValidated):
    from_serial: PatchBlockRef
    old_target: PatchBlockRef
    new_target: PatchBlockRef
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("from_serial", "old_target", "new_target")

@dataclass(frozen=True)
class PatchRedirectBranch(PatchRedirectGoto):
    fallthrough_helper_block_id: PlanBlockRef | None = None
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = (
        "fallthrough_helper_block_id",
    )

@dataclass(frozen=True)
class PatchConvertToGoto(_PatchRefValidated):
    block_serial: PatchBlockRef
    goto_target: PatchBlockRef
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("block_serial", "goto_target")

@dataclass(frozen=True)
class PatchRemoveEdge(_PatchRefValidated):
    from_serial: PatchBlockRef
    to_serial: PatchBlockRef
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("from_serial", "to_serial")


@dataclass(frozen=True)
class PatchFragmentBlockMaterialization(_PatchRefValidated):
    """One fragment-local realization using plan-owned block identities."""

    block_ref: PlanBlockRef
    block: FragmentBlock
    materialization: FragmentBlockMaterialization
    source_ref: PlanBlockRef | None = None
    native_body_id: str | None = None
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("block_ref",)
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = ("source_ref",)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.block_ref, PlanBlockRef):
            raise TypeError("fragment block materialization requires PlanBlockRef")
        if not isinstance(self.block, FragmentBlock):
            raise TypeError("fragment block materialization requires FragmentBlock")
        if self.block_ref.local_block_id != self.block.block_id:
            raise ValueError("fragment block ref differs from materialization payload")
        if self.block.materialization is not self.materialization:
            raise ValueError("fragment block materialization differs from payload")
        if not isinstance(self.materialization, FragmentBlockMaterialization):
            raise TypeError("fragment block materialization kind is invalid")
        if self.source_ref is not None and not isinstance(
            self.source_ref, PlanBlockRef
        ):
            raise TypeError("fragment materialization source requires PlanBlockRef")
        if (
            self.materialization is FragmentBlockMaterialization.CLONE_PUBLISHED
        ) != (self.source_ref is not None):
            raise ValueError("only cloned fragment blocks require a source ref")
        if (
            self.materialization is FragmentBlockMaterialization.IMPORT_NATIVE
        ) != (self.native_body_id is not None):
            raise ValueError("only imported fragment blocks require a native body id")


@dataclass(frozen=True)
class PatchFragmentOperation(_PatchRefValidated):
    """One complete direct, conditional, or call-fallthrough fragment edit."""

    source_ref: PlanBlockRef
    target_refs: tuple[PlanBlockRef, ...]
    operation: FragmentOperation
    fallthrough_helper_id: str | None = None
    fallthrough_helper_ref: PlanBlockRef | None = None
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("source_ref",)
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = ("target_refs",)
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = ("fallthrough_helper_ref",)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.source_ref, PlanBlockRef) or any(
            not isinstance(ref, PlanBlockRef) for ref in self.target_refs
        ):
            raise TypeError("fragment operation requires PlanBlockRefs")
        if not isinstance(self.operation, FragmentOperation):
            raise TypeError("fragment operation requires typed semantic intent")
        if self.source_ref.local_block_id != self.operation.source_block_id:
            raise ValueError("fragment operation source differs from semantic intent")
        if tuple(ref.local_block_id for ref in self.target_refs) != tuple(
            edge.target_block_id for edge in self.operation.edges
        ):
            raise ValueError("fragment operation targets differ from semantic intent")
        if self.fallthrough_helper_id is not None and not self.fallthrough_helper_id:
            raise ValueError("fragment fallthrough helper id must not be empty")
        if (self.fallthrough_helper_id is None) != (
            self.fallthrough_helper_ref is None
        ):
            raise ValueError("fragment helper id and PlanBlockRef must agree")
        if (
            self.fallthrough_helper_ref is not None
            and self.fallthrough_helper_ref.local_block_id
            != self.fallthrough_helper_id
        ):
            raise ValueError("fragment helper PlanBlockRef differs from its id")


@dataclass(frozen=True)
class PatchFragmentOperationNormalization:
    """Pre-operation rewrite of proven computed-branch envelopes."""

    operations: tuple[FragmentOperation, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.operations, tuple) or not self.operations or any(
            not isinstance(operation, FragmentOperation)
            or operation.computed_branch_normalization is None
            for operation in self.operations
        ):
            raise TypeError("fragment normalization requires typed operations")


@dataclass(frozen=True)
class PatchFragmentTerminalEffects:
    """Atomic terminal carrier, return, and route obligations."""

    return_carriers: tuple[FragmentReturnCarrier, ...]
    terminal_returns: tuple[FragmentTerminalReturn, ...]
    terminal_routes: tuple[FragmentTerminalRoute, ...]

    def __post_init__(self) -> None:
        for values, expected, description in (
            (self.return_carriers, FragmentReturnCarrier, "return carriers"),
            (self.terminal_returns, FragmentTerminalReturn, "terminal returns"),
            (self.terminal_routes, FragmentTerminalRoute, "terminal routes"),
        ):
            if not isinstance(values, tuple) or any(
                not isinstance(value, expected) for value in values
            ):
                raise TypeError(f"fragment {description} require typed tuples")
        if (
            not self.return_carriers
            and not self.terminal_returns
            and not self.terminal_routes
        ):
            raise ValueError("fragment terminal effects must not be empty")


@dataclass(frozen=True)
class PatchFragmentRootPublication(_PatchRefValidated):
    """One root swap performed only after the staged graph validates."""

    root_ref: PlanBlockRef
    original_ref: PlanBlockRef
    predecessor_ref: PlanBlockRef | None = None
    edge_role: SemanticEdgeRole | None = None
    fallthrough_helper_id: str | None = None
    fallthrough_helper_ref: PlanBlockRef | None = None
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("root_ref", "original_ref")
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = (
        "predecessor_ref",
        "fallthrough_helper_ref",
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.root_ref, PlanBlockRef) or not isinstance(
            self.original_ref, PlanBlockRef
        ):
            raise TypeError("fragment root publication requires PlanBlockRefs")
        if self.edge_role is not None and not isinstance(
            self.edge_role, SemanticEdgeRole
        ):
            raise TypeError("fragment root publication requires semantic edge role")
        if self.predecessor_ref is None or self.edge_role is None:
            raise ValueError("fragment root publication requires predecessor edge authority")
        if self.fallthrough_helper_id is not None and not self.fallthrough_helper_id:
            raise ValueError("fragment root helper id must not be empty")
        if (self.fallthrough_helper_id is None) != (
            self.fallthrough_helper_ref is None
        ):
            raise ValueError("fragment root helper id and PlanBlockRef must agree")
        if (
            self.fallthrough_helper_ref is not None
            and self.fallthrough_helper_ref.local_block_id
            != self.fallthrough_helper_id
        ):
            raise ValueError("fragment root helper PlanBlockRef differs from its id")


class FragmentRootInventory(Protocol):
    plan_id: str
    atomic_group_id: str
    items: tuple[object, ...]


@dataclass(frozen=True)
class FragmentContractBundle:
    """Complete semantic obligations carried by a lowered PatchPlan."""

    fragment_plan: FragmentPlan
    prepared_projection: ProjectedFragment
    cfg_projection: CfgProjection
    prepublication_validation: FragmentValidationResult
    root_inventory: FragmentRootInventory
    fragment_postconditions: tuple[FragmentValidationPostcondition, ...]

    def __post_init__(self) -> None:
        plan = self.fragment_plan
        if not isinstance(plan, FragmentPlan):
            raise TypeError("fragment contract requires FragmentPlan")
        if not isinstance(self.prepared_projection, ProjectedFragment):
            raise TypeError("fragment contract requires ProjectedFragment")
        if not isinstance(self.cfg_projection, CfgProjection):
            raise TypeError("fragment contract requires CfgProjection")
        if not isinstance(self.prepublication_validation, FragmentValidationResult):
            raise TypeError("fragment contract requires validation evidence")
        if (
            self.cfg_projection.plan_id != plan.plan_id
            or self.prepublication_validation.plan_id != plan.plan_id
            or self.prepublication_validation.atomic_group_id != plan.atomic_group_id
            or self.root_inventory.plan_id != plan.plan_id
            or self.root_inventory.atomic_group_id != plan.atomic_group_id
        ):
            raise ValueError("fragment contract authority differs from plan")
        if not self.prepublication_validation.passed:
            raise ValueError("cannot lower a fragment that failed preflight")
        if set(self.fragment_postconditions) != set(FragmentValidationPostcondition):
            raise ValueError("fragment contract postcondition inventory is incomplete")

@dataclass(frozen=True)
class PatchNopInstructions(_PatchRefValidated):
    block_serial: PatchBlockRef
    insn_eas: tuple[int, ...]
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("block_serial",)

@dataclass(frozen=True)
class PatchZeroStateWrite(_PatchRefValidated):
    """Zero the source operand of a state variable write instruction."""
    block_serial: PatchBlockRef
    insn_ea: int
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("block_serial",)

@dataclass(frozen=True)
class PatchPromoteOperandToScalar(_PatchRefValidated):
    """Promote a fused sub-instruction operand into a fresh kreg standalone insn."""
    block_serial: PatchBlockRef
    host_ea: int
    host_opcode: int
    operand_side: str  # "l" | "r"
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("block_serial",)

@dataclass(frozen=True)
class PatchLowerConditionalStateTransition(_PatchRefValidated):
    source_serial: PatchBlockRef
    old_dispatcher_serial: PatchBlockRef
    rewrite_from_ea: int
    condition_operand: object
    false_target_serial: PatchBlockRef
    true_target_serial: PatchBlockRef
    proof_id: str | None = None
    state_register: int | None = None
    state_size: int | None = None
    false_state: int | None = None
    true_state: int | None = None
    false_state_write_ea: int | None = None
    true_state_write_ea: int | None = None
    _REF_FIELDS: ClassVar[tuple[str, ...]] = (
        "source_serial", "old_dispatcher_serial", "false_target_serial", "true_target_serial"
    )

@dataclass(frozen=True)
class PatchNormalizeNWayDispatcherExit(_PatchRefValidated):
    block_serial: PatchBlockRef
    dispatcher_entry_serial: PatchBlockRef
    keep_target_serial: PatchBlockRef | None = None
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("block_serial", "dispatcher_entry_serial")
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = ("keep_target_serial",)

@dataclass(frozen=True)
class PatchBypassDispatcherTrampoline(_PatchRefValidated):
    source_serial: PatchBlockRef
    trampoline_serial: PatchBlockRef
    target_serial: PatchBlockRef
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("source_serial", "trampoline_serial", "target_serial")

@dataclass(frozen=True)
class PatchCanonicalizeJumpTableCaseOverlap(_PatchRefValidated):
    jtbl_serial: PatchBlockRef
    retarget_map: tuple[tuple[PatchBlockRef, PatchBlockRef], ...]
    deduplicate: bool = False

    def __post_init__(self) -> None:
        jtbl_serial = _coerce_compiler_ref(self.jtbl_serial)
        object.__setattr__(self, "jtbl_serial", jtbl_serial)
        _require_patch_ref(jtbl_serial, "jtbl_serial")
        retarget_map = tuple(
            (_coerce_compiler_ref(source), _coerce_compiler_ref(target))
            for source, target in self.retarget_map
        )
        object.__setattr__(self, "retarget_map", retarget_map)
        for source, target in retarget_map:
            _require_patch_ref(source, "retarget_map source")
            _require_patch_ref(target, "retarget_map target")

@dataclass(frozen=True)
class PatchScalarizeLocalAliasAccess(_PatchRefValidated):
    block_serial: PatchBlockRef
    host_ea: int
    host_opcode: int
    alias_token: str
    base_token: str
    host_text_sha1: str | None = None
    value_size: int | None = None
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("block_serial",)

@dataclass(frozen=True)
class PatchRetargetOutputStore(_PatchRefValidated):
    block_serial: PatchBlockRef
    host_ea: int
    host_opcode: int
    alias_token: str
    output_token: str
    host_text_sha1: str | None = None
    value_size: int | None = None
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("block_serial",)

@dataclass(frozen=True)
class PatchPhaseCycleLowering(_PatchRefValidated):
    header_entries: tuple[PatchBlockRef, ...]
    header_target: PatchBlockRef
    body_entries: tuple[PatchBlockRef, ...]
    body_target: PatchBlockRef
    next_phase_entries: tuple[PatchBlockRef, ...]
    next_phase_target: PatchBlockRef
    terminal_entries: tuple[PatchBlockRef, ...] = ()
    terminal_target: PatchBlockRef | None = None
    state_roles: tuple[tuple[str, int], ...] = ()
    reason: str = "dispatcher_phase_cycle"
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("header_target", "body_target", "next_phase_target")
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = ("terminal_target",)
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = (
        "header_entries", "body_entries", "next_phase_entries", "terminal_entries"
    )

@dataclass(frozen=True)
class PatchEdgeSplitTrampoline(_PatchRefValidated):
    """Finalized edge-split trampoline materialization step."""

    block_id: PlanBlockRef
    source_serial: PatchBlockRef
    via_pred: PatchBlockRef
    old_target: PatchBlockRef
    apply_old_target: PatchBlockRef
    new_target: PatchBlockRef
    template_block: PatchBlockRef
    _REF_FIELDS: ClassVar[tuple[str, ...]] = (
        "block_id", "source_serial", "via_pred", "old_target", "apply_old_target", "new_target", "template_block"
    )


@dataclass(frozen=True)
class PatchEdgeSplitCorridor(_PatchRefValidated):
    """Finalized strict 1-way corridor clone for an edge split."""

    clone_block_ids: tuple[PlanBlockRef, ...]
    source_serial: PatchBlockRef
    via_pred: PatchBlockRef
    old_target: PatchBlockRef
    new_target: PatchBlockRef
    clone_until: PatchBlockRef
    corridor_serials: tuple[PatchBlockRef, ...]
    source_new_target: PatchBlockRef | None = None
    rule_priority: int = 0
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("source_serial", "via_pred", "old_target", "new_target", "clone_until")
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = ("source_new_target",)
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = ("clone_block_ids", "corridor_serials")

@dataclass(frozen=True)
class PatchConditionalRedirect(_PatchRefValidated):
    """Finalized materialization of a cloned conditional block plus NOP fallthrough."""

    block_id: PlanBlockRef
    fallthrough_block_id: PlanBlockRef
    source_serial: PatchBlockRef
    ref_block: PatchBlockRef
    conditional_target: PatchBlockRef
    fallthrough_target: PatchBlockRef
    old_target_serial: PatchBlockRef | None = None
    instructions: tuple[InsnSnapshot, ...] = ()
    _REF_FIELDS: ClassVar[tuple[str, ...]] = (
        "block_id", "fallthrough_block_id", "source_serial", "ref_block", "conditional_target", "fallthrough_target"
    )
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = ("old_target_serial",)

@dataclass(frozen=True)
class PatchInsertBlock(_PatchRefValidated):
    """Finalized materialization of an inserted standalone block."""

    block_id: PlanBlockRef
    pred_serial: PatchBlockRef
    succ_serial: PatchBlockRef
    instructions: tuple[InsnSnapshot, ...]
    old_target_serial: PatchBlockRef | None = None
    captured_body: CapturedBlockBody | None = None
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("block_id", "pred_serial", "succ_serial")
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = ("old_target_serial",)

@dataclass(frozen=True)
class PatchDuplicateBlock(_PatchRefValidated):
    """Finalized materialization of a duplicated block plus predecessor redirect."""

    block_id: PlanBlockRef
    source_serial: PatchBlockRef
    pred_serial: PatchBlockRef | None
    pred_redirect_kind: str
    source_successors: tuple[PatchBlockRef, ...]
    target_serial: PatchBlockRef | None = None
    conditional_target: PatchBlockRef | None = None
    fallthrough_target: PatchBlockRef | None = None
    fallthrough_block_id: PlanBlockRef | None = None
    _REF_FIELDS: ClassVar[tuple[str, ...]] = (
        "block_id", "source_serial"
    )
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = (
        "pred_serial", "target_serial", "conditional_target", "fallthrough_target", "fallthrough_block_id"
    )
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = ("source_successors",)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.block_id, PlanBlockRef):
            raise TypeError("block_id must be a PlanBlockRef")

@dataclass(frozen=True)
class PatchDuplicateReplayEntry(_PatchRefValidated):
    """Finalized per-predecessor clone/replay route."""

    pred_serial: PatchBlockRef
    target_serial: PatchBlockRef
    replay_block_id: PlanBlockRef
    captured_body: CapturedBlockBody
    clone_block_id: PlanBlockRef | None = None
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("pred_serial", "target_serial", "replay_block_id")
    _OPTIONAL_REF_FIELDS: ClassVar[tuple[str, ...]] = ("clone_block_id",)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.replay_block_id, PlanBlockRef):
            raise TypeError("replay_block_id must be a PlanBlockRef")
        if self.clone_block_id is not None:
            if not isinstance(self.clone_block_id, PlanBlockRef):
                raise TypeError("clone_block_id must be a PlanBlockRef")


@dataclass(frozen=True)
class PatchDuplicateReplayAndRedirect(_PatchRefValidated):
    """Finalized duplicate-group replay materialization step."""

    source_serial: PatchBlockRef
    dispatcher_entry: PatchBlockRef
    per_pred_replays: tuple[PatchDuplicateReplayEntry, ...]
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("source_serial", "dispatcher_entry")

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.per_pred_replays, tuple) or any(
            not isinstance(entry, PatchDuplicateReplayEntry)
            for entry in self.per_pred_replays
        ):
            raise TypeError(
                "per_pred_replays must contain PatchDuplicateReplayEntry values"
            )

@dataclass(frozen=True)
class PatchCloneConditionalAsGoto(_PatchRefValidated):
    """Finalized clone-conditional-as-goto materialization step."""

    block_id: PlanBlockRef
    source_serial: PatchBlockRef
    pred_serial: PatchBlockRef
    goto_target: PatchBlockRef
    source_successors: tuple[PatchBlockRef, PatchBlockRef]
    conditional_target: PatchBlockRef
    fallthrough_target: PatchBlockRef
    reason: str = "fix_predecessor_clone_as_goto"
    _REF_FIELDS: ClassVar[tuple[str, ...]] = (
        "block_id", "source_serial", "pred_serial", "goto_target", "conditional_target", "fallthrough_target"
    )
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = ("source_successors",)

@dataclass(frozen=True)
class PatchCloneConditionalAsGotoFromBranchArm(_PatchRefValidated):
    """Finalized clone-conditional-as-goto-from-branch-arm materialization step.

    Sibling of :class:`PatchCloneConditionalAsGoto` for the case where the
    predecessor is itself a 2-way conditional whose ``pred_arm`` reaches the
    cloned source.  ``pred_arm == 1`` rewires the explicit conditional branch;
    ``pred_arm == 0`` materializes the implicit fallthrough through the
    mutation backend's adjacent helper-block path.
    """

    block_id: PlanBlockRef
    source_serial: PatchBlockRef
    pred_serial: PatchBlockRef
    pred_arm: int
    goto_target: PatchBlockRef
    source_successors: tuple[PatchBlockRef, PatchBlockRef]
    pred_successors: tuple[PatchBlockRef, PatchBlockRef]
    pred_branch_target_serial: PatchBlockRef
    pred_fallthrough_target_serial: PatchBlockRef
    conditional_target: PatchBlockRef
    fallthrough_target: PatchBlockRef
    reason: str = "fix_predecessor_clone_as_goto_from_branch_arm"
    _REF_FIELDS: ClassVar[tuple[str, ...]] = (
        "block_id", "source_serial", "pred_serial", "goto_target", "pred_branch_target_serial",
        "pred_fallthrough_target_serial", "conditional_target", "fallthrough_target"
    )
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = ("source_successors", "pred_successors")

@dataclass(frozen=True)
class PatchPrivateTerminalSuffix(_PatchRefValidated):
    """Finalized materialization of a private terminal suffix chain for one anchor.

    Clones each block in the shared suffix, wires the cloned chain in order,
    and redirects the anchor to the clone of shared_entry.

    Attributes:
        anchor_serial: Block whose edge to shared_entry gets rewired to clone chain.
        shared_entry_serial: First block in the shared suffix.
        return_block_serial: Terminal stop/return block (last in the suffix).
        suffix_serials: Ordered shared suffix serials (entry..return_block).
        clone_block_ids: Plan-local block IDs for each clone (parallel to suffix_serials).
    """

    anchor_serial: PatchBlockRef
    shared_entry_serial: PatchBlockRef
    return_block_serial: PatchBlockRef
    suffix_serials: tuple[PatchBlockRef, ...]
    clone_block_ids: tuple[PlanBlockRef, ...]
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("anchor_serial", "shared_entry_serial", "return_block_serial")
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = ("suffix_serials", "clone_block_ids")

@dataclass(frozen=True)
class PatchPrivateTerminalSuffixGroup(_PatchRefValidated):
    """Grouped materialization of private terminal suffix chains for multiple anchors."""

    shared_entry_serial: PatchBlockRef
    return_block_serial: PatchBlockRef
    suffix_serials: tuple[PatchBlockRef, ...]
    anchors: tuple[PatchBlockRef, ...]
    # Parallel to anchors: per_anchor_clone_block_ids[i] are clone IDs for anchors[i]
    per_anchor_clone_block_ids: tuple[tuple[PlanBlockRef, ...], ...]

    def __post_init__(self) -> None:
        shared_entry = _coerce_compiler_ref(self.shared_entry_serial)
        return_block = _coerce_compiler_ref(self.return_block_serial)
        object.__setattr__(self, "shared_entry_serial", shared_entry)
        object.__setattr__(self, "return_block_serial", return_block)
        _require_patch_ref(shared_entry, "shared_entry_serial")
        _require_patch_ref(return_block, "return_block_serial")
        for field_name in ("suffix_serials", "anchors"):
            refs = tuple(_coerce_compiler_ref(ref) for ref in getattr(self, field_name))
            object.__setattr__(self, field_name, refs)
            for ref in refs:
                _require_patch_ref(ref, field_name)
        for refs in self.per_anchor_clone_block_ids:
            if any(not isinstance(ref, PlanBlockRef) for ref in refs):
                raise TypeError("per_anchor_clone_block_ids must contain PlanBlockRef values")

@dataclass(frozen=True)
class PatchExitPathLoweringSite(_PatchRefValidated):
    """Typed per-anchor terminal lowering coordinates."""

    anchor_serial: PatchBlockRef
    kind: ExitPathLoweringKind
    const_value: int | None = None
    source_stkoff: int | None = None
    source_mreg: int | None = None
    materializer_serials: tuple[PatchBlockRef, ...] = ()
    skip_terminal_control_tail: bool = False
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("anchor_serial",)
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = ("materializer_serials",)


@dataclass(frozen=True)
class PatchExitPathLoweringGroup(_PatchRefValidated):
    """Grouped direct terminal lowering for multiple anchors sharing the same suffix."""

    shared_entry_serial: PatchBlockRef
    return_block_serial: PatchBlockRef
    suffix_serials: tuple[PatchBlockRef, ...]
    sites: tuple[PatchExitPathLoweringSite, ...]
    per_site_clone_block_ids: tuple[tuple[PatchBlockRef, tuple[PlanBlockRef, ...]], ...]
    _REF_FIELDS: ClassVar[tuple[str, ...]] = ("shared_entry_serial", "return_block_serial")
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = ("suffix_serials",)

    def __post_init__(self) -> None:
        super().__post_init__()
        if any(not isinstance(site, PatchExitPathLoweringSite) for site in self.sites):
            raise TypeError("sites must contain PatchExitPathLoweringSite values")
        for anchor, refs in self.per_site_clone_block_ids:
            _require_patch_ref(anchor, "per_site_clone_block_ids anchor")
            if any(not isinstance(ref, PlanBlockRef) for ref in refs):
                raise TypeError("per_site_clone_block_ids must contain PlanBlockRef values")


@dataclass(frozen=True)
class PatchReorderBlocks(_PatchRefValidated):
    """Reorder handler blocks by copying them in DFS order to end of MBA."""

    dfs_block_order: tuple[PatchBlockRef, ...]
    non_2way_serials: tuple[PatchBlockRef, ...] = ()
    two_way_serials: tuple[PatchBlockRef, ...] = ()
    copy_lineage: tuple[tuple[PatchBlockRef, PlanBlockRef], ...] = ()
    two_way_trampoline_lineage: tuple[tuple[PatchBlockRef, PlanBlockRef], ...] = ()
    _REF_TUPLE_FIELDS: ClassVar[tuple[str, ...]] = (
        "dfs_block_order", "non_2way_serials", "two_way_serials"
    )

    def __post_init__(self) -> None:
        super().__post_init__()
        for field_name in (
            "copy_lineage",
            "two_way_trampoline_lineage",
        ):
            pairs = tuple(
                (_coerce_compiler_ref(source), created)
                for source, created in getattr(self, field_name)
            )
            object.__setattr__(self, field_name, pairs)
            for source, created in pairs:
                _require_patch_ref(source, f"{field_name} source")
                if not isinstance(created, PlanBlockRef):
                    raise TypeError(f"{field_name} target must be a PlanBlockRef")

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
    ExitPathLoweringGroup,
]


PatchOperation = Union[
    PatchFragmentBlockMaterialization,
    PatchFragmentOperation,
    PatchFragmentOperationNormalization,
    PatchFragmentTerminalEffects,
    PatchFragmentRootPublication,
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
    PatchExitPathLoweringGroup,
    PatchReorderBlocks,
]

PatchStep: TypeAlias = PatchOperation


def _validate_fragment_contract_steps(
    plan_id: str,
    steps: tuple[PatchStep, ...],
    contract: FragmentContractBundle,
) -> None:
    """Reject any PatchStep drift from the preflighted semantic bundle."""
    fragment = contract.fragment_plan
    if fragment.plan_id != plan_id:
        raise ValueError("fragment contract plan authority differs")
    block_steps = tuple(
        step for step in steps if isinstance(step, PatchFragmentBlockMaterialization)
    )
    if len(block_steps) != len(fragment.blocks):
        raise ValueError("fragment block PatchStep inventory differs")
    block_by_id = {block.block_id: block for block in fragment.blocks}
    seen_block_ids: set[str] = set()
    for step in block_steps:
        block = block_by_id.get(step.block_ref.local_block_id)
        if (
            block is None
            or step.block != block
            or step.block_ref.local_block_id in seen_block_ids
        ):
            raise ValueError("fragment block PatchStep payload differs")
        seen_block_ids.add(step.block_ref.local_block_id)
        expected_source = block.replaces_block_id
        if (
            None if step.source_ref is None else step.source_ref.local_block_id
        ) != expected_source or step.native_body_id != block.native_body_id:
            raise ValueError("fragment block PatchStep authority differs")

    operation_steps = tuple(
        step for step in steps if isinstance(step, PatchFragmentOperation)
    )
    if tuple(step.operation for step in operation_steps) != fragment.operations:
        raise ValueError("fragment operation PatchStep inventory differs")
    for step in operation_steps:
        expected_helper = (
            f"fallthrough-helper:{step.operation.operation_id}"
            if step.operation.roles.intersection(
                {
                    SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                    SemanticEdgeRole.CALL_FALLTHROUGH,
                }
            )
            else None
        )
        if (
            step.fallthrough_helper_id != expected_helper
            or (
                None
                if step.fallthrough_helper_ref is None
                else step.fallthrough_helper_ref.local_block_id
            )
            != expected_helper
        ):
            raise ValueError("fragment operation PatchStep helper differs")
    normalizations = tuple(
        step for step in steps if isinstance(step, PatchFragmentOperationNormalization)
    )
    expected_normalized = tuple(
        operation
        for operation in fragment.operations
        if operation.computed_branch_normalization is not None
    )
    if tuple(
        operation for step in normalizations for operation in step.operations
    ) != expected_normalized or len(normalizations) != bool(expected_normalized):
        raise ValueError("fragment normalization PatchStep inventory differs")

    terminal_steps = tuple(
        step for step in steps if isinstance(step, PatchFragmentTerminalEffects)
    )
    expected_terminal_count = int(
        bool(
            fragment.return_carriers
            or fragment.terminal_returns
            or fragment.terminal_routes
        )
    )
    if len(terminal_steps) != expected_terminal_count:
        raise ValueError("fragment terminal PatchStep inventory differs")
    if terminal_steps and (
        terminal_steps[0].return_carriers != fragment.return_carriers
        or terminal_steps[0].terminal_returns != fragment.terminal_returns
        or terminal_steps[0].terminal_routes != fragment.terminal_routes
    ):
        raise ValueError("fragment terminal PatchStep payload differs")

    root_steps = tuple(
        step for step in steps if isinstance(step, PatchFragmentRootPublication)
    )
    inventory = contract.root_inventory.items
    if len(root_steps) != len(inventory):
        raise ValueError("fragment root PatchStep inventory differs")
    for step, item in zip(root_steps, inventory):
        root = fragment.block(item.root_block_id)
        expected_helper = (
            f"root-fallthrough-helper:{item.predecessor_block_id}:{item.root_block_id}"
            if item.requires_helper
            else None
        )
        if (
            step.root_ref.local_block_id != item.root_block_id
            or step.original_ref.local_block_id != item.original_block_id
            or root.replaces_block_id != item.original_block_id
            or step.predecessor_ref is None
            or step.predecessor_ref.local_block_id != item.predecessor_block_id
            or step.edge_role is not item.role
            or step.fallthrough_helper_id != expected_helper
            or (
                None
                if step.fallthrough_helper_ref is None
                else step.fallthrough_helper_ref.local_block_id
            )
            != expected_helper
        ):
            raise ValueError("fragment root PatchStep payload differs")

    recognized = (
        PatchFragmentBlockMaterialization,
        PatchFragmentOperationNormalization,
        PatchFragmentTerminalEffects,
        PatchFragmentOperation,
        PatchFragmentRootPublication,
    )
    if len(tuple(step for step in steps if isinstance(step, recognized))) != len(steps):
        raise ValueError("semantic PatchPlan contains a non-fragment operation")


def _iter_patch_refs(value: object):
    if isinstance(value, _PATCH_BLOCK_REF_TYPES):
        yield value
        return
    if isinstance(value, tuple):
        for item in value:
            yield from _iter_patch_refs(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _iter_patch_refs(key)
            yield from _iter_patch_refs(item)
        return
    if hasattr(value, "__dataclass_fields__"):
        for item in fields(value):
            if item.name.startswith("_"):
                continue
            yield from _iter_patch_refs(getattr(value, item.name))


@dataclass(frozen=True)
class PatchPlan:
    """Ordered backend-facing execution plan."""

    plan_id: str = field(default_factory=lambda: uuid4().hex)
    snapshot_id: str = field(default_factory=lambda: uuid4().hex)
    source_maturity: MaturityEnvelope | None = None
    source_generation: int | None = None
    steps: tuple[PatchStep, ...] = ()
    new_blocks: tuple[PatchBlockSpec, ...] = ()
    relocation_map: PatchRelocationMap = field(default_factory=PatchRelocationMap)
    execution_policy: ExecutionPolicy = ExecutionPolicy.STRICT
    metadata: tuple[tuple[str, object], ...] = ()
    semantic_contract: FragmentContractBundle | None = None
    source_coordinates: tuple[tuple[NativeBlockRef | LogicalBlockRef, int], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.plan_id, str) or not self.plan_id.strip():
            raise ValueError("PatchPlan requires a non-empty plan_id")
        if not isinstance(self.snapshot_id, str) or not self.snapshot_id.strip():
            raise ValueError("PatchPlan requires a non-empty snapshot_id")
        if self.source_maturity is not None and not isinstance(
            self.source_maturity, MaturityEnvelope
        ):
            raise TypeError("source_maturity must be a portable MaturityEnvelope")
        if self.source_generation is not None and (
            not isinstance(self.source_generation, int) or isinstance(self.source_generation, bool)
            or self.source_generation < 0
        ):
            raise TypeError("source_generation must be a non-negative integer")
        if self.semantic_contract is not None:
            if not isinstance(self.semantic_contract, FragmentContractBundle):
                raise TypeError("semantic_contract must be a FragmentContractBundle")
            if self.semantic_contract.fragment_plan.plan_id != self.plan_id:
                raise ValueError("semantic contract authority differs from PatchPlan")
            _validate_fragment_contract_steps(
                self.plan_id,
                tuple(self.steps),
                self.semantic_contract,
            )
        if any(
            not isinstance(ref, (NativeBlockRef, LogicalBlockRef))
            or not isinstance(serial, int)
            or isinstance(serial, bool)
            or serial < 0
            for ref, serial in self.source_coordinates
        ):
            raise TypeError("source coordinates require typed refs and non-negative coordinates")
        if len({ref for ref, _serial in self.source_coordinates}) != len(
            self.source_coordinates
        ):
            raise ValueError("source coordinates contain duplicate typed refs")
        refs = tuple(_iter_patch_refs((self.steps, self.new_blocks, self.relocation_map)))
        for ref in refs:
            if isinstance(ref, PlanBlockRef) and ref.plan_id != self.plan_id:
                raise ValueError("PatchPlan plan authority differs from PlanBlockRef")

    @property
    def concrete_operations(self) -> tuple[PatchOperation, ...]:
        return self.steps


    @property
    def contains_block_creation(self) -> bool:
        has_reorder = any(isinstance(s, PatchReorderBlocks) for s in self.steps)
        return bool(self.new_blocks or has_reorder)

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


LoweringInput: TypeAlias = PatchPlan


class _PlanRefAllocator:
    """Allocate deterministic symbolic block identifiers per plan build."""

    def __init__(self, plan_id: str) -> None:
        self._plan_id = plan_id
        self._next_ordinal = 0

    def alloc(self, namespace: str) -> PlanBlockRef:
        block_id = PlanBlockRef(
            plan_id=self._plan_id,
            local_block_id=f"{namespace}:{self._next_ordinal}",
        )
        self._next_ordinal += 1
        return block_id

    def peek(self, namespace: str) -> PlanBlockRef:
        return PlanBlockRef(
            plan_id=self._plan_id,
            local_block_id=f"{namespace}:{self._next_ordinal}",
        )


@dataclass(frozen=True)
class _PendingEdgeSplitTrampoline:
    modification: EdgeRedirectViaPredSplit
    block_id: PlanBlockRef


@dataclass(frozen=True)
class _PendingEdgeSplitCorridor:
    modification: EdgeRedirectViaPredSplit
    corridor_serials: tuple[int, ...]
    clone_block_ids: tuple[PlanBlockRef, ...]


@dataclass(frozen=True)
class _PendingConditionalRedirect:
    modification: CreateConditionalRedirect
    block_id: PlanBlockRef
    fallthrough_block_id: PlanBlockRef


@dataclass(frozen=True)
class _PendingInsertBlock:
    modification: InsertBlock
    block_id: PlanBlockRef


@dataclass(frozen=True)
class _PendingDuplicateBlock:
    modification: DuplicateBlock
    block_id: PlanBlockRef
    pred_redirect_kind: str
    source_successors: tuple[int, ...]
    conditional_target: int | None = None
    fallthrough_target: int | None = None
    fallthrough_block_id: PlanBlockRef | None = None


@dataclass(frozen=True)
class _PendingDuplicateReplayAndRedirect:
    modification: DuplicateReplayAndRedirect
    replay_block_ids: tuple[PlanBlockRef, ...]
    clone_block_ids: tuple[PlanBlockRef | None, ...]


@dataclass(frozen=True)
class _PendingCloneConditionalAsGoto:
    modification: CloneConditionalAsGoto
    block_id: PlanBlockRef
    source_successors: tuple[int, int]
    conditional_target: int
    fallthrough_target: int


@dataclass(frozen=True)
class _PendingCloneConditionalAsGotoFromBranchArm:
    modification: CloneConditionalAsGotoFromBranchArm
    block_id: PlanBlockRef
    source_successors: tuple[int, int]
    pred_successors: tuple[int, int]
    pred_branch_target_serial: int
    pred_fallthrough_target_serial: int
    conditional_target: int
    fallthrough_target: int


@dataclass(frozen=True)
class _PendingPrivateTerminalSuffix:
    modification: PrivateTerminalSuffix
    clone_block_ids: tuple[PlanBlockRef, ...]


@dataclass(frozen=True)
class _PendingPrivateTerminalSuffixGroup:
    modification: PrivateTerminalSuffixGroup
    per_anchor_clone_block_ids: tuple[tuple[PlanBlockRef, ...], ...]


@dataclass(frozen=True)
class _PendingExitPathLoweringGroup:
    modification: ExitPathLoweringGroup
    per_site_clone_block_ids: dict[int, tuple[PlanBlockRef, ...]]


@dataclass(frozen=True)
class _PendingReorderBlocks:
    """Pre-resolution ReorderBlocks with virtual block IDs (not yet concrete serials)."""
    dfs_block_order: tuple[int, ...]
    non_2way_serials: tuple[int, ...]
    virtual_ids: tuple[PlanBlockRef, ...]  # one per block in non_2way_serials, in order
    two_way_serials: tuple[int, ...] = ()
    two_way_virtual_id_pairs: tuple[tuple[PlanBlockRef, PlanBlockRef], ...] = ()


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
            ExitPathLoweringGroup,
        ),
    )


def _rewrite_block_ref(block_ref: PatchBlockRef, relocation_map: PatchRelocationMap) -> PatchBlockRef:
    if isinstance(block_ref, PlanBlockRef):
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
    return PatchRelocationMap(
        planned_lineage=tuple(
            (spec.block_id, spec.template_block)
            for spec in new_blocks
        ),
        source_stop=(None if cfg is None or not cfg.blocks else max(cfg.blocks)),
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


def _has_redirectable_conditional_tail(block: BlockSnapshot) -> bool:
    """Mirror the backend redirect predicate using portable snapshot semantics."""
    tail = block.tail
    return tail is not None and tail.kind in {
        InsnKind.COND_JUMP,
        InsnKind.EQUALITY_JUMP,
    }


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
    allocator: _PlanRefAllocator,
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
    allocator: _PlanRefAllocator,
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


def _compile_duplicate_block_step(
    modification: DuplicateBlock,
    cfg: FlowGraph,
    allocator: _PlanRefAllocator,
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
    fallthrough_block_id: PlanBlockRef | None = None

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
    allocator: _PlanRefAllocator,
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
    allocator: _PlanRefAllocator,
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
    replay_ids: list[PlanBlockRef] = []
    clone_ids: list[PlanBlockRef | None] = []
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
    step: PatchStep | _PendingEdgeSplitTrampoline | _PendingEdgeSplitCorridor | _PendingConditionalRedirect | _PendingInsertBlock | _PendingDuplicateBlock | _PendingDuplicateReplayAndRedirect | _PendingCloneConditionalAsGoto | _PendingCloneConditionalAsGotoFromBranchArm | _PendingPrivateTerminalSuffix | _PendingPrivateTerminalSuffixGroup | _PendingExitPathLoweringGroup | _PendingReorderBlocks,
    relocation_map: PatchRelocationMap,
) -> PatchStep:
    match step:
        case PatchRedirectBranch(
            from_serial=src,
            old_target=old,
            new_target=new,
            fallthrough_helper_block_id=helper_block_id,
        ):
            return PatchRedirectBranch(
                from_serial=src,
                old_target=relocation_map.rewrite_serial(old),
                new_target=relocation_map.rewrite_serial(new),
                fallthrough_helper_block_id=helper_block_id,
            )

        case PatchRedirectGoto(from_serial=src, old_target=old, new_target=new):
            return PatchRedirectGoto(
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
            return PatchEdgeSplitTrampoline(
                block_id=block_id,
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
            return PatchEdgeSplitCorridor(
                clone_block_ids=clone_ids,
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
            return PatchConditionalRedirect(
                block_id=block_id,
                fallthrough_block_id=fallthrough_block_id,
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
            return PatchInsertBlock(
                block_id=block_id,
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
            return PatchDuplicateBlock(
                block_id=block_id,
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
                finalized_replays.append(
                    PatchDuplicateReplayEntry(
                        pred_serial=entry.pred_serial,
                        target_serial=relocation_map.rewrite_serial(entry.target_serial),
                        replay_block_id=replay_id,
                        captured_body=entry.captured_body,
                        clone_block_id=clone_id,
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
            return PatchCloneConditionalAsGoto(
                block_id=block_id,
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
            return PatchCloneConditionalAsGotoFromBranchArm(
                block_id=block_id,
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
            return PatchPrivateTerminalSuffix(
                anchor_serial=anchor,
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                clone_block_ids=clone_ids,
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
            return PatchPrivateTerminalSuffixGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                anchors=anchors,
                per_anchor_clone_block_ids=per_anchor_ids,
            )

        case _PendingExitPathLoweringGroup(
            modification=ExitPathLoweringGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                sites=sites,
            ),
            per_site_clone_block_ids=per_site_ids,
        ):
            typed_sites = tuple(
                PatchExitPathLoweringSite(
                    anchor_serial=site.anchor_serial,
                    kind=site.kind,
                    const_value=site.const_value,
                    source_stkoff=site.source_stkoff,
                    source_mreg=site.source_mreg,
                    materializer_serials=site.materializer_serials,
                    skip_terminal_control_tail=site.skip_terminal_control_tail,
                )
                for site in sites
            )
            typed_per_site_ids: list[
                tuple[PatchBlockRef, tuple[PlanBlockRef, ...]]
            ] = []
            for anchor, clone_ids in per_site_ids.items():
                typed_anchor = _coerce_compiler_ref(anchor)
                _require_patch_ref(typed_anchor, "per-site anchor")
                typed_per_site_ids.append((typed_anchor, clone_ids))
            return PatchExitPathLoweringGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                sites=typed_sites,
                per_site_clone_block_ids=tuple(typed_per_site_ids),
            )

        case _PendingReorderBlocks(
            dfs_block_order=order,
            non_2way_serials=non_2way,
            virtual_ids=vids,
            two_way_serials=two_way,
            two_way_virtual_id_pairs=two_way_pairs,
        ):
            copy_lineage = list(zip(non_2way, vids))
            two_way_trampoline_lineage: list[tuple[PatchBlockRef, PlanBlockRef]] = []
            for old_serial, (copy_vid, tramp_vid) in zip(two_way, two_way_pairs):
                copy_lineage.append((old_serial, copy_vid))
                two_way_trampoline_lineage.append((old_serial, tramp_vid))

            _result = PatchReorderBlocks(
                dfs_block_order=order,
                non_2way_serials=non_2way,
                two_way_serials=two_way,
                copy_lineage=tuple(copy_lineage),
                two_way_trampoline_lineage=tuple(two_way_trampoline_lineage),
            )
            return _result

        case PatchReorderBlocks():
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
def _compile_patch_plan_impl(
    modifications: list[GraphModification],
    cfg: FlowGraph | None = None,
    execution_policy: ExecutionPolicy = ExecutionPolicy.STRICT,
    *,
    plan_id: str,
    snapshot_id: str,
    source_maturity: MaturityEnvelope | None,
    source_generation: int | None,
) -> PatchPlan:
    """Compile planner modifications into ordered PatchPlan steps."""
    allocator = _PlanRefAllocator(plan_id)
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
        | _PendingExitPathLoweringGroup
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
                if cfg is None:
                    raise ValueError(
                        "RedirectBranch compilation requires source FlowGraph authority"
                    )
                source_block = cfg.get_block(src)
                if source_block is None or source_block.nsucc != 2:
                    raise ValueError(
                        f"RedirectBranch source block {src} is not a live 2-way block"
                    )
                if not _has_redirectable_conditional_tail(source_block):
                    raise ValueError(
                        f"RedirectBranch source block {src} has no redirectable "
                        "conditional tail"
                    )
                conditional_target = _infer_conditional_target(source_block)
                if conditional_target is None:
                    raise ValueError(
                        f"RedirectBranch source block {src} has no explicit branch arm"
                    )
                fallthrough_target = _infer_fallthrough_target(
                    source_block,
                    conditional_target=conditional_target,
                )
                if old not in source_block.succs:
                    raise ValueError(
                        f"RedirectBranch old target {old} is not a successor of {src}"
                    )
                helper_block_id = None
                if old == fallthrough_target and old != conditional_target:
                    helper_block_id = allocator.alloc(
                        "redirect_branch_fallthrough"
                    )
                    new_blocks.append(
                        PatchBlockSpec(
                            block_id=helper_block_id,
                            kind="redirect_branch_fallthrough",
                            template_block=src,
                            incoming_edge=PatchEdgeRef(
                                source=src,
                                target=helper_block_id,
                            ),
                            outgoing_edges=(
                                PatchEdgeRef(
                                    source=helper_block_id,
                                    target=new,
                                ),
                            ),
                        )
                    )
                raw_steps.append(
                    PatchRedirectBranch(
                        from_serial=src,
                        old_target=old,
                        new_target=new,
                        fallthrough_helper_block_id=helper_block_id,
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
                state_register=state_register,
                state_size=state_size,
                false_state=false_state,
                true_state=true_state,
                false_state_write_ea=false_state_write_ea,
                true_state_write_ea=true_state_write_ea,
            ):
                raw_steps.append(PatchLowerConditionalStateTransition(
                    source_serial=src,
                    old_dispatcher_serial=dispatcher,
                    rewrite_from_ea=ea,
                    condition_operand=condition,
                    false_target_serial=false_target,
                    true_target_serial=true_target,
                    proof_id=proof_id,
                    state_register=state_register,
                    state_size=state_size,
                    false_state=false_state,
                    true_state=true_state,
                    false_state_write_ea=false_state_write_ea,
                    true_state_write_ea=true_state_write_ea,
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
                    raise ValueError(
                        "compile_patch_plan requires FlowGraph context for "
                        "CreateConditionalRedirect"
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
                    raise ValueError(
                        "compile_patch_plan requires FlowGraph context for InsertBlock"
                    )
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
                    raise ValueError(
                        "compile_patch_plan requires FlowGraph context for DuplicateBlock"
                    )
                else:
                    compiled_duplicate = _compile_duplicate_block_step(
                        modification,
                        cfg,
                        allocator,
                    )
                    if compiled_duplicate is None:
                        raise ValueError(
                            "DuplicateBlock cannot be compiled under the exact source snapshot"
                        )
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
                clone_ids: list[PlanBlockRef] = []
                for idx, suffix_serial in enumerate(suffix):
                    clone_id = allocator.alloc(f"private_suffix_a{anchor}")
                    clone_ids.append(clone_id)
                    # Build edges: last clone has no outgoing (0-way terminal);
                    # others chain to next clone.
                    if idx < len(suffix) - 1:
                        next_clone_id = allocator.peek(f"private_suffix_a{anchor}")
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
                per_anchor_clone_ids: list[tuple[PlanBlockRef, ...]] = []
                for anchor in anchors:
                    anchor_clone_ids: list[PlanBlockRef] = []
                    for idx, suffix_serial in enumerate(suffix):
                        clone_id = allocator.alloc(f"private_suffix_g_a{anchor}")
                        anchor_clone_ids.append(clone_id)
                        if idx < len(suffix) - 1:
                            next_clone_id = allocator.peek(
                                f"private_suffix_g_a{anchor}"
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

            case ExitPathLoweringGroup(
                shared_entry_serial=shared_entry,
                suffix_serials=suffix,
                sites=sites,
            ):
                if not suffix:
                    raise ValueError(
                        "ExitPathLoweringGroup requires non-empty suffix_serials"
                    )
                per_site_clone_ids: dict[int, tuple[PlanBlockRef, ...]] = {}
                for site in sites:
                    if site.kind is ExitPathLoweringKind.RETURN_CONST:
                        per_site_clone_ids[int(site.anchor_serial)] = ()
                        continue
                    clone_sources = tuple(
                        int(serial) for serial in site.materializer_serials
                    )
                    if not clone_sources:
                        clone_sources = tuple(int(serial) for serial in suffix[:-1])
                    if not clone_sources:
                        raise ValueError(
                            "ExitPathLoweringGroup requires materializer "
                            "blocks or a non-terminal suffix"
                        )
                    site_clone_ids: list[PlanBlockRef] = []
                    for idx, source_serial in enumerate(clone_sources):
                        clone_id = allocator.alloc(
                            f"direct_terminal_a{site.anchor_serial}"
                        )
                        site_clone_ids.append(clone_id)
                        if idx < len(clone_sources) - 1:
                            next_clone_id = allocator.peek(
                                f"direct_terminal_a{site.anchor_serial}"
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
                    _PendingExitPathLoweringGroup(
                        modification=modification,
                        per_site_clone_block_ids=per_site_clone_ids,
                    )
                )

            case ReorderBlocks(
                dfs_block_order=order,
                non_2way_serials=non_2way,
                two_way_serials=two_way,
            ):
                # Allocate one PlanBlockRef per non-2way block that will be copied
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

                two_way_pairs: list[tuple[PlanBlockRef, PlanBlockRef]] = []
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
    executable_source_refs = {
        ref
        for ref in _iter_patch_refs((steps, symbolic_specs, relocation_map))
        if isinstance(ref, (NativeBlockRef, LogicalBlockRef))
    }
    return PatchPlan(
        plan_id=plan_id,
        snapshot_id=snapshot_id,
        source_maturity=source_maturity,
        source_generation=source_generation,
        steps=steps,
        new_blocks=symbolic_specs,
        relocation_map=relocation_map,
        execution_policy=execution_policy,
        source_coordinates=tuple(
            (ref, int(serial))
            for serial, ref in sorted((_COMPILER_BLOCK_REFS.get() or {}).items())
            if ref in executable_source_refs
        ),
    )


def compile_patch_plan(
    modifications: list[GraphModification],
    cfg: FlowGraph | None = None,
    execution_policy: ExecutionPolicy = ExecutionPolicy.STRICT,
    *,
    plan_id: str | None = None,
    snapshot_id: str | None = None,
    source_maturity: MaturityEnvelope | None = None,
    source_generation: int | None = None,
    block_refs_by_serial: Mapping[int, NativeBlockRef | LogicalBlockRef] | None = None,
) -> PatchPlan:
    """Compile serial-local planner input into a typed immutable plan."""
    plan_id = plan_id or uuid4().hex
    if snapshot_id is None and cfg is not None:
        snapshot_value = cfg.metadata.get("snapshot_id")
        snapshot_id = (
            str(snapshot_value)
            if snapshot_value is not None and str(snapshot_value).strip()
            else f"flow-graph:{id(cfg):x}"
        )
    snapshot_id = snapshot_id or uuid4().hex
    block_refs_by_serial = dict(block_refs_by_serial or {})
    if any(
        not isinstance(ref, (NativeBlockRef, LogicalBlockRef))
        for ref in block_refs_by_serial.values()
    ):
        raise TypeError("source block authority requires native or logical references")
    token = _COMPILER_BLOCK_REFS.set(block_refs_by_serial)
    try:
        plan = _compile_patch_plan_impl(
            modifications,
            cfg,
            execution_policy,
            plan_id=plan_id,
            snapshot_id=snapshot_id,
            source_maturity=source_maturity,
            source_generation=source_generation,
        )
        return plan
    finally:
        _COMPILER_BLOCK_REFS.reset(token)


def ensure_patch_plan(lowering_input: LoweringInput) -> PatchPlan:
    """Validate the typed execution boundary without compatibility lowering."""
    if not isinstance(lowering_input, PatchPlan):
        raise TypeError("execution lowering requires PatchPlan")
    return lowering_input


# Keep the public compiler as the metadata-bearing API even though the
# authority-scoped wrapper delegates to the implementation above.
compile_patch_plan.__algorithm_metadata__ = (  # type: ignore[attr-defined]
    _compile_patch_plan_impl.__algorithm_metadata__  # type: ignore[attr-defined]
)


__all__ = [
    "ExecutionPolicy",
    "PlanBlockRef",
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
    "PatchExitPathLoweringGroup",
    "PatchReorderBlocks",
    "PatchOperation",
    "projected_source_coordinate",
    "PatchStep",
    "PatchPlan",
    "LoweringInput",
    "BlockCreatingGraphModification",
    "is_block_creating_modification",
    "compile_patch_plan",
    "ensure_patch_plan",
]
