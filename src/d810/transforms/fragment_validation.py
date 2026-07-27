"""Pure projected-state validation for detached semantic fragments.

The Hex-Rays backend lifts its unpublished staged graph into these serial-free
records.  Validation operates only on that projection and the portable
``FragmentPlan``.  Every postcondition produces a positive or negative outcome
so the diagnostic database can explain why publication was accepted or
aborted without reconstructing intent from text logs.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum

from d810.ir.block_identity import StableBlockIdentity
from d810.ir.flowgraph import BlockKind, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.fragment_plan import (
    FragmentBlockRole,
    FragmentBoundaryPort,
    FragmentBoundaryPortKind,
    FragmentDataFlowObligation,
    FragmentFlagCorridor,
    FragmentOperation,
    FragmentPlan,
    FragmentRangeAssumption,
    FragmentRangeObservation,
    FragmentReturnCarrier,
    FragmentTerminalReturn,
    FragmentValueSite,
    superseded_direct_transfer_carrier_block_ids,
    superseded_referenced_conditional_carrier_block_ids,
)


_BADADDR = 0xFFFFFFFFFFFFFFFF


def _identifier(value: str, description: str) -> str:
    value = str(value).strip()
    if not value:
        raise ValueError(f"{description} must not be empty")
    return value


def _native_ea(value: int, description: str) -> int:
    value = int(value)
    if not 0 <= value < _BADADDR:
        raise ValueError(f"{description} must be a native EA")
    return value


class FragmentBindingState(str, Enum):
    """Authority state represented by one projected physical realization."""

    PUBLISHED = "published"
    STAGED = "staged"


class FragmentValidationPostcondition(str, Enum):
    """Machine-queryable semantic acceptance conditions."""

    GRAPH_CLOSURE = "graph_closure"
    ROOT_REACHABILITY = "root_reachability"
    INTERNAL_CONNECTIVITY = "internal_connectivity"
    OPERATION_REACHABILITY = "operation_reachability"
    TEMPORARY_BOUNDARY_PORT = "temporary_boundary_port"
    ORIGINAL_SUPERSESSION = "original_supersession"
    DISPATCHER_ABSENCE = "dispatcher_absence"
    PRED_SUCC_SYMMETRY = "pred_succ_symmetry"
    BLOCK_TOPOLOGY = "block_topology"
    OPERATION_TOPOLOGY = "operation_topology"
    FALLTHROUGH_TOPOLOGY = "fallthrough_topology"
    TERMINAL_EFFECT_SCOPE = "terminal_effect_scope"
    RETURN_CARRIER_INTEGRITY = "return_carrier_integrity"
    TERMINAL_RETURN_INTEGRITY = "terminal_return_integrity"
    TERMINAL_ROUTE_ATOMICITY = "terminal_route_atomicity"
    USE_DEF_INTEGRITY = "use_def_integrity"
    DEF_USE_INTEGRITY = "def_use_integrity"
    FLAG_CORRIDOR_INTEGRITY = "flag_corridor_integrity"
    VALUE_RANGE_PROVEN = "value_range_proven"
    IDENTITY_OWNERSHIP = "identity_ownership"
    VERSION_LINEAGE = "version_lineage"
    POSTVALIDATION_SCOPE = "postvalidation_scope"
    ROOT_AUTHORITY = "root_authority"
    OBSERVABLE_OPERATION = "observable_operation"
    OBSERVABLE_RETURN_CARRIER = "observable_return_carrier"
    OBSERVABLE_TERMINAL_RETURN = "observable_terminal_return"
    OBSERVABLE_FALLTHROUGH_HELPER = "observable_fallthrough_helper"
    POSTVALIDATION_COVERAGE = "postvalidation_coverage"


@dataclass(frozen=True, slots=True)
class ProjectedFragmentBlock:
    """One unpublished post-publication block projection."""

    block_id: str
    kind: BlockKind
    successors: tuple[str, ...]
    predecessors: tuple[str, ...]
    physical_position: int
    adjacent_fallthrough_target_id: str | None
    terminator_ea: int | None
    terminator_kind: InsnKind
    instruction_eas: tuple[int, ...] = ()
    flag_write_eas: frozenset[int] = frozenset()

    def __post_init__(self) -> None:
        block_id = _identifier(self.block_id, "projected fragment block id")
        if not isinstance(self.kind, BlockKind):
            raise TypeError("projected fragment block requires a BlockKind")
        successors = tuple(
            _identifier(value, "projected successor") for value in self.successors
        )
        predecessors = tuple(
            _identifier(value, "projected predecessor") for value in self.predecessors
        )
        physical_position = int(self.physical_position)
        if physical_position < 0:
            raise ValueError("projected physical position must be non-negative")
        adjacent_fallthrough_target_id = (
            None
            if self.adjacent_fallthrough_target_id is None
            else _identifier(
                self.adjacent_fallthrough_target_id,
                "projected adjacent fallthrough target",
            )
        )
        instruction_eas = tuple(
            _native_ea(value, "projected instruction") for value in self.instruction_eas
        )
        if len(set(instruction_eas)) != len(instruction_eas):
            raise ValueError("projected instruction order contains duplicate EAs")
        flag_write_eas = frozenset(
            _native_ea(value, "projected flag write") for value in self.flag_write_eas
        )
        if not flag_write_eas.issubset(instruction_eas):
            raise ValueError("projected flag writes must be projected instructions")
        terminator_ea = (
            None
            if self.terminator_ea is None
            else _native_ea(self.terminator_ea, "projected terminator")
        )
        if not isinstance(self.terminator_kind, InsnKind):
            raise TypeError("projected terminator requires an InsnKind")
        if terminator_ea is not None and (
            not instruction_eas or terminator_ea != instruction_eas[-1]
        ):
            raise ValueError(
                "projected terminator must be the final projected instruction: "
                f"{block_id} terminator=0x{terminator_ea:X} "
                f"instructions={tuple(hex(ea) for ea in instruction_eas)!r}"
            )
        object.__setattr__(self, "block_id", block_id)
        object.__setattr__(self, "successors", successors)
        object.__setattr__(self, "predecessors", predecessors)
        object.__setattr__(self, "physical_position", physical_position)
        object.__setattr__(
            self,
            "adjacent_fallthrough_target_id",
            adjacent_fallthrough_target_id,
        )
        object.__setattr__(self, "instruction_eas", instruction_eas)
        object.__setattr__(self, "flag_write_eas", flag_write_eas)
        object.__setattr__(self, "terminator_ea", terminator_ea)


@dataclass(frozen=True, slots=True)
class ProjectedIdentityBinding:
    """Serial-free logical owner and version bound to one projected block."""

    block_id: str
    logical_owner_id: str
    version: int
    generation: int
    state: FragmentBindingState
    stable_identity: StableBlockIdentity | None
    previous_version: int | None = None

    def __post_init__(self) -> None:
        block_id = _identifier(self.block_id, "projected binding block id")
        logical_owner_id = _identifier(
            self.logical_owner_id,
            "projected logical owner id",
        )
        version = int(self.version)
        generation = int(self.generation)
        previous_version = (
            None if self.previous_version is None else int(self.previous_version)
        )
        if version < 0 or generation < 0:
            raise ValueError(
                "projected binding version and generation must be non-negative"
            )
        if previous_version is not None and previous_version < 0:
            raise ValueError("projected predecessor version must be non-negative")
        if not isinstance(self.state, FragmentBindingState):
            raise TypeError("projected binding requires a FragmentBindingState")
        if self.stable_identity is not None and not isinstance(
            self.stable_identity,
            StableBlockIdentity,
        ):
            raise TypeError("projected binding stable identity has the wrong type")
        object.__setattr__(self, "block_id", block_id)
        object.__setattr__(self, "logical_owner_id", logical_owner_id)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "previous_version", previous_version)


@dataclass(frozen=True, slots=True)
class ProjectedDataFlowRelation:
    """One projected reaching-definition relation."""

    value_id: str
    definition_site_id: str
    use_site_id: str
    use_def_observed: bool
    def_use_observed: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "value_id",
            _identifier(self.value_id, "projected data-flow value id"),
        )
        object.__setattr__(
            self,
            "definition_site_id",
            _identifier(
                self.definition_site_id,
                "projected definition site id",
            ),
        )
        object.__setattr__(
            self,
            "use_site_id",
            _identifier(self.use_site_id, "projected use site id"),
        )
        if not isinstance(self.use_def_observed, bool) or not isinstance(
            self.def_use_observed,
            bool,
        ):
            raise TypeError("projected data-flow direction flags must be booleans")
        if not self.use_def_observed and not self.def_use_observed:
            raise ValueError(
                "projected data-flow relation requires an observed direction"
            )


@dataclass(frozen=True, slots=True)
class ProjectedRangeFact:
    """Inclusive range proven for one projected value site."""

    site_id: str
    value_id: str
    observation: FragmentRangeObservation
    lo: int | None = None
    hi: int | None = None

    def __post_init__(self) -> None:
        site_id = _identifier(self.site_id, "projected range site id")
        value_id = _identifier(self.value_id, "projected range value id")
        if not isinstance(self.observation, FragmentRangeObservation):
            raise TypeError("projected range fact requires an instruction observation")
        lo = None if self.lo is None else int(self.lo)
        hi = None if self.hi is None else int(self.hi)
        if lo is None and hi is None:
            raise ValueError("projected range fact requires at least one bound")
        if lo is not None and hi is not None and lo > hi:
            raise ValueError("projected range lower bound exceeds upper bound")
        if any(bound is not None and bound < 0 for bound in (lo, hi)):
            raise ValueError("projected range bounds must be unsigned")
        object.__setattr__(self, "site_id", site_id)
        object.__setattr__(self, "value_id", value_id)
        object.__setattr__(self, "lo", lo)
        object.__setattr__(self, "hi", hi)


@dataclass(frozen=True, slots=True)
class ProjectedTerminalEffectDiagnostic:
    """Portable explanation for one failed live terminal-effect observation."""

    effect_id: str
    reason: str

    def __post_init__(self) -> None:
        effect_id = _identifier(
            self.effect_id,
            "projected terminal-effect diagnostic id",
        )
        reason = str(self.reason).strip()
        if not reason:
            raise ValueError(
                "projected terminal-effect diagnostic reason must not be empty"
            )
        object.__setattr__(self, "effect_id", effect_id)
        object.__setattr__(self, "reason", reason)


@dataclass(frozen=True, slots=True)
class ProjectedFallthroughHelper:
    """Backend-owned adjacent helper for one semantic fallthrough arm."""

    helper_block_id: str
    operation_id: str
    source_block_id: str
    semantic_target_block_id: str

    def __post_init__(self) -> None:
        for field_name, description in (
            ("helper_block_id", "projected fallthrough helper block"),
            ("operation_id", "projected fallthrough operation"),
            ("source_block_id", "projected fallthrough source"),
            ("semantic_target_block_id", "projected fallthrough target"),
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), description),
            )


@dataclass(frozen=True, slots=True)
class ProjectedRootFallthroughHelper:
    """Adjacent helper required to publish one physical root fallthrough."""

    helper_block_id: str
    source_block_id: str
    root_block_id: str

    def __post_init__(self) -> None:
        for field_name, description in (
            ("helper_block_id", "projected root fallthrough helper block"),
            ("source_block_id", "projected root fallthrough source"),
            ("root_block_id", "projected root fallthrough target"),
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), description),
            )


@dataclass(frozen=True, slots=True)
class ProjectedFragment:
    """Complete serial-free graph and semantic projection of a staged fragment."""

    entry_block_id: str
    blocks: tuple[ProjectedFragmentBlock, ...]
    identity_bindings: tuple[ProjectedIdentityBinding, ...]
    fallthrough_helpers: tuple[ProjectedFallthroughHelper, ...] = ()
    root_fallthrough_helpers: tuple[ProjectedRootFallthroughHelper, ...] = ()
    return_carriers: tuple[FragmentReturnCarrier, ...] = ()
    terminal_returns: tuple[FragmentTerminalReturn, ...] = ()
    terminal_effect_diagnostics: tuple[ProjectedTerminalEffectDiagnostic, ...] = ()
    data_flow_relations: tuple[ProjectedDataFlowRelation, ...] = ()
    value_ranges: tuple[ProjectedRangeFact, ...] = ()

    def __post_init__(self) -> None:
        entry_block_id = _identifier(
            self.entry_block_id,
            "projected fragment entry block",
        )
        blocks = tuple(self.blocks)
        identity_bindings = tuple(self.identity_bindings)
        fallthrough_helpers = tuple(self.fallthrough_helpers)
        root_fallthrough_helpers = tuple(self.root_fallthrough_helpers)
        return_carriers = tuple(self.return_carriers)
        terminal_returns = tuple(self.terminal_returns)
        terminal_effect_diagnostics = tuple(self.terminal_effect_diagnostics)
        data_flow_relations = tuple(self.data_flow_relations)
        value_ranges = tuple(self.value_ranges)
        if any(not isinstance(block, ProjectedFragmentBlock) for block in blocks):
            raise TypeError("projection contains an invalid block")
        if any(
            not isinstance(binding, ProjectedIdentityBinding)
            for binding in identity_bindings
        ):
            raise TypeError("projection contains an invalid identity binding")
        if any(
            not isinstance(helper, ProjectedFallthroughHelper)
            for helper in fallthrough_helpers
        ):
            raise TypeError("projection contains an invalid fallthrough helper")
        if any(
            not isinstance(helper, ProjectedRootFallthroughHelper)
            for helper in root_fallthrough_helpers
        ):
            raise TypeError("projection contains an invalid root fallthrough helper")
        if any(
            not isinstance(carrier, FragmentReturnCarrier)
            for carrier in return_carriers
        ):
            raise TypeError("projection contains an invalid return carrier")
        if any(
            not isinstance(terminal_return, FragmentTerminalReturn)
            for terminal_return in terminal_returns
        ):
            raise TypeError("projection contains an invalid terminal return")
        if any(
            not isinstance(diagnostic, ProjectedTerminalEffectDiagnostic)
            for diagnostic in terminal_effect_diagnostics
        ):
            raise TypeError("projection contains an invalid terminal-effect diagnostic")
        if any(
            not isinstance(relation, ProjectedDataFlowRelation)
            for relation in data_flow_relations
        ):
            raise TypeError("projection contains an invalid data-flow relation")
        if any(not isinstance(fact, ProjectedRangeFact) for fact in value_ranges):
            raise TypeError("projection contains an invalid range fact")
        object.__setattr__(self, "entry_block_id", entry_block_id)
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(self, "identity_bindings", identity_bindings)
        object.__setattr__(self, "fallthrough_helpers", fallthrough_helpers)
        object.__setattr__(
            self,
            "root_fallthrough_helpers",
            root_fallthrough_helpers,
        )
        object.__setattr__(self, "return_carriers", return_carriers)
        object.__setattr__(self, "terminal_returns", terminal_returns)
        object.__setattr__(
            self,
            "terminal_effect_diagnostics",
            terminal_effect_diagnostics,
        )
        object.__setattr__(self, "data_flow_relations", data_flow_relations)
        object.__setattr__(self, "value_ranges", value_ranges)

    def block(self, block_id: str) -> ProjectedFragmentBlock:
        block_id = str(block_id)
        for block in self.blocks:
            if block.block_id == block_id:
                return block
        raise KeyError(block_id)

    def binding(self, block_id: str) -> ProjectedIdentityBinding:
        block_id = str(block_id)
        for binding in self.identity_bindings:
            if binding.block_id == block_id:
                return binding
        raise KeyError(block_id)


@dataclass(frozen=True, slots=True)
class FragmentValidationOutcome:
    """One positive or negative semantic postcondition result."""

    postcondition: FragmentValidationPostcondition
    subject_id: str
    passed: bool
    reason: str
    block_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.postcondition, FragmentValidationPostcondition):
            raise TypeError("validation outcome requires a postcondition")
        object.__setattr__(
            self,
            "subject_id",
            _identifier(self.subject_id, "fragment validation subject"),
        )
        object.__setattr__(self, "passed", bool(self.passed))
        object.__setattr__(self, "reason", str(self.reason))
        object.__setattr__(
            self,
            "block_ids",
            tuple(str(block_id) for block_id in self.block_ids),
        )


@dataclass(frozen=True, slots=True)
class FragmentValidationResult:
    """All pre-publication semantic outcomes for one fragment."""

    plan_id: str
    atomic_group_id: str
    outcomes: tuple[FragmentValidationOutcome, ...]

    @property
    def passed(self) -> bool:
        return bool(self.outcomes) and all(outcome.passed for outcome in self.outcomes)

    @property
    def failures(self) -> tuple[FragmentValidationOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if not outcome.passed)


@dataclass(frozen=True, slots=True)
class PublishedFragmentObservation:
    """Read-only observable semantics after root publication.

    The backend reports semantic operation identities and validation outcomes,
    not physical block survival.  This allows an optimizer to coalesce or
    delete staged blocks while preserving the predicate, destinations, data
    flow, and terminal behavior required by the plan.
    """

    plan_id: str
    atomic_group_id: str
    published_root_ids: tuple[str, ...]
    observable_operations: tuple[FragmentOperation, ...]
    semantic_outcomes: tuple[FragmentValidationOutcome, ...]
    fallthrough_helpers: tuple[ProjectedFallthroughHelper, ...]
    root_fallthrough_helpers: tuple[ProjectedRootFallthroughHelper, ...]
    observable_return_carriers: tuple[FragmentReturnCarrier, ...] = ()
    observable_terminal_returns: tuple[FragmentTerminalReturn, ...] = ()

    def __post_init__(self) -> None:
        plan_id = _identifier(self.plan_id, "published fragment plan id")
        atomic_group_id = _identifier(
            self.atomic_group_id,
            "published fragment atomic group id",
        )
        published_root_ids = tuple(
            _identifier(root, "published fragment root")
            for root in self.published_root_ids
        )
        observable_operations = tuple(self.observable_operations)
        semantic_outcomes = tuple(self.semantic_outcomes)
        fallthrough_helpers = tuple(self.fallthrough_helpers)
        root_fallthrough_helpers = tuple(self.root_fallthrough_helpers)
        observable_return_carriers = tuple(self.observable_return_carriers)
        observable_terminal_returns = tuple(self.observable_terminal_returns)
        if any(
            not isinstance(operation, FragmentOperation)
            for operation in observable_operations
        ):
            raise TypeError("published fragment contains an invalid operation")
        if any(
            not isinstance(outcome, FragmentValidationOutcome)
            for outcome in semantic_outcomes
        ):
            raise TypeError("published fragment contains an invalid outcome")
        if any(
            not isinstance(helper, ProjectedFallthroughHelper)
            for helper in fallthrough_helpers
        ):
            raise TypeError("published fragment contains an invalid fallthrough helper")
        if any(
            not isinstance(helper, ProjectedRootFallthroughHelper)
            for helper in root_fallthrough_helpers
        ):
            raise TypeError(
                "published fragment contains an invalid root fallthrough helper"
            )
        if any(
            not isinstance(carrier, FragmentReturnCarrier)
            for carrier in observable_return_carriers
        ):
            raise TypeError(
                "published fragment contains an invalid observable return carrier"
            )
        if any(
            not isinstance(terminal_return, FragmentTerminalReturn)
            for terminal_return in observable_terminal_returns
        ):
            raise TypeError(
                "published fragment contains an invalid observable terminal return"
            )
        object.__setattr__(self, "plan_id", plan_id)
        object.__setattr__(self, "atomic_group_id", atomic_group_id)
        object.__setattr__(self, "published_root_ids", published_root_ids)
        object.__setattr__(self, "observable_operations", observable_operations)
        object.__setattr__(self, "semantic_outcomes", semantic_outcomes)
        object.__setattr__(self, "fallthrough_helpers", fallthrough_helpers)
        object.__setattr__(
            self,
            "root_fallthrough_helpers",
            root_fallthrough_helpers,
        )
        object.__setattr__(
            self,
            "observable_return_carriers",
            observable_return_carriers,
        )
        object.__setattr__(
            self,
            "observable_terminal_returns",
            observable_terminal_returns,
        )


@dataclass(frozen=True, slots=True)
class PublishedFragmentGraphObservation:
    """One live post-root graph read and its derived semantic observation."""

    projection: ProjectedFragment
    semantics: PublishedFragmentObservation

    def __post_init__(self) -> None:
        if not isinstance(self.projection, ProjectedFragment):
            raise TypeError("published graph observation requires ProjectedFragment")
        if not isinstance(self.semantics, PublishedFragmentObservation):
            raise TypeError(
                "published graph observation requires PublishedFragmentObservation"
            )


def _outcome(
    outcomes: list[FragmentValidationOutcome],
    postcondition: FragmentValidationPostcondition,
    subject_id: str,
    passed: bool,
    reason: str,
    *block_ids: str,
) -> None:
    outcomes.append(
        FragmentValidationOutcome(
            postcondition=postcondition,
            subject_id=subject_id,
            passed=passed,
            reason=reason,
            block_ids=tuple(block_ids),
        )
    )


def _reachable(
    blocks: dict[str, ProjectedFragmentBlock],
    roots: tuple[str, ...],
) -> frozenset[str]:
    visited: set[str] = set()
    queue = deque(root for root in roots if root in blocks)
    while queue:
        block_id = queue.popleft()
        if block_id in visited:
            continue
        block = blocks.get(block_id)
        if block is None:
            continue
        visited.add(block_id)
        queue.extend(target for target in block.successors if target not in visited)
    return frozenset(visited)


def _reachability_witness(
    blocks: dict[str, ProjectedFragmentBlock],
    root: str,
    target: str,
) -> tuple[str, ...]:
    """Return one deterministic shortest path through the projected graph."""
    if root not in blocks or target not in blocks:
        return ()
    predecessors: dict[str, str | None] = {root: None}
    queue = deque((root,))
    while queue:
        block_id = queue.popleft()
        if block_id == target:
            path: list[str] = []
            cursor: str | None = target
            while cursor is not None:
                path.append(cursor)
                cursor = predecessors[cursor]
            return tuple(reversed(path))
        for successor in blocks[block_id].successors:
            if successor in blocks and successor not in predecessors:
                predecessors[successor] = block_id
                queue.append(successor)
    return ()


def _boundary_port_entry_witness(
    port: FragmentBoundaryPort,
    projection: ProjectedFragment,
    blocks: dict[str, ProjectedFragmentBlock],
) -> tuple[str, ...]:
    """Prove one exact temporary predecessor-to-root attachment."""
    if port.kind is not FragmentBoundaryPortKind.TEMPORARY_DISPATCHER_ENTRY:
        return ()
    predecessor = blocks.get(port.source_block_id)
    root = blocks.get(port.target_block_id)
    if predecessor is None or root is None:
        return ()
    if (
        port.target_block_id in predecessor.successors
        and port.source_block_id in root.predecessors
    ):
        return (port.source_block_id, port.target_block_id)
    matching_helpers = tuple(
        helper
        for helper in projection.root_fallthrough_helpers
        if helper.source_block_id == port.source_block_id
        and helper.root_block_id == port.target_block_id
    )
    if len(matching_helpers) != 1:
        return ()
    (helper,) = matching_helpers
    helper_block = blocks.get(helper.helper_block_id)
    if (
        helper_block is None
        or helper.helper_block_id not in predecessor.successors
        or port.source_block_id not in helper_block.predecessors
        or port.target_block_id not in helper_block.successors
        or helper.helper_block_id not in root.predecessors
    ):
        return ()
    return (
        port.source_block_id,
        helper.helper_block_id,
        port.target_block_id,
    )


def _boundary_port_egress_witness(
    port: FragmentBoundaryPort,
    plan: FragmentPlan,
    projection: ProjectedFragment,
    blocks: dict[str, ProjectedFragmentBlock],
) -> tuple[str, ...]:
    """Prove one exact staged-operation-to-published-target egress."""
    if port.kind is not FragmentBoundaryPortKind.TEMPORARY_DISPATCHER_EGRESS:
        return ()
    source = blocks.get(port.source_block_id)
    target = blocks.get(port.target_block_id)
    if source is None or target is None:
        return ()
    operation = next(
        (
            operation
            for operation in plan.operations
            if operation.source_block_id == port.source_block_id
            and any(
                edge.target_block_id == port.target_block_id for edge in operation.edges
            )
        ),
        None,
    )
    if operation is None:
        return ()
    if (
        port.target_block_id in source.successors
        and port.source_block_id in target.predecessors
    ):
        return (port.source_block_id, port.target_block_id)
    matching_helpers = tuple(
        helper
        for helper in projection.fallthrough_helpers
        if helper.operation_id == operation.operation_id
        and helper.source_block_id == port.source_block_id
        and helper.semantic_target_block_id == port.target_block_id
    )
    if len(matching_helpers) != 1:
        return ()
    (helper,) = matching_helpers
    helper_block = blocks.get(helper.helper_block_id)
    if (
        helper_block is None
        or helper.helper_block_id not in source.successors
        or port.source_block_id not in helper_block.predecessors
        or port.target_block_id not in helper_block.successors
        or helper.helper_block_id not in target.predecessors
    ):
        return ()
    return (
        port.source_block_id,
        helper.helper_block_id,
        port.target_block_id,
    )


def _validate_boundary_ports(
    plan: FragmentPlan,
    projection: ProjectedFragment,
    blocks: dict[str, ProjectedFragmentBlock],
    outcomes: list[FragmentValidationOutcome],
) -> None:
    for port in plan.boundary_ports:
        witness = (
            _boundary_port_entry_witness(port, projection, blocks)
            if port.kind is FragmentBoundaryPortKind.TEMPORARY_DISPATCHER_ENTRY
            else _boundary_port_egress_witness(port, plan, projection, blocks)
        )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.TEMPORARY_BOUNDARY_PORT,
            port.port_id,
            bool(witness),
            (
                f"typed {port.kind.value} has exact projected topology; "
                f"retirement obligation {port.retirement_obligation_id} remains"
                if witness
                else f"typed {port.kind.value} lacks its exact projected topology"
            ),
            *(witness or (port.source_block_id, port.target_block_id)),
        )


def _projected_publication_authority_roots(
    plan: FragmentPlan,
    projection: ProjectedFragment,
    blocks: dict[str, ProjectedFragmentBlock],
) -> tuple[str, ...]:
    """Return entry authorities whose exact projected attachment is proven."""
    return tuple(
        dict.fromkeys(
            (
                projection.entry_block_id,
                *(
                    port.source_block_id
                    for port in plan.boundary_ports
                    if _boundary_port_entry_witness(port, projection, blocks)
                ),
            )
        )
    )


def projected_publication_authority_roots(
    plan: FragmentPlan,
    projection: ProjectedFragment,
) -> tuple[str, ...]:
    """Normalize literal entry and validated typed ports as entry authority."""
    if not isinstance(plan, FragmentPlan):
        raise TypeError("publication authority roots require a FragmentPlan")
    if not isinstance(projection, ProjectedFragment):
        raise TypeError("publication authority roots require a ProjectedFragment")
    blocks = {block.block_id: block for block in projection.blocks}
    return _projected_publication_authority_roots(plan, projection, blocks)


def _site_present(
    site: FragmentValueSite,
    blocks: dict[str, ProjectedFragmentBlock],
) -> bool:
    block = blocks.get(site.block_id)
    return bool(block is not None and site.instruction_ea in block.instruction_eas)


def _is_opaque_boundary_endpoint(block_id: str) -> bool:
    return block_id.startswith(("unowned@", "unowned:"))


def _validate_graph(
    projection: ProjectedFragment,
    blocks: dict[str, ProjectedFragmentBlock],
    outcomes: list[FragmentValidationOutcome],
) -> None:
    block_ids = tuple(block.block_id for block in projection.blocks)
    binding_lists: dict[str, list[ProjectedIdentityBinding]] = {}
    for binding in projection.identity_bindings:
        binding_lists.setdefault(binding.block_id, []).append(binding)
    binding_states = {
        block_id: bindings[0].state
        for block_id, bindings in binding_lists.items()
        if len(bindings) == 1
    }

    def permits_opaque_boundary(block_id: str, endpoint: str) -> bool:
        return binding_states.get(
            block_id
        ) is FragmentBindingState.PUBLISHED and _is_opaque_boundary_endpoint(endpoint)

    references_closed = (
        len(blocks) == len(projection.blocks)
        and projection.entry_block_id in blocks
        and all(
            target in blocks or permits_opaque_boundary(block.block_id, target)
            for block in projection.blocks
            for target in (*block.successors, *block.predecessors)
        )
    )
    _outcome(
        outcomes,
        FragmentValidationPostcondition.GRAPH_CLOSURE,
        "projection",
        references_closed,
        "all staged graph references are closed and published boundaries are explicit"
        if references_closed
        else "projection has duplicate blocks, a missing entry, or an unowned staged edge endpoint",
        *block_ids,
    )

    positions = tuple(block.physical_position for block in projection.blocks)
    unique_positions = len(set(positions)) == len(positions)
    shape_valid = True
    malformed: list[str] = []
    for block in projection.blocks:
        successor_count = len(block.successors)
        expected_successor_count = {
            BlockKind.NONE: 0,
            BlockKind.STOP: 0,
            BlockKind.EXTERNAL: 0,
            BlockKind.ZERO_WAY: 0,
            BlockKind.ONE_WAY: 1,
            BlockKind.TWO_WAY: 2,
        }.get(block.kind)
        valid = (
            successor_count >= 2
            if block.kind is BlockKind.N_WAY
            else expected_successor_count is not None
            and successor_count == expected_successor_count
        )
        valid = valid and len(set(block.successors)) == successor_count
        valid = valid and len(set(block.predecessors)) == len(block.predecessors)
        if not valid:
            shape_valid = False
            malformed.append(block.block_id)
    _outcome(
        outcomes,
        FragmentValidationPostcondition.BLOCK_TOPOLOGY,
        "projection",
        shape_valid and unique_positions,
        "block kinds, edges, and physical positions are coherent"
        if shape_valid and unique_positions
        else "block kind, duplicate edge, or physical-position invariant failed",
        *malformed,
    )

    symmetry_valid = True
    asymmetric: set[str] = set()
    for block in projection.blocks:
        for successor in block.successors:
            target = blocks.get(successor)
            if target is None and permits_opaque_boundary(block.block_id, successor):
                continue
            if target is None or block.block_id not in target.predecessors:
                symmetry_valid = False
                asymmetric.update((block.block_id, successor))
        for predecessor in block.predecessors:
            source = blocks.get(predecessor)
            if source is None and permits_opaque_boundary(block.block_id, predecessor):
                continue
            if source is None or block.block_id not in source.successors:
                symmetry_valid = False
                asymmetric.update((predecessor, block.block_id))
    _outcome(
        outcomes,
        FragmentValidationPostcondition.PRED_SUCC_SYMMETRY,
        "projection",
        symmetry_valid,
        "every successor and predecessor relation is reciprocal"
        if symmetry_valid
        else "projected predecessor/successor relation is asymmetric",
        *sorted(asymmetric),
    )

    blocks_by_position = {block.physical_position: block for block in projection.blocks}
    entry_reachable = _reachable(blocks, (projection.entry_block_id,))
    for block in projection.blocks:
        if block.kind is not BlockKind.TWO_WAY:
            continue
        if (
            binding_states.get(block.block_id) is FragmentBindingState.PUBLISHED
            and block.block_id not in entry_reachable
        ):
            _outcome(
                outcomes,
                FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY,
                block.block_id,
                True,
                "unreachable published conditional is outside staged fallthrough topology",
                block.block_id,
            )
            continue
        adjacent = blocks_by_position.get(block.physical_position + 1)
        fallthrough_target = None if not block.successors else block.successors[0]
        opaque_adjacent = bool(
            fallthrough_target is not None
            and permits_opaque_boundary(block.block_id, fallthrough_target)
        )
        passed = bool(
            len(block.successors) == 2
            and block.adjacent_fallthrough_target_id == fallthrough_target
            and (
                (adjacent is not None and fallthrough_target == adjacent.block_id)
                or (adjacent is None and opaque_adjacent)
            )
        )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY,
            block.block_id,
            passed,
            "two-way physical fallthrough witness matches the adjacent first successor"
            if passed
            else (
                "two-way physical fallthrough witness is missing, "
                "nonadjacent, or misordered"
            ),
            block.block_id,
            "" if adjacent is None else adjacent.block_id,
        )


def _validate_reachability(
    plan: FragmentPlan,
    blocks: dict[str, ProjectedFragmentBlock],
    projection: ProjectedFragment,
    outcomes: list[FragmentValidationOutcome],
    *,
    include_detached_native_body_roots: bool,
) -> None:
    entry_reachable = _reachable(blocks, (projection.entry_block_id,))
    publication_authority_roots = _projected_publication_authority_roots(
        plan,
        projection,
        blocks,
    )
    boundary_port_predecessors = publication_authority_roots[1:]
    publication_reachable = _reachable(blocks, publication_authority_roots)
    connectivity_roots = (
        (
            *plan.roots,
            *(
                entry_block_id
                for native_body in plan.native_bodies
                for entry_block_id in native_body.entry_block_ids
            ),
        )
        if include_detached_native_body_roots
        else publication_authority_roots
    )
    fragment_reachable = _reachable(blocks, connectivity_roots)
    connectivity_authority = (
        "a publication or native-body root"
        if include_detached_native_body_roots
        else (
            "the projected function entry or a typed temporary boundary port"
            if boundary_port_predecessors
            else "the projected function entry"
        )
    )
    disconnected_authority = (
        "all publication and native-body roots"
        if include_detached_native_body_roots
        else (
            "the projected function entry and typed temporary boundary ports"
            if boundary_port_predecessors
            else "the projected function entry"
        )
    )
    for root in plan.roots:
        reachable_port = next(
            (
                (port, witness)
                for port in plan.boundary_ports
                if port.target_block_id == root
                and (
                    witness := _boundary_port_entry_witness(
                        port,
                        projection,
                        blocks,
                    )
                )
            ),
            None,
        )
        entry_reaches_root = root in entry_reachable
        passed = entry_reaches_root or reachable_port is not None
        if entry_reaches_root:
            reason = "publication root is reachable from projected function entry"
            root_witness = (root,)
        elif reachable_port is not None:
            port, root_witness = reachable_port
            reason = (
                f"publication root is reachable from typed boundary port "
                f"{port.port_id}; retirement obligation "
                f"{port.retirement_obligation_id} remains"
            )
        else:
            reason = (
                "publication root is unreachable from projected function entry "
                "and typed boundary ports"
                if boundary_port_predecessors
                else "publication root is unreachable from projected function entry"
            )
            root_witness = (root,)
        _outcome(
            outcomes,
            FragmentValidationPostcondition.ROOT_REACHABILITY,
            root,
            passed,
            reason,
            *root_witness,
        )
    superseded_carrier_block_ids = superseded_direct_transfer_carrier_block_ids(
        plan
    ) | superseded_referenced_conditional_carrier_block_ids(plan)
    for block in plan.blocks:
        if block.role not in {
            FragmentBlockRole.REPLACEMENT,
            FragmentBlockRole.SYNTHETIC,
            FragmentBlockRole.IMPORTED,
        }:
            continue
        connected = block.block_id in fragment_reachable
        superseded_carrier = block.block_id in superseded_carrier_block_ids
        passed = connected or superseded_carrier
        _outcome(
            outcomes,
            FragmentValidationPostcondition.INTERNAL_CONNECTIVITY,
            block.block_id,
            passed,
            (
                "staged fragment block is an evidence-only carrier for a typed "
                "superseded direct transfer"
                if superseded_carrier
                else f"staged fragment block is connected to {connectivity_authority}"
            )
            if passed
            else f"staged fragment block is disconnected from {disconnected_authority}",
            block.block_id,
        )
    for operation in plan.operations:
        passed = operation.source_block_id in fragment_reachable
        _outcome(
            outcomes,
            FragmentValidationPostcondition.OPERATION_REACHABILITY,
            operation.operation_id,
            passed,
            f"required operation is reachable from {connectivity_authority}"
            if passed
            else (f"required operation is unreachable from {disconnected_authority}"),
            operation.source_block_id,
        )
    for original in plan.owned_originals:
        passed = original not in publication_reachable
        _outcome(
            outcomes,
            FragmentValidationPostcondition.ORIGINAL_SUPERSESSION,
            original,
            passed,
            "owned original is unreachable from all publication authority"
            if passed
            else "owned original remains reachable from publication authority",
            original,
        )
    for dispatcher in plan.prohibited_dispatcher_blocks:
        passed = dispatcher not in publication_reachable
        witness = ()
        if not passed:
            witness = next(
                (
                    candidate
                    for authority_root in publication_authority_roots
                    if (
                        candidate := _reachability_witness(
                            blocks,
                            authority_root,
                            dispatcher,
                        )
                    )
                ),
                (),
            )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.DISPATCHER_ABSENCE,
            dispatcher,
            passed,
            "prohibited dispatcher router is unreachable from publication authority"
            if passed
            else (
                "publication authority enters a prohibited dispatcher router; "
                f"witness={' -> '.join(witness)}"
            ),
            *(witness or (dispatcher,)),
        )


def _validate_operation(
    operation: FragmentOperation,
    blocks: dict[str, ProjectedFragmentBlock],
    helpers: tuple[ProjectedFallthroughHelper, ...],
    outcomes: list[FragmentValidationOutcome],
) -> None:
    source = blocks.get(operation.source_block_id)
    expected_targets = {edge.target_block_id for edge in operation.edges}
    actual_targets = set() if source is None else set(source.successors)
    expected_kind = (
        BlockKind.ONE_WAY if len(operation.edges) == 1 else BlockKind.TWO_WAY
    )
    matching_helpers = tuple(
        helper for helper in helpers if helper.operation_id == operation.operation_id
    )
    physical_targets = set(expected_targets)
    helper = None
    helper_block = None
    fallthrough_target_id = None
    fallthrough_edges = tuple(
        edge
        for edge in operation.edges
        if edge.role
        in {
            SemanticEdgeRole.CALL_FALLTHROUGH,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }
    )
    if len(fallthrough_edges) == 1:
        fallthrough_target_id = fallthrough_edges[0].target_block_id
        if len(matching_helpers) == 1:
            helper = matching_helpers[0]
            helper_block = blocks.get(helper.helper_block_id)
            physical_targets.remove(fallthrough_target_id)
            physical_targets.add(helper.helper_block_id)
    topology_valid = bool(
        source is not None
        and source.kind is expected_kind
        and actual_targets == physical_targets
        and len(actual_targets) == len(operation.edges)
        and (
            not matching_helpers
            if not fallthrough_edges
            else len(fallthrough_edges) == 1
            and helper is not None
            and helper.source_block_id == operation.source_block_id
            and helper.semantic_target_block_id == fallthrough_target_id
            and helper_block is not None
            and helper_block.kind is BlockKind.ONE_WAY
            and helper_block.successors == (fallthrough_target_id,)
            and helper_block.predecessors == (operation.source_block_id,)
        )
    )
    _outcome(
        outcomes,
        FragmentValidationPostcondition.OPERATION_TOPOLOGY,
        operation.operation_id,
        topology_valid,
        "projected operation has exactly its planned semantic destinations"
        if topology_valid
        else "projected operation shape or destinations differ from the plan",
        operation.source_block_id,
        *sorted(expected_targets),
    )

    if not fallthrough_edges:
        return
    passed = bool(
        source is not None
        and helper is not None
        and helper_block is not None
        and helper.source_block_id == operation.source_block_id
        and helper.semantic_target_block_id == fallthrough_edges[0].target_block_id
        and helper_block.physical_position == source.physical_position + 1
        and helper_block.kind is BlockKind.ONE_WAY
        and helper_block.successors == (fallthrough_edges[0].target_block_id,)
        and helper_block.predecessors == (operation.source_block_id,)
    )
    _outcome(
        outcomes,
        FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY,
        operation.operation_id,
        passed,
        "semantic fallthrough uses one adjacent transparent helper"
        if passed
        else "semantic fallthrough helper is missing, nonadjacent, or nontransparent",
        operation.source_block_id,
        "" if helper is None else helper.helper_block_id,
        fallthrough_edges[0].target_block_id,
    )


def _validate_root_fallthrough_helpers(
    plan: FragmentPlan,
    projection: ProjectedFragment,
    blocks: dict[str, ProjectedFragmentBlock],
    outcomes: list[FragmentValidationOutcome],
) -> None:
    pairs: set[tuple[str, str]] = set()
    for helper in projection.root_fallthrough_helpers:
        helper_block = blocks.get(helper.helper_block_id)
        source = blocks.get(helper.source_block_id)
        root = blocks.get(helper.root_block_id)
        pair = (helper.source_block_id, helper.root_block_id)
        unique = pair not in pairs
        pairs.add(pair)
        source_topology_valid = bool(
            source is not None
            and (
                (
                    source.kind is BlockKind.TWO_WAY
                    and len(source.successors) == 2
                    and source.successors[0] == helper.helper_block_id
                )
                or (
                    source.kind is BlockKind.ONE_WAY
                    and source.successors == (helper.helper_block_id,)
                )
            )
        )
        passed = bool(
            unique
            and helper.root_block_id in plan.roots
            and helper_block is not None
            and root is not None
            and source_topology_valid
            and helper_block.physical_position == source.physical_position + 1
            and helper_block.kind is BlockKind.ONE_WAY
            and helper_block.successors == (helper.root_block_id,)
            and helper_block.predecessors == (helper.source_block_id,)
            and helper.helper_block_id in root.predecessors
        )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY,
            helper.helper_block_id,
            passed,
            "root fallthrough uses one adjacent synthetic helper"
            if passed
            else "root fallthrough helper is missing, duplicated, or malformed",
            helper.source_block_id,
            helper.helper_block_id,
            helper.root_block_id,
        )


def _validate_terminal_effects(
    plan: FragmentPlan,
    projection: ProjectedFragment,
    blocks: dict[str, ProjectedFragmentBlock],
    outcomes: list[FragmentValidationOutcome],
) -> None:
    diagnostic_lists: dict[str, list[ProjectedTerminalEffectDiagnostic]] = {}
    for diagnostic in projection.terminal_effect_diagnostics:
        diagnostic_lists.setdefault(diagnostic.effect_id, []).append(diagnostic)

    def diagnostic_suffix(effect_id: str) -> str:
        diagnostics = tuple(diagnostic_lists.get(effect_id, ()))
        if not diagnostics:
            return ""
        if len(diagnostics) != 1:
            return f"; live_observation=ambiguous({len(diagnostics)})"
        return f"; live_observation={diagnostics[0].reason}"

    observed_carriers_by_id: dict[str, list[FragmentReturnCarrier]] = {}
    for carrier in projection.return_carriers:
        observed_carriers_by_id.setdefault(carrier.carrier_id, []).append(carrier)
    observed_returns_by_id: dict[str, list[FragmentTerminalReturn]] = {}
    for terminal_return in projection.terminal_returns:
        observed_returns_by_id.setdefault(
            terminal_return.return_id,
            [],
        ).append(terminal_return)

    planned_carrier_ids = {carrier.carrier_id for carrier in plan.return_carriers}
    planned_return_ids = {
        terminal_return.return_id for terminal_return in plan.terminal_returns
    }
    observed_carrier_ids = {
        carrier.carrier_id for carrier in projection.return_carriers
    }
    observed_return_ids = {
        terminal_return.return_id for terminal_return in projection.terminal_returns
    }
    scope_valid = bool(
        len(observed_carrier_ids) == len(projection.return_carriers)
        and len(observed_return_ids) == len(projection.terminal_returns)
        and observed_carrier_ids == planned_carrier_ids
        and observed_return_ids == planned_return_ids
    )
    _outcome(
        outcomes,
        FragmentValidationPostcondition.TERMINAL_EFFECT_SCOPE,
        "terminal-effects",
        scope_valid,
        "projected terminal effects exactly match the planned identity set"
        if scope_valid
        else (
            "projected terminal effect identity set differs: "
            f"planned_carriers={sorted(planned_carrier_ids)!r}; "
            f"observed_carriers={sorted(observed_carrier_ids)!r}; "
            f"planned_returns={sorted(planned_return_ids)!r}; "
            f"observed_returns={sorted(observed_return_ids)!r}"
        ),
        *sorted(
            {carrier.block_id for carrier in plan.return_carriers}
            | {terminal_return.block_id for terminal_return in plan.terminal_returns}
        ),
    )

    carrier_integrity: dict[str, bool] = {}
    for carrier in plan.return_carriers:
        observed = tuple(observed_carriers_by_id.get(carrier.carrier_id, ()))
        block = blocks.get(carrier.block_id)
        corridor_present = False
        if block is not None:
            instructions = block.instruction_eas
            try:
                start = instructions.index(carrier.state_write_ea)
                end = instructions.index(carrier.carrier_ea, start + 1)
            except ValueError:
                pass
            else:
                corridor_present = (
                    instructions[start : end + 1] == carrier.corridor_instruction_eas
                )
        passed = bool(
            len(observed) == 1 and observed[0] == carrier and corridor_present
        )
        carrier_integrity[carrier.carrier_id] = passed
        _outcome(
            outcomes,
            FragmentValidationPostcondition.RETURN_CARRIER_INTEGRITY,
            carrier.carrier_id,
            passed,
            "return carrier and its state-write corridor match the plan"
            if passed
            else (
                "return carrier integrity failed: "
                f"observed_count={len(observed)}; "
                f"exact_match={int(len(observed) == 1 and observed[0] == carrier)}; "
                f"corridor_present={int(corridor_present)}; "
                "instruction_eas="
                f"{[] if block is None else [hex(ea) for ea in block.instruction_eas]!r}"
                f"{diagnostic_suffix(carrier.carrier_id)}"
            ),
            carrier.block_id,
        )

    return_integrity: dict[str, bool] = {}
    for terminal_return in plan.terminal_returns:
        observed = tuple(observed_returns_by_id.get(terminal_return.return_id, ()))
        block = blocks.get(terminal_return.block_id)
        passed = bool(
            len(observed) == 1
            and observed[0] == terminal_return
            and block is not None
            and block.kind is BlockKind.ZERO_WAY
            and not block.successors
            and bool(block.instruction_eas)
            and block.instruction_eas[-1] == terminal_return.instruction_ea
        )
        return_integrity[terminal_return.return_id] = passed
        block_kind = "missing" if block is None else block.kind.name.lower()
        successors = () if block is None else block.successors
        tail_ea = (
            None
            if block is None or not block.instruction_eas
            else block.instruction_eas[-1]
        )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.TERMINAL_RETURN_INTEGRITY,
            terminal_return.return_id,
            passed,
            "terminal return is the zero-way block tail required by the plan"
            if passed
            else (
                "terminal return integrity failed: "
                f"observed_count={len(observed)}; "
                "exact_match="
                f"{int(len(observed) == 1 and observed[0] == terminal_return)}; "
                f"kind={block_kind}; successor_count={len(successors)}; "
                f"tail_ea={None if tail_ea is None else hex(tail_ea)}"
            ),
            terminal_return.block_id,
        )

    operation_integrity = {
        outcome.subject_id: outcome.passed
        for outcome in outcomes
        if outcome.postcondition is FragmentValidationPostcondition.OPERATION_TOPOLOGY
    }
    for terminal_route in plan.terminal_routes:
        passed = bool(
            operation_integrity.get(terminal_route.operation_id, False)
            and carrier_integrity.get(terminal_route.carrier_id, False)
            and return_integrity.get(terminal_route.return_id, False)
        )
        carrier = next(
            item
            for item in plan.return_carriers
            if item.carrier_id == terminal_route.carrier_id
        )
        terminal_return = next(
            item
            for item in plan.terminal_returns
            if item.return_id == terminal_route.return_id
        )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.TERMINAL_ROUTE_ATOMICITY,
            terminal_route.terminal_route_id,
            passed,
            "route, return carrier, and terminal return are all present"
            if passed
            else "route, return carrier, and terminal return did not validate "
            "as one fragment",
            carrier.block_id,
            terminal_return.block_id,
        )


def _validate_data_flow(
    obligation: FragmentDataFlowObligation,
    blocks: dict[str, ProjectedFragmentBlock],
    relations: tuple[ProjectedDataFlowRelation, ...],
    outcomes: list[FragmentValidationOutcome],
) -> None:
    definition = obligation.definition
    expected_use_ids = {use.site_id for use in obligation.uses}
    missing_site_ids = tuple(
        site.site_id
        for site in (definition, *obligation.uses)
        if not _site_present(site, blocks)
    )
    sites_present = not missing_site_ids
    use_def_valid = sites_present
    observed_use_def: list[tuple[str, tuple[str, ...], int]] = []
    for use in obligation.uses:
        actual_relations = tuple(
            relation
            for relation in relations
            if relation.value_id == definition.value_id
            and relation.use_site_id == use.site_id
            and relation.use_def_observed
        )
        actual_definitions = {
            relation.definition_site_id for relation in actual_relations
        }
        observed_use_def.append(
            (
                use.site_id,
                tuple(sorted(actual_definitions)),
                len(actual_relations),
            )
        )
        if actual_definitions != {definition.site_id} or len(actual_relations) != 1:
            use_def_valid = False
    _outcome(
        outcomes,
        FragmentValidationPostcondition.USE_DEF_INTEGRITY,
        obligation.obligation_id,
        use_def_valid,
        "every planned use has exactly the planned reaching definition"
        if use_def_valid
        else (
            "a planned use is missing, ambiguous, or reached by another definition; "
            f"missing_sites={missing_site_ids!r}; "
            f"observed_use_def={tuple(observed_use_def)!r}"
        ),
        definition.block_id,
        *(use.block_id for use in obligation.uses),
    )

    def_use_relations = tuple(
        relation
        for relation in relations
        if relation.value_id == definition.value_id
        and relation.definition_site_id == definition.site_id
        and relation.def_use_observed
    )
    actual_use_ids = {relation.use_site_id for relation in def_use_relations}
    def_use_valid = (
        sites_present
        and actual_use_ids == expected_use_ids
        and len(def_use_relations) == len(expected_use_ids)
    )
    _outcome(
        outcomes,
        FragmentValidationPostcondition.DEF_USE_INTEGRITY,
        obligation.obligation_id,
        def_use_valid,
        "the planned definition reaches exactly its declared uses"
        if def_use_valid
        else (
            "the planned definition lost a use or reaches an undeclared use; "
            f"missing_sites={missing_site_ids!r}; "
            f"expected_uses={tuple(sorted(expected_use_ids))!r}; "
            f"observed_uses={tuple(sorted(actual_use_ids))!r}; "
            f"observed_relation_count={len(def_use_relations)}"
        ),
        definition.block_id,
        *(use.block_id for use in obligation.uses),
    )


def _corridor_writes(
    corridor: FragmentFlagCorridor,
    blocks: dict[str, ProjectedFragmentBlock],
) -> frozenset[int]:
    writes: set[int] = set()
    for index, block_id in enumerate(corridor.block_path):
        block = blocks.get(block_id)
        if block is None:
            continue
        instructions = block.instruction_eas
        start = 0
        end = len(instructions)
        if index == 0:
            try:
                start = instructions.index(corridor.producer.instruction_ea)
            except ValueError:
                start = len(instructions)
        if index == len(corridor.block_path) - 1:
            try:
                end = instructions.index(corridor.consumer.instruction_ea)
            except ValueError:
                end = 0
        writes.update(set(instructions[start:end]) & block.flag_write_eas)
    return frozenset(writes)


def _validate_flag_corridor(
    corridor: FragmentFlagCorridor,
    blocks: dict[str, ProjectedFragmentBlock],
    outcomes: list[FragmentValidationOutcome],
) -> None:
    sites_present = _site_present(corridor.producer, blocks) and _site_present(
        corridor.consumer,
        blocks,
    )
    path_connected = sites_present and len(set(corridor.block_path)) == len(
        corridor.block_path
    )
    for source, target in zip(corridor.block_path, corridor.block_path[1:]):
        source_block = blocks.get(source)
        if source_block is None or target not in source_block.successors:
            path_connected = False
            break
    if path_connected and len(corridor.block_path) == 1:
        block = blocks[corridor.block_path[0]]
        path_connected = block.instruction_eas.index(
            corridor.producer.instruction_ea
        ) < block.instruction_eas.index(corridor.consumer.instruction_ea)
    producer_block = blocks.get(corridor.producer.block_id)
    producer_write_observed = bool(
        producer_block is not None
        and corridor.producer.instruction_ea in producer_block.flag_write_eas
    )
    observed_writes = _corridor_writes(corridor, blocks)
    unpermitted_writes = observed_writes - corridor.permitted_flag_write_eas
    passed = path_connected and producer_write_observed and not unpermitted_writes
    reason = "flag corridor is connected and contains no intervening clobber"
    if not path_connected:
        reason = "flag producer-to-consumer corridor is disconnected or missing"
    elif not producer_write_observed:
        reason = "flag producer is not an observed condition-code writer"
    elif unpermitted_writes:
        reason = "flag corridor contains an intervening unpermitted flag write"
    _outcome(
        outcomes,
        FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY,
        corridor.corridor_id,
        passed,
        reason,
        *corridor.block_path,
    )


def _range_satisfies(
    assumption: FragmentRangeAssumption,
    fact: ProjectedRangeFact,
) -> bool:
    if assumption.lo is not None and (fact.lo is None or fact.lo < assumption.lo):
        return False
    if assumption.hi is not None and (fact.hi is None or fact.hi > assumption.hi):
        return False
    return True


def _validate_range(
    assumption: FragmentRangeAssumption,
    facts: tuple[ProjectedRangeFact, ...],
    outcomes: list[FragmentValidationOutcome],
) -> None:
    matching = tuple(
        fact
        for fact in facts
        if fact.site_id == assumption.site.site_id
        and fact.value_id == assumption.site.value_id
        and fact.observation is assumption.observation
    )
    passed = len(matching) == 1 and _range_satisfies(assumption, matching[0])
    _outcome(
        outcomes,
        FragmentValidationPostcondition.VALUE_RANGE_PROVEN,
        assumption.assumption_id,
        passed,
        "projected value range is within the plan assumption"
        if passed
        else "projected value range is absent, ambiguous, or wider than assumed",
        assumption.site.block_id,
    )


def _validate_identity(
    plan: FragmentPlan,
    projection: ProjectedFragment,
    blocks: dict[str, ProjectedFragmentBlock],
    outcomes: list[FragmentValidationOutcome],
) -> None:
    binding_lists: dict[str, list[ProjectedIdentityBinding]] = {}
    for binding in projection.identity_bindings:
        binding_lists.setdefault(binding.block_id, []).append(binding)

    all_projected_bound = all(
        len(binding_lists.get(block_id, ())) == 1 for block_id in blocks
    )
    unique_version_coordinates = len(
        {
            (binding.logical_owner_id, binding.version)
            for binding in projection.identity_bindings
        }
    ) == len(projection.identity_bindings)
    _outcome(
        outcomes,
        FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
        "projection-bindings",
        all_projected_bound and unique_version_coordinates,
        "every projected block has one unique logical owner version"
        if all_projected_bound and unique_version_coordinates
        else "a projected block lacks one exact logical owner version",
        *blocks,
    )

    binding_by_id = {
        block_id: bindings[0]
        for block_id, bindings in binding_lists.items()
        if len(bindings) == 1
    }
    for block in plan.blocks:
        binding = binding_by_id.get(block.block_id)
        expected_state = (
            FragmentBindingState.STAGED
            if block.role
            in {
                FragmentBlockRole.REPLACEMENT,
                FragmentBlockRole.SYNTHETIC,
                FragmentBlockRole.IMPORTED,
            }
            else FragmentBindingState.PUBLISHED
        )
        passed = bool(
            binding is not None
            and binding.state is expected_state
            and binding.stable_identity == block.stable_identity
        )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
            block.block_id,
            passed,
            "projected identity and authority state match the plan"
            if passed
            else "projected identity or authority state differs from the plan",
            block.block_id,
        )

        if block.role in {
            FragmentBlockRole.SYNTHETIC,
            FragmentBlockRole.IMPORTED,
        }:
            lineage_valid = bool(
                binding is not None and binding.previous_version is None
            )
            owner_description = (
                "imported native owner"
                if block.role is FragmentBlockRole.IMPORTED
                else "new synthetic owner"
            )
            _outcome(
                outcomes,
                FragmentValidationPostcondition.VERSION_LINEAGE,
                block.block_id,
                lineage_valid,
                f"{owner_description} has no predecessor version"
                if lineage_valid
                else f"{owner_description} incorrectly claims a predecessor version",
                block.block_id,
            )
        elif block.role is FragmentBlockRole.REPLACEMENT:
            original = binding_by_id.get(str(block.replaces_block_id))
            owner_valid = bool(
                binding is not None
                and original is not None
                and binding.logical_owner_id == original.logical_owner_id
            )
            _outcome(
                outcomes,
                FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                f"{block.block_id}:replacement-owner",
                owner_valid,
                "replacement and original share one logical owner"
                if owner_valid
                else "replacement and original resolve to different logical owners",
                str(block.replaces_block_id),
                block.block_id,
            )
            lineage_valid = bool(
                binding is not None
                and original is not None
                and binding.previous_version == original.version
                and binding.version > original.version
                and binding.generation == original.generation + 1
            )
            _outcome(
                outcomes,
                FragmentValidationPostcondition.VERSION_LINEAGE,
                block.block_id,
                lineage_valid,
                "staged replacement directly descends from the published owner"
                if lineage_valid
                else "staged replacement owner or predecessor lineage drifted",
                str(block.replaces_block_id),
                block.block_id,
            )

    for helper in projection.fallthrough_helpers:
        binding = binding_by_id.get(helper.helper_block_id)
        owner_valid = bool(
            binding is not None
            and binding.state is FragmentBindingState.STAGED
            and binding.stable_identity is None
        )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
            helper.helper_block_id,
            owner_valid,
            "fallthrough helper has one staged synthetic owner"
            if owner_valid
            else "fallthrough helper lacks staged synthetic ownership",
            helper.helper_block_id,
        )
        lineage_valid = bool(binding is not None and binding.previous_version is None)
        _outcome(
            outcomes,
            FragmentValidationPostcondition.VERSION_LINEAGE,
            helper.helper_block_id,
            lineage_valid,
            "fallthrough helper starts a new logical lineage"
            if lineage_valid
            else "fallthrough helper incorrectly claims prior authority",
            helper.helper_block_id,
        )

    for helper in projection.root_fallthrough_helpers:
        binding = binding_by_id.get(helper.helper_block_id)
        owner_valid = bool(
            binding is not None
            and binding.state is FragmentBindingState.STAGED
            and binding.stable_identity is None
        )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
            helper.helper_block_id,
            owner_valid,
            "root fallthrough helper has one staged synthetic owner"
            if owner_valid
            else "root fallthrough helper lacks staged synthetic ownership",
            helper.helper_block_id,
        )
        lineage_valid = bool(binding is not None and binding.previous_version is None)
        _outcome(
            outcomes,
            FragmentValidationPostcondition.VERSION_LINEAGE,
            helper.helper_block_id,
            lineage_valid,
            "root fallthrough helper starts a new logical lineage"
            if lineage_valid
            else "root fallthrough helper incorrectly claims prior authority",
            helper.helper_block_id,
        )


def _validate_fragment_projection(
    plan: FragmentPlan,
    projection: ProjectedFragment,
    *,
    include_detached_native_body_roots: bool,
) -> FragmentValidationResult:
    if not isinstance(plan, FragmentPlan):
        raise TypeError("fragment validation requires a FragmentPlan")
    if not isinstance(projection, ProjectedFragment):
        raise TypeError("fragment validation requires a ProjectedFragment")

    outcomes: list[FragmentValidationOutcome] = []
    blocks = {block.block_id: block for block in projection.blocks}
    _validate_graph(projection, blocks, outcomes)
    _validate_reachability(
        plan,
        blocks,
        projection,
        outcomes,
        include_detached_native_body_roots=include_detached_native_body_roots,
    )
    known_operation_ids = {operation.operation_id for operation in plan.operations}
    for helper in projection.fallthrough_helpers:
        if helper.operation_id not in known_operation_ids:
            _outcome(
                outcomes,
                FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY,
                helper.helper_block_id,
                False,
                "fallthrough helper does not belong to a planned operation",
                helper.helper_block_id,
            )
    for operation in plan.operations:
        _validate_operation(
            operation,
            blocks,
            projection.fallthrough_helpers,
            outcomes,
        )
    _validate_boundary_ports(plan, projection, blocks, outcomes)
    _validate_terminal_effects(plan, projection, blocks, outcomes)
    _validate_root_fallthrough_helpers(plan, projection, blocks, outcomes)
    for obligation in plan.data_flow_obligations:
        _validate_data_flow(
            obligation,
            blocks,
            projection.data_flow_relations,
            outcomes,
        )
    for corridor in plan.flag_corridors:
        _validate_flag_corridor(corridor, blocks, outcomes)
    for assumption in plan.value_range_assumptions:
        _validate_range(assumption, projection.value_ranges, outcomes)
    _validate_identity(plan, projection, blocks, outcomes)
    return FragmentValidationResult(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        outcomes=tuple(outcomes),
    )


def validate_fragment_projection(
    plan: FragmentPlan,
    projection: ProjectedFragment,
) -> FragmentValidationResult:
    """Prove a closed detached fragment before root publication."""
    return _validate_fragment_projection(
        plan,
        projection,
        include_detached_native_body_roots=True,
    )


def compare_fragment_projection_obligations(
    expected: ProjectedFragment,
    observed: ProjectedFragment,
) -> tuple[str, ...]:
    """Compare staged semantics while ignoring backend-local owner tokens."""
    mismatches: list[str] = []
    expected_blocks = {block.block_id: block for block in expected.blocks}
    observed_blocks = {block.block_id: block for block in observed.blocks}
    if set(expected_blocks) != set(observed_blocks):
        mismatches.append("block-set")
    for block_id in sorted(set(expected_blocks) & set(observed_blocks)):
        left = expected_blocks[block_id]
        right = observed_blocks[block_id]
        if (
            left.kind,
            left.successors,
            frozenset(left.predecessors),
            left.adjacent_fallthrough_target_id,
        ) != (
            right.kind,
            right.successors,
            frozenset(right.predecessors),
            right.adjacent_fallthrough_target_id,
        ):
            mismatches.append(f"block:{block_id}")
        if left.instruction_eas != right.instruction_eas:
            mismatches.append(f"block:{block_id}:instruction-eas")
        if (left.terminator_ea, left.terminator_kind) != (
            right.terminator_ea,
            right.terminator_kind,
        ):
            mismatches.append(f"block:{block_id}:terminator")
        if left.flag_write_eas != right.flag_write_eas:
            mismatches.append(f"block:{block_id}:flag-writes")
    for label, left, right in (
        (
            "fallthrough-helpers",
            expected.fallthrough_helpers,
            observed.fallthrough_helpers,
        ),
        (
            "root-fallthrough-helpers",
            expected.root_fallthrough_helpers,
            observed.root_fallthrough_helpers,
        ),
        ("return-carriers", expected.return_carriers, observed.return_carriers),
        ("terminal-returns", expected.terminal_returns, observed.terminal_returns),
        ("data-flow", expected.data_flow_relations, observed.data_flow_relations),
        ("value-ranges", expected.value_ranges, observed.value_ranges),
        (
            "terminal-effect-diagnostics",
            expected.terminal_effect_diagnostics,
            observed.terminal_effect_diagnostics,
        ),
    ):
        if left != right:
            mismatches.append(label)

    def binding_shape(projection: ProjectedFragment) -> tuple[object, ...]:
        owner_groups: dict[str, list[str]] = {}
        for binding in projection.identity_bindings:
            owner_groups.setdefault(binding.logical_owner_id, []).append(
                binding.block_id
            )
        owner_class = {
            block_id: tuple(sorted(group))
            for group in owner_groups.values()
            for block_id in group
        }
        return tuple(
            sorted(
                (
                    binding.block_id,
                    owner_class[binding.block_id],
                    binding.state,
                    binding.stable_identity,
                    binding.previous_version is None,
                )
                for binding in projection.identity_bindings
            )
        )

    if binding_shape(expected) != binding_shape(observed):
        mismatches.append("identity-bindings")
    return tuple(mismatches)


def validate_published_fragment_projection(
    plan: FragmentPlan,
    projection: ProjectedFragment,
) -> FragmentValidationResult:
    """Prove every required operation is reachable from published entry authority."""
    return _validate_fragment_projection(
        plan,
        projection,
        include_detached_native_body_roots=False,
    )


def _required_postpublication_outcomes(
    plan: FragmentPlan,
    projection: ProjectedFragment,
) -> tuple[tuple[FragmentValidationPostcondition, str], ...]:
    required: list[tuple[FragmentValidationPostcondition, str]] = []
    required.extend(
        (FragmentValidationPostcondition.ORIGINAL_SUPERSESSION, block_id)
        for block_id in plan.owned_originals
    )
    required.extend(
        (FragmentValidationPostcondition.DISPATCHER_ABSENCE, block_id)
        for block_id in plan.prohibited_dispatcher_blocks
    )
    required.extend(
        (FragmentValidationPostcondition.TEMPORARY_BOUNDARY_PORT, port.port_id)
        for port in plan.boundary_ports
    )
    for operation in plan.operations:
        required.append(
            (
                FragmentValidationPostcondition.OPERATION_TOPOLOGY,
                operation.operation_id,
            )
        )
        if operation.roles.intersection(
            {
                SemanticEdgeRole.CALL_FALLTHROUGH,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        ):
            required.append(
                (
                    FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY,
                    operation.operation_id,
                )
            )
    required.append(
        (
            FragmentValidationPostcondition.TERMINAL_EFFECT_SCOPE,
            "terminal-effects",
        )
    )
    required.extend(
        (
            FragmentValidationPostcondition.RETURN_CARRIER_INTEGRITY,
            carrier.carrier_id,
        )
        for carrier in plan.return_carriers
    )
    required.extend(
        (
            FragmentValidationPostcondition.TERMINAL_RETURN_INTEGRITY,
            terminal_return.return_id,
        )
        for terminal_return in plan.terminal_returns
    )
    required.extend(
        (
            FragmentValidationPostcondition.TERMINAL_ROUTE_ATOMICITY,
            terminal_route.terminal_route_id,
        )
        for terminal_route in plan.terminal_routes
    )
    for obligation in plan.data_flow_obligations:
        required.extend(
            (
                (
                    FragmentValidationPostcondition.USE_DEF_INTEGRITY,
                    obligation.obligation_id,
                ),
                (
                    FragmentValidationPostcondition.DEF_USE_INTEGRITY,
                    obligation.obligation_id,
                ),
            )
        )
    required.extend(
        (FragmentValidationPostcondition.FLAG_CORRIDOR_INTEGRITY, corridor.corridor_id)
        for corridor in plan.flag_corridors
    )
    required.extend(
        (FragmentValidationPostcondition.VALUE_RANGE_PROVEN, assumption.assumption_id)
        for assumption in plan.value_range_assumptions
    )
    required.extend(
        (FragmentValidationPostcondition.IDENTITY_OWNERSHIP, block.block_id)
        for block in plan.blocks
    )
    required.extend(
        (FragmentValidationPostcondition.VERSION_LINEAGE, block.block_id)
        for block in plan.blocks
        if block.role
        in {
            FragmentBlockRole.REPLACEMENT,
            FragmentBlockRole.SYNTHETIC,
            FragmentBlockRole.IMPORTED,
        }
    )
    for helper in (
        *projection.fallthrough_helpers,
        *projection.root_fallthrough_helpers,
    ):
        required.extend(
            (
                (
                    FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                    helper.helper_block_id,
                ),
                (
                    FragmentValidationPostcondition.VERSION_LINEAGE,
                    helper.helper_block_id,
                ),
            )
        )
    required.extend(
        (
            FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY,
            helper.helper_block_id,
        )
        for helper in projection.root_fallthrough_helpers
    )
    return tuple(required)


def _validate_observable_helpers(
    expected: tuple[ProjectedFallthroughHelper | ProjectedRootFallthroughHelper, ...],
    observed: tuple[ProjectedFallthroughHelper | ProjectedRootFallthroughHelper, ...],
    outcomes: list[FragmentValidationOutcome],
) -> None:
    expected_by_id = {helper.helper_block_id: helper for helper in expected}
    observed_by_id = {helper.helper_block_id: helper for helper in observed}
    exact_cardinality = (
        len(expected_by_id) == len(expected)
        and len(observed_by_id) == len(observed)
        and len(observed) == len(expected)
    )
    for helper_id in sorted(set(expected_by_id) | set(observed_by_id)):
        planned = expected_by_id.get(helper_id)
        actual = observed_by_id.get(helper_id)
        passed = bool(
            exact_cardinality
            and planned is not None
            and actual is not None
            and type(actual) is type(planned)
            and actual == planned
        )
        block_ids = ()
        if planned is not None:
            block_ids = (
                planned.source_block_id,
                planned.helper_block_id,
                (
                    planned.semantic_target_block_id
                    if isinstance(planned, ProjectedFallthroughHelper)
                    else planned.root_block_id
                ),
            )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.OBSERVABLE_FALLTHROUGH_HELPER,
            helper_id,
            passed,
            "published helper matches its projected semantic topology"
            if passed
            else "published helper is missing, extra, duplicated, or changed",
            *block_ids,
        )


def validate_published_fragment_observation(
    plan: FragmentPlan,
    observation: PublishedFragmentObservation,
    prepublication_projection: ProjectedFragment,
) -> FragmentValidationResult:
    """Validate post-publication semantics without requiring block survival."""
    if not isinstance(plan, FragmentPlan):
        raise TypeError("published fragment validation requires a FragmentPlan")
    if not isinstance(observation, PublishedFragmentObservation):
        raise TypeError(
            "published fragment validation requires a PublishedFragmentObservation"
        )
    if not isinstance(prepublication_projection, ProjectedFragment):
        raise TypeError(
            "published fragment validation requires its prepublication projection"
        )

    outcomes = list(observation.semantic_outcomes)
    observed_operation_ids = tuple(
        operation.operation_id for operation in observation.observable_operations
    )
    observed_carrier_ids = tuple(
        carrier.carrier_id for carrier in observation.observable_return_carriers
    )
    observed_return_ids = tuple(
        terminal_return.return_id
        for terminal_return in observation.observable_terminal_returns
    )
    scope_valid = (
        observation.plan_id == plan.plan_id
        and observation.atomic_group_id == plan.atomic_group_id
        and len(set(observation.published_root_ids))
        == len(observation.published_root_ids)
        and len(set(observed_operation_ids)) == len(observed_operation_ids)
        and len(set(observed_carrier_ids)) == len(observed_carrier_ids)
        and len(set(observed_return_ids)) == len(observed_return_ids)
        and set(observed_carrier_ids)
        == {carrier.carrier_id for carrier in plan.return_carriers}
        and set(observed_return_ids)
        == {terminal_return.return_id for terminal_return in plan.terminal_returns}
    )
    _outcome(
        outcomes,
        FragmentValidationPostcondition.POSTVALIDATION_SCOPE,
        plan.plan_id,
        scope_valid,
        "published observation has the exact plan scope"
        if scope_valid
        else "published observation plan, atomic group, or identity set drifted",
        *observation.published_root_ids,
    )

    observed_roots = set(observation.published_root_ids)
    planned_roots = set(plan.roots)
    for root in plan.roots:
        passed = root in observed_roots and observed_roots == planned_roots
        _outcome(
            outcomes,
            FragmentValidationPostcondition.ROOT_AUTHORITY,
            root,
            passed,
            "planned root owns published authority"
            if passed
            else "published root authority is missing or contains an unplanned root",
            root,
        )

    observed_by_id = {
        operation.operation_id: operation
        for operation in observation.observable_operations
    }
    for operation in plan.operations:
        observed = observed_by_id.get(operation.operation_id)
        passed = observed == operation and len(observed_by_id) == len(plan.operations)
        _outcome(
            outcomes,
            FragmentValidationPostcondition.OBSERVABLE_OPERATION,
            operation.operation_id,
            passed,
            "published observable operation matches predicate and destinations"
            if passed
            else "published operation is missing, extra, or semantically different",
            operation.source_block_id,
            *(edge.target_block_id for edge in operation.edges),
        )

    observed_carriers_by_id = {
        carrier.carrier_id: carrier
        for carrier in observation.observable_return_carriers
    }
    for carrier in plan.return_carriers:
        observed = observed_carriers_by_id.get(carrier.carrier_id)
        passed = bool(
            observed == carrier
            and len(observed_carriers_by_id) == len(plan.return_carriers)
        )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.OBSERVABLE_RETURN_CARRIER,
            carrier.carrier_id,
            passed,
            "published return carrier matches the planned portable semantics"
            if passed
            else "published return carrier is missing, extra, or changed",
            carrier.block_id,
        )

    observed_returns_by_id = {
        terminal_return.return_id: terminal_return
        for terminal_return in observation.observable_terminal_returns
    }
    for terminal_return in plan.terminal_returns:
        observed = observed_returns_by_id.get(terminal_return.return_id)
        passed = bool(
            observed == terminal_return
            and len(observed_returns_by_id) == len(plan.terminal_returns)
        )
        _outcome(
            outcomes,
            FragmentValidationPostcondition.OBSERVABLE_TERMINAL_RETURN,
            terminal_return.return_id,
            passed,
            "published terminal return matches the planned portable semantics"
            if passed
            else "published terminal return is missing, extra, or changed",
            terminal_return.block_id,
        )

    _validate_observable_helpers(
        prepublication_projection.fallthrough_helpers,
        observation.fallthrough_helpers,
        outcomes,
    )
    _validate_observable_helpers(
        prepublication_projection.root_fallthrough_helpers,
        observation.root_fallthrough_helpers,
        outcomes,
    )

    semantic_outcomes = observation.semantic_outcomes
    for postcondition, subject_id in _required_postpublication_outcomes(
        plan,
        prepublication_projection,
    ):
        matching = tuple(
            outcome
            for outcome in semantic_outcomes
            if outcome.postcondition is postcondition
            and outcome.subject_id == subject_id
        )
        passed = len(matching) == 1 and matching[0].passed
        _outcome(
            outcomes,
            FragmentValidationPostcondition.POSTVALIDATION_COVERAGE,
            f"{postcondition.value}:{subject_id}",
            passed,
            "required semantic postcondition is present and passed"
            if passed
            else "required semantic postcondition is missing, duplicated, or failed",
            *(() if not matching else matching[0].block_ids),
        )

    return FragmentValidationResult(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        outcomes=tuple(outcomes),
    )


__all__ = [
    "FragmentBindingState",
    "FragmentValidationOutcome",
    "FragmentValidationPostcondition",
    "FragmentValidationResult",
    "PublishedFragmentObservation",
    "ProjectedDataFlowRelation",
    "ProjectedFallthroughHelper",
    "ProjectedFragment",
    "ProjectedFragmentBlock",
    "ProjectedIdentityBinding",
    "ProjectedRangeFact",
    "ProjectedRootFallthroughHelper",
    "ProjectedTerminalEffectDiagnostic",
    "compare_fragment_projection_obligations",
    "projected_publication_authority_roots",
    "validate_fragment_projection",
    "validate_published_fragment_projection",
    "validate_published_fragment_observation",
]
