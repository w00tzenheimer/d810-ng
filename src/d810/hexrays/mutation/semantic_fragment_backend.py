"""Live Hex-Rays realization of portable semantic fragment plans."""

from __future__ import annotations

from dataclasses import dataclass, field

import ida_hexrays

from d810.core.typing import TYPE_CHECKING
from d810.hexrays.ir.logical_block_proxy import (
    LogicalBlockProxy,
    LogicalBlockVersion,
)
from d810.hexrays.ir.semantic_edge import (
    LogicalSemanticEdge,
    LogicalSemanticEdgeOperation,
)
from d810.ir.flowgraph import BlockKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.fragment_plan import (
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentPlan,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    FragmentValidationPostcondition,
    PublishedFragmentObservation,
    ProjectedFallthroughHelper,
    ProjectedFragment,
    ProjectedFragmentBlock,
    ProjectedIdentityBinding,
    validate_fragment_projection,
)

if TYPE_CHECKING:
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier


_BADADDR = 0xFFFFFFFFFFFFFFFF


class SemanticFragmentBackendRejected(RuntimeError):
    """The live backend cannot realize a plan without guessing."""


@dataclass(frozen=True, slots=True)
class SemanticFragmentRuntimeBinding:
    """One exact logical version used by a live fragment transaction."""

    block_id: str
    proxy: LogicalBlockProxy
    version: LogicalBlockVersion
    state: FragmentBindingState


@dataclass(frozen=True, slots=True)
class SemanticFragmentRootEdgeBinding:
    """One serial-free incoming edge whose root authority will change."""

    edge_id: str
    root_block_id: str
    predecessor: SemanticFragmentRuntimeBinding
    original: SemanticFragmentRuntimeBinding
    replacement: SemanticFragmentRuntimeBinding
    role: SemanticEdgeRole


@dataclass(slots=True)
class SemanticFragmentRootPublicationToken:
    """Complete rollback authority captured before the first root write."""

    plan_id: str
    atomic_group_id: str
    edges: tuple[SemanticFragmentRootEdgeBinding, ...]
    attempted_edge_ids: list[str] = field(default_factory=list)

    def edge(self, edge_id: str) -> SemanticFragmentRootEdgeBinding:
        for edge in self.edges:
            if edge.edge_id == edge_id:
                return edge
        raise SemanticFragmentBackendRejected(
            f"root publication token has no edge {edge_id!r}"
        )


@dataclass(slots=True)
class SemanticFragmentBackendState:
    """Transaction-local serial-free bindings for one staged fragment."""

    plan_id: str
    atomic_group_id: str
    bindings: dict[str, SemanticFragmentRuntimeBinding] = field(default_factory=dict)
    staged_block_ids: list[str] = field(default_factory=list)
    fallthrough_helpers: list[ProjectedFallthroughHelper] = field(
        default_factory=list
    )
    projection: ProjectedFragment | None = None

    def binding(self, block_id: str) -> SemanticFragmentRuntimeBinding:
        try:
            return self.bindings[str(block_id)]
        except KeyError as exc:
            raise SemanticFragmentBackendRejected(
                f"fragment block {block_id!r} has no live logical binding"
            ) from exc


def _gateway(modifier: DeferredGraphModifier):
    gateway = modifier._mutation_gateway
    if gateway is None or not gateway.active:
        raise SemanticFragmentBackendRejected(
            "semantic fragment staging requires an active mutation gateway"
        )
    return gateway


def _transaction_id(modifier: DeferredGraphModifier) -> str:
    gateway = _gateway(modifier)
    batch_id = gateway.active_batch_id
    if batch_id is None:
        raise SemanticFragmentBackendRejected(
            "semantic fragment staging has no active transaction id"
        )
    return batch_id


def _published_binding(
    modifier: DeferredGraphModifier,
    block_id: str,
    stable_identity,
) -> SemanticFragmentRuntimeBinding:
    gateway = _gateway(modifier)
    rebound = gateway.identity_index.rebind_identity(stable_identity)
    if rebound.block is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {block_id!r} does not rebind uniquely"
        )
    proxy = gateway.identity_index.logical_proxy_for_handle(rebound.block.handle)
    if proxy is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {block_id!r} has no logical proxy"
        )
    version = proxy.resolve()
    if version is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {block_id!r} has no published version"
        )
    return SemanticFragmentRuntimeBinding(
        block_id=str(block_id),
        proxy=proxy,
        version=version,
        state=FragmentBindingState.PUBLISHED,
    )


def _live_block_for_binding(
    modifier: DeferredGraphModifier,
    binding: SemanticFragmentRuntimeBinding,
):
    gateway = _gateway(modifier)
    bound = gateway.identity_index.resolve_logical_version(
        binding.version,
        transaction_id=_transaction_id(modifier),
    )
    if bound is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {binding.block_id!r} has no transaction-local physical version"
        )
    block = modifier.mba.get_mblock(int(bound.serial))
    if block is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {binding.block_id!r} is absent from the live MBA"
        )
    return block


def _clone_replacement(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    replacement_block,
) -> None:
    original_binding = state.binding(str(replacement_block.replaces_block_id))
    staged = modifier._stage_detached_semantic_replacement(
        original_version=original_binding.version,
    )

    state.bindings[replacement_block.block_id] = SemanticFragmentRuntimeBinding(
        block_id=replacement_block.block_id,
        proxy=original_binding.proxy,
        version=staged,
        state=FragmentBindingState.STAGED,
    )
    state.staged_block_ids.append(replacement_block.block_id)


def _create_empty_block(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    block,
    *,
    reference_version: LogicalBlockVersion,
) -> None:
    staged = modifier._stage_empty_semantic_block(
        reference_version=reference_version,
    )
    gateway = _gateway(modifier)
    proxy = gateway.identity_index.logical_proxy_for_handle(staged.handle)
    if proxy is None:
        raise SemanticFragmentBackendRejected(
            f"synthetic fragment block {block.block_id!r} has no logical proxy"
        )
    state.bindings[block.block_id] = SemanticFragmentRuntimeBinding(
        block_id=block.block_id,
        proxy=proxy,
        version=staged,
        state=FragmentBindingState.STAGED,
    )
    state.staged_block_ids.append(block.block_id)


def _realize_operations(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> None:
    for operation in plan.operations:
        source = state.binding(operation.source_block_id)
        helper_version = modifier._realize_semantic_edge_operation(
            LogicalSemanticEdgeOperation(
                source=source.proxy,
                edges=tuple(
                    LogicalSemanticEdge(
                        role=edge.role,
                        target=state.binding(edge.target_block_id).proxy,
                    )
                    for edge in operation.edges
                ),
                predicate_anchor_ea=operation.predicate_anchor_ea,
                description=f"fragment operation {operation.operation_id}",
            )
        )
        if len(operation.edges) == 1:
            if helper_version is not None:
                raise SemanticFragmentBackendRejected(
                    "direct fragment operation unexpectedly created a helper"
                )
            continue
        if helper_version is None:
            raise SemanticFragmentBackendRejected(
                "conditional fragment operation did not create a fallthrough helper"
            )
        helper_block_id = f"fallthrough-helper:{operation.operation_id}"
        if helper_block_id in state.bindings:
            raise SemanticFragmentBackendRejected(
                f"conditional helper id collision: {helper_block_id!r}"
            )
        gateway = _gateway(modifier)
        helper_proxy = gateway.identity_index.logical_proxy_for_handle(
            helper_version.handle
        )
        if helper_proxy is None:
            raise SemanticFragmentBackendRejected(
                "conditional fallthrough helper has no logical proxy"
            )
        state.bindings[helper_block_id] = SemanticFragmentRuntimeBinding(
            block_id=helper_block_id,
            proxy=helper_proxy,
            version=helper_version,
            state=FragmentBindingState.STAGED,
        )
        state.staged_block_ids.append(helper_block_id)
        fallthrough_target = next(
            edge.target_block_id
            for edge in operation.edges
            if edge.role is SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
        )
        state.fallthrough_helpers.append(
            ProjectedFallthroughHelper(
                helper_block_id=helper_block_id,
                operation_id=operation.operation_id,
                source_block_id=operation.source_block_id,
                semantic_target_block_id=fallthrough_target,
            )
        )


def _block_kind(block_type: int) -> BlockKind:
    return {
        int(ida_hexrays.BLT_NONE): BlockKind.NONE,
        int(ida_hexrays.BLT_STOP): BlockKind.STOP,
        int(ida_hexrays.BLT_XTRN): BlockKind.EXTERNAL,
        int(ida_hexrays.BLT_0WAY): BlockKind.ZERO_WAY,
        int(ida_hexrays.BLT_1WAY): BlockKind.ONE_WAY,
        int(ida_hexrays.BLT_2WAY): BlockKind.TWO_WAY,
        int(ida_hexrays.BLT_NWAY): BlockKind.N_WAY,
    }.get(int(block_type), BlockKind.UNKNOWN)


def _instruction_eas(block) -> tuple[int, ...]:
    result: list[int] = []
    instruction = block.head
    while instruction is not None:
        ea = int(getattr(instruction, "ea", -1) or -1)
        if 0 <= ea < _BADADDR and ea not in result:
            result.append(ea)
        if instruction is block.tail:
            break
        instruction = instruction.next
    return tuple(result)


def _unowned_endpoint(modifier: DeferredGraphModifier, serial: int) -> str:
    block = modifier.mba.get_mblock(int(serial))
    if block is not None:
        for candidate in (
            int(getattr(block, "start", -1) or -1),
            int(getattr(getattr(block, "head", None), "ea", -1) or -1),
        ):
            if 0 <= candidate < _BADADDR:
                return f"unowned@0x{candidate:X}"
    return "unowned@unknown-ea"


def _project_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    *,
    simulate_root_publication: bool = True,
) -> ProjectedFragment:
    live_by_id = {
        block_id: _live_block_for_binding(modifier, binding)
        for block_id, binding in state.bindings.items()
    }
    ids_by_serial: dict[int, str] = {}
    for block_id, block in live_by_id.items():
        serial = int(block.serial)
        if serial in ids_by_serial:
            raise SemanticFragmentBackendRejected(
                "two fragment block ids resolve to one physical version"
            )
        ids_by_serial[serial] = block_id

    successors: dict[str, list[str]] = {}
    predecessors: dict[str, list[str]] = {}
    for block_id, block in live_by_id.items():
        successors[block_id] = [
            ids_by_serial.get(
                int(serial),
                _unowned_endpoint(modifier, int(serial)),
            )
            for serial in block.succset
        ]
        predecessors[block_id] = [
            ids_by_serial.get(
                int(serial),
                _unowned_endpoint(modifier, int(serial)),
            )
            for serial in block.predset
        ]

    if simulate_root_publication:
        for root_id in plan.roots:
            replacement = plan.block(root_id)
            original_id = str(replacement.replaces_block_id)
            for predecessor_id in tuple(predecessors[original_id]):
                predecessors[original_id].remove(predecessor_id)
                predecessors[root_id].append(predecessor_id)
                if predecessor_id not in successors:
                    continue
                successors[predecessor_id] = [
                    root_id if target_id == original_id else target_id
                    for target_id in successors[predecessor_id]
                ]

    entry_ids = tuple(
        block_id
        for block_id, block in live_by_id.items()
        if int(block.serial) == 0
    )
    if len(entry_ids) != 1:
        raise SemanticFragmentBackendRejected(
            "fragment plan must own exactly one projected function entry"
        )

    projected_blocks = tuple(
        ProjectedFragmentBlock(
            block_id=block_id,
            kind=_block_kind(int(block.type)),
            successors=tuple(successors[block_id]),
            predecessors=tuple(predecessors[block_id]),
            physical_position=int(block.serial),
            instruction_eas=_instruction_eas(block),
            flag_write_eas=frozenset(),
        )
        for block_id, block in live_by_id.items()
    )
    projected_bindings = tuple(
        ProjectedIdentityBinding(
            block_id=binding.block_id,
            logical_owner_id=binding.proxy.proxy_token,
            version=binding.version.version_id.version,
            generation=binding.version.generation,
            state=binding.state,
            stable_identity=binding.version.handle.stable_identity,
            previous_version=(
                None
                if binding.version.predecessor_version_id is None
                else binding.version.predecessor_version_id.version
            ),
        )
        for binding in state.bindings.values()
    )
    return ProjectedFragment(
        entry_block_id=entry_ids[0],
        blocks=projected_blocks,
        identity_bindings=projected_bindings,
        fallthrough_helpers=tuple(state.fallthrough_helpers),
    )


def _binding_for_live_serial(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    serial: int,
) -> SemanticFragmentRuntimeBinding:
    matches = tuple(
        binding
        for binding in state.bindings.values()
        if int(_live_block_for_binding(modifier, binding).serial) == int(serial)
    )
    if len(matches) != 1:
        raise SemanticFragmentBackendRejected(
            "root predecessor is not owned by exactly one fragment binding"
        )
    return matches[0]


def _incoming_root_edge_role(predecessor, original) -> SemanticEdgeRole:
    successors = tuple(int(value) for value in predecessor.succset)
    original_serial = int(original.serial)
    if successors == (original_serial,):
        return SemanticEdgeRole.DIRECT
    tail = predecessor.tail
    if (
        len(successors) != 2
        or tail is None
        or not ida_hexrays.is_mcode_jcond(int(tail.opcode))
        or getattr(tail, "d", None) is None
        or int(tail.d.t) != int(ida_hexrays.mop_b)
    ):
        raise SemanticFragmentBackendRejected(
            "root predecessor is not a supported one-way or conditional edge"
        )
    taken_serial = int(tail.d.b)
    fallthroughs = tuple(
        successor for successor in successors if successor != taken_serial
    )
    if taken_serial not in successors or len(fallthroughs) != 1:
        raise SemanticFragmentBackendRejected(
            "root predecessor conditional topology is inconsistent"
        )
    if original_serial == taken_serial:
        return SemanticEdgeRole.CONDITIONAL_TAKEN
    if original_serial != fallthroughs[0]:
        raise SemanticFragmentBackendRejected(
            "root predecessor does not target its declared original"
        )
    if (
        predecessor.nextb is None
        or int(predecessor.nextb.serial) != original_serial
    ):
        raise SemanticFragmentBackendRejected(
            "root predecessor physical fallthrough is not adjacent"
        )
    return SemanticEdgeRole.CONDITIONAL_FALLTHROUGH


def prepare_semantic_fragment_root_publication(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> SemanticFragmentRootPublicationToken:
    """Capture every incoming root edge before exposing any staged version."""
    state = modifier._semantic_fragment_state
    if state is None:
        raise SemanticFragmentBackendRejected("semantic fragment is not staged")
    if state.plan_id != plan.plan_id or state.atomic_group_id != plan.atomic_group_id:
        raise SemanticFragmentBackendRejected(
            "staged semantic fragment does not match root publication request"
        )

    edges: list[SemanticFragmentRootEdgeBinding] = []
    for root_block_id in plan.roots:
        replacement = state.binding(root_block_id)
        original_block_id = str(plan.block(root_block_id).replaces_block_id)
        original = state.binding(original_block_id)
        original_live = _live_block_for_binding(modifier, original)
        replacement_live = _live_block_for_binding(modifier, replacement)
        if tuple(int(value) for value in replacement_live.predset):
            raise SemanticFragmentBackendRejected(
                f"replacement root {root_block_id!r} is already published"
            )
        predecessor_serials = tuple(int(value) for value in original_live.predset)
        if not predecessor_serials:
            raise SemanticFragmentBackendRejected(
                f"owned original {original_block_id!r} has no incoming root authority"
            )
        for predecessor_serial in predecessor_serials:
            predecessor = _binding_for_live_serial(
                modifier,
                state,
                predecessor_serial,
            )
            if predecessor.state is not FragmentBindingState.PUBLISHED:
                raise SemanticFragmentBackendRejected(
                    "root predecessor must be a published logical version"
                )
            predecessor_live = _live_block_for_binding(modifier, predecessor)
            role = _incoming_root_edge_role(predecessor_live, original_live)
            edge_id = f"{root_block_id}:{predecessor.block_id}:{role.value}"
            edges.append(
                SemanticFragmentRootEdgeBinding(
                    edge_id=edge_id,
                    root_block_id=root_block_id,
                    predecessor=predecessor,
                    original=original,
                    replacement=replacement,
                    role=role,
                )
            )
    edge_ids = tuple(edge.edge_id for edge in edges)
    if len(set(edge_ids)) != len(edge_ids):
        raise SemanticFragmentBackendRejected(
            "semantic fragment root publication contains duplicate edges"
        )
    unsupported = tuple(
        edge
        for edge in edges
        if edge.role
        not in {
            SemanticEdgeRole.DIRECT,
            SemanticEdgeRole.CONDITIONAL_TAKEN,
        }
    )
    if unsupported:
        raise SemanticFragmentBackendRejected(
            "conditional root publication requires its dedicated atomic lowering"
        )
    return SemanticFragmentRootPublicationToken(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        edges=tuple(edges),
    )


def observe_published_semantic_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> PublishedFragmentObservation:
    """Observe the actual live graph without projecting another root rewrite."""
    state = modifier._semantic_fragment_state
    if state is None:
        raise SemanticFragmentBackendRejected("semantic fragment is not staged")
    projection = _project_fragment(
        modifier,
        plan,
        state,
        simulate_root_publication=False,
    )
    validation = validate_fragment_projection(plan, projection)
    outcomes_by_subject: dict[str, list] = {}
    for outcome in validation.outcomes:
        outcomes_by_subject.setdefault(outcome.subject_id, []).append(outcome)

    published_roots = []
    for root_block_id in plan.roots:
        original_block_id = str(plan.block(root_block_id).replaces_block_id)
        if (
            not projection.block(original_block_id).predecessors
            and bool(projection.block(root_block_id).predecessors)
        ):
            published_roots.append(root_block_id)

    observable_operations = []
    for operation in plan.operations:
        relevant = outcomes_by_subject.get(operation.operation_id, ())
        topology = tuple(
            outcome
            for outcome in relevant
            if outcome.postcondition
            in {
                FragmentValidationPostcondition.OPERATION_TOPOLOGY,
                FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY,
            }
        )
        expected_count = 1 if len(operation.edges) == 1 else 2
        if len(topology) == expected_count and all(
            outcome.passed for outcome in topology
        ):
            observable_operations.append(operation)

    return PublishedFragmentObservation(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        published_root_ids=tuple(published_roots),
        observable_operations=tuple(observable_operations),
        semantic_outcomes=validation.outcomes,
    )


def stage_semantic_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> ProjectedFragment:
    """Stage direct replacement routes without exposing any publication root."""
    if not isinstance(plan, FragmentPlan):
        raise TypeError("semantic fragment backend requires a FragmentPlan")
    if modifier._semantic_fragment_state is not None:
        raise RuntimeError("a semantic fragment is already staged")
    if plan.data_flow_obligations or plan.flag_corridors or plan.value_range_assumptions:
        raise SemanticFragmentBackendRejected(
            "live semantic proof projection is required for data-flow plans"
        )

    state = SemanticFragmentBackendState(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
    )
    modifier._semantic_fragment_state = state
    try:
        for block in plan.blocks:
            if block.materialization is FragmentBlockMaterialization.REUSE_PUBLISHED:
                state.bindings[block.block_id] = _published_binding(
                    modifier,
                    block.block_id,
                    block.stable_identity,
                )
        for block in plan.blocks:
            if block.role is FragmentBlockRole.REPLACEMENT:
                _clone_replacement(modifier, state, block)
        reference_version = state.binding(plan.roots[0]).version
        for block in plan.blocks:
            if block.materialization is FragmentBlockMaterialization.CREATE_EMPTY:
                _create_empty_block(
                    modifier,
                    state,
                    block,
                    reference_version=reference_version,
                )
        _realize_operations(modifier, plan, state)
        projection = _project_fragment(modifier, plan, state)
        state.projection = projection
        return projection
    except Exception:
        discard_staged_semantic_fragment(modifier, plan)
        raise


def discard_staged_semantic_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> None:
    """Remove every unpublished physical version staged for ``plan``."""
    state = modifier._semantic_fragment_state
    if state is None:
        return
    if state.plan_id != plan.plan_id or state.atomic_group_id != plan.atomic_group_id:
        raise RuntimeError("staged semantic fragment does not match discard request")
    modifier._discard_detached_semantic_versions(
        tuple(
            state.binding(block_id).version
            for block_id in state.staged_block_ids
        )
    )
    modifier._semantic_fragment_state = None


__all__ = [
    "SemanticFragmentBackendRejected",
    "SemanticFragmentBackendState",
    "SemanticFragmentRootEdgeBinding",
    "SemanticFragmentRootPublicationToken",
    "discard_staged_semantic_fragment",
    "observe_published_semantic_fragment",
    "prepare_semantic_fragment_root_publication",
    "stage_semantic_fragment",
]
