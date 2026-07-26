"""Pure projection of a semantic fragment from immutable snapshot evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass

from d810.core.typing import Protocol
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.cfg_transaction import CfgProjection, PlanBlockRef
from d810.transforms.fragment_plan import (
    FragmentBlockMaterialization,
    FragmentConditionalSelectEnvelope,
    FragmentPlan,
    FragmentReturnCarrier,
    FragmentTerminalReturn,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    FragmentValidationPostcondition,
    ProjectedDataFlowRelation,
    ProjectedFallthroughHelper,
    ProjectedFragment,
    ProjectedFragmentBlock,
    ProjectedIdentityBinding,
    ProjectedRangeFact,
    ProjectedRootFallthroughHelper,
    ProjectedTerminalEffectDiagnostic,
)


class FragmentProjectionFailure(ValueError):
    """Typed prewrite failure to derive one projection obligation."""

    live_mutation_started = False
    failure_phase = "projection"

    def __init__(
        self,
        postcondition: FragmentValidationPostcondition,
        subject_id: str,
        reason: str,
    ) -> None:
        if not isinstance(postcondition, FragmentValidationPostcondition):
            raise TypeError("fragment projection failure requires a postcondition")
        self.postcondition = postcondition
        self.subject_id = str(subject_id)
        self.reason = str(reason)
        super().__init__(self.reason)


class FragmentRootInventoryItem(Protocol):
    root_block_id: str
    original_block_id: str
    predecessor_block_id: str
    role: SemanticEdgeRole
    requires_helper: bool


class FragmentRootInventory(Protocol):
    plan_id: str
    atomic_group_id: str
    items: tuple[FragmentRootInventoryItem, ...]


@dataclass(frozen=True, slots=True)
class FragmentProjectionBlockInput:
    """Read-only evidence for one existing or prepared physical block."""

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
        if not self.block_id:
            raise ValueError("fragment projection input requires a block id")
        if not isinstance(self.kind, BlockKind):
            raise TypeError("fragment projection input requires a BlockKind")
        if self.physical_position < 0:
            raise ValueError(
                "fragment projection physical position must be non-negative"
            )
        if self.terminator_ea is not None and self.terminator_ea < 0:
            raise ValueError("fragment projection terminator EA must be non-negative")
        if not isinstance(self.terminator_kind, InsnKind):
            raise TypeError("fragment projection input requires an InsnKind terminator")
        instruction_eas = tuple(self.instruction_eas)
        if self.terminator_ea is not None and (
            not instruction_eas or instruction_eas[-1] != self.terminator_ea
        ):
            raise ValueError(
                "fragment projection terminator must be its final instruction"
            )
        object.__setattr__(self, "successors", tuple(self.successors))
        object.__setattr__(self, "predecessors", tuple(self.predecessors))
        object.__setattr__(self, "instruction_eas", instruction_eas)
        object.__setattr__(self, "flag_write_eas", frozenset(self.flag_write_eas))


@dataclass(frozen=True, slots=True)
class FragmentCloneSourceInstruction:
    """Typed immutable instruction evidence inherited by a detached clone."""

    native_ea: int
    opcode: int
    kind: InsnKind
    destination_is_discardable: bool
    operand_shape: tuple[object, ...]

    def __post_init__(self) -> None:
        if self.native_ea < 0 or self.opcode < 0:
            raise ValueError("clone-source instruction values must be non-negative")
        if not isinstance(self.kind, InsnKind):
            raise TypeError("clone-source instruction requires a portable kind")
        if not isinstance(self.destination_is_discardable, bool):
            raise TypeError("clone-source destination evidence must be boolean")
        object.__setattr__(self, "operand_shape", tuple(self.operand_shape))


@dataclass(frozen=True, slots=True)
class FragmentCloneSourceInstructions:
    """Prewrite instruction evidence for a ``CLONE_PUBLISHED`` block."""

    block_id: str
    source_block_id: str
    instructions: tuple[FragmentCloneSourceInstruction, ...]

    def __post_init__(self) -> None:
        if not self.block_id or not self.source_block_id:
            raise ValueError("clone-source evidence requires block ids")
        instructions = tuple(self.instructions)
        if any(
            not isinstance(instruction, FragmentCloneSourceInstruction)
            for instruction in instructions
        ):
            raise TypeError("clone-source evidence contains an invalid instruction")
        object.__setattr__(self, "instructions", instructions)


@dataclass(frozen=True, slots=True)
class FragmentProjectionInput:
    """Immutable evidence required to project a fragment without live reads."""

    snapshot_id: str
    entry_block_id: str
    blocks: tuple[FragmentProjectionBlockInput, ...]
    identity_bindings: tuple[ProjectedIdentityBinding, ...]
    data_flow_relations: tuple[ProjectedDataFlowRelation, ...] = ()
    value_ranges: tuple[ProjectedRangeFact, ...] = ()
    return_carriers: tuple[FragmentReturnCarrier, ...] = ()
    terminal_returns: tuple[FragmentTerminalReturn, ...] = ()
    terminal_effect_diagnostics: tuple[ProjectedTerminalEffectDiagnostic, ...] = ()
    clone_source_instructions: tuple[FragmentCloneSourceInstructions, ...] = ()

    def __post_init__(self) -> None:
        if not self.snapshot_id or not self.entry_block_id:
            raise ValueError(
                "fragment projection input requires snapshot and entry ids"
            )
        object.__setattr__(self, "blocks", tuple(self.blocks))
        object.__setattr__(self, "identity_bindings", tuple(self.identity_bindings))
        object.__setattr__(
            self,
            "data_flow_relations",
            tuple(self.data_flow_relations),
        )
        object.__setattr__(self, "value_ranges", tuple(self.value_ranges))
        object.__setattr__(self, "return_carriers", tuple(self.return_carriers))
        object.__setattr__(self, "terminal_returns", tuple(self.terminal_returns))
        object.__setattr__(
            self,
            "terminal_effect_diagnostics",
            tuple(self.terminal_effect_diagnostics),
        )
        object.__setattr__(
            self,
            "clone_source_instructions",
            tuple(self.clone_source_instructions),
        )


def _next_position(positions: dict[str, int]) -> int:
    return max(positions.values(), default=-1) + 1


def _complete_projected_data_flow_authority(
    plan: FragmentPlan,
    snapshot_relations: tuple[ProjectedDataFlowRelation, ...],
) -> tuple[ProjectedDataFlowRelation, ...]:
    """Project every required relation that realization must later observe.

    Snapshot relations retain any already observable extra definitions or uses.
    A relation introduced by the planned topology or typed materialization cannot
    exist in the live prewrite graph, so add its two required query directions to
    the immutable expected post-state. Staged live observation must still match
    this authority before root publication.
    """
    relations = list(dict.fromkeys(snapshot_relations))
    for obligation in plan.data_flow_obligations:
        definition = obligation.definition
        for use in obligation.uses:
            relation_key = (
                definition.value_id,
                definition.site_id,
                use.site_id,
            )
            for use_def_observed, def_use_observed in (
                (True, False),
                (False, True),
            ):
                if any(
                    (
                        relation.value_id,
                        relation.definition_site_id,
                        relation.use_site_id,
                    )
                    == relation_key
                    and (
                        relation.use_def_observed
                        if use_def_observed
                        else relation.def_use_observed
                    )
                    for relation in relations
                ):
                    continue
                relations.append(
                    ProjectedDataFlowRelation(
                        value_id=definition.value_id,
                        definition_site_id=definition.site_id,
                        use_site_id=use.site_id,
                        use_def_observed=use_def_observed,
                        def_use_observed=def_use_observed,
                    )
                )
    return tuple(
        sorted(
            relations,
            key=lambda relation: (
                relation.value_id,
                relation.definition_site_id,
                relation.use_site_id,
                relation.use_def_observed,
                relation.def_use_observed,
            ),
        )
    )


def _validate_clone_storage_predicate_sources(
    plan: FragmentPlan,
    snapshot: FragmentProjectionInput,
) -> None:
    block_evidence_by_id = {block.block_id: block for block in snapshot.blocks}
    evidence_by_block_id = {
        evidence.block_id: evidence for evidence in snapshot.clone_source_instructions
    }
    if len(evidence_by_block_id) != len(snapshot.clone_source_instructions):
        raise FragmentProjectionFailure(
            FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
            "clone-source-instructions",
            "clone-source snapshot contains duplicate block ids",
        )
    terminal_transfer_kinds = {
        InsnKind.COND_JUMP,
        InsnKind.GOTO,
        InsnKind.INDIRECT_JUMP,
    }
    unsafe_control_kinds = terminal_transfer_kinds | {
        InsnKind.TABLE_JUMP,
        InsnKind.CALL,
        InsnKind.RET,
    }
    for operation in plan.operations:
        predicate = operation.storage_predicate_materialization
        source = plan.block(operation.source_block_id)
        if (
            predicate is None
            or source.materialization
            is not FragmentBlockMaterialization.CLONE_PUBLISHED
        ):
            continue
        evidence = evidence_by_block_id.get(source.block_id)
        if evidence is None:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                operation.operation_id,
                "clone-owned storage predicate lacks immutable source evidence",
            )
        instructions = evidence.instructions
        cut_indexes = tuple(
            index
            for index, instruction in enumerate(instructions)
            if instruction.native_ea == predicate.cut_after_ea
        )
        if not cut_indexes:
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.OPERATION_TOPOLOGY,
                operation.operation_id,
                "clone-owned storage predicate cut anchor is absent",
            )
        first_cut_index = cut_indexes[0]
        last_cut_index = cut_indexes[-1]
        if cut_indexes != tuple(range(first_cut_index, last_cut_index + 1)):
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.OPERATION_TOPOLOGY,
                operation.operation_id,
                "clone-owned storage predicate cut anchor is not contiguous",
            )
        suffix = instructions[last_cut_index + 1 :]
        unsafe_explicit_suffix = tuple(
            instruction
            for index, instruction in enumerate(suffix)
            if (
                instruction.kind in {InsnKind.CALL, InsnKind.RET}
                or (
                    index != len(suffix) - 1
                    and instruction.kind in unsafe_control_kinds
                )
                or (
                    index != len(suffix) - 1
                    and not instruction.destination_is_discardable
                )
            )
        )
        explicit_transfer_suffix = bool(
            suffix
            and suffix[-1].kind in terminal_transfer_kinds
            and not unsafe_explicit_suffix
        )
        source_input = block_evidence_by_id.get(evidence.source_block_id)
        fallthrough_targets = tuple(
            edge.target_block_id
            for edge in operation.edges
            if edge.role is SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
        )
        implicit_dispatcher_suffix = bool(
            suffix
            and source_input is not None
            and source_input.kind is BlockKind.ONE_WAY
            and source_input.terminator_kind is InsnKind.UNKNOWN
            and source_input.successors == fallthrough_targets
            and len(fallthrough_targets) == 1
            and all(
                instruction.kind in {InsnKind.NOP, InsnKind.MOV}
                and instruction.destination_is_discardable
                for instruction in suffix
            )
        )
        if not explicit_transfer_suffix and not implicit_dispatcher_suffix:
            evidence = json.dumps(
                {
                    "cut_after_ea": f"0x{predicate.cut_after_ea:X}",
                    "cut_indexes": cut_indexes,
                    "source_kind": (
                        None if source_input is None else source_input.kind.value
                    ),
                    "source_successors": (
                        () if source_input is None else source_input.successors
                    ),
                    "source_terminator_kind": (
                        None
                        if source_input is None
                        else source_input.terminator_kind.value
                    ),
                    "planned_fallthrough_targets": fallthrough_targets,
                    "suffix": tuple(
                        {
                            "native_ea": f"0x{instruction.native_ea:X}",
                            "opcode": instruction.opcode,
                            "kind": instruction.kind.value,
                            "destination_is_discardable": (
                                instruction.destination_is_discardable
                            ),
                            "operand_shape": instruction.operand_shape,
                        }
                        for instruction in suffix
                    ),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.OPERATION_TOPOLOGY,
                operation.operation_id,
                "clone-owned storage predicate suffix is not atomically discardable"
                f" evidence={evidence}",
            )


def project_fragment(
    plan: FragmentPlan,
    snapshot: FragmentProjectionInput,
    inventory: FragmentRootInventory,
) -> ProjectedFragment:
    """Derive the complete unpublished post-state without backend callbacks."""
    if (
        inventory.plan_id != plan.plan_id
        or inventory.atomic_group_id != plan.atomic_group_id
    ):
        raise FragmentProjectionFailure(
            FragmentValidationPostcondition.ROOT_AUTHORITY,
            "root-inventory",
            "fragment root inventory authority differs from the plan",
        )

    evidence = {block.block_id: block for block in snapshot.blocks}
    if len(evidence) != len(snapshot.blocks):
        raise FragmentProjectionFailure(
            FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
            "snapshot-blocks",
            "fragment projection snapshot contains duplicate block ids",
        )
    if snapshot.entry_block_id not in evidence:
        raise FragmentProjectionFailure(
            FragmentValidationPostcondition.ROOT_REACHABILITY,
            snapshot.entry_block_id,
            "fragment projection entry lacks snapshot evidence",
        )

    _validate_clone_storage_predicate_sources(plan, snapshot)

    successors = {
        block_id: list(block.successors) for block_id, block in evidence.items()
    }
    kinds = {block_id: block.kind for block_id, block in evidence.items()}
    positions = {
        block_id: block.physical_position for block_id, block in evidence.items()
    }
    adjacency = {
        block_id: block.adjacent_fallthrough_target_id
        for block_id, block in evidence.items()
    }
    terminator_eas = {
        block_id: block.terminator_ea for block_id, block in evidence.items()
    }
    terminator_kinds = {
        block_id: block.terminator_kind for block_id, block in evidence.items()
    }
    instruction_eas = {
        block_id: block.instruction_eas for block_id, block in evidence.items()
    }
    flag_write_eas = {
        block_id: block.flag_write_eas for block_id, block in evidence.items()
    }
    bindings = {binding.block_id: binding for binding in snapshot.identity_bindings}
    if len(bindings) != len(snapshot.identity_bindings):
        raise FragmentProjectionFailure(
            FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
            "snapshot-bindings",
            "fragment projection snapshot contains duplicate bindings",
        )

    for block in plan.blocks:
        if block.materialization is FragmentBlockMaterialization.REUSE_PUBLISHED:
            if block.block_id not in evidence or block.block_id not in bindings:
                raise FragmentProjectionFailure(
                    FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                    block.block_id,
                    f"fragment block {block.block_id!r} lacks snapshot evidence",
                )
            continue
        if block.materialization is FragmentBlockMaterialization.CLONE_PUBLISHED:
            original_id = str(block.replaces_block_id)
            original = evidence.get(original_id)
            original_binding = bindings.get(original_id)
            if original is None or original_binding is None:
                raise FragmentProjectionFailure(
                    FragmentValidationPostcondition.IDENTITY_OWNERSHIP,
                    block.block_id,
                    f"replacement {block.block_id!r} lacks original evidence",
                )
            successors[block.block_id] = list(original.successors)
            kinds[block.block_id] = original.kind
            positions[block.block_id] = original.physical_position
            positions[original_id] = _next_position(positions)
            adjacency[block.block_id] = original.adjacent_fallthrough_target_id
            terminator_eas[block.block_id] = original.terminator_ea
            terminator_kinds[block.block_id] = original.terminator_kind
            instruction_eas[block.block_id] = original.instruction_eas
            flag_write_eas[block.block_id] = original.flag_write_eas
            bindings[block.block_id] = ProjectedIdentityBinding(
                block_id=block.block_id,
                logical_owner_id=original_binding.logical_owner_id,
                version=original_binding.version + 1,
                generation=original_binding.generation + 1,
                state=FragmentBindingState.STAGED,
                stable_identity=block.stable_identity,
                previous_version=original_binding.version,
            )
            continue

        prepared = evidence.get(block.block_id)
        if (
            block.materialization is FragmentBlockMaterialization.IMPORT_NATIVE
            and prepared is not None
        ):
            successors[block.block_id] = list(prepared.successors)
            kinds[block.block_id] = prepared.kind
            positions[block.block_id] = prepared.physical_position
            adjacency[block.block_id] = prepared.adjacent_fallthrough_target_id
            terminator_eas[block.block_id] = prepared.terminator_ea
            terminator_kinds[block.block_id] = prepared.terminator_kind
            instruction_eas[block.block_id] = prepared.instruction_eas
            flag_write_eas[block.block_id] = prepared.flag_write_eas
        else:
            successors[block.block_id] = []
            kinds[block.block_id] = BlockKind.ZERO_WAY
            positions[block.block_id] = _next_position(positions)
            adjacency[block.block_id] = None
            terminator_eas[block.block_id] = None
            terminator_kinds[block.block_id] = InsnKind.UNKNOWN
            instruction_eas[block.block_id] = ()
            flag_write_eas[block.block_id] = frozenset()
        bindings[block.block_id] = ProjectedIdentityBinding(
            block_id=block.block_id,
            logical_owner_id=f"plan:{plan.plan_id}:{block.block_id}",
            version=0,
            generation=0,
            state=FragmentBindingState.STAGED,
            stable_identity=block.stable_identity,
        )

    for carrier in snapshot.return_carriers:
        rows = list(instruction_eas.get(carrier.block_id, ()))
        if carrier.carrier_ea not in rows:
            insertion = rows.index(carrier.state_write_ea) + 1
            rows.insert(insertion, carrier.carrier_ea)
        instruction_eas[carrier.block_id] = tuple(rows)
    for terminal in snapshot.terminal_returns:
        rows = list(instruction_eas.get(terminal.block_id, ()))
        if terminal.instruction_ea not in rows:
            rows.append(terminal.instruction_ea)
        instruction_eas[terminal.block_id] = tuple(rows)
        kinds[terminal.block_id] = BlockKind.ZERO_WAY
        successors[terminal.block_id] = []
        adjacency[terminal.block_id] = None
        terminator_eas[terminal.block_id] = terminal.instruction_ea
        terminator_kinds[terminal.block_id] = InsnKind.RET

    fallthrough_helpers: list[ProjectedFallthroughHelper] = []
    for operation in plan.operations:
        edge_targets = [edge.target_block_id for edge in operation.edges]
        if any(target not in successors for target in edge_targets):
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.OPERATION_TOPOLOGY,
                operation.operation_id,
                f"fragment operation {operation.operation_id!r} has an unknown target",
            )
        fallthrough_edges = tuple(
            edge
            for edge in operation.edges
            if edge.role
            in {
                SemanticEdgeRole.CALL_FALLTHROUGH,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        )
        projected_targets: list[str] = []
        for edge in operation.edges:
            if edge not in fallthrough_edges:
                projected_targets.append(edge.target_block_id)
                continue
            helper_id = f"fallthrough-helper:{operation.operation_id}"
            if helper_id not in successors:
                insertion_position = positions[operation.source_block_id] + 1
                for block_id in tuple(positions):
                    if positions[block_id] >= insertion_position:
                        positions[block_id] += 1
                positions[helper_id] = insertion_position
                successors[helper_id] = [edge.target_block_id]
                kinds[helper_id] = BlockKind.ONE_WAY
                adjacency[helper_id] = None
                terminator_eas[helper_id] = None
                terminator_kinds[helper_id] = InsnKind.GOTO
                instruction_eas[helper_id] = ()
                flag_write_eas[helper_id] = frozenset()
                bindings[helper_id] = ProjectedIdentityBinding(
                    block_id=helper_id,
                    logical_owner_id=f"plan:{plan.plan_id}:{helper_id}",
                    version=0,
                    generation=0,
                    state=FragmentBindingState.STAGED,
                    stable_identity=None,
                )
                fallthrough_helpers.append(
                    ProjectedFallthroughHelper(
                        helper_block_id=helper_id,
                        operation_id=operation.operation_id,
                        source_block_id=operation.source_block_id,
                        semantic_target_block_id=edge.target_block_id,
                    )
                )
            projected_targets.append(helper_id)
        if fallthrough_edges:
            helper_id = f"fallthrough-helper:{operation.operation_id}"
            projected_targets = [helper_id] + [
                target for target in projected_targets if target != helper_id
            ]
            adjacency[operation.source_block_id] = (
                helper_id
                if any(
                    edge.role is SemanticEdgeRole.CONDITIONAL_FALLTHROUGH
                    for edge in fallthrough_edges
                )
                else None
            )
        else:
            adjacency[operation.source_block_id] = None
        successors[operation.source_block_id] = projected_targets
        kinds[operation.source_block_id] = (
            BlockKind.TWO_WAY if len(projected_targets) == 2 else BlockKind.ONE_WAY
        )
        normalization = operation.computed_branch_normalization
        conditional_select_envelope = (
            None if normalization is None else normalization.conditional_select_envelope
        )
        if isinstance(
            conditional_select_envelope,
            FragmentConditionalSelectEnvelope,
        ):
            predicate_anchor_ea = int(operation.predicate_anchor_ea)
            rows = list(instruction_eas[operation.source_block_id])
            if rows.count(predicate_anchor_ea) != 1:
                raise FragmentProjectionFailure(
                    FragmentValidationPostcondition.OPERATION_TOPOLOGY,
                    operation.operation_id,
                    "conditional-select replacement requires exactly one "
                    "predicate anchor in its immutable instruction evidence",
                )
            rows = rows[: rows.index(predicate_anchor_ea) + 1]
            instruction_eas[operation.source_block_id] = tuple(rows)
            flag_write_eas[operation.source_block_id] = frozenset(
                ea for ea in flag_write_eas[operation.source_block_id] if ea in rows
            )
            terminator_eas[operation.source_block_id] = predicate_anchor_ea
            terminator_kinds[operation.source_block_id] = InsnKind.COND_JUMP
        direct_rewrite = operation.direct_transfer_rewrite
        if direct_rewrite is not None:
            rewrite_anchor_ea = int(direct_rewrite.rewrite_anchor_ea)
            rows = list(instruction_eas[operation.source_block_id])
            if rewrite_anchor_ea in rows:
                rows = rows[: rows.index(rewrite_anchor_ea) + 1]
            else:
                rows.append(rewrite_anchor_ea)
            instruction_eas[operation.source_block_id] = tuple(rows)
            flag_write_eas[operation.source_block_id] = frozenset(
                ea for ea in flag_write_eas[operation.source_block_id] if ea in rows
            )
            terminator_eas[operation.source_block_id] = rewrite_anchor_ea
            terminator_kinds[operation.source_block_id] = InsnKind.GOTO

    root_helpers: list[ProjectedRootFallthroughHelper] = []
    for item in inventory.items:
        if (
            item.predecessor_block_id not in successors
            or item.original_block_id not in successors
        ):
            raise FragmentProjectionFailure(
                FragmentValidationPostcondition.ROOT_AUTHORITY,
                item.root_block_id,
                "root inventory references an unknown projected block",
            )
        target_id = item.root_block_id
        if item.requires_helper:
            helper_id = (
                "root-fallthrough-helper:"
                f"{item.predecessor_block_id}:{item.root_block_id}"
            )
            positions[helper_id] = positions[item.predecessor_block_id] + 1
            for block_id in tuple(positions):
                if (
                    block_id != helper_id
                    and positions[block_id] >= positions[helper_id]
                ):
                    positions[block_id] += 1
            successors[helper_id] = [item.root_block_id]
            kinds[helper_id] = BlockKind.ONE_WAY
            adjacency[helper_id] = None
            terminator_eas[helper_id] = None
            terminator_kinds[helper_id] = InsnKind.UNKNOWN
            instruction_eas[helper_id] = ()
            flag_write_eas[helper_id] = frozenset()
            bindings[helper_id] = ProjectedIdentityBinding(
                block_id=helper_id,
                logical_owner_id=f"plan:{plan.plan_id}:{helper_id}",
                version=0,
                generation=0,
                state=FragmentBindingState.STAGED,
                stable_identity=None,
            )
            root_helpers.append(
                ProjectedRootFallthroughHelper(
                    helper_block_id=helper_id,
                    source_block_id=item.predecessor_block_id,
                    root_block_id=item.root_block_id,
                )
            )
            target_id = helper_id
            if kinds[item.predecessor_block_id] is BlockKind.TWO_WAY:
                adjacency[item.predecessor_block_id] = helper_id
        successors[item.predecessor_block_id] = [
            target_id if target == item.original_block_id else target
            for target in successors[item.predecessor_block_id]
        ]

    predecessors = {block_id: [] for block_id in successors}
    for source, targets in successors.items():
        for target in targets:
            if target in predecessors:
                predecessors[target].append(source)
    projected_blocks = tuple(
        ProjectedFragmentBlock(
            block_id=block_id,
            kind=kinds[block_id],
            successors=tuple(successors[block_id]),
            predecessors=tuple(predecessors[block_id]),
            physical_position=positions[block_id],
            adjacent_fallthrough_target_id=adjacency[block_id],
            terminator_ea=terminator_eas[block_id],
            terminator_kind=terminator_kinds[block_id],
            instruction_eas=instruction_eas[block_id],
            flag_write_eas=flag_write_eas[block_id],
        )
        for block_id in sorted(
            successors,
            key=lambda value: (positions[value], value),
        )
    )
    return ProjectedFragment(
        entry_block_id=snapshot.entry_block_id,
        blocks=projected_blocks,
        identity_bindings=tuple(bindings[block.block_id] for block in projected_blocks),
        fallthrough_helpers=tuple(fallthrough_helpers),
        root_fallthrough_helpers=tuple(root_helpers),
        return_carriers=tuple(snapshot.return_carriers),
        terminal_returns=tuple(snapshot.terminal_returns),
        terminal_effect_diagnostics=snapshot.terminal_effect_diagnostics,
        data_flow_relations=_complete_projected_data_flow_authority(
            plan,
            snapshot.data_flow_relations,
        ),
        value_ranges=snapshot.value_ranges,
    )


def fragment_cfg_projection(
    plan: FragmentPlan,
    snapshot: FragmentProjectionInput,
    projection: ProjectedFragment,
) -> CfgProjection:
    """Normalize a serial-free fragment into a portable CFG projection."""
    ordered = tuple(
        sorted(
            projection.blocks,
            key=lambda block: block.physical_position,
        )
    )
    node_by_id = {block.block_id: index for index, block in enumerate(ordered)}
    blocks = {
        node_by_id[block.block_id]: BlockSnapshot(
            serial=node_by_id[block.block_id],
            block_type=-1,
            succs=tuple(
                node_by_id[target]
                for target in block.successors
                if target in node_by_id
            ),
            preds=tuple(
                node_by_id[source]
                for source in block.predecessors
                if source in node_by_id
            ),
            flags=0,
            start_ea=block.instruction_eas[0] if block.instruction_eas else 0,
            insn_snapshots=(),
            kind=block.kind,
            tail_kind=(
                InsnKind.COND_JUMP
                if block.kind is BlockKind.TWO_WAY
                else InsnKind.GOTO
                if block.kind is BlockKind.ONE_WAY
                else None
            ),
        )
        for block in ordered
    }
    return CfgProjection(
        plan_id=plan.plan_id,
        snapshot_id=snapshot.snapshot_id,
        graph=FlowGraph(
            blocks=blocks,
            entry_serial=node_by_id[projection.entry_block_id],
            func_ea=0,
            metadata={
                "fragment_block_ids": tuple(block.block_id for block in ordered),
                "node_identity_scope": "projection-local",
            },
        ),
        focus_refs=tuple(
            PlanBlockRef(plan.plan_id, block.block_id) for block in ordered
        ),
    )


__all__ = [
    "FragmentCloneSourceInstruction",
    "FragmentCloneSourceInstructions",
    "FragmentProjectionBlockInput",
    "FragmentProjectionFailure",
    "FragmentProjectionInput",
    "fragment_cfg_projection",
    "project_fragment",
]
