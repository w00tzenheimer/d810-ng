"""Lower preflighted semantic fragments into the shared PatchPlan IR.

The lowering is deliberately pure.  It does not inspect an MBA and it never
assigns a native block serial: every fragment-local block remains a
``PlanBlockRef`` until the transaction binder owns a live attempt.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Protocol
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.transforms.cfg_transaction import CfgProjection, PlanBlockRef
from d810.transforms.fragment_plan import (
    FragmentBlockMaterialization,
    FragmentOperation,
    FragmentPlan,
    FragmentReturnCarrier,
    FragmentTerminalReturn,
    FragmentTerminalRoute,
)
from d810.transforms.fragment_validation import (
    FragmentValidationOutcome,
    FragmentValidationPostcondition,
    FragmentValidationResult,
    ProjectedFragment,
    validate_fragment_projection,
)
from d810.transforms.plan import (
    FragmentContractBundle,
    PatchFragmentBlockMaterialization,
    PatchFragmentOperation,
    PatchFragmentOperationNormalization,
    PatchFragmentRootPublication,
    PatchFragmentTerminalEffects,
    PatchPlan,
)


class _RootInventoryItem(Protocol):
    root_block_id: str
    original_block_id: str
    predecessor_block_id: str
    role: SemanticEdgeRole
    requires_helper: bool


class _RootInventory(Protocol):
    plan_id: str
    atomic_group_id: str
    items: tuple[_RootInventoryItem, ...]


class PreparedFragmentProjection(Protocol):
    """Portable authority required by ``lower_fragment_plan``.

    The concrete Hex-Rays preparation authority structurally satisfies this
    protocol; unit tests and other backends can provide the same immutable
    values without importing a live-backend module.
    """

    plan_id: str
    atomic_group_id: str
    snapshot_id: str
    generation: int
    projection: ProjectedFragment
    cfg_projection: CfgProjection
    root_inventory: _RootInventory


class _SharedTransactionParticipant(Protocol):
    def lower(
        self, plan: object, prepared_projection: object | None = None
    ) -> object: ...


class PatchTransactionLifecycle(Protocol):
    """Participant-neutral execution phases owned by the coordinator."""

    def begin(self, patch_plan: PatchPlan) -> object: ...
    def realize(self, patch_plan: PatchPlan, begun: object) -> object: ...
    def observe(self, patch_plan: PatchPlan, realized: object) -> object: ...
    def validate(self, patch_plan: PatchPlan, observed: object) -> object: ...
    def commit(self, patch_plan: PatchPlan, validated: object) -> object: ...
    def fail(self, patch_plan: PatchPlan, error: Exception, phase: str) -> None: ...


def _operation_fallthrough_helper_id(operation: FragmentOperation) -> str | None:
    """Name a helper only when the typed operation cannot use physical adjacency."""
    if operation.requires_fallthrough_helper:
        return f"fallthrough-helper:{operation.operation_id}"
    return None


@dataclass(frozen=True)
class PatchTransactionParticipant:
    """Participant for plans already expressed in the shared execution IR."""

    def lower(
        self, plan: object, prepared_projection: object | None = None
    ) -> PatchPlan:
        if prepared_projection is not None:
            raise ValueError("PatchPlan participant does not accept fragment preflight")
        if not isinstance(plan, PatchPlan):
            raise TypeError("PatchTransactionParticipant requires PatchPlan")
        return plan


@dataclass(frozen=True)
class FragmentTransactionParticipant:
    """Participant lowering preflighted FragmentPlan intent into PatchPlan."""

    def lower(
        self, plan: object, prepared_projection: object | None = None
    ) -> PatchPlan:
        if not isinstance(plan, FragmentPlan):
            raise TypeError("FragmentTransactionParticipant requires FragmentPlan")
        if prepared_projection is None:
            raise ValueError("fragment participant requires prepared projection")
        return lower_fragment_plan(plan, prepared_projection)


@dataclass(frozen=True)
class CfgTransactionCoordinator:
    """Own the same lifecycle sequence for every transaction participant."""

    lifecycle: PatchTransactionLifecycle

    def execute(
        self,
        participant: _SharedTransactionParticipant,
        plan: object,
        *,
        prepared_projection: object | None = None,
    ) -> object:
        lowered = participant.lower(plan, prepared_projection)
        if not isinstance(lowered, PatchPlan):
            raise TypeError("transaction participant did not produce PatchPlan")
        phase = "begin"
        try:
            begun = self.lifecycle.begin(lowered)
            phase = "realize"
            realized = self.lifecycle.realize(lowered, begun)
            phase = "observe"
            observed = self.lifecycle.observe(lowered, realized)
            phase = "validate"
            validated = self.lifecycle.validate(lowered, observed)
            phase = "commit"
            return self.lifecycle.commit(lowered, validated)
        except Exception as error:
            self.lifecycle.fail(lowered, error, phase)
            raise


def _prepared_authority(prepared_projection: object) -> PreparedFragmentProjection:
    authority = getattr(prepared_projection, "authority", prepared_projection)
    required = (
        "plan_id",
        "atomic_group_id",
        "snapshot_id",
        "generation",
        "projection",
        "cfg_projection",
        "root_inventory",
    )
    if any(not hasattr(authority, name) for name in required):
        raise TypeError(
            "fragment lowering requires complete prepared projection authority"
        )
    return authority  # type: ignore[return-value]


def lower_fragment_plan(
    plan: FragmentPlan,
    prepared_projection: PreparedFragmentProjection | object,
) -> PatchPlan:
    """Lower one already-preflighted FragmentPlan into typed Patch operations."""
    if not isinstance(plan, FragmentPlan):
        raise TypeError("fragment lowering requires FragmentPlan")
    prepared = _prepared_authority(prepared_projection)
    if (
        prepared.plan_id != plan.plan_id
        or prepared.atomic_group_id != plan.atomic_group_id
        or prepared.cfg_projection.plan_id != plan.plan_id
        or prepared.cfg_projection.snapshot_id != prepared.snapshot_id
        or prepared.root_inventory.plan_id != plan.plan_id
        or prepared.root_inventory.atomic_group_id != plan.atomic_group_id
    ):
        raise ValueError("prepared fragment projection authority differs from plan")

    validation = validate_fragment_projection(plan, prepared.projection)
    if not validation.passed:
        raise ValueError("cannot lower a fragment that failed semantic preflight")

    refs = {
        block.block_id: PlanBlockRef(plan.plan_id, block.block_id)
        for block in plan.blocks
    }
    steps: list[object] = []
    materialization_order = {
        FragmentBlockMaterialization.REUSE_PUBLISHED: 0,
        FragmentBlockMaterialization.CLONE_PUBLISHED: 1,
        FragmentBlockMaterialization.IMPORT_NATIVE: 2,
        FragmentBlockMaterialization.CREATE_EMPTY: 3,
    }
    for block in sorted(
        plan.blocks,
        key=lambda item: materialization_order[item.materialization],
    ):
        source_ref = (
            None if block.replaces_block_id is None else refs[block.replaces_block_id]
        )
        steps.append(
            PatchFragmentBlockMaterialization(
                block_ref=refs[block.block_id],
                block=block,
                materialization=block.materialization,
                source_ref=source_ref,
                native_body_id=block.native_body_id,
            )
        )
    normalized_operations = tuple(
        operation
        for operation in plan.operations
        if operation.computed_branch_normalization is not None
        or (
            operation.storage_predicate_materialization is not None
            and plan.block(operation.source_block_id).materialization
            is FragmentBlockMaterialization.CLONE_PUBLISHED
        )
    )
    if normalized_operations:
        steps.append(PatchFragmentOperationNormalization(normalized_operations))
    if plan.return_carriers or plan.terminal_returns or plan.terminal_routes:
        steps.append(
            PatchFragmentTerminalEffects(
                return_carriers=plan.return_carriers,
                terminal_returns=plan.terminal_returns,
                terminal_routes=plan.terminal_routes,
            )
        )
    for operation in plan.operations:
        fallthrough_helper_id = _operation_fallthrough_helper_id(operation)
        steps.append(
            PatchFragmentOperation(
                source_ref=refs[operation.source_block_id],
                target_refs=tuple(
                    refs[edge.target_block_id] for edge in operation.edges
                ),
                operation=operation,
                fallthrough_helper_id=fallthrough_helper_id,
                fallthrough_helper_ref=(
                    None
                    if fallthrough_helper_id is None
                    else PlanBlockRef(plan.plan_id, fallthrough_helper_id)
                ),
            )
        )
    for inventory_item in prepared.root_inventory.items:
        root_id = inventory_item.root_block_id
        root = plan.block(root_id)
        root_helper_id = (
            None
            if not inventory_item.requires_helper
            else "root-fallthrough-helper:"
            f"{inventory_item.predecessor_block_id}:{root_id}"
        )
        steps.append(
            PatchFragmentRootPublication(
                root_ref=refs[root_id],
                original_ref=refs[str(root.replaces_block_id)],
                predecessor_ref=refs[inventory_item.predecessor_block_id],
                edge_role=inventory_item.role,
                fallthrough_helper_id=root_helper_id,
                fallthrough_helper_ref=(
                    None
                    if root_helper_id is None
                    else PlanBlockRef(plan.plan_id, root_helper_id)
                ),
            )
        )

    bundle = FragmentContractBundle(
        fragment_plan=plan,
        prepared_projection=prepared.projection,
        cfg_projection=prepared.cfg_projection,
        prepublication_validation=validation,
        root_inventory=prepared.root_inventory,
        fragment_postconditions=tuple(FragmentValidationPostcondition),
    )
    return PatchPlan(
        plan_id=plan.plan_id,
        snapshot_id=prepared.snapshot_id,
        source_generation=int(prepared.generation),
        steps=tuple(steps),  # type: ignore[arg-type]
        semantic_contract=bundle,
    )


__all__ = [
    "CfgTransactionCoordinator",
    "FragmentContractBundle",
    "FragmentTransactionParticipant",
    "PatchFragmentBlockMaterialization",
    "PatchFragmentOperation",
    "PatchFragmentOperationNormalization",
    "PatchFragmentRootPublication",
    "PatchFragmentTerminalEffects",
    "PreparedFragmentProjection",
    "PatchTransactionParticipant",
    "lower_fragment_plan",
]
