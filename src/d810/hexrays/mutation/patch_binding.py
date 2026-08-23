"""Bind portable PatchPlan references at the live mutation boundary."""

from __future__ import annotations

from dataclasses import dataclass

from d810.hexrays.ir.mba_identity_index import (
    MbaBlockIdentityIndex,
    PlanBlockReservation,
)
from d810.ir.block_identity import RebindStatus
from d810.transforms.cfg_transaction import (
    CfgBlockRef,
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
    TransactionAttemptId,
)
from d810.transforms.patch_binding import (
    BoundPatchPlan,
    PatchBindingRejected,
    iter_refs,
    realize_value,
)
from d810.transforms.plan import PatchPlan


@dataclass(frozen=True, slots=True)
class PatchBindingResult:
    """Hex-Rays binding wrapper; reservations stay outside portable authority."""

    bound_plan: BoundPatchPlan
    reservations: tuple[PlanBlockReservation, ...]

    def __post_init__(self) -> None:
        if type(self.bound_plan) is not BoundPatchPlan:
            raise TypeError("binding result requires the exact BoundPatchPlan")
        if type(self.reservations) is not tuple:
            raise TypeError("binding reservations must be an exact tuple")
        if any(type(item) is not PlanBlockReservation for item in self.reservations):
            raise TypeError("binding reservations must be exact PlanBlockReservation values")

    @property
    def bindings(self):
        return self.bound_plan.bindings


class BoundModifier:
    """Narrow adapter exposing integer coordinates only to queue calls."""

    def __init__(self, modifier: object, bound_plan: BoundPatchPlan) -> None:
        self._modifier = modifier
        self._bound_plan = bound_plan

    def __getattr__(self, name: str):
        target = getattr(self._modifier, name)
        if not callable(target) or not name.startswith("queue_"):
            return target

        def queue_bound(*args, **kwargs):
            return target(
                *(realize_value(self._bound_plan, arg) for arg in args),
                **{
                    key: realize_value(self._bound_plan, value)
                    for key, value in kwargs.items()
                },
            )

        return queue_bound


def bind_patch_plan(
    plan: PatchPlan,
    identity_index: MbaBlockIdentityIndex,
    transaction_attempt: TransactionAttemptId,
) -> PatchBindingResult:
    """Resolve one plan under an already-active typed transaction attempt."""
    if not isinstance(plan, PatchPlan):
        raise TypeError("patch binding requires a PatchPlan")
    if not isinstance(identity_index, MbaBlockIdentityIndex):
        raise TypeError("patch binding requires MbaBlockIdentityIndex")
    if not isinstance(transaction_attempt, TransactionAttemptId):
        raise TypeError("patch binding requires TransactionAttemptId")
    if transaction_attempt.plan_id != plan.plan_id:
        raise PatchBindingRejected("transaction attempt plan authority differs")
    try:
        identity_index.require_active_attempt(transaction_attempt)
    except (TypeError, ValueError) as exc:
        raise PatchBindingRejected(str(exc)) from exc
    if plan.snapshot_id != identity_index.snapshot_id:
        raise PatchBindingRejected("source snapshot authority differs")
    if plan.source_generation != identity_index.generation:
        raise PatchBindingRejected("source generation authority differs")
    source_provider_stage = (
        None if plan.source_maturity is None else plan.source_maturity.provider_id
    )
    if source_provider_stage is not None and source_provider_stage != identity_index.maturity:
        raise PatchBindingRejected("source maturity authority differs")

    refs = tuple(
        dict.fromkeys(iter_refs((plan.steps, plan.new_blocks, plan.relocation_map)))
    )
    planned_refs = tuple(spec.block_id for spec in plan.new_blocks)
    if len(set(planned_refs)) != len(planned_refs):
        raise PatchBindingRejected("plan contains duplicate planned block creations")
    unknown_planned = tuple(
        ref for ref in refs if isinstance(ref, PlanBlockRef) and ref not in planned_refs
    )
    if unknown_planned:
        raise PatchBindingRejected("PlanBlockRef lacks a creation specification")

    source_refs = tuple(
        ref for ref in refs if isinstance(ref, (NativeBlockRef, LogicalBlockRef))
    )
    source_coordinates = dict(plan.source_coordinates)
    if not set(source_refs).issubset(source_coordinates):
        raise PatchBindingRejected(
            "executable block references lack sealed source coordinates"
        )

    initial_quantity = identity_index.transaction_quantity(
        transaction_attempt.attempt_id
    )
    planned_coordinates = {
        ref: initial_quantity + offset for offset, ref in enumerate(planned_refs)
    }
    bindings: list[tuple[CfgBlockRef, int]] = []
    for ref in refs:
        if isinstance(ref, PlanBlockRef):
            continue
        elif isinstance(ref, NativeBlockRef):
            result = identity_index.rebind_identity(ref.identity)
            if result.status is not RebindStatus.BOUND or result.block is None:
                raise PatchBindingRejected(
                    f"native reference is not unique: {result.status.value}"
                )
            serial = result.block.serial
        elif isinstance(ref, LogicalBlockRef):
            block = identity_index.resolve_logical_ref(
                ref,
                transaction_id=transaction_attempt.attempt_id,
            )
            serial = None if block is None else block.serial
        else:  # pragma: no cover - PatchPlan validation owns this boundary.
            raise PatchBindingRejected("unsupported block reference")
        if serial is None:
            raise PatchBindingRejected(
                "typed block reference has no unique live binding"
            )
        if int(source_coordinates[ref]) != int(serial):
            raise PatchBindingRejected(
                "source coordinate differs from current binder resolution"
            )
        bindings.append((ref, int(serial)))

    # Reservation changes identity-index state, so it follows every fallible
    # source-authority resolution and still precedes the first SDK write.
    reservations: list[PlanBlockReservation] = []
    for ref in planned_refs:
        reservations.append(identity_index.reserve_plan_block(transaction_attempt, ref))
        bindings.append((ref, planned_coordinates[ref]))

    try:
        from d810.hexrays.ir_maturity import hexrays_maturity_envelope
    except ModuleNotFoundError as exc:
        if exc.name != "ida_hexrays":
            raise
        # Portable unit tests do not load the vendor module; retain the exact
        # provider stage while leaving semantic IR mapping to the live adapter.
        from d810.ir.maturity import MaturityEnvelope

        maturity = MaturityEnvelope(
            ir=None, provider="hexrays", provider_id=int(identity_index.maturity or 0)
        )
    else:
        maturity = hexrays_maturity_envelope(int(identity_index.maturity))
    if plan.source_maturity is not None and plan.source_maturity.provider_id != maturity.provider_id:
        raise PatchBindingRejected("source maturity provider stage differs from live binder")
    bound_plan = BoundPatchPlan(
        plan=plan,
        attempt_id=transaction_attempt,
        session_id=identity_index.session_id,
        generation=identity_index.generation,
        maturity=maturity,
        bindings=tuple(bindings),
    )
    return PatchBindingResult(bound_plan=bound_plan, reservations=tuple(reservations))


__all__ = [
    "BoundModifier",
    "BoundPatchPlan",
    "PatchBindingResult",
    "PatchBindingRejected",
    "bind_patch_plan",
]
