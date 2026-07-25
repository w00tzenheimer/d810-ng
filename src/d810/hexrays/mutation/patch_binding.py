"""Bind portable PatchPlan references at the live mutation boundary."""

from __future__ import annotations

from dataclasses import dataclass, fields

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
from d810.transforms.plan import PatchPlan


class PatchBindingRejected(ValueError):
    """The immutable plan does not belong to the active live authority."""


@dataclass(frozen=True, slots=True)
class BoundPatchPlan:
    """Attempt-local serial bindings; never portable plan state."""

    plan: PatchPlan
    attempt_id: TransactionAttemptId
    session_id: str
    generation: int
    maturity: int
    bindings: tuple[tuple[CfgBlockRef, int], ...]
    reservations: tuple[PlanBlockReservation, ...]

    def serial_for(self, ref: CfgBlockRef | None) -> int | None:
        if ref is None:
            return None
        matches = tuple(serial for candidate, serial in self.bindings if candidate == ref)
        if len(matches) != 1:
            raise PatchBindingRejected(
                f"typed block reference has {len(matches)} live bindings"
            )
        return int(matches[0])

    def realize_value(self, value: object) -> object:
        """Resolve references recursively at the final backend call boundary."""
        # Exit-path sites are the one nested operation payload consumed by the
        # legacy IDA queue API.  Rebuild that boundary DTO with attempt-local
        # coordinates instead of allowing typed refs to leak into the backend.
        from d810.transforms.graph_modification import ExitPathLoweringSite
        from d810.transforms.plan import PatchExitPathLoweringSite

        if isinstance(value, (NativeBlockRef, LogicalBlockRef, PlanBlockRef)):
            return self.serial_for(value)
        if isinstance(value, PatchExitPathLoweringSite):
            return ExitPathLoweringSite(
                anchor_serial=int(self.serial_for(value.anchor_serial)),
                kind=value.kind,
                const_value=value.const_value,
                source_stkoff=value.source_stkoff,
                source_mreg=value.source_mreg,
                materializer_serials=tuple(
                    int(self.serial_for(ref)) for ref in value.materializer_serials
                ),
                skip_terminal_control_tail=value.skip_terminal_control_tail,
            )
        if isinstance(value, tuple):
            return tuple(self.realize_value(item) for item in value)
        if isinstance(value, list):
            return [self.realize_value(item) for item in value]
        if isinstance(value, dict):
            return {
                self.realize_value(key): self.realize_value(item)
                for key, item in value.items()
            }
        return value


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
                *(self._bound_plan.realize_value(arg) for arg in args),
                **{
                    key: self._bound_plan.realize_value(value)
                    for key, value in kwargs.items()
                },
            )

        return queue_bound


def _iter_refs(value: object):
    if isinstance(value, (NativeBlockRef, LogicalBlockRef, PlanBlockRef)):
        yield value
        return
    if isinstance(value, tuple):
        for item in value:
            yield from _iter_refs(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _iter_refs(key)
            yield from _iter_refs(item)
        return
    if hasattr(value, "__dataclass_fields__"):
        for item in fields(value):
            if not item.name.startswith("_"):
                yield from _iter_refs(getattr(value, item.name))


def bind_patch_plan(
    plan: PatchPlan,
    identity_index: MbaBlockIdentityIndex,
    transaction_attempt: TransactionAttemptId,
) -> BoundPatchPlan:
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
        None
        if plan.source_maturity is None
        else plan.source_maturity.provider_id
    )
    if source_provider_stage != identity_index.maturity:
        raise PatchBindingRejected("source maturity authority differs")

    refs = tuple(dict.fromkeys(_iter_refs((plan.steps, plan.new_blocks, plan.relocation_map))))
    planned_refs = tuple(spec.block_id for spec in plan.new_blocks)
    if len(set(planned_refs)) != len(planned_refs):
        raise PatchBindingRejected("plan contains duplicate planned block creations")
    unknown_planned = tuple(
        ref for ref in refs
        if isinstance(ref, PlanBlockRef) and ref not in planned_refs
    )
    if unknown_planned:
        raise PatchBindingRejected("PlanBlockRef lacks a creation specification")

    source_refs = tuple(
        ref for ref in refs if isinstance(ref, (NativeBlockRef, LogicalBlockRef))
    )
    source_coordinates = dict(plan.source_coordinates)
    if set(source_coordinates) != set(source_refs):
        raise PatchBindingRejected(
            "source coordinate coverage differs from executable block authority"
        )

    initial_quantity = identity_index.transaction_quantity(transaction_attempt.attempt_id)
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
            raise PatchBindingRejected("typed block reference has no unique live binding")
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

    return BoundPatchPlan(
        plan=plan,
        attempt_id=transaction_attempt,
        session_id=identity_index.session_id,
        generation=identity_index.generation,
        maturity=int(identity_index.maturity),
        bindings=tuple(bindings),
        reservations=tuple(reservations),
    )


__all__ = [
    "BoundModifier",
    "BoundPatchPlan",
    "PatchBindingRejected",
    "bind_patch_plan",
]
