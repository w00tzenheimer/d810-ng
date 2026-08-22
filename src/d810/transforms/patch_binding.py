"""Neutral, nominal authority for one live :class:`PatchPlan` binding.

The DTO in this module deliberately knows nothing about Hex-Rays reservations
or identity indexes.  Those backend concerns travel beside the exact bound
plan and never become part of the portable authority object.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

from d810.transforms.cfg_transaction import (
    CfgBlockRef,
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
    TransactionAttemptId,
)
from d810.ir.maturity import IRMaturity, MaturityEnvelope, SnapshotForm
from d810.transforms.plan import PatchExitPathLoweringSite, PatchPlan


class PatchBindingRejected(ValueError):
    """The exact neutral binding is malformed or belongs to another authority."""


def _validate_binding_pair(value: object, label: str) -> tuple[CfgBlockRef, int]:
    if type(value) is not tuple or len(value) != 2:
        raise TypeError(f"{label} must contain exact (CfgBlockRef, int) pairs")
    ref, serial = value
    if type(ref) not in (NativeBlockRef, LogicalBlockRef, PlanBlockRef):
        raise TypeError(f"{label} reference must be a CfgBlockRef")
    if type(serial) is not int or serial < 0:
        raise TypeError(f"{label} serial must be an exact non-negative int")
    return ref, serial


@dataclass(frozen=True, slots=True)
class BoundPatchPlan:
    """Exact nominal live binding, without backend reservation state."""

    plan: PatchPlan
    attempt_id: TransactionAttemptId
    session_id: str
    generation: int
    maturity: MaturityEnvelope
    bindings: tuple[tuple[CfgBlockRef, int], ...]

    def __post_init__(self) -> None:
        if type(self.plan) is not PatchPlan:
            raise TypeError("bound plan requires the exact PatchPlan type")
        # The plan is shared with preparation and may have been corrupted via
        # object.__setattr__; rerun its own invariants before authority joins.
        PatchPlan.__post_init__(self.plan)
        if type(self.attempt_id) is not TransactionAttemptId:
            raise TypeError("bound plan requires the exact TransactionAttemptId type")
        _validate_transaction_attempt(self.attempt_id)
        if type(self.session_id) is not str or not self.session_id.strip():
            raise TypeError("bound plan session_id must be a non-empty string")
        if type(self.generation) is not int or self.generation < 0:
            raise TypeError("bound plan generation must be an exact non-negative int")
        _validate_maturity_envelope(self.maturity)
        if self.attempt_id.plan_id != self.plan.plan_id:
            raise ValueError("bound plan attempt belongs to a foreign plan")
        if self.attempt_id.session_id != self.session_id:
            raise ValueError("bound plan session differs from attempt")
        if self.attempt_id.generation != self.generation:
            raise ValueError("bound plan generation differs from attempt")
        if type(self.bindings) is not tuple:
            raise TypeError("bound plan bindings must be an exact tuple")
        rows = tuple(_validate_binding_pair(item, "bindings") for item in self.bindings)
        refs = tuple(item[0] for item in rows)
        serials = tuple(item[1] for item in rows)
        if len(set(refs)) != len(refs):
            raise ValueError("bound plan bindings must not duplicate references")
        if len(set(serials)) != len(serials):
            raise ValueError("bound plan bindings must not duplicate live serials")
        object.__setattr__(self, "bindings", rows)


def _validate_transaction_attempt(value: TransactionAttemptId) -> None:
    """Re-run the nested attempt invariant without trusting equality."""
    for name in ("plan_id", "session_id", "attempt_id"):
        field = getattr(value, name)
        if type(field) is not str or not field.strip():
            raise TypeError(f"bound plan attempt {name} must be an exact non-empty string")
    if type(value.generation) is not int or value.generation < 0:
        raise TypeError("bound plan attempt generation must be an exact non-negative int")
    # Keep the attempt's own public invariant authoritative as well.
    TransactionAttemptId.__post_init__(value)


def _validate_maturity_envelope(value: object) -> None:
    """Validate the closed provider envelope without normalizing it."""
    if type(value) is not MaturityEnvelope:
        raise TypeError("bound plan maturity must be an exact MaturityEnvelope")
    if value.ir is not None and type(value.ir) is not IRMaturity:
        raise TypeError("bound plan maturity ir must be an exact IRMaturity or None")
    if type(value.snapshot_form) is not SnapshotForm:
        raise TypeError("bound plan snapshot form must be an exact SnapshotForm")
    if type(value.provider) is not str:
        raise TypeError("bound plan maturity provider must be an exact string")
    if type(value.provider_id) is not int or value.provider_id < 0:
        raise TypeError("bound plan maturity provider_id must be an exact non-negative int")
    if value.provider_name is not None and type(value.provider_name) is not str:
        raise TypeError("bound plan maturity provider_name must be an exact string or None")


def serial_for(bound_plan: BoundPatchPlan, ref: CfgBlockRef | None) -> int | None:
    """Look up one bound coordinate without exposing backend state."""
    if type(bound_plan) is not BoundPatchPlan:
        raise TypeError("serial lookup requires the exact BoundPatchPlan type")
    if ref is None:
        return None
    matches = tuple(serial for candidate, serial in bound_plan.bindings if candidate == ref)
    if len(matches) != 1:
        raise PatchBindingRejected(f"typed block reference has {len(matches)} live bindings")
    return matches[0]


def realize_value(bound_plan: BoundPatchPlan, value: object) -> object:
    """Resolve typed references recursively at the backend call boundary."""
    if type(bound_plan) is not BoundPatchPlan:
        raise TypeError("value realization requires the exact BoundPatchPlan type")
    if type(value) in (NativeBlockRef, LogicalBlockRef, PlanBlockRef):
        return serial_for(bound_plan, value)
    if type(value) is PatchExitPathLoweringSite:
        from d810.transforms.graph_modification import ExitPathLoweringSite

        return ExitPathLoweringSite(
            anchor_serial=int(serial_for(bound_plan, value.anchor_serial)),
            kind=value.kind,
            const_value=value.const_value,
            source_stkoff=value.source_stkoff,
            source_mreg=value.source_mreg,
            materializer_serials=tuple(
                int(serial_for(bound_plan, ref)) for ref in value.materializer_serials
            ),
            skip_terminal_control_tail=value.skip_terminal_control_tail,
        )
    if type(value) is tuple:
        return tuple(realize_value(bound_plan, item) for item in value)
    if type(value) is list:
        return [realize_value(bound_plan, item) for item in value]
    if type(value) is dict:
        return {
            realize_value(bound_plan, key): realize_value(bound_plan, item)
            for key, item in value.items()
        }
    return value


def iter_refs(value: object):
    """Yield typed references from a plan payload, retaining encounter order."""
    if type(value) in (NativeBlockRef, LogicalBlockRef, PlanBlockRef):
        yield value
        return
    if type(value) is tuple:
        for item in value:
            yield from iter_refs(item)
        return
    if type(value) is dict:
        for key, item in value.items():
            yield from iter_refs(key)
            yield from iter_refs(item)
        return
    if hasattr(value, "__dataclass_fields__"):
        for item in fields(value):
            if not item.name.startswith("_"):
                yield from iter_refs(getattr(value, item.name))


def validate_bound_patch_plan(bound_plan: BoundPatchPlan) -> BoundPatchPlan:
    """Revalidate an exact bound DTO without rebuilding or copying it."""
    if type(bound_plan) is not BoundPatchPlan:
        raise TypeError("bound plan validation requires the exact BoundPatchPlan type")
    BoundPatchPlan.__post_init__(bound_plan)
    return bound_plan


__all__ = [
    "BoundPatchPlan",
    "PatchBindingRejected",
    "iter_refs",
    "realize_value",
    "serial_for",
    "validate_bound_patch_plan",
]
