"""Read-only, one-receipt-per-invariant preflight for a
``NativePatchPlan``/``NativePatchOperation``.

Task 5 ("Read-only capture, lowering, and preflight") of
``_gitless/profile-guided-native-mutation-implementer-plan.md``, Step 4.
Preflight rereads the live database (current bytes, original bytes,
inherited patch rows, item shape, incoming refs, function ownership) via
``capture.py``, independently re-decodes the plan's own ``replacement_bytes``,
and compares each against the operation's already-authorized ``expected_*``
fields -- one typed receipt per invariant. **Expected-before fields are
authorization, not diagnostics**: a single mismatch makes the *whole plan*
unauthorized (:attr:`PlanPreflightResult.authorized`), not merely a flagged
warning on one operation.

This module writes nothing. It has no dependency on
``d810.backends.ida.native_patch.gateway`` -- there is no gateway yet (Task 6);
preflight only ever returns a decision, and "no state transition beyond a
recorded rejection" (the global design requirement) describes the eventual
caller's behaviour, not something this module does itself.

Scope -- what is and is not checked here (an explicit, flagged decision)
--------------------------------------------------------------------------

The Task 5 design requirements name exactly seven invariants: current bytes,
original bytes, inherited patch rows, item shapes, incoming refs, function
ownership, and the decoded replacement. This module checks exactly those
seven (:class:`OperationInvariant`) and nothing more. File-backing,
debugger-active state, and post-apply CFG-fingerprint validation (section
15.1 step 10 of the report) are real invariants elsewhere in the design but
are deliberately out of scope here -- they belong to Task 6's gateway, which
owns the live apply this module never performs.

Rejection-reason vocabulary (an explicit, flagged decision)
--------------------------------------------------------------------------

Five of the seven invariants reuse a stable name from section 16 of
``_gitless/REVERSIBLE-NATIVE-PATCHES.md`` verbatim: ``EXTERNAL_INTERFERENCE``
(current bytes), ``PREEXISTING_PATCH_CONFLICT`` (patch rows),
``INCOMING_INTERIOR_REFERENCE`` (incoming refs),
``FUNCTION_OWNERSHIP_CHANGE_REQUIRED`` (function ownership), and
``POST_DECODE_MISMATCH`` (decoded replacement). Two are new, local additions
because section 16's list has no exact fit: ``UNEXPLAINED_BYTE_DELTA``
(original-byte-layer mismatch -- reused from the list, but note it is a
*repurposing*: section 16 names it for a different context) and
``ITEM_SHAPE_MISMATCH`` (no section-16 name covers "the live item map
disagrees with what the plan captured" at all, so this is a new stable
string, following the same pattern the module docstring for
``native_patch_lowering.py`` already establishes for
``EDGE_STATE_CONTRACT_REQUIRED``/``SYNTHETIC_NATIVE_ORIGIN``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from d810.backends.ida.native_patch.capture import (
    LiveDatabaseReader,
    capture_range_evidence,
)
from d810.capabilities.native_patch import NativeInstructionSequenceShape
from d810.transforms.native_patch_lowering import NativeEdgeCaptureEvidence
from d810.transforms.native_patch_plan import NativePatchOperation, NativePatchPlan

__all__ = [
    "InvariantReceipt",
    "OperationInvariant",
    "OperationPreflightResult",
    "PlanPreflightResult",
    "preflight_operation",
    "preflight_operation_live",
    "preflight_plan_live",
]

DecodeReplacement = Callable[[int, bytes], NativeInstructionSequenceShape]


class OperationInvariant(str, Enum):
    """The seven invariants this module checks -- see the module docstring's
    "Scope" section for what is deliberately excluded."""

    CURRENT_BYTES = "current_bytes"
    ORIGINAL_BYTES = "original_bytes"
    PATCH_ROWS = "patch_rows"
    ITEM_SHAPE = "item_shape"
    INCOMING_REFS = "incoming_refs"
    FUNCTION_OWNERSHIP = "function_ownership"
    DECODED_REPLACEMENT = "decoded_replacement"
    #: Reread of the live evidence itself failed (capture-level abstention,
    #: e.g. unloaded bytes or no owning function) before any of the seven
    #: comparisons above could even be attempted.
    CAPTURE = "capture"


_REJECTION_REASON: dict[OperationInvariant, str] = {
    OperationInvariant.CURRENT_BYTES: "EXTERNAL_INTERFERENCE",
    OperationInvariant.ORIGINAL_BYTES: "UNEXPLAINED_BYTE_DELTA",
    OperationInvariant.PATCH_ROWS: "PREEXISTING_PATCH_CONFLICT",
    OperationInvariant.ITEM_SHAPE: "ITEM_SHAPE_MISMATCH",
    OperationInvariant.INCOMING_REFS: "INCOMING_INTERIOR_REFERENCE",
    OperationInvariant.FUNCTION_OWNERSHIP: "FUNCTION_OWNERSHIP_CHANGE_REQUIRED",
    OperationInvariant.DECODED_REPLACEMENT: "POST_DECODE_MISMATCH",
}


@dataclass(frozen=True, slots=True)
class InvariantReceipt:
    """One typed pass/fail receipt for one invariant.

    ``ea`` is the global-constraint native EA anchor -- present on every
    receipt, passing or failing.
    """

    invariant: OperationInvariant
    ea: int
    ok: bool
    reason: str | None = None

    def __post_init__(self) -> None:
        if not self.ok and self.reason is None:
            raise ValueError("a failed receipt must carry a reason")
        if self.ok and self.reason is not None:
            raise ValueError("a passing receipt must not carry a reason")


def _receipt(invariant: OperationInvariant, ea: int, ok: bool) -> InvariantReceipt:
    return InvariantReceipt(
        invariant=invariant,
        ea=ea,
        ok=ok,
        reason=None if ok else _REJECTION_REASON[invariant],
    )


@dataclass(frozen=True, slots=True)
class OperationPreflightResult:
    operation_id: str
    ea: int
    receipts: tuple[InvariantReceipt, ...]

    @property
    def ok(self) -> bool:
        return all(receipt.ok for receipt in self.receipts)

    @property
    def rejection_reasons(self) -> tuple[str, ...]:
        return tuple(receipt.reason for receipt in self.receipts if not receipt.ok)


@dataclass(frozen=True, slots=True)
class PlanPreflightResult:
    plan_id: str
    operation_results: tuple[OperationPreflightResult, ...]

    @property
    def authorized(self) -> bool:
        """A single mismatch anywhere makes the whole plan unauthorized --
        expected-before fields are authorization, not diagnostics."""
        return all(result.ok for result in self.operation_results)


def _same_content(a: tuple, b: tuple) -> bool:
    """Order-independent comparison for patch-row/incoming-ref tuples.

    Both sides are tuples of frozen, hashable dataclasses; a live reread is
    not guaranteed to enumerate in the same order the plan's capture did.
    """
    return frozenset(a) == frozenset(b)


def preflight_operation(
    *,
    operation: NativePatchOperation,
    live: NativeEdgeCaptureEvidence,
    decode_replacement: DecodeReplacement,
) -> OperationPreflightResult:
    """Compare ``operation``'s authorized ``expected_*`` fields against
    already-captured live evidence. Pure -- no IDA call here; see
    :func:`preflight_operation_live` for the version that rereads the
    database itself via ``capture.py``.
    """
    ea = operation.range.start_ea
    receipts = (
        _receipt(
            OperationInvariant.CURRENT_BYTES,
            ea,
            operation.expected_current_bytes == live.expected_current_bytes,
        ),
        _receipt(
            OperationInvariant.ORIGINAL_BYTES,
            ea,
            operation.expected_original_bytes == live.expected_original_bytes,
        ),
        _receipt(
            OperationInvariant.PATCH_ROWS,
            ea,
            _same_content(operation.expected_patch_rows, live.expected_patch_rows),
        ),
        _receipt(
            OperationInvariant.ITEM_SHAPE,
            ea,
            operation.expected_item_shape == live.expected_item_shape,
        ),
        _receipt(
            OperationInvariant.INCOMING_REFS,
            ea,
            _same_content(
                operation.expected_incoming_refs, live.expected_incoming_refs
            ),
        ),
        _receipt(
            OperationInvariant.FUNCTION_OWNERSHIP,
            ea,
            operation.expected_function_ownership == live.expected_function_ownership,
        ),
        _receipt(
            OperationInvariant.DECODED_REPLACEMENT,
            ea,
            (
                operation.expected_after_shape == operation.expected_before_shape
                if operation.is_metadata_only
                else decode_replacement(ea, operation.replacement_bytes)
                == operation.expected_after_shape
            ),
        ),
    )
    return OperationPreflightResult(
        operation_id=operation.operation_id, ea=ea, receipts=receipts
    )


def preflight_operation_live(
    reader: LiveDatabaseReader,
    operation: NativePatchOperation,
    decode_replacement: DecodeReplacement,
) -> OperationPreflightResult:
    """Reread the live database via ``capture.py``, then preflight against it.

    A capture-level abstention (unloaded bytes, no owning function) is
    reported as a single failed ``CAPTURE`` receipt rather than raised --
    preflight always returns a typed rejection, never crashes on a read it
    cannot authorize.
    """
    outcome = capture_range_evidence(
        reader,
        operation.range,
        function_ea=operation.expected_function_ownership.owning_function_entry_ea,
    )
    if not outcome.ok:
        return OperationPreflightResult(
            operation_id=operation.operation_id,
            ea=outcome.ea,
            receipts=(
                InvariantReceipt(
                    invariant=OperationInvariant.CAPTURE,
                    ea=outcome.ea,
                    ok=False,
                    reason=outcome.reason,
                ),
            ),
        )
    return preflight_operation(
        operation=operation,
        live=outcome.evidence,
        decode_replacement=decode_replacement,
    )


def preflight_plan_live(
    reader: LiveDatabaseReader,
    plan: NativePatchPlan,
    decode_replacement: DecodeReplacement,
) -> PlanPreflightResult:
    """Preflight every operation in ``plan`` against the live database."""
    return PlanPreflightResult(
        plan_id=plan.plan_id,
        operation_results=tuple(
            preflight_operation_live(reader, operation, decode_replacement)
            for operation in plan.operations
        ),
    )
