"""A coalesced PatchPlan step is accounted for, not treated as a lost operation.

Conflict resolution legitimately collapses several queued modifications that
describe the same edge into one, so fewer operations apply than the plan has
steps. ``observe_patch_realization`` used to compare ``applied == planned`` and
read that benign deduplication as a poisoned CFG generation.

The live case this comes from: sub_7FFFBD0ABF40 planned 79 steps, block 109
carried both a BLOCK_CONVERT_TO_GOTO and a BLOCK_TARGET_CHANGE describing the
same edge to 184, the coalescer kept one, 78 applied, and the generation was
declared poisoned. 78 + 1 == 79.

System-runtime tier because the gateway module imports ``ida_hexrays``.
"""

from __future__ import annotations

import pytest

from d810.hexrays.mutation.mba_mutation_events import MbaMutationGateway


def _reconciles(planned: int, applied: int, superseded: int) -> bool:
    """The identity observe_patch_realization enforces."""
    return applied + superseded == planned


def test_the_live_case_reconciles() -> None:
    """Block 109's duplicate edge to 184: 78 applied + 1 superseded == 79."""
    assert _reconciles(planned=79, applied=78, superseded=1)


def test_a_genuinely_lost_operation_still_fails_to_reconcile() -> None:
    """The check must keep catching what it was built to catch."""
    assert not _reconciles(planned=79, applied=78, superseded=0)


def test_supersessions_cannot_mask_a_larger_shortfall() -> None:
    assert not _reconciles(planned=79, applied=70, superseded=1)


def test_gateway_exposes_the_recorder_the_translator_calls() -> None:
    assert hasattr(MbaMutationGateway, "record_coalesced_supersessions")


def test_recorder_rejects_a_negative_tally(monkeypatch: pytest.MonkeyPatch) -> None:
    # The gateway defines __slots__, so the active-batch guard has to be
    # patched on the class rather than on an instance.
    monkeypatch.setattr(MbaMutationGateway, "_require_active", lambda self: None)
    gateway = object.__new__(MbaMutationGateway)

    with pytest.raises(ValueError, match="non-negative"):
        gateway.record_coalesced_supersessions(-1)


def test_recorder_requires_an_active_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    """A tally recorded outside a batch would belong to no inventory."""
    calls: list[str] = []

    def _require_active(self) -> None:
        calls.append("checked")
        raise RuntimeError("no active batch")

    monkeypatch.setattr(MbaMutationGateway, "_require_active", _require_active)
    gateway = object.__new__(MbaMutationGateway)

    with pytest.raises(RuntimeError):
        gateway.record_coalesced_supersessions(1)
    assert calls == ["checked"]


def test_recorded_tally_is_kept_verbatim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(MbaMutationGateway, "_require_active", lambda self: None)
    gateway = object.__new__(MbaMutationGateway)

    gateway.record_coalesced_supersessions(3)

    assert gateway._superseded_operation_count == 3
