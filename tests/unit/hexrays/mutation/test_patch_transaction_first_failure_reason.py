"""``_first_failure`` must never erase the exception type (ticket d81-aw7v).

An exception raised with no arguments -- a bare ``assert`` or
``raise SomeError()`` -- has an empty ``str()``. The old implementation
recorded ``str(error) or "runtime failure"``, so every such failure persisted
the same anonymous literal into ``cfg_transaction_attempts.first_failure_reason``
and the only fact that could locate it (the exception type) was lost. A Target A
preflight rejection was invisible for exactly this reason.
"""

from __future__ import annotations

import pytest

from d810.hexrays.mutation.patch_transaction import _first_failure


class _EmptyMessageError(Exception):
    """Stand-in for any exception constructed with no arguments."""


def test_first_failure_keeps_type_and_message_when_message_is_present() -> None:
    reason, obligation = _first_failure(ValueError("bad projection"), "preflight")

    assert reason == "ValueError: bad projection"
    assert obligation == "runtime:preflight"


def test_first_failure_records_the_type_when_the_message_is_empty() -> None:
    reason, obligation = _first_failure(_EmptyMessageError(), "preflight")

    assert reason == "_EmptyMessageError"
    assert obligation == "runtime:preflight"


def test_first_failure_never_records_the_anonymous_fallback() -> None:
    # The regression under investigation: a bare ``assert`` in the preflight
    # path produced ``AssertionError()`` and the reason column read
    # "runtime failure" for every distinct defect.
    reason, _ = _first_failure(AssertionError(), "preflight")

    assert reason == "AssertionError"
    assert reason != "runtime failure"


@pytest.mark.parametrize(
    "phase", ["projection", "preflight", "binding", "realization", "observation"]
)
def test_first_failure_obligation_names_the_phase(phase: str) -> None:
    _, obligation = _first_failure(AssertionError(), phase)

    assert obligation == f"runtime:{phase}"
