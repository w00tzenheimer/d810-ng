"""Regression tests for the ``raise_on_nonconvergence`` path of
``run_valrange_fixpoint``.

Coverage gap addressed: R1 added ``raise_on_nonconvergence`` to both
``run_forward_fixpoint`` AND ``run_valrange_fixpoint``, but the
focused pure-Python tests in ``test_forward_dataflow.py`` only cover
the former.  DSVE (``_run_valrange_fixpoint``) and the diagnostic
dump (``microcode_dump.py``) now depend on the valrange-specific
exception + ``converged=False`` path.

Strategy: construct a tiny fake mba (no IDA needed) and monkeypatch
``_envs_equal`` and ``valrange_transfer`` in the valrange_dataflow
module so the worklist never drains within ``max_iterations``.  Then
assert both behaviors:

  * default ``raise_on_nonconvergence=False`` → partial
    ``FixpointResult`` with ``converged=False``
  * ``raise_on_nonconvergence=True`` → ``FixpointDidNotConverge``
"""
from __future__ import annotations

import pytest

from d810.core.typing import Any

from d810.evaluator.hexrays_microcode import valrange_dataflow as vd_module
from d810.evaluator.hexrays_microcode.forward_dataflow import (
    FixpointDidNotConverge,
    FixpointResult,
)
from d810.evaluator.hexrays_microcode.valrange_dataflow import (
    run_valrange_fixpoint,
)


class _FakeBlock:
    def __init__(self, serial: int, predset: list[int], succset: list[int]) -> None:
        self.serial = serial
        self.predset = predset
        self.succset = succset


class _FakeMba:
    """Minimal mba_t surface for the valrange engine's outer loop.

    The engine accesses ``mba.qty`` for the node range and
    ``mba.get_mblock(serial)`` for ``predset`` / ``succset``.  Other
    per-instruction details are bypassed by monkeypatching the
    transfer function -- those branches never run.
    """

    def __init__(self, blocks: list[_FakeBlock]) -> None:
        self.qty = len(blocks)
        self._blocks = {blk.serial: blk for blk in blocks}

    def get_mblock(self, serial: int) -> _FakeBlock:
        return self._blocks[serial]


def _two_node_back_edge_mba() -> _FakeMba:
    """0 <-> 1 cycle: entry seeded with both nodes; each succ-edges to
    the other so the worklist keeps cycling when state never settles."""
    return _FakeMba(
        [
            _FakeBlock(serial=0, predset=[1], succset=[1]),
            _FakeBlock(serial=1, predset=[0], succset=[0]),
        ]
    )


@pytest.fixture
def force_nonconvergent_valrange(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch the valrange engine so the worklist never settles:

    * ``valrange_transfer`` always returns a non-empty env (changes
      from the initial empty out_states).
    * ``_envs_equal`` always says "not equal" so the worklist keeps
      appending successors every iteration.
    * ``_refine_for_branch_edge`` is a no-op pass-through (the fake
      mba has no real branch info).
    """

    def fake_transfer(mba: Any, serial: int, in_state: Any) -> Any:
        # Return a fresh dict each call -- forces _envs_equal to fire.
        return {"counter": serial}

    def fake_envs_equal(a: Any, b: Any) -> bool:
        return False

    def fake_refine_for_branch_edge(
        pred_blk: Any, succ_serial: int, env: Any
    ) -> Any:
        return env

    monkeypatch.setattr(vd_module, "valrange_transfer", fake_transfer)
    monkeypatch.setattr(vd_module, "_envs_equal", fake_envs_equal)
    monkeypatch.setattr(
        vd_module, "_refine_for_branch_edge", fake_refine_for_branch_edge
    )


def test_default_returns_partial_result_with_converged_false(
    force_nonconvergent_valrange: None,
) -> None:
    """Without ``raise_on_nonconvergence``, the valrange engine returns
    a :class:`FixpointResult` with ``converged=False`` so callers can
    check the flag and degrade gracefully."""
    result = run_valrange_fixpoint(_two_node_back_edge_mba(), max_iterations=5)

    assert isinstance(result, FixpointResult)
    assert result.converged is False
    assert result.iterations == 5


def test_raise_on_nonconvergence_true_raises_typed_exception(
    force_nonconvergent_valrange: None,
) -> None:
    """Soundness-critical callers (DSVE) pass
    ``raise_on_nonconvergence=True`` so the partial-state path is
    impossible."""
    with pytest.raises(FixpointDidNotConverge) as excinfo:
        run_valrange_fixpoint(
            _two_node_back_edge_mba(),
            max_iterations=5,
            raise_on_nonconvergence=True,
        )
    assert excinfo.value.iterations == 5
    assert excinfo.value.max_iterations == 5


def test_raise_on_nonconvergence_true_is_noop_when_converged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the fixpoint reaches a true fixpoint within
    ``max_iterations``, the kwarg is a no-op and a normal result is
    returned with ``converged=True``."""

    def fake_transfer(mba: Any, serial: int, in_state: Any) -> Any:
        # Always return the same empty env -> _envs_equal succeeds,
        # worklist drains immediately.
        return {}

    def fake_refine_for_branch_edge(
        pred_blk: Any, succ_serial: int, env: Any
    ) -> Any:
        # The real implementation reads ``pred_blk.type`` which is
        # absent on the test fake; pass through unchanged.
        return env

    monkeypatch.setattr(vd_module, "valrange_transfer", fake_transfer)
    monkeypatch.setattr(
        vd_module, "_refine_for_branch_edge", fake_refine_for_branch_edge
    )
    # _envs_equal is the real implementation here so {} == {} succeeds.

    mba = _two_node_back_edge_mba()
    result = run_valrange_fixpoint(
        mba, max_iterations=50, raise_on_nonconvergence=True
    )

    assert isinstance(result, FixpointResult)
    assert result.converged is True
