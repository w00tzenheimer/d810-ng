"""Skipped-maturity outcome records must use the lifecycle-owned session id.

Ticket d81-y3oi(b): ``_observe_skipped_maturities`` used to fabricate
``session_id=f"optblock:{func_ea:x}"`` even though the lifecycle coordinator
already knows this callback's real session identity (the same
``DecompilationSessionContext.identity_key`` every other unflatten outcome
producer publishes). A fabricated id can never join
``diagnostic_sessions``/``unflatten_candidate_outcomes`` rows for the same
decompile, breaking ``unflat-why --session``.
"""

from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.hexrays.hooks.optblock_adapter import (
    BlockOptimizerManager,
    _lifecycle_diag_session_id,
)


class StateMachineCffUnflattener:
    """Stand-in matched by EXACT class name (see ``_state_machine_rule_registered``);
    the leading underscore this project's test-double naming convention would
    normally use must be omitted here or the match silently fails.
    """


class _Lifecycle:
    def __init__(self, identity_key: str | None) -> None:
        self._identity_key = identity_key
        self.lookups: list[int] = []

    def current_session(self, function_ea: int):
        self.lookups.append(int(function_ea))
        if self._identity_key is None:
            return None
        return SimpleNamespace(identity_key=self._identity_key)


def _manager(*, lifecycle) -> BlockOptimizerManager:
    manager = object.__new__(BlockOptimizerManager)
    manager.cfg_rules = (StateMachineCffUnflattener(),)
    manager._decompilation_lifecycle = lifecycle
    # LOCOPT -> GLBOPT1 skips CALLS entirely, so a callback fires below.
    manager.current_maturity = int(ida_hexrays.MMAT_LOCOPT)
    return manager


def test_lifecycle_diag_session_id_reuses_the_session_identity_key():
    lifecycle = _Lifecycle("sample.i64:0x401000:1")

    session_id = _lifecycle_diag_session_id(lifecycle, 0x401000)

    assert session_id == "sample.i64:0x401000:1"
    assert lifecycle.lookups == [0x401000]


def test_lifecycle_diag_session_id_falls_back_without_a_session():
    lifecycle = _Lifecycle(None)

    session_id = _lifecycle_diag_session_id(lifecycle, 0x401000)

    assert session_id == "optblock:401000"


def test_lifecycle_diag_session_id_falls_back_without_a_lifecycle():
    assert _lifecycle_diag_session_id(None, 0x401000) == "optblock:401000"


def test_observe_skipped_maturities_publishes_the_lifecycle_session_id(monkeypatch):
    observed: list[dict] = []
    monkeypatch.setattr(
        "d810.hexrays.hooks.optblock_adapter.observe_unflat_candidate_outcome",
        lambda **kwargs: observed.append(kwargs),
    )
    lifecycle = _Lifecycle("sample.i64:0x401000:1")
    manager = _manager(lifecycle=lifecycle)
    mba = SimpleNamespace(
        entry_ea=0x401000,
        maturity=int(ida_hexrays.MMAT_GLBOPT1),
    )

    manager._observe_skipped_maturities(mba)

    assert observed, "expected at least one skipped-maturity outcome record"
    assert all(record["session_id"] == "sample.i64:0x401000:1" for record in observed)
    assert all(record["session_id"] != "optblock:401000" for record in observed)
