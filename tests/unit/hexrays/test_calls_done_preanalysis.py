from d810.hexrays.preanalysis import calls_done_preanalysis as calls_done
from d810.hexrays.preanalysis.flowchart_preanalysis import request_hexrays_redo


def test_calls_done_handler_receives_live_mba_and_can_request_redo(
    monkeypatch,
) -> None:
    monkeypatch.setattr(calls_done, "_CALLS_DONE_PREANALYSIS_HANDLERS", {})
    received: list[tuple[int, object]] = []
    mba = object()

    def handler(*, function_ea: int, mba: object, decision: dict) -> None:
        received.append((function_ea, mba))
        request_hexrays_redo(decision, "unit_calls_redo", round=2)

    calls_done.register_calls_done_preanalysis_handler("unit", handler)
    decision: dict[str, object] = {"request_redo": False}

    calls_done.run_calls_done_preanalysis_handlers(
        function_ea=0x40A560,
        mba=mba,
        decision=decision,
    )

    assert received == [(0x40A560, mba)]
    assert decision == {
        "request_redo": True,
        "reason": "unit_calls_redo",
        "details": {"round": 2},
    }


def test_calls_done_handler_failure_does_not_gate_later_handler(monkeypatch) -> None:
    monkeypatch.setattr(calls_done, "_CALLS_DONE_PREANALYSIS_HANDLERS", {})

    def failing(*, function_ea: int, mba: object, decision: dict) -> None:
        raise RuntimeError("boom")

    def succeeding(*, function_ea: int, mba: object, decision: dict) -> None:
        request_hexrays_redo(decision, "later_calls_handler")

    calls_done.register_calls_done_preanalysis_handler("failing", failing)
    calls_done.register_calls_done_preanalysis_handler("succeeding", succeeding)
    decision: dict[str, object] = {"request_redo": False}

    calls_done.run_calls_done_preanalysis_handlers(
        function_ea=0x40A560,
        mba=object(),
        decision=decision,
    )

    assert decision["request_redo"] is True
    assert decision["reason"] == "later_calls_handler"
