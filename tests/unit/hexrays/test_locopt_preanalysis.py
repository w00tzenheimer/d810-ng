from d810.hexrays.preanalysis import locopt_preanalysis as locopt
from d810.hexrays.preanalysis.flowchart_preanalysis import request_hexrays_redo


def test_locopt_handler_receives_live_mba_and_can_request_redo(
    monkeypatch,
) -> None:
    monkeypatch.setattr(locopt, "_LOCOPT_PREANALYSIS_HANDLERS", {})
    received: list[tuple[int, object]] = []
    mba = object()

    def handler(*, function_ea: int, mba: object, decision: dict) -> None:
        received.append((function_ea, mba))
        request_hexrays_redo(decision, "unit_locopt_redo", roots=5)

    locopt.register_locopt_preanalysis_handler("unit", handler)
    decision: dict[str, object] = {"request_redo": False}

    locopt.run_locopt_preanalysis_handlers(
        function_ea=0x40A560,
        mba=mba,
        decision=decision,
    )

    assert received == [(0x40A560, mba)]
    assert decision == {
        "request_redo": True,
        "reason": "unit_locopt_redo",
        "details": {"roots": 5},
    }


def test_locopt_handler_failure_does_not_gate_later_handler(monkeypatch) -> None:
    monkeypatch.setattr(locopt, "_LOCOPT_PREANALYSIS_HANDLERS", {})

    def failing(*, function_ea: int, mba: object, decision: dict) -> None:
        raise RuntimeError("boom")

    def succeeding(*, function_ea: int, mba: object, decision: dict) -> None:
        request_hexrays_redo(decision, "later_locopt_handler")

    locopt.register_locopt_preanalysis_handler("failing", failing)
    locopt.register_locopt_preanalysis_handler("succeeding", succeeding)
    decision: dict[str, object] = {"request_redo": False}

    locopt.run_locopt_preanalysis_handlers(
        function_ea=0x40A560,
        mba=object(),
        decision=decision,
    )

    assert decision["request_redo"] is True
    assert decision["reason"] == "later_locopt_handler"
