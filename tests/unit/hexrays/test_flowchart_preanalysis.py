from d810.hexrays.preanalysis import flowchart_preanalysis as flowchart


def test_flowchart_preanalysis_handler_can_request_redo(monkeypatch) -> None:
    monkeypatch.setattr(flowchart, "_FLOWCHART_PREANALYSIS_HANDLERS", {})
    calls: list[tuple[int, object]] = []
    mba = object()

    def handler(*, function_ea: int, mba: object, decision: dict) -> None:
        calls.append((function_ea, mba))
        flowchart.request_hexrays_redo(
            decision,
            "unit_test_redo",
            materialized_target_count=2,
        )

    flowchart.register_flowchart_preanalysis_handler("unit", handler)
    decision: dict[str, object] = {"request_redo": False}

    flowchart.run_flowchart_preanalysis_handlers(
        function_ea=0x180013BD0,
        mba=mba,
        decision=decision,
    )

    assert calls == [(0x180013BD0, mba)]
    assert decision["request_redo"] is True
    assert decision["reason"] == "unit_test_redo"
    assert decision["details"] == {"materialized_target_count": 2}


def test_flowchart_preanalysis_handler_failures_do_not_gate_later_handlers(
    monkeypatch,
) -> None:
    monkeypatch.setattr(flowchart, "_FLOWCHART_PREANALYSIS_HANDLERS", {})

    def failing_handler(*, function_ea: int, mba: object, decision: dict) -> None:
        raise RuntimeError("boom")

    def succeeding_handler(*, function_ea: int, mba: object, decision: dict) -> None:
        flowchart.request_hexrays_redo(decision, "later_handler")

    flowchart.register_flowchart_preanalysis_handler("failing", failing_handler)
    flowchart.register_flowchart_preanalysis_handler("succeeding", succeeding_handler)
    decision: dict[str, object] = {"request_redo": False}

    flowchart.run_flowchart_preanalysis_handlers(
        function_ea=0x180013BD0,
        mba=object(),
        decision=decision,
    )

    assert decision["request_redo"] is True
    assert decision["reason"] == "later_handler"
