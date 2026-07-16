from d810.hexrays.preanalysis import stkpnts_preanalysis as stkpnts


def test_stkpnts_handler_receives_transient_points(monkeypatch) -> None:
    monkeypatch.setattr(stkpnts, "_STKPNTS_PREANALYSIS_HANDLERS", {})
    received: list[tuple[int, object, object]] = []
    mba = object()
    stack_points = object()

    def handler(
        *,
        function_ea: int,
        mba: object,
        stack_points: object,
        decision: dict,
    ) -> None:
        received.append((function_ea, mba, stack_points))
        decision["stack_points_modified"] = 3

    stkpnts.register_stkpnts_preanalysis_handler("unit", handler)
    decision: dict[str, object] = {}

    stkpnts.run_stkpnts_preanalysis_handlers(
        function_ea=0x40A560,
        mba=mba,
        stack_points=stack_points,
        decision=decision,
    )

    assert received == [(0x40A560, mba, stack_points)]
    assert decision == {"stack_points_modified": 3}


def test_stkpnts_handler_failure_does_not_gate_later_handler(
    monkeypatch,
) -> None:
    monkeypatch.setattr(stkpnts, "_STKPNTS_PREANALYSIS_HANDLERS", {})
    called: list[str] = []

    def failing(**_kwargs: object) -> None:
        raise RuntimeError("boom")

    def succeeding(**_kwargs: object) -> None:
        called.append("succeeding")

    stkpnts.register_stkpnts_preanalysis_handler("failing", failing)
    stkpnts.register_stkpnts_preanalysis_handler("succeeding", succeeding)

    stkpnts.run_stkpnts_preanalysis_handlers(
        function_ea=0x40A560,
        mba=object(),
        stack_points=object(),
        decision={},
    )

    assert called == ["succeeding"]
