from d810.hexrays.preanalysis import callinfo_preanalysis as callinfo


def test_callinfo_handler_receives_live_call_site(monkeypatch) -> None:
    monkeypatch.setattr(callinfo, "_CALLINFO_PREANALYSIS_HANDLERS", {})
    received: list[tuple[int, object, object]] = []
    block = object()
    call_type = object()

    def handler(
        *,
        function_ea: int,
        block: object,
        call_type: object,
        decision: dict,
    ) -> None:
        received.append((function_ea, block, call_type))
        decision["callinfo"] = "prepared"

    callinfo.register_callinfo_preanalysis_handler("unit", handler)
    decision: dict[str, object] = {"callinfo": None}

    callinfo.run_callinfo_preanalysis_handlers(
        function_ea=0x40A560,
        block=block,
        call_type=call_type,
        decision=decision,
    )

    assert received == [(0x40A560, block, call_type)]
    assert decision == {"callinfo": "prepared"}


def test_callinfo_handler_failure_does_not_gate_later_handler(monkeypatch) -> None:
    monkeypatch.setattr(callinfo, "_CALLINFO_PREANALYSIS_HANDLERS", {})

    def failing(**_kwargs: object) -> None:
        raise RuntimeError("boom")

    def succeeding(*, decision: dict, **_kwargs: object) -> None:
        decision["callinfo"] = "prepared"

    callinfo.register_callinfo_preanalysis_handler("failing", failing)
    callinfo.register_callinfo_preanalysis_handler("succeeding", succeeding)
    decision: dict[str, object] = {"callinfo": None}

    callinfo.run_callinfo_preanalysis_handlers(
        function_ea=0x40A560,
        block=object(),
        call_type=object(),
        decision=decision,
    )

    assert decision["callinfo"] == "prepared"
