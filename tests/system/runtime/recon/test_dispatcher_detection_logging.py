"""Logging regression tests for dispatcher detection."""

from types import SimpleNamespace

import ida_hexrays

from d810.recon.flow import dispatcher_detection


def _cache_for_maturity(maturity: int):
    cache = dispatcher_detection.DispatcherCache.__new__(
        dispatcher_detection.DispatcherCache
    )
    cache.mba = SimpleNamespace(
        entry_ea=0x18000E360,
        maturity=maturity,
        qty=0,
        get_mblock=lambda _serial: None,
    )
    cache.func_ea = cache.mba.entry_ea
    cache._analysis = None
    cache._last_maturity = -1
    cache._previous_type = None
    cache._persisted_initial_state = None
    cache.blocks_analyzed = 0
    cache.blocks_skipped = 0
    return cache


def test_analyze_log_uses_maturity_name(monkeypatch):
    messages: list[str] = []

    def _record_debug(message, *args, **_kwargs) -> None:
        messages.append(message % args)

    monkeypatch.setattr(dispatcher_detection.logger, "debug", _record_debug)

    _cache_for_maturity(ida_hexrays.MMAT_CALLS).analyze()

    assert any(
        message == "Analyzing function 0x18000e360 at maturity MMAT_CALLS"
        for message in messages
    )


def test_conditional_chain_classification_log_uses_maturity_name(monkeypatch):
    messages: list[str] = []

    def _record_info(message, *args, **_kwargs) -> None:
        messages.append(message % args)

    monkeypatch.setattr(dispatcher_detection.logger, "info", _record_info)
    cache = _cache_for_maturity(ida_hexrays.MMAT_CALLS)
    analysis = dispatcher_detection.DispatcherAnalysis(
        func_ea=cache.func_ea,
        maturity=cache.mba.maturity,
        nested_loop_depth=2,
    )

    cache._classify_dispatcher_type(analysis)

    assert analysis.dispatcher_type is dispatcher_detection.DispatcherType.CONDITIONAL_CHAIN
    assert messages
    assert "maturity=MMAT_CALLS" in messages[0]
    assert f"maturity={ida_hexrays.MMAT_CALLS}" not in messages[0]
