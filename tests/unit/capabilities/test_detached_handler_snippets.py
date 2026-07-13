from __future__ import annotations

from d810.capabilities.detached_handler_snippets import (
    prepare_detached_handler_snippets,
    register_detached_handler_snippet_preparer,
    reset_detached_handler_snippet_preparer_for_tests,
    unregister_detached_handler_snippet_preparer,
)


def setup_function() -> None:
    reset_detached_handler_snippet_preparer_for_tests()


def teardown_function() -> None:
    reset_detached_handler_snippet_preparer_for_tests()


def test_absent_preparer_is_a_noop() -> None:
    assert prepare_detached_handler_snippets(0x401000, live_mba=object()) == 0


def test_registered_preparer_receives_live_mba() -> None:
    calls: list[tuple[int, object | None]] = []
    live_mba = object()

    def preparer(function_ea: int, *, live_mba: object | None = None) -> int:
        calls.append((function_ea, live_mba))
        return 3

    register_detached_handler_snippet_preparer(preparer)

    assert prepare_detached_handler_snippets(0x401000, live_mba=live_mba) == 3
    assert calls == [(0x401000, live_mba)]


def test_stale_unregister_does_not_clear_newer_preparer() -> None:
    def stale(function_ea: int, *, live_mba: object | None = None) -> int:
        return 1

    def current(function_ea: int, *, live_mba: object | None = None) -> int:
        return 2

    register_detached_handler_snippet_preparer(stale)
    register_detached_handler_snippet_preparer(current)
    unregister_detached_handler_snippet_preparer(stale)

    assert prepare_detached_handler_snippets(0x401000) == 2
