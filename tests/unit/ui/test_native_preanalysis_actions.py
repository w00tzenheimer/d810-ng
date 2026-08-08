"""UI actions must prepare the manager-owned lifecycle before decompiling."""

from __future__ import annotations

from types import SimpleNamespace

from d810.ui.actions.decompile_function import DecompileFunction
from d810.ui.actions.deobfuscate_this import DeobfuscateThisFunction


def test_decompile_action_prepares_before_first_decompile() -> None:
    calls: list[tuple[str, int]] = []

    class _Manager:
        def decompile_with_native_preanalysis(
            self, function_ea: int, decompile, invalidate
        ):
            calls.append(("controller", function_ea))
            return decompile()

    class _IdaApi:
        BWN_DISASM = 1

        @staticmethod
        def get_screen_ea() -> int:
            return 0x401000

        @staticmethod
        def get_func(_ea: int) -> object:
            return SimpleNamespace(start_ea=0x401000)

        @staticmethod
        def decompile(function_ea: int) -> object:
            calls.append(("decompile", function_ea))
            return object()

        @staticmethod
        def mark_cfunc_dirty(function_ea: int, _close_views: bool) -> None:
            calls.append(("invalidate", function_ea))

        @staticmethod
        def open_pseudocode(function_ea: int, _flags: int) -> None:
            assert calls == [("controller", function_ea)]
            calls.append(("open", function_ea))

    action = DecompileFunction(
        SimpleNamespace(manager=_Manager()),
        ida_modules={"idaapi": _IdaApi()},
    )

    assert action.execute(SimpleNamespace()) == 1
    # Opening the pseudocode view IS the decompilation, so it must be the
    # callable handed to the controller -- not a second request after it.
    assert calls == [
        ("controller", 0x401000),
        ("open", 0x401000),
    ]


def test_decompile_action_issues_exactly_one_decompilation() -> None:
    """One user action must not cost two full decompilations.

    ``idaapi.decompile(ea)`` and ``open_pseudocode(ea, 0)`` are two separate
    decompilation requests -- the second passes DECOMP_WARNINGS (0x8) where the
    first passes 0x0, so it does not reuse the first result. Measured on a
    219-block flattened function that is ~25 s each, the redundant pass was
    51.5% of the wall clock and reproduced the whole unflattening (65 graph
    modifications) for a cfunc that was then discarded unrendered.
    """
    decompile_calls: list[int] = []
    open_calls: list[int] = []

    class _Manager:
        def decompile_with_native_preanalysis(
            self, function_ea: int, decompile, invalidate
        ):
            return decompile()

    class _IdaApi:
        BWN_DISASM = 1

        @staticmethod
        def get_screen_ea() -> int:
            return 0x401000

        @staticmethod
        def get_func(_ea: int) -> object:
            return SimpleNamespace(start_ea=0x401000)

        @staticmethod
        def decompile(function_ea: int) -> object:
            decompile_calls.append(function_ea)
            return object()

        @staticmethod
        def mark_cfunc_dirty(function_ea: int, _close_views: bool) -> None:
            pass

        @staticmethod
        def open_pseudocode(function_ea: int, _flags: int) -> None:
            open_calls.append(function_ea)

    action = DecompileFunction(
        SimpleNamespace(manager=_Manager()),
        ida_modules={"idaapi": _IdaApi()},
    )
    assert action.execute(SimpleNamespace()) == 1

    total = len(decompile_calls) + len(open_calls)
    assert total == 1, (
        f"expected exactly one decompilation request, got {total}: "
        f"decompile={decompile_calls} open_pseudocode={open_calls}"
    )
    assert open_calls == [0x401000]
    assert decompile_calls == []


def test_deobfuscate_action_prepares_before_view_refresh() -> None:
    calls: list[tuple[str, int]] = []

    class _Manager:
        def decompile_with_native_preanalysis(
            self, function_ea: int, decompile, invalidate
        ):
            calls.append(("controller", function_ea))
            return decompile()

    class _Vdui:
        cfunc = SimpleNamespace(entry_ea=0x402000)

        @staticmethod
        def refresh_view(_force: bool) -> None:
            assert calls == [("controller", 0x402000)]
            calls.append(("refresh", 0x402000))

    class _IdaApi:
        @staticmethod
        def get_widget_vdui(_widget: object) -> object:
            return _Vdui()

        @staticmethod
        def mark_cfunc_dirty(function_ea: int, _close_views: bool) -> None:
            calls.append(("invalidate", function_ea))

    action = DeobfuscateThisFunction(
        SimpleNamespace(manager=_Manager()),
        ida_modules={"idaapi": _IdaApi()},
    )

    assert action.execute(SimpleNamespace(widget=object())) == 1
    assert calls == [("controller", 0x402000), ("refresh", 0x402000)]
