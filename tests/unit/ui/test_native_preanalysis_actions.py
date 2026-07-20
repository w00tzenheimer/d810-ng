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
            assert calls == [("controller", function_ea)]
            calls.append(("decompile", function_ea))
            return object()

        @staticmethod
        def mark_cfunc_dirty(function_ea: int, _close_views: bool) -> None:
            calls.append(("invalidate", function_ea))

        @staticmethod
        def open_pseudocode(function_ea: int, _flags: int) -> None:
            calls.append(("open", function_ea))

    action = DecompileFunction(
        SimpleNamespace(manager=_Manager()),
        ida_modules={"idaapi": _IdaApi()},
    )

    assert action.execute(SimpleNamespace()) == 1
    assert calls == [
        ("controller", 0x401000),
        ("decompile", 0x401000),
        ("open", 0x401000),
    ]


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
