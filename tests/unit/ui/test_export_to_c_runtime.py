"""Unit tests for runtime behavior in export_to_c action."""
from __future__ import annotations

from d810.ui.actions import export_to_c


class _FakeIdaApi:
    def __init__(self):
        self.calls: list[str] = []

    def change_hexrays_config(self, directive: str):
        self.calls.append(directive)


def test_temporary_hexrays_config_restores(monkeypatch):
    fake = _FakeIdaApi()
    monkeypatch.setattr(
        export_to_c,
        "_get_collapse_lvars_restore_directive",
        lambda: "COLLAPSE_LVARS = YES",
    )

    with export_to_c._temporary_hexrays_config(fake, "COLLAPSE_LVARS = NO"):
        assert fake.calls == ["COLLAPSE_LVARS = NO"]

    assert fake.calls == ["COLLAPSE_LVARS = NO", "COLLAPSE_LVARS = YES"]


def test_temporary_hexrays_config_no_restore_if_apply_fails():
    class _FailingIdaApi:
        def __init__(self):
            self.calls: list[str] = []

        def change_hexrays_config(self, directive: str):
            self.calls.append(directive)
            raise RuntimeError("boom")

    fake = _FailingIdaApi()

    with export_to_c._temporary_hexrays_config(fake, "COLLAPSE_LVARS = NO"):
        pass

    assert fake.calls == ["COLLAPSE_LVARS = NO"]


def test_decompile_function_temporarily_disables_lvar_collapse(monkeypatch):
    class _FakeHexrays:
        @staticmethod
        def init_hexrays_plugin():
            return True

        @staticmethod
        def decompile(_func_ea):
            class _Cfunc:
                def __str__(self):
                    return "int demo(void)\n{\n  return 0;\n}"

            return _Cfunc()

    class _FakeFuncs:
        @staticmethod
        def get_func_name(_func_ea):
            return "demo"

    class _FakeLines:
        @staticmethod
        def tag_remove(text: str):
            return text

    fake_idaapi = _FakeIdaApi()
    monkeypatch.setattr(
        export_to_c,
        "_get_collapse_lvars_restore_directive",
        lambda: "COLLAPSE_LVARS = YES",
    )

    result = export_to_c._decompile_function(
        0x1000,
        _FakeHexrays(),
        _FakeFuncs(),
        _FakeLines(),
        fake_idaapi,
    )

    assert result is not None
    func_name, lines = result
    assert func_name == "demo"
    assert "return 0;" in "\n".join(lines)
    assert fake_idaapi.calls == ["COLLAPSE_LVARS = NO", "COLLAPSE_LVARS = YES"]

