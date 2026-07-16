from __future__ import annotations

import sys
import types

from d810 import qt_shim


def test_ida_gui_detection_accepts_virtualenv_backed_idapython(
    monkeypatch,
) -> None:
    idaapi = types.SimpleNamespace(is_idaq=lambda: True)
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setattr(sys, "executable", "/app/ida/.venv/bin/python3")

    assert qt_shim._is_ida_gui_available() is True
