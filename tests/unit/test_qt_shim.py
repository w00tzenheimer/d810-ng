from __future__ import annotations

import sys
import types
import warnings
from pathlib import Path

from d810 import qt_shim


QT_SHIM_SOURCE = Path(qt_shim.__file__).read_text(encoding="utf-8")


def test_ida_gui_detection_accepts_virtualenv_backed_idapython(
    monkeypatch,
) -> None:
    idaapi = types.SimpleNamespace(is_idaq=lambda: True)
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setattr(sys, "executable", "/app/ida/.venv/bin/python3")

    assert qt_shim._is_ida_gui_available() is True


def test_pyqt5_branch_imports_qpixmap_from_qtgui() -> None:
    pyqt5_gui_imports = QT_SHIM_SOURCE.rsplit("from PyQt5.QtGui import", 1)[1].split(
        "from PyQt5.QtWidgets import", 1
    )[0]
    pyqt5_widget_imports = QT_SHIM_SOURCE.rsplit(
        "from PyQt5.QtWidgets import", 1
    )[1].split("QT_VERSION = 5", 1)[0]

    assert "QPixmap," in pyqt5_gui_imports
    assert "QPixmap," not in pyqt5_widget_imports


def test_headless_shim_reports_graphics_unavailable() -> None:
    assert qt_shim.QT_GRAPHICS_AVAILABLE is False


def test_qt_flag_or_uses_values_instead_of_pyside_enum_bitwise_or(
    monkeypatch,
) -> None:
    class _WarningFlag:
        def __init__(self, value: int) -> None:
            self.value = value

        def __or__(self, other: object) -> object:
            del other
            warnings.warn(
                "PySide6 compatibility bitwise operation",
                RuntimeWarning,
                stacklevel=2,
            )
            return self

    class _ItemFlag:
        def __init__(self, value: int) -> None:
            self.value = value

    monkeypatch.setattr(qt_shim, "QT6", True)
    monkeypatch.setattr(qt_shim, "Qt", types.SimpleNamespace(ItemFlag=_ItemFlag))

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        combined = qt_shim.qt_flag_or(_WarningFlag(0x01), _WarningFlag(0x10))

    assert isinstance(combined, _ItemFlag)
    assert combined.value == 0x11
