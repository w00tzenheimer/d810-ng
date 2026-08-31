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

    monkeypatch.setattr(qt_shim, "QT6", True)

    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        combined = qt_shim.qt_flag_or(_WarningFlag(0x01), _WarningFlag(0x10))

    assert isinstance(combined, _WarningFlag)
    assert combined.value == 0x11


def test_qt_flag_or_preserves_the_pyside_flag_family(monkeypatch) -> None:
    class _ItemFlag:
        def __init__(self, value: int) -> None:
            self.value = value

    class _AlignmentFlag:
        def __init__(self, value: int) -> None:
            self.value = value

    monkeypatch.setattr(qt_shim, "QT6", True)
    monkeypatch.setattr(qt_shim, "Qt", types.SimpleNamespace(ItemFlag=_ItemFlag))

    combined = qt_shim.qt_flag_or(_AlignmentFlag(0x01), _AlignmentFlag(0x10))

    assert isinstance(combined, _AlignmentFlag)
    assert combined.value == 0x11


# --- d81-vqqy: symmetric Signal/Slot resolution -------------------------------


def _fake_pyqt5_qtcore() -> types.SimpleNamespace:
    """A QtCore that spells signals the PyQt5 way only."""
    return types.SimpleNamespace(pyqtSignal=lambda *a, **k: ("sig", a), pyqtSlot=lambda *a, **k: (lambda f: f))


def _fake_pyside6_qtcore() -> types.SimpleNamespace:
    """A QtCore that spells signals the PySide6 way only."""
    return types.SimpleNamespace(Signal=lambda *a, **k: ("sig", a), Slot=lambda *a, **k: (lambda f: f))


def test_resolver_fills_pyside6_spellings_from_a_pyqt5_qtcore() -> None:
    names = qt_shim._resolve_signal_slot(_fake_pyqt5_qtcore())

    assert set(names) == {"Signal", "Slot", "pyqtSignal", "pyqtSlot"}
    assert names["Signal"] is names["pyqtSignal"]
    assert names["Slot"] is names["pyqtSlot"]


def test_resolver_fills_pyqt5_spellings_from_a_pyside6_qtcore() -> None:
    names = qt_shim._resolve_signal_slot(_fake_pyside6_qtcore())

    assert set(names) == {"Signal", "Slot", "pyqtSignal", "pyqtSlot"}
    assert names["pyqtSignal"] is names["Signal"]
    assert names["pyqtSlot"] is names["Slot"]


def test_resolver_does_not_mutate_the_binding_module() -> None:
    qtcore = _fake_pyside6_qtcore()
    before = set(vars(qtcore))

    qt_shim._resolve_signal_slot(qtcore)

    assert set(vars(qtcore)) == before
    assert not hasattr(qtcore, "pyqtSignal")


def test_resolver_imports_nothing() -> None:
    """Importing a Qt binding inside headless IDA kills the interpreter."""
    before = set(sys.modules)

    qt_shim._resolve_signal_slot(_fake_pyqt5_qtcore())

    assert set(sys.modules) == before


def test_shim_exports_all_four_signal_slot_spellings() -> None:
    for name in ("Signal", "Slot", "pyqtSignal", "pyqtSlot"):
        assert hasattr(qt_shim, name), f"qt_shim.{name} missing"
        assert name in qt_shim.__all__, f"{name} missing from __all__"


def test_headless_qtcore_exposes_both_signal_spellings() -> None:
    assert qt_shim._QT_AVAILABLE is False
    for name in ("Signal", "Slot", "pyqtSignal", "pyqtSlot"):
        assert hasattr(qt_shim.QtCore, name), f"stub QtCore.{name} missing"


def test_headless_signal_is_usable_under_either_spelling() -> None:
    for factory in (qt_shim.QtCore.Signal, qt_shim.QtCore.pyqtSignal):
        sig = factory(str)
        sig.connect(lambda *a: None)
        sig.emit("x")
        sig.disconnect()


def test_headless_slot_is_usable_as_a_decorator() -> None:
    for slot in (qt_shim.QtCore.Slot, qt_shim.QtCore.pyqtSlot):

        @slot(str)
        def handler(value):
            return value

        assert handler("ok") == "ok"


def test_loaded_qtcore_is_none_when_no_binding_is_loaded(monkeypatch) -> None:
    for name in ("PySide6.QtCore", "PyQt5.QtCore"):
        monkeypatch.delitem(sys.modules, name, raising=False)

    assert qt_shim._loaded_qtcore() is None


def test_loaded_qtcore_finds_an_already_imported_binding(monkeypatch) -> None:
    fake = types.SimpleNamespace(Signal=lambda *a: None, Slot=lambda *a: None)
    monkeypatch.setitem(sys.modules, "PySide6.QtCore", fake)

    assert qt_shim._loaded_qtcore() is fake


def test_loaded_qtcore_imports_nothing(monkeypatch) -> None:
    """A binding import inside headless IDA can take the interpreter down."""
    for name in ("PySide6.QtCore", "PyQt5.QtCore"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    before = set(sys.modules)

    qt_shim._loaded_qtcore()

    assert set(sys.modules) == before


def test_headless_prefers_a_loaded_binding_over_the_stub(monkeypatch) -> None:
    """IDA 9.1 headless has PyQt5 loaded; signals there should be real."""
    import importlib

    sentinel = object()
    fake = types.SimpleNamespace(pyqtSignal=lambda *a: sentinel)
    monkeypatch.setitem(sys.modules, "PyQt5.QtCore", fake)
    monkeypatch.delitem(sys.modules, "PySide6.QtCore", raising=False)

    reloaded = importlib.reload(qt_shim)
    try:
        assert reloaded._QT_AVAILABLE is False, "still headless"
        assert reloaded.Signal("x") is sentinel
        assert reloaded.pyqtSignal("x") is sentinel
    finally:
        monkeypatch.undo()
        importlib.reload(qt_shim)
