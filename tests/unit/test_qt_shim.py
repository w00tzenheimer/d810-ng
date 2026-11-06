"""Unit tests for d810.qt_shim Qt binding compatibility."""

from __future__ import annotations

import ast
import sys
import types
from pathlib import Path

import pytest

from d810 import qt_shim


def _source_tree() -> ast.Module:
    source = Path(qt_shim.__file__).read_text(encoding="utf-8")
    return ast.parse(source)


def _imports_from(tree: ast.Module, module: str) -> list[ast.ImportFrom]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == module
    ]


def _imported_names(node: ast.ImportFrom) -> set[str]:
    return {alias.name for alias in node.names}


def _catches_import_error(handler: ast.ExceptHandler) -> bool:
    exc_type = handler.type
    if exc_type is None:
        return True
    if isinstance(exc_type, ast.Name):
        return exc_type.id == "ImportError"
    if isinstance(exc_type, ast.Tuple):
        return any(
            isinstance(element, ast.Name) and element.id == "ImportError"
            for element in exc_type.elts
        )
    return False


class TestIdaGuiDetection:
    def test_gui_detected_with_venv_interpreter(self, monkeypatch):
        fake_idaapi = types.ModuleType("idaapi")
        fake_idaapi.is_idaq = lambda: True
        monkeypatch.setitem(sys.modules, "idaapi", fake_idaapi)
        monkeypatch.setattr(
            sys,
            "executable",
            r"C:\Users\John\AppData\Roaming\Hex-Rays\IDA Pro\venv\Scripts\python.exe",
        )

        assert qt_shim._is_ida_gui_available() is True

    def test_headless_ida_is_not_gui(self, monkeypatch):
        fake_idaapi = types.ModuleType("idaapi")
        fake_idaapi.is_idaq = lambda: False
        monkeypatch.setitem(sys.modules, "idaapi", fake_idaapi)
        monkeypatch.setattr(sys, "executable", r"C:\IDA\idat64.exe")

        assert qt_shim._is_ida_gui_available() is False

    def test_missing_idaapi_is_not_gui(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "idaapi", None)
        monkeypatch.setattr(sys, "executable", r"C:\IDA\ida64.exe")

        assert qt_shim._is_ida_gui_available() is False


class TestPyQt5FallbackImports:
    @pytest.fixture(scope="class")
    @classmethod
    def tree(cls) -> ast.Module:
        return _source_tree()

    def test_qpixmap_comes_from_qtgui(self, tree):
        names: set[str] = set()
        for node in _imports_from(tree, "PyQt5.QtGui"):
            names |= _imported_names(node)

        assert "QPixmap" in names

    def test_qpixmap_is_not_imported_from_qtwidgets(self, tree):
        names: set[str] = set()
        for node in _imports_from(tree, "PyQt5.QtWidgets"):
            names |= _imported_names(node)

        assert "QPixmap" not in names

    def test_sip_is_not_part_of_combined_pyqt5_import(self, tree):
        for node in _imports_from(tree, "PyQt5"):
            names = _imported_names(node)
            assert not ({"QtCore", "QtGui", "QtWidgets"} & names and "sip" in names), (
                "sip must not be imported in the same statement as the Qt modules: "
                "IDA's bundled PyQt5 does not ship the sip submodule."
            )

    def test_sip_import_has_standalone_fallback(self, tree):
        sip_tries = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Try)
            and any(
                isinstance(child, ast.ImportFrom)
                and child.module == "PyQt5"
                and any(alias.name == "sip" for alias in child.names)
                for child in ast.walk(node)
            )
        ]
        assert sip_tries, "expected a guarded 'from PyQt5 import sip'"

        for node in sip_tries:
            assert any(_catches_import_error(handler) for handler in node.handlers)
            assert any(
                isinstance(child, ast.Import)
                and any(alias.name == "sip" for alias in child.names)
                for child in ast.walk(node)
            )
            assert any(
                isinstance(child, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "sip"
                    for target in child.targets
                )
                and isinstance(child.value, ast.Constant)
                and child.value.value is None
                for child in ast.walk(node)
            )


class TestWrapInstance:
    def test_missing_sip_raises_runtime_error(self, monkeypatch):
        monkeypatch.setattr(qt_shim, "QT6", False)
        monkeypatch.setattr(qt_shim, "sip", None)

        with pytest.raises(RuntimeError, match="sip"):
            qt_shim.wrapinstance(0, object)
