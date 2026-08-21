from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest


WIDGET = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "ui"
    / "checkable_choice_list.py"
)


class _Signal:
    def __init__(self) -> None:
        self.callbacks: list[object] = []

    def connect(self, callback: object) -> None:
        self.callbacks.append(callback)

    def emit(self, *args: object) -> None:
        for callback in tuple(self.callbacks):
            callback(*args)


class _Widget:
    def __init__(self, parent: object | None = None) -> None:
        self.parent = parent
        self.layout: _VBoxLayout | None = None
        self.minimum_height: int | None = None
        self.maximum_height: int | None = None


class _ScrollArea(_Widget):
    def __init__(self, parent: object | None = None) -> None:
        super().__init__(parent)
        self.widget: _Widget | None = None
        self.resizable = False

    def setWidgetResizable(self, resizable: bool) -> None:
        self.resizable = resizable

    def setWidget(self, widget: _Widget) -> None:
        self.widget = widget

    def setMinimumHeight(self, height: int) -> None:
        self.minimum_height = height

    def setMaximumHeight(self, height: int) -> None:
        self.maximum_height = height


class _VBoxLayout:
    def __init__(self, parent: _Widget) -> None:
        parent.layout = self
        self.widgets: list[_CheckBox] = []

    def setContentsMargins(self, *margins: int) -> None:
        del margins

    def setSpacing(self, spacing: int) -> None:
        del spacing

    def addWidget(self, widget: _CheckBox) -> None:
        self.widgets.append(widget)

    def addStretch(self, stretch: int) -> None:
        del stretch


class _CheckBox(_Widget):
    def __init__(self, text: str, parent: object | None = None) -> None:
        super().__init__(parent)
        self.text = text
        self._checked = False
        self._blocked = False
        self.toggled = _Signal()

    def setChecked(self, checked: bool) -> None:
        changed = self._checked != checked
        self._checked = checked
        if changed and not self._blocked:
            self.toggled.emit(checked)

    def isChecked(self) -> bool:
        return self._checked

    def blockSignals(self, blocked: bool) -> bool:
        previous = self._blocked
        self._blocked = blocked
        return previous


def _load_widget(monkeypatch: pytest.MonkeyPatch):
    qt = types.SimpleNamespace(Qt=types.SimpleNamespace())
    widgets = types.SimpleNamespace(
        QCheckBox=_CheckBox,
        QScrollArea=_ScrollArea,
        QVBoxLayout=_VBoxLayout,
        QWidget=_Widget,
    )
    monkeypatch.setitem(
        sys.modules,
        "d810.qt_shim",
        types.SimpleNamespace(QtCore=qt, QtWidgets=widgets),
    )
    module_name = "d810.ui._checkable_choice_list_contract"
    spec = importlib.util.spec_from_file_location(module_name, WIDGET)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def test_choice_list_initializes_in_declared_order_and_bounds_height(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    calls: list[tuple[str, ...]] = []
    widget = module.CheckableChoiceListWidget(
        ("one", "two", "three"),
        ("three", "one"),
        lambda selected: calls.append(selected) or True,
    )

    assert widget.choices() == ("one", "two", "three")
    assert widget.selected_choices() == ("one", "three")
    assert widget.checkbox_for("one").isChecked() is True
    assert widget.checkbox_for("two").isChecked() is False
    assert widget.checkbox_for("three").isChecked() is True
    assert widget.minimum_height == 72
    assert widget.maximum_height == 72


def test_choice_list_emits_declared_order_and_accepts_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    calls: list[tuple[str, ...]] = []
    widget = module.CheckableChoiceListWidget(
        ("one", "two", "three"),
        ("three",),
        lambda selected: calls.append(selected) or True,
    )

    widget.checkbox_for("one").setChecked(True)

    assert calls == [("one", "three")]
    assert widget.selected_choices() == ("one", "three")


def test_choice_list_rejection_restores_checkbox_and_pure_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    calls: list[tuple[str, ...]] = []
    widget = module.CheckableChoiceListWidget(
        ("one", "two"),
        ("one",),
        lambda selected: calls.append(selected) or False,
    )

    widget.checkbox_for("one").setChecked(False)

    assert calls == [()]
    assert widget.checkbox_for("one").isChecked() is True
    assert widget.selected_choices() == ("one",)


def test_choice_list_refreshes_under_blocked_signals_and_validates_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    calls: list[tuple[str, ...]] = []
    widget = module.CheckableChoiceListWidget(
        ("one", "two"),
        (),
        lambda selected: calls.append(selected) or True,
    )

    widget.set_selection(["two"])

    assert calls == []
    assert widget.selected_choices() == ("two",)
    assert widget.checkbox_for("two").isChecked() is True
    with pytest.raises(ValueError, match="duplicate"):
        widget.set_selection(["two", "two"])
    with pytest.raises(ValueError, match="unknown"):
        widget.set_selection(["missing"])


def test_choice_list_has_no_native_item_model_dependency() -> None:
    source = WIDGET.read_text(encoding="utf-8")

    assert "QListWidget" not in source
    assert "itemChanged" not in source


def test_checkbox_for_declares_the_public_checkbox_return_contract() -> None:
    source = WIDGET.read_text(encoding="utf-8")

    assert "def checkbox_for(self, choice: str) -> QtWidgets.QCheckBox | None:" in source
