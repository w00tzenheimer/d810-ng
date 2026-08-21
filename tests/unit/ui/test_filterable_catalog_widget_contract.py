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
    / "filterable_catalog_widget.py"
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

    def setLayout(self, layout: _VBoxLayout) -> None:
        self.layout = layout


class _VBoxLayout:
    def __init__(self, parent: _Widget | None = None) -> None:
        self.parent = parent
        self.widgets: list[object] = []
        if parent is not None:
            parent.layout = self

    def addWidget(self, widget: object) -> None:
        self.widgets.append(widget)

    def addStretch(self, stretch: int) -> None:
        del stretch


class _LineEdit(_Widget):
    def __init__(self, parent: object | None = None) -> None:
        super().__init__(parent)
        self._text = ""
        self._blocked = False
        self.textChanged = _Signal()

    def setPlaceholderText(self, text: str) -> None:
        self.placeholder = text

    def setText(self, text: str) -> None:
        self._text = text
        if not self._blocked:
            self.textChanged.emit(text)

    def text(self) -> str:
        return self._text

    def blockSignals(self, blocked: bool) -> bool:
        previous = self._blocked
        self._blocked = blocked
        return previous


class _Header:
    def __init__(self) -> None:
        self.sectionClicked = _Signal()


class _TreeWidget(_Widget):
    def __init__(self, parent: object | None = None) -> None:
        super().__init__(parent)
        self._header = _Header()
        self.items: list[_TreeWidgetItem] = []
        self.widgets: dict[tuple[_TreeWidgetItem, int], object] = {}
        self.current_item: _TreeWidgetItem | None = None
        self.selected_items: list[_TreeWidgetItem] = []
        self.itemClicked = _Signal()
        self.itemDoubleClicked = _Signal()
        self.itemSelectionChanged = _Signal()
        self.sorting_enabled = True
        self.header_labels: list[str] = []

    def setColumnCount(self, count: int) -> None:
        self.column_count = count

    def setHeaderLabels(self, labels: list[str]) -> None:
        self.header_labels = labels

    def header(self) -> _Header:
        return self._header

    def setSortingEnabled(self, enabled: bool) -> None:
        self.sorting_enabled = enabled

    def clear(self) -> None:
        self.items = []
        self.widgets = {}
        self.current_item = None
        self.selected_items = []

    def addTopLevelItem(self, item: _TreeWidgetItem) -> None:
        self.items.append(item)

    def setItemWidget(self, item: _TreeWidgetItem, column: int, widget: object) -> None:
        self.widgets[(item, column)] = widget

    def itemWidget(self, item: _TreeWidgetItem, column: int) -> object | None:
        return self.widgets.get((item, column))

    def setCurrentItem(self, item: _TreeWidgetItem) -> None:
        self.current_item = item
        self.selected_items = [item]

    def currentItem(self) -> _TreeWidgetItem | None:
        return self.current_item

    def selectedItems(self) -> list[_TreeWidgetItem]:
        return getattr(self, "selected_items", [])


class _TreeWidgetItem:
    def __init__(self, parent: object | None = None, strings: list[str] | None = None) -> None:
        del parent
        self.strings = list(strings or [""] * 4)
        self.data_values: dict[tuple[int, object], object] = {}

    def setData(self, column: int, role: object, value: object) -> None:
        self.data_values[(column, role)] = value

    def data(self, column: int, role: object) -> object:
        return self.data_values.get((column, role))

    def setText(self, column: int, text: str) -> None:
        self.strings[column] = text

    def text(self, column: int) -> str:
        return self.strings[column]


class _CheckBox(_Widget):
    def __init__(self, text: str = "", parent: object | None = None) -> None:
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


class _Button(_Widget):
    def __init__(self, text: str = "", parent: object | None = None) -> None:
        super().__init__(parent)
        self._text = text
        self._enabled = True
        self.clicked = _Signal()

    def setText(self, text: str) -> None:
        self._text = text

    def text(self) -> str:
        return self._text

    def setEnabled(self, enabled: bool) -> None:
        self._enabled = enabled

    def isEnabled(self) -> bool:
        return self._enabled


class _Dialog(_Widget):
    Accepted = 1
    Rejected = 0

    def __init__(self, parent: object | None = None) -> None:
        super().__init__(parent)
        self.result = self.Rejected

    def setWindowTitle(self, title: str) -> None:
        self.title = title

    def accept(self) -> None:
        self.result = self.Accepted

    def reject(self) -> None:
        self.result = self.Rejected


def _load_widget(monkeypatch: pytest.MonkeyPatch):
    qtcore = types.SimpleNamespace(
        Qt=types.SimpleNamespace(UserRole=32),
        pyqtSignal=lambda *args, **kwargs: _Signal(),
    )
    widgets = types.SimpleNamespace(
        QWidget=_Widget,
        QDialog=_Dialog,
        QLineEdit=_LineEdit,
        QTreeWidget=_TreeWidget,
        QTreeWidgetItem=_TreeWidgetItem,
        QCheckBox=_CheckBox,
        QPushButton=_Button,
        QVBoxLayout=_VBoxLayout,
    )
    monkeypatch.setitem(
        sys.modules,
        "d810.qt_shim",
        types.SimpleNamespace(
            QT_GRAPHICS_AVAILABLE=True,
            QtCore=qtcore,
            QtWidgets=widgets,
        ),
    )
    module_name = "d810.ui._filterable_catalog_widget_contract"
    spec = importlib.util.spec_from_file_location(module_name, WIDGET)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def _catalog(module):
    columns = (
        module.CatalogColumnSpec("include", "Include", searchable=False),
        module.CatalogColumnSpec("pass", "Pass"),
        module.CatalogColumnSpec("id", "ID"),
        module.CatalogColumnSpec("purpose", "Purpose"),
    )
    rows = (
        module.CatalogRow("pass.z", ("Zeta", "pass.z", "Alpha")),
        module.CatalogRow("pass.a", ("Alpha", "pass.a", "Omega")),
    )
    return columns, rows


def test_widget_renders_generic_columns_filter_and_embedded_include_checkboxes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    columns, rows = _catalog(module)
    widget = module.FilterableCatalogWidget(
        columns, rows, mode=module.CatalogSelectionMode.MULTI_CHECK, action_verb="Add"
    )

    assert widget.filter_edit.__class__ is _LineEdit
    assert widget.tree.header_labels == ["Include", "Pass", "ID", "Purpose"]
    assert widget.tree.sorting_enabled is False
    assert [item.data(0, widget._user_role()) for item in widget.tree.items] == [
        "pass.a",
        "pass.z",
    ]
    assert all(
        isinstance(widget.tree.itemWidget(item, 0), _CheckBox)
        for item in widget.tree.items
    )

    widget.tree.itemWidget(widget.tree.items[0], 0).setChecked(True)
    assert widget.selected_keys() == ("pass.a",)
    widget.set_rows(rows)
    assert widget.selected_keys() == ("pass.a",)


def test_widget_headers_and_filter_drive_pure_projection_and_preserve_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    columns, rows = _catalog(module)
    widget = module.FilterableCatalogWidget(
        columns, rows, mode=module.CatalogSelectionMode.MULTI_CHECK, action_verb="Add"
    )
    widget.set_checked("pass.z", True)
    widget.filter_edit.setText("omega")
    assert [row.key for row in widget.view().rows] == ["pass.a"]
    assert widget.selected_keys() == ("pass.z",)

    widget.tree.header().sectionClicked.emit(1)
    assert widget._state.sort_column == 1
    assert widget._state.sort_direction.value == "ascending"
    widget.tree.header().sectionClicked.emit(1)
    assert widget._state.sort_direction.value == "descending"


def test_single_mode_uses_activated_row_identity_and_current_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    columns, rows = _catalog(module)
    widget = module.FilterableCatalogWidget(
        columns, rows, mode=module.CatalogSelectionMode.SINGLE
    )
    widget.tree.itemClicked.emit(widget.tree.items[0], 2)

    assert widget.current_key() == "pass.a"
    assert widget.selected_keys() == ("pass.a",)
    assert widget.tree.currentItem() is widget.tree.items[0]
    assert widget.tree.selectedItems() == [widget.tree.items[0]]


def test_single_mode_rebuilds_restore_the_native_current_item_by_stable_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    columns, rows = _catalog(module)
    widget = module.FilterableCatalogWidget(
        columns, rows, mode=module.CatalogSelectionMode.SINGLE
    )
    widget.tree.itemClicked.emit(widget.tree.items[1], 2)
    current_key = widget.current_key()
    assert current_key == "pass.z"

    widget.set_query("zeta")
    widget.set_sort(1)
    widget.set_rows(tuple(reversed(rows)))

    current_item = widget.tree.currentItem()
    assert current_item is not None
    assert current_item.data(0, widget._user_role()) == current_key
    assert widget.tree.selectedItems() == [current_item]


def test_public_set_query_syncs_visible_filter_text_and_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    columns, rows = _catalog(module)
    widget = module.FilterableCatalogWidget(
        columns, rows, mode=module.CatalogSelectionMode.MULTI_CHECK
    )

    widget.set_query(" omega ")

    assert widget.filter_edit.text() == "omega"
    assert [row.key for row in widget.view().rows] == ["pass.a"]


def test_invalid_sort_is_transactional_and_followup_valid_sort_still_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    columns, rows = _catalog(module)
    widget = module.FilterableCatalogWidget(
        columns, rows, mode=module.CatalogSelectionMode.MULTI_CHECK
    )
    before_keys = [item.data(0, widget._user_role()) for item in widget.tree.items]

    with pytest.raises(ValueError, match="sort column"):
        widget.set_sort(99)

    assert widget._state.sort_column == 2
    assert [item.data(0, widget._user_role()) for item in widget.tree.items] == before_keys
    widget.set_sort(1)
    assert widget._state.sort_column == 1


def test_invalid_row_replacement_is_transactional_and_valid_replacement_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    columns, rows = _catalog(module)
    widget = module.FilterableCatalogWidget(
        columns, rows, mode=module.CatalogSelectionMode.MULTI_CHECK
    )
    before_keys = [item.data(0, widget._user_role()) for item in widget.tree.items]

    with pytest.raises(ValueError, match="cell count"):
        widget.set_rows((module.CatalogRow("broken", ("only one",)),))

    assert [item.data(0, widget._user_role()) for item in widget.tree.items] == before_keys
    widget.set_rows(rows)
    assert [item.data(0, widget._user_role()) for item in widget.tree.items] == before_keys


def test_dialog_accept_button_tracks_view_and_cancel_has_no_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    columns, rows = _catalog(module)
    dialog = module.FilterableCatalogDialog(
        "Add pass",
        columns,
        rows,
        mode=module.CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )

    assert dialog.accept_button.text() == "Add 0 passes"
    assert dialog.accept_button.isEnabled() is False
    dialog.catalog.set_checked("pass.z", True)
    assert dialog.accept_button.text() == "Add 1 pass"
    assert dialog.accept_button.isEnabled() is True
    dialog.cancel_button.clicked.emit()
    assert dialog.selected_keys() == ()


def test_multi_check_activation_does_not_accept_dialog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    columns, rows = _catalog(module)
    dialog = module.FilterableCatalogDialog(
        "Add pass",
        columns,
        rows,
        mode=module.CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    dialog.catalog.tree.itemDoubleClicked.emit(dialog.catalog.tree.items[0], 1)
    assert dialog.selected_keys() == ()
    assert dialog.catalog.selected_keys() == ("pass.a",)


def test_native_reject_after_accept_clears_the_current_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_widget(monkeypatch)
    columns, rows = _catalog(module)
    dialog = module.FilterableCatalogDialog(
        "Add pass",
        columns,
        rows,
        mode=module.CatalogSelectionMode.MULTI_CHECK,
        action_verb="Add",
    )
    dialog.catalog.set_checked("pass.z", True)
    dialog.accept_button.clicked.emit()
    assert dialog.selected_keys() == ("pass.z",)

    dialog.reject()

    assert dialog.selected_keys() == ()


def test_widget_uses_item_widgets_and_never_item_changed_model_callbacks() -> None:
    source = WIDGET.read_text(encoding="utf-8")

    assert "QTreeWidget" in source
    assert "setItemWidget" in source
    assert "itemChanged" not in source
