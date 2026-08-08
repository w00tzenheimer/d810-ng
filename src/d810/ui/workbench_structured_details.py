"""Native structured details for the Build workspace without a web dependency."""

from __future__ import annotations

import json

from d810.core import typing
from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtCore, QtWidgets, qt_flag_or
from d810.ui.workbench_structured_details_logic import (
    DetailSection,
    JsonTreeNode,
    apply_json_tree_scalar,
    json_value_tree,
)


def _user_role() -> typing.Any:
    try:
        return QtCore.Qt.ItemDataRole.UserRole
    except AttributeError:
        return QtCore.Qt.UserRole


def _item_editable_flag() -> typing.Any:
    try:
        return QtCore.Qt.ItemFlag.ItemIsEditable
    except AttributeError:
        return QtCore.Qt.ItemIsEditable


def _display_json_scalar(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


if QT_GRAPHICS_AVAILABLE:

    class StructuredDetailsView(QtWidgets.QScrollArea):
        """A scrollable, titled field/value presentation of snapshot details."""

        def __init__(self, parent: typing.Any = None) -> None:
            super().__init__(parent)
            self.setWidgetResizable(True)
            self._content = QtWidgets.QWidget()
            self._layout = QtWidgets.QVBoxLayout(self._content)
            self._layout.setContentsMargins(4, 4, 4, 4)
            self._layout.setSpacing(6)
            self._layout.addStretch(1)
            self.setWidget(self._content)

        def set_sections(self, sections: tuple[DetailSection, ...]) -> None:
            """Replace the view with semantic field/value groups."""

            while self._layout.count():
                item = self._layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    # Layout removal alone leaves the old widget painted at
                    # its previous geometry until deferred deletion runs.
                    # Hide and detach it now so a re-render never doubles
                    # labels in the compact dossier rail.
                    widget.hide()
                    widget.setParent(None)
                    widget.deleteLater()
            for section in sections:
                group = QtWidgets.QGroupBox(section.title)
                section_layout = QtWidgets.QVBoxLayout(group)
                section_layout.setContentsMargins(6, 6, 6, 6)
                section_layout.setSpacing(4)
                for field in section.fields:
                    field_widget = QtWidgets.QWidget()
                    field_layout = QtWidgets.QVBoxLayout(field_widget)
                    field_layout.setContentsMargins(0, 0, 0, 0)
                    field_layout.setSpacing(0)
                    label = QtWidgets.QLabel(field.label)
                    label.setStyleSheet("font-weight: bold;")
                    value = QtWidgets.QLabel(field.value)
                    value.setWordWrap(True)
                    value.setTextInteractionFlags(_text_selectable())
                    field_layout.addWidget(label)
                    field_layout.addWidget(value)
                    section_layout.addWidget(field_widget)
                self._layout.addWidget(group)
            self._layout.addStretch(1)


    def _text_selectable() -> typing.Any:
        try:
            return QtCore.Qt.TextInteractionFlag.TextSelectableByMouse
        except AttributeError:
            return QtCore.Qt.TextSelectableByMouse


    class JsonTreeEditor(QtWidgets.QTreeWidget):
        """One JSON value as an optionally editable field/property tree."""

        def __init__(self, parent: typing.Any = None) -> None:
            super().__init__(parent)
            self.setColumnCount(2)
            self.setHeaderLabels(["Field", "Value"])
            self.setAlternatingRowColors(True)
            self._value: object = {}
            self._editable = False
            self._rendering = False
            self._on_value_changed: typing.Callable[[object], None] | None = None
            self.itemChanged.connect(self._on_item_changed)
            try:
                self.header().setStretchLastSection(True)
            except AttributeError:
                pass

        def set_json(self, value: object, *, editable: bool) -> None:
            self._value = value
            self._editable = editable
            self._rendering = True
            try:
                self.clear()
                for node in json_value_tree(value, editable=editable):
                    self.addTopLevelItem(self._item_for_node(node))
                self.expandAll()
            finally:
                self._rendering = False

        def set_on_value_changed(
            self,
            callback: typing.Callable[[object], None] | None,
        ) -> None:
            self._on_value_changed = callback

        def _item_for_node(self, node: JsonTreeNode) -> typing.Any:
            value = "" if node.children else _display_json_scalar(node.value)
            item = QtWidgets.QTreeWidgetItem([node.key, value])
            item.setData(0, _user_role(), node.path)
            item.setData(1, _user_role(), node.editable and node.is_scalar)
            if node.editable and node.is_scalar:
                item.setFlags(qt_flag_or(item.flags(), _item_editable_flag()))
            for child in node.children:
                item.addChild(self._item_for_node(child))
            return item

        def _on_item_changed(self, item: typing.Any, column: int) -> None:
            if self._rendering or column != 1:
                return
            if not bool(item.data(1, _user_role())):
                return
            path = tuple(item.data(0, _user_role()) or ())
            try:
                updated = apply_json_tree_scalar(self._value, path, item.text(1))
            except ValueError:
                return
            self.set_json(updated, editable=self._editable)
            if self._on_value_changed is not None:
                self._on_value_changed(updated)


    class RawJsonDialog(QtWidgets.QDialog):
        """Optional raw JSON view; only recipe options can be applied."""

        def __init__(
            self,
            title: str,
            value: object,
            *,
            editable: bool,
            on_apply: typing.Callable[[object], None] | None = None,
            parent: typing.Any = None,
        ) -> None:
            super().__init__(parent)
            self._on_apply = on_apply
            self.setWindowTitle(title)
            self.editor = QtWidgets.QPlainTextEdit()
            self.editor.setPlainText(json.dumps(value, indent=2, sort_keys=True))
            self.editor.setReadOnly(not editable)

            layout = QtWidgets.QVBoxLayout(self)
            layout.setContentsMargins(8, 8, 8, 8)
            layout.addWidget(self.editor, stretch=1)
            controls = QtWidgets.QHBoxLayout()
            controls.addStretch(1)
            if editable:
                apply_button = QtWidgets.QPushButton("Apply options")
                apply_button.clicked.connect(self._apply)
                controls.addWidget(apply_button)
            close_button = QtWidgets.QPushButton("Close")
            close_button.clicked.connect(self.reject)
            controls.addWidget(close_button)
            layout.addLayout(controls)

        def _apply(self, checked: bool = False) -> None:
            del checked
            try:
                value = json.loads(self.editor.toPlainText())
            except json.JSONDecodeError as exc:
                QtWidgets.QMessageBox.warning(self, "Invalid JSON", str(exc))
                return
            if self._on_apply is not None:
                self._on_apply(value)
            self.accept()


    class NodeInspectorView(QtWidgets.QStackedWidget):
        """Intentional empty state plus grouped node, option, and contract details."""

        def __init__(self, parent: typing.Any = None) -> None:
            super().__init__(parent)
            self._options: object = {}
            self._contract: object = {}
            self._options_callback: typing.Callable[[object], None] | None = None
            self._options_editable = False

            self._empty_page = QtWidgets.QWidget()
            empty_layout = QtWidgets.QVBoxLayout(self._empty_page)
            empty_layout.setContentsMargins(8, 8, 8, 8)
            self._empty_label = QtWidgets.QLabel(
                "Select a registered node to inspect its inputs, outputs, options, and contract."
            )
            self._empty_label.setWordWrap(True)
            empty_layout.addWidget(self._empty_label)
            empty_layout.addStretch(1)
            self.addWidget(self._empty_page)

            self._details_page = QtWidgets.QWidget()
            details_layout = QtWidgets.QVBoxLayout(self._details_page)
            details_layout.setContentsMargins(0, 0, 0, 0)
            details_layout.setSpacing(6)
            self.details = StructuredDetailsView()
            details_layout.addWidget(self.details, stretch=2)

            self.options_group = QtWidgets.QGroupBox("Recipe options")
            options_layout = QtWidgets.QVBoxLayout(self.options_group)
            options_layout.setContentsMargins(6, 6, 6, 6)
            self.options_tree = JsonTreeEditor()
            self.options_tree.set_on_value_changed(self._apply_options)
            options_layout.addWidget(self.options_tree)
            options_controls = QtWidgets.QHBoxLayout()
            options_controls.addStretch(1)
            self.options_raw_button = QtWidgets.QToolButton()
            self.options_raw_button.setText("Edit raw JSON")
            self.options_raw_button.clicked.connect(self._show_raw_options)
            options_controls.addWidget(self.options_raw_button)
            options_layout.addLayout(options_controls)
            details_layout.addWidget(self.options_group, stretch=1)

            self.contract_group = QtWidgets.QGroupBox("Pass contract (read-only)")
            contract_layout = QtWidgets.QVBoxLayout(self.contract_group)
            contract_layout.setContentsMargins(6, 6, 6, 6)
            self.contract_tree = JsonTreeEditor()
            contract_layout.addWidget(self.contract_tree)
            contract_controls = QtWidgets.QHBoxLayout()
            contract_controls.addStretch(1)
            self.contract_raw_button = QtWidgets.QToolButton()
            self.contract_raw_button.setText("View raw contract")
            self.contract_raw_button.clicked.connect(self.show_contract_raw)
            contract_controls.addWidget(self.contract_raw_button)
            contract_layout.addLayout(contract_controls)
            details_layout.addWidget(self.contract_group, stretch=1)
            self.addWidget(self._details_page)
            self.show_empty()

        def show_empty(self, message: str | None = None) -> None:
            self._empty_label.setText(
                message
                or "Select a registered node to inspect its inputs, outputs, options, and contract."
            )
            self.setCurrentWidget(self._empty_page)

        def show_node(
            self,
            sections: tuple[DetailSection, ...],
            options: object,
            contract: object,
            *,
            editable_options: bool,
            on_options_changed: typing.Callable[[object], None] | None,
        ) -> None:
            self._options = options
            self._contract = contract
            self._options_editable = editable_options
            self._options_callback = on_options_changed
            self.details.set_sections(sections)
            self.options_tree.set_json(options, editable=editable_options)
            self.contract_tree.set_json(contract, editable=False)
            self.options_group.setVisible(editable_options)
            self.setCurrentWidget(self._details_page)

        def show_options_raw(self) -> None:
            self._show_raw_options()

        def show_contract_raw(self) -> None:
            dialog = RawJsonDialog(
                "View pass contract",
                self._contract,
                editable=False,
                parent=self,
            )
            dialog.exec_()

        def _show_raw_options(self, checked: bool = False) -> None:
            del checked
            if not self._options_editable:
                return
            dialog = RawJsonDialog(
                "Edit recipe options",
                self._options,
                editable=True,
                on_apply=self._apply_options,
                parent=self,
            )
            dialog.exec_()

        def _apply_options(self, value: object) -> None:
            if not self._options_editable or not isinstance(value, dict):
                return
            self._options = value
            self.options_tree.set_json(value, editable=True)
            if self._options_callback is not None:
                self._options_callback(value)


else:

    class StructuredDetailsView:
        """Unavailable structured details placeholder for headless imports."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Structured details require IDA GUI graphics support")


    class JsonTreeEditor:
        """Unavailable JSON tree placeholder for headless imports."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Structured details require IDA GUI graphics support")


    class RawJsonDialog:
        """Unavailable raw JSON dialog placeholder for headless imports."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Structured details require IDA GUI graphics support")


    class NodeInspectorView:
        """Unavailable node inspector placeholder for headless imports."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Structured details require IDA GUI graphics support")


__all__ = [
    "JsonTreeEditor",
    "NodeInspectorView",
    "RawJsonDialog",
    "StructuredDetailsView",
]
