"""Generic Qt rendering for the pure filterable catalog model."""

from __future__ import annotations

from dataclasses import replace

from d810.core import typing
from d810.ui.filterable_catalog_logic import (
    CatalogColumnSpec,
    CatalogRow,
    CatalogSelectionMode,
    FilterableCatalogView,
    initial_filterable_catalog_state,
    project_filterable_catalog,
    set_catalog_checked,
    set_catalog_current,
    set_catalog_query,
    set_catalog_sort,
)

try:
    from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtCore, QtWidgets, Signal
except ImportError:  # Narrow fake-Qt adapters may omit the availability flag.
    from d810.qt_shim import QtCore, QtWidgets, Signal

    QT_GRAPHICS_AVAILABLE = True


def _signal_factory() -> typing.Any:
    """Signal factory for either binding; the shim resolves the spelling."""
    return Signal


if QT_GRAPHICS_AVAILABLE:

    class FilterableCatalogWidget(QtWidgets.QWidget):
        """Render a filterable catalog while keeping selection in pure state."""

        selection_changed = _signal_factory()(object)
        activated = _signal_factory()(str)

        def __init__(
            self,
            columns: typing.Sequence[CatalogColumnSpec],
            rows: typing.Sequence[CatalogRow],
            *,
            mode: CatalogSelectionMode,
            action_verb: str = "Select",
            parent: typing.Any = None,
        ) -> None:
            super().__init__(parent)
            self._columns = tuple(columns)
            self._rows = tuple(rows)
            self._mode = CatalogSelectionMode(mode)
            self._action_verb = action_verb
            # The catalog contract makes the initial ID column explicit.  It
            # must not drift when the caller changes the visible column order.
            self._state = initial_filterable_catalog_state(
                self._columns, initial_sort_column_id="id"
            )
            self._repopulating = False
            self._checkboxes: dict[str, typing.Any] = {}
            self._view: FilterableCatalogView

            self.filter_edit = QtWidgets.QLineEdit(self)
            self.filter_edit.setPlaceholderText("Filter")
            self.tree = QtWidgets.QTreeWidget(self)
            self.tree.setColumnCount(len(self._columns))
            self.tree.setHeaderLabels([column.label for column in self._columns])
            self.tree.setSortingEnabled(False)

            layout = QtWidgets.QVBoxLayout(self)
            layout.addWidget(self.filter_edit)
            layout.addWidget(self.tree)

            self.filter_edit.textChanged.connect(self._filter_changed)
            self.tree.header().sectionClicked.connect(self.set_sort)
            self.tree.itemClicked.connect(self._item_clicked)
            self.tree.itemDoubleClicked.connect(self._item_activated)
            self._render()

        @staticmethod
        def _user_role() -> typing.Any:
            """Return the stable item-data role on both Qt enum layouts."""

            try:
                return QtCore.Qt.UserRole
            except AttributeError:
                return QtCore.Qt.ItemDataRole.UserRole

        def set_rows(self, rows: typing.Sequence[CatalogRow]) -> None:
            """Replace display rows while retaining still-valid selections."""

            candidate_rows = tuple(rows)
            valid_keys = {row.key for row in candidate_rows}
            candidate_state = replace(
                self._state,
                checked_keys=tuple(
                    key for key in self._state.checked_keys if key in valid_keys
                ),
                current_key=(
                    self._state.current_key
                    if self._state.current_key in valid_keys
                    else None
                ),
            )
            candidate_view = self._project(candidate_rows, candidate_state)
            self._rows = candidate_rows
            self._state = candidate_state
            self._render(candidate_view)

        def set_query(self, query: str) -> None:
            candidate_state = set_catalog_query(self._state, query)
            candidate_view = self._project(self._rows, candidate_state)
            self._state = candidate_state
            normalized_query = candidate_state.query
            if self.filter_edit.text() != normalized_query:
                self.filter_edit.blockSignals(True)
                try:
                    self.filter_edit.setText(normalized_query)
                finally:
                    self.filter_edit.blockSignals(False)
            self._render(candidate_view)

        def set_sort(self, column: int) -> None:
            candidate_state = set_catalog_sort(self._state, column)
            candidate_view = self._project(self._rows, candidate_state)
            self._state = candidate_state
            self._render(candidate_view)

        def _filter_changed(self, query: str) -> None:
            self.set_query(query)

        def set_checked(self, key: str, checked: bool) -> None:
            valid_keys = {row.key for row in self._rows}
            self._state = set_catalog_checked(
                self._state,
                key,
                bool(checked),
                valid_keys=valid_keys,
                mode=self._mode,
            )
            self._render()
            self.selection_changed.emit(self.selected_keys())

        def selected_keys(self) -> tuple[str, ...]:
            view = self._view
            if self._mode is CatalogSelectionMode.SINGLE:
                return (view.current_key,) if view.current_key is not None else ()
            return view.checked_keys

        def current_key(self) -> str | None:
            return self._view.current_key

        def view(self) -> FilterableCatalogView:
            return self._view

        def _project(
            self,
            rows: typing.Sequence[CatalogRow],
            state: typing.Any,
        ) -> FilterableCatalogView:
            return project_filterable_catalog(
                rows,
                self._columns,
                state,
                self._mode,
                action_verb=self._action_verb,
            )

        def _render(self, view: FilterableCatalogView | None = None) -> None:
            self._view = view or self._project(self._rows, self._state)
            include_column = next(
                (
                    index
                    for index, column in enumerate(self._columns)
                    if column.column_id.casefold() == "include"
                ),
                None,
            )
            self._checkboxes = {}
            self._repopulating = True
            try:
                self.tree.clear()
                role = self._user_role()
                cell_index_by_column: list[int | None] = []
                cell_index = 0
                for index in range(len(self._columns)):
                    if index == include_column:
                        cell_index_by_column.append(None)
                    else:
                        cell_index_by_column.append(cell_index)
                        cell_index += 1
                checked = set(self._view.checked_keys)
                current_item: typing.Any = None
                for row in self._view.rows:
                    item = QtWidgets.QTreeWidgetItem()
                    item.setData(0, role, row.key)
                    for column_index, cell_index in enumerate(cell_index_by_column):
                        item.setText(
                            column_index,
                            "" if cell_index is None else row.cells[cell_index],
                        )
                    self.tree.addTopLevelItem(item)
                    if row.key == self._view.current_key:
                        current_item = item
                    if include_column is not None and self._mode is CatalogSelectionMode.MULTI_CHECK:
                        checkbox = QtWidgets.QCheckBox("", self.tree)
                        checkbox.toggled.connect(
                            lambda value, key=row.key: self._checkbox_toggled(
                                key, bool(value)
                            )
                        )
                        checkbox.blockSignals(True)
                        try:
                            checkbox.setChecked(row.key in checked)
                        finally:
                            checkbox.blockSignals(False)
                        self._checkboxes[row.key] = checkbox
                        self.tree.setItemWidget(item, include_column, checkbox)
                if current_item is not None:
                    self.tree.setCurrentItem(current_item)
            finally:
                self._repopulating = False

        def _key_for_item(self, item: typing.Any) -> str | None:
            value = item.data(0, self._user_role())
            return None if value is None else str(value)

        def _item_clicked(self, item: typing.Any, column: int = 0) -> None:
            del column
            if self._mode is not CatalogSelectionMode.SINGLE:
                return
            key = self._key_for_item(item)
            if key is None:
                return
            self._state = set_catalog_current(
                self._state,
                key,
                valid_keys={row.key for row in self._rows},
                mode=self._mode,
            )
            self._render()
            self.selection_changed.emit(self.selected_keys())

        def _item_activated(self, item: typing.Any, column: int = 0) -> None:
            del column
            key = self._key_for_item(item)
            if key is None:
                return
            if self._mode is CatalogSelectionMode.MULTI_CHECK:
                checkbox = self._checkboxes.get(key)
                if checkbox is not None:
                    self.set_checked(key, not bool(checkbox.isChecked()))
            else:
                self._item_clicked(item)
            self.activated.emit(key)

        def _checkbox_toggled(self, key: str, checked: bool) -> None:
            if self._repopulating:
                return
            self.set_checked(key, checked)


    class FilterableCatalogDialog(QtWidgets.QDialog):
        """Generic modal shell for accepting a catalog selection."""

        def __init__(
            self,
            title: str,
            columns: typing.Sequence[CatalogColumnSpec],
            rows: typing.Sequence[CatalogRow],
            *,
            mode: CatalogSelectionMode,
            action_verb: str = "Select",
            parent: typing.Any = None,
        ) -> None:
            super().__init__(parent)
            self.setWindowTitle(title)
            self.catalog = FilterableCatalogWidget(
                columns,
                rows,
                mode=mode,
                action_verb=action_verb,
                parent=self,
            )
            self.widget = self.catalog
            self.accept_button = QtWidgets.QPushButton(self)
            self.cancel_button = QtWidgets.QPushButton("Cancel", self)
            self._accepted_keys: tuple[str, ...] = ()

            layout = QtWidgets.QVBoxLayout(self)
            layout.addWidget(self.catalog)
            layout.addWidget(self.accept_button)
            layout.addWidget(self.cancel_button)
            self.accept_button.clicked.connect(self._accept_selection)
            self.cancel_button.clicked.connect(self._cancel_selection)
            self.catalog.selection_changed.connect(self._refresh_action)
            self.catalog.activated.connect(self._activated)
            self._refresh_action(self.catalog.selected_keys())

        def selected_keys(self) -> tuple[str, ...]:
            return self._accepted_keys

        def _refresh_action(self, selected: object = None) -> None:
            del selected
            view = self.catalog.view()
            self.accept_button.setText(view.action_text)
            self.accept_button.setEnabled(view.action_enabled)

        def _accept_selection(self) -> None:
            if not self.catalog.view().action_enabled:
                return
            self._accepted_keys = self.catalog.selected_keys()
            self.accept()

        def _cancel_selection(self) -> None:
            self._accepted_keys = ()
            self.reject()

        def reject(self) -> None:
            self._accepted_keys = ()
            super().reject()

        def done(self, result: int) -> None:
            if result != getattr(QtWidgets.QDialog, "Accepted", 1):
                self._accepted_keys = ()
            super().done(result)

        def closeEvent(self, event: typing.Any) -> None:
            self._accepted_keys = ()
            super().closeEvent(event)

        def _activated(self, key: str) -> None:
            del key
            if self.catalog._mode is CatalogSelectionMode.SINGLE:
                self._accept_selection()


else:

    class FilterableCatalogWidget:
        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("FilterableCatalogWidget requires IDA Pro Qt")


    class FilterableCatalogDialog:
        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("FilterableCatalogDialog requires IDA Pro Qt")


__all__ = ["FilterableCatalogDialog", "FilterableCatalogWidget"]
