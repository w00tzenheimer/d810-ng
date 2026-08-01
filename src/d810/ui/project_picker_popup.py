"""Anchored searchable picker for the D-810 configuration catalog."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from d810.core import typing
from d810.ui.project_picker_logic import (
    ProjectPickerEntry,
    filter_project_picker_entries,
)

try:
    import ida_kernwin  # noqa: F401

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


if IDA_AVAILABLE:
    from d810.qt_shim import QtCore, QtWidgets

    def _popup_window_flag():
        try:
            return QtCore.Qt.WindowType.Popup
        except AttributeError:
            return QtCore.Qt.Popup


    class ProjectPickerPopup(QtWidgets.QFrame):
        """A compact, searchable select anchored below a configuration button."""

        def __init__(
            self,
            entries: Sequence[ProjectPickerEntry],
            *,
            current_project_index: int,
            on_project_selected: Callable[[int], None],
            parent: typing.Any = None,
        ) -> None:
            super().__init__(parent)
            self._entries = tuple(entries)
            self._visible_entries: tuple[ProjectPickerEntry, ...] = ()
            self._current_project_index = int(current_project_index)
            self._on_project_selected = on_project_selected

            self.setWindowFlags(_popup_window_flag())
            self.setWindowTitle("Choose D-810 configuration")
            self.setFrameShape(QtWidgets.QFrame.StyledPanel)

            self.search_edit = QtWidgets.QLineEdit()
            self.search_edit.setPlaceholderText(
                "Search configurations by filename, description, or runtime..."
            )
            self.search_edit.setClearButtonEnabled(True)

            self.results = QtWidgets.QTableWidget(0, 2)
            self.results.horizontalHeader().setVisible(False)
            self.results.verticalHeader().setVisible(False)
            self.results.setShowGrid(False)
            self.results.setColumnWidth(0, 390)
            self.results.horizontalHeader().setStretchLastSection(True)
            try:
                select_rows = QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
                single_selection = (
                    QtWidgets.QAbstractItemView.SelectionMode.SingleSelection
                )
                no_edits = QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
            except AttributeError:
                select_rows = QtWidgets.QAbstractItemView.SelectRows
                single_selection = QtWidgets.QAbstractItemView.SingleSelection
                no_edits = QtWidgets.QAbstractItemView.NoEditTriggers
            self.results.setSelectionBehavior(select_rows)
            self.results.setSelectionMode(single_selection)
            self.results.setEditTriggers(no_edits)
            self.results.setSortingEnabled(False)

            self.result_count = QtWidgets.QLabel()
            self.result_count.setStyleSheet("color: palette(mid);")

            layout = QtWidgets.QVBoxLayout(self)
            layout.setContentsMargins(8, 8, 8, 6)
            layout.setSpacing(6)
            layout.addWidget(self.search_edit)
            layout.addWidget(self.results, 1)
            layout.addWidget(self.result_count)

            self.search_edit.textChanged.connect(self._render_entries)
            self.search_edit.returnPressed.connect(self._select_current_row)
            self.results.cellClicked.connect(self._select_row)
            self.results.itemDoubleClicked.connect(self._select_current_row)

        def show_for(self, anchor: typing.Any) -> None:
            """Reset, position, and focus the popup beneath ``anchor``."""

            self.search_edit.clear()
            self._render_entries("")
            popup_width = min(max(anchor.width(), 520), 960)
            self.resize(popup_width, 360)
            self.move(anchor.mapToGlobal(QtCore.QPoint(0, anchor.height())))
            self.show()
            self.raise_()
            self.activateWindow()
            self.search_edit.setFocus()

        def _render_entries(self, query: str) -> None:
            self._visible_entries = filter_project_picker_entries(self._entries, query)
            self.results.setRowCount(len(self._visible_entries))
            current_row: int | None = None
            for row, entry in enumerate(self._visible_entries):
                filename_item = QtWidgets.QTableWidgetItem(entry.filename)
                behavior_item = QtWidgets.QTableWidgetItem(entry.behavior)
                tooltip = "\n\n".join(
                    value for value in (entry.behavior, entry.description) if value
                )
                filename_item.setToolTip(tooltip)
                behavior_item.setToolTip(tooltip)
                self.results.setItem(row, 0, filename_item)
                self.results.setItem(row, 1, behavior_item)
                if entry.project_index == self._current_project_index:
                    current_row = row
            self.result_count.setText(
                f"{len(self._visible_entries)} of {len(self._entries)} configurations"
            )
            if current_row is not None:
                self.results.setCurrentCell(current_row, 0)
            elif self._visible_entries:
                self.results.setCurrentCell(0, 0)

        def _select_row(self, row: int, _column: int = 0) -> None:
            if row < 0 or row >= len(self._visible_entries):
                return
            project_index = self._visible_entries[row].project_index
            self.close()
            self._on_project_selected(project_index)

        def _select_current_row(self, *_: typing.Any) -> None:
            self._select_row(self.results.currentRow())


else:

    class ProjectPickerPopup:
        """Import-safe stub used outside IDA."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("ProjectPickerPopup requires IDA Pro")


__all__ = ["IDA_AVAILABLE", "ProjectPickerPopup"]
