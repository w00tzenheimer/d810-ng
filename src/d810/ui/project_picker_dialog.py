"""Native Qt picker for a large D-810 project configuration catalog."""

from __future__ import annotations

from collections.abc import Sequence

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
    from d810.qt_shim import QtWidgets

    class ProjectPickerDialog(QtWidgets.QDialog):
        """Search the full catalog while returning a stable manager index."""

        def __init__(
            self,
            entries: Sequence[ProjectPickerEntry],
            *,
            current_project_index: int,
            parent: typing.Any = None,
        ) -> None:
            super().__init__(parent)
            self._entries = tuple(entries)
            self._visible_entries: tuple[ProjectPickerEntry, ...] = ()
            self._current_project_index = int(current_project_index)
            self._selected_project_index: int | None = None

            self.setWindowTitle("Choose D-810 configuration")
            self.resize(1080, 640)

            self.filter_edit = QtWidgets.QLineEdit()
            self.filter_edit.setPlaceholderText(
                "Filter filename, description, or runtime..."
            )
            self.filter_edit.setClearButtonEnabled(True)
            self.result_count = QtWidgets.QLabel()

            self.results = QtWidgets.QTableWidget(0, 3)
            self.results.setHorizontalHeaderLabels(
                ["Configuration", "Behavior", "Description"]
            )
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
            # The catalog contains paired source/runtime names that are
            # materially different.  Reserve enough horizontal room to make
            # those identities scannable before the description expands.
            self.results.setColumnWidth(0, 330)
            self.results.setColumnWidth(1, 270)
            self.results.horizontalHeader().setStretchLastSection(True)

            self.load_button = QtWidgets.QPushButton("Load selected")
            self.cancel_button = QtWidgets.QPushButton("Cancel")

            button_row = QtWidgets.QHBoxLayout()
            button_row.addWidget(self.result_count)
            button_row.addStretch(1)
            button_row.addWidget(self.load_button)
            button_row.addWidget(self.cancel_button)

            layout = QtWidgets.QVBoxLayout()
            layout.addWidget(self.filter_edit)
            layout.addWidget(self.results, 1)
            layout.addLayout(button_row)
            self.setLayout(layout)

            self.filter_edit.textChanged.connect(self._render_entries)
            self.results.itemDoubleClicked.connect(self._accept_selected)
            self.load_button.clicked.connect(self._accept_selected)
            self.cancel_button.clicked.connect(self.reject)

            self._render_entries("")
            self.filter_edit.setFocus()

        def selected_project_index(self) -> int | None:
            return self._selected_project_index

        def _render_entries(self, query: str) -> None:
            self._visible_entries = filter_project_picker_entries(self._entries, query)
            self.results.setRowCount(len(self._visible_entries))
            current_row: int | None = None
            for row, entry in enumerate(self._visible_entries):
                items = (
                    QtWidgets.QTableWidgetItem(entry.filename),
                    QtWidgets.QTableWidgetItem(entry.behavior),
                    QtWidgets.QTableWidgetItem(entry.description or "-"),
                )
                for column, item in enumerate(items):
                    item.setToolTip(item.text())
                    self.results.setItem(row, column, item)
                if entry.project_index == self._current_project_index:
                    current_row = row
            self.result_count.setText(
                f"{len(self._visible_entries)} of {len(self._entries)} configurations"
            )
            self.load_button.setEnabled(bool(self._visible_entries))
            if current_row is not None:
                self.results.setCurrentCell(current_row, 0)
            elif self._visible_entries:
                self.results.setCurrentCell(0, 0)

        def _accept_selected(self, *_: typing.Any) -> None:
            row = self.results.currentRow()
            if row < 0 or row >= len(self._visible_entries):
                return
            self._selected_project_index = self._visible_entries[row].project_index
            self.accept()

else:

    class ProjectPickerDialog:
        """Import-safe stub used outside IDA."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("ProjectPickerDialog requires IDA Pro")


__all__ = ["IDA_AVAILABLE", "ProjectPickerDialog"]
