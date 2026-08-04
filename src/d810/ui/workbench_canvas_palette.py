"""Anchored searchable picker for legal maturity-canvas additions."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from d810.core import typing
from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtCore, QtWidgets
from d810.ui.workbench_canvas_palette_logic import (
    CanvasPaletteRow,
    project_canvas_add_palette,
)

try:
    import ida_kernwin  # noqa: F401

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


if IDA_AVAILABLE and QT_GRAPHICS_AVAILABLE:

    def _popup_window_flag() -> typing.Any:
        try:
            return QtCore.Qt.WindowType.Popup
        except AttributeError:
            return QtCore.Qt.Popup


    class CanvasPassPickerPopup(QtWidgets.QFrame):
        """A compact picker that binds selection to the currently visible rows."""

        def __init__(
            self,
            *,
            on_pass_selected: Callable[[str, str], None],
            parent: typing.Any = None,
        ) -> None:
            super().__init__(parent)
            self._catalog: tuple[typing.Any, ...] = ()
            self._stage_id = ""
            self._draft: typing.Any = None
            self._visible_rows: tuple[CanvasPaletteRow, ...] = ()
            self._on_pass_selected = on_pass_selected

            self.setWindowFlags(_popup_window_flag())
            self.setWindowTitle("Add registered canvas node")
            self.setFrameShape(QtWidgets.QFrame.StyledPanel)

            self.search_edit = QtWidgets.QLineEdit()
            self.search_edit.setPlaceholderText(
                "Search legal passes by name, identifier, or contract..."
            )
            self.search_edit.setClearButtonEnabled(True)

            self.results = QtWidgets.QTableWidget(0, 2)
            self.results.horizontalHeader().setVisible(False)
            self.results.verticalHeader().setVisible(False)
            self.results.setShowGrid(False)
            self.results.setColumnWidth(0, 310)
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

            self.search_edit.textChanged.connect(self._render_rows)
            self.search_edit.returnPressed.connect(self._select_current_row)
            self.results.cellClicked.connect(self._select_row)
            self.results.itemDoubleClicked.connect(self._select_current_row)

        def show_for(
            self,
            anchor: typing.Any,
            catalog: Sequence[typing.Any],
            stage_id: str,
            draft: typing.Any,
        ) -> None:
            """Reset, position, and focus the popup beneath ``anchor``."""
            self._catalog = tuple(catalog)
            self._stage_id = str(stage_id)
            self._draft = draft
            self.search_edit.clear()
            self._render_rows("")
            popup_width = min(max(anchor.width(), 520), 960)
            self.resize(popup_width, 360)
            self.move(anchor.mapToGlobal(QtCore.QPoint(0, anchor.height())))
            self.show()
            self.raise_()
            self.activateWindow()
            self.search_edit.setFocus()

        def _render_rows(self, query: str) -> None:
            self._visible_rows = project_canvas_add_palette(
                self._catalog,
                self._stage_id,
                self._draft,
                query,
            )
            self.results.setRowCount(len(self._visible_rows))
            for row, entry in enumerate(self._visible_rows):
                title_item = QtWidgets.QTableWidgetItem(
                    f"{entry.title} ({entry.pass_id})"
                )
                subtitle_item = QtWidgets.QTableWidgetItem(entry.subtitle)
                title_item.setToolTip(entry.detail)
                subtitle_item.setToolTip(entry.detail)
                self.results.setItem(row, 0, title_item)
                self.results.setItem(row, 1, subtitle_item)
            self.result_count.setText(
                f"{len(self._visible_rows)} legal registered nodes"
            )
            if self._visible_rows:
                self.results.setCurrentCell(0, 0)

        def _select_row(self, row: int, _column: int = 0) -> None:
            if 0 <= row < len(self._visible_rows):
                pass_id = self._visible_rows[row].pass_id
                self.close()
                self._on_pass_selected(self._stage_id, pass_id)

        def _select_current_row(self, *_: typing.Any) -> None:
            self._select_row(self.results.currentRow())


else:

    class CanvasPassPickerPopup:
        """Import-safe stub used outside the IDA GUI graphics environment."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("CanvasPassPickerPopup requires IDA GUI graphics support")


__all__ = ["CanvasPassPickerPopup", "IDA_AVAILABLE"]
