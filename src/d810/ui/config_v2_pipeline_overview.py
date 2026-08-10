"""Compact Qt projection of the configured config-v2 pass pipeline."""

from __future__ import annotations

from d810.qt_shim import QHeaderView, QtCore, QtWidgets
from d810.ui.config_v2_editing_logic import ConfigV2PipelineOverview


class ConfigV2PipelineOverviewWidget(QtWidgets.QWidget):
    """Show only configured active passes, in their configured order."""

    inspect_requested = QtCore.pyqtSignal(int)
    edit_pipeline_requested = QtCore.pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._overview: ConfigV2PipelineOverview | None = None

        self._unavailable = QtWidgets.QLabel("Active pipeline unavailable.", self)
        self._unavailable.setWordWrap(True)

        self._tree = QtWidgets.QTreeWidget(self)
        self._tree.setColumnCount(2)
        self._tree.setHeaderLabels(("Order", "Active pass"))
        self._tree.setRootIsDecorated(False)
        self._tree.setUniformRowHeights(True)
        self._tree.setAlternatingRowColors(True)
        header = self._tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)

        self._edit_pipeline = QtWidgets.QPushButton("Edit pipeline...", self)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(self._unavailable)
        layout.addWidget(self._tree, 1)
        layout.addWidget(self._edit_pipeline)

        # QTreeWidget activation covers both the platform's double-click action
        # and keyboard activation via Enter/Return.
        self._tree.itemActivated.connect(self._activate_item)
        self._edit_pipeline.clicked.connect(self.edit_pipeline_requested.emit)
        self.set_overview(None)

    def set_overview(self, overview: ConfigV2PipelineOverview | None) -> None:
        """Render a manager-projected active pipeline without catalog expansion."""

        self._overview = overview
        self._tree.clear()
        if overview is None:
            self._unavailable.setText("Active pipeline unavailable.")
            self._unavailable.setVisible(True)
            self._tree.setVisible(False)
            self._edit_pipeline.setEnabled(False)
            return

        for row in overview.rows:
            selection_suffix = (
                f" - {row.selected_transform_summary}"
                if row.selected_transform_summary
                else ""
            )
            item = QtWidgets.QTreeWidgetItem(
                (
                    f"{row.index + 1}.",
                    f"{row.display_name}{selection_suffix}",
                )
            )
            item.setData(0, QtCore.Qt.UserRole, row.index)
            tooltip = f"{row.purpose}\nRuns during: {row.runs_during}"
            item.setToolTip(0, tooltip)
            item.setToolTip(1, tooltip)
            self._tree.addTopLevelItem(item)

        has_rows = bool(overview.rows)
        self._unavailable.setText("No active passes configured.")
        self._unavailable.setVisible(not has_rows)
        self._tree.setVisible(has_rows)
        self._edit_pipeline.setEnabled(True)

    def row_height(self) -> int:
        """Return one rendered row's height for the dock density planner."""

        model = self._tree.model()
        if model is None or model.rowCount() == 0:
            return 0
        return int(self._tree.rowHeight(model.index(0, 0)))

    def _activate_item(self, item, _column: int) -> None:
        if item is None or self._overview is None:
            return
        index = int(item.data(0, QtCore.Qt.UserRole))
        if not 0 <= index < len(self._overview.rows):
            return
        if self._overview.rows[index].index != index:
            return
        self.inspect_requested.emit(index)


__all__ = ["ConfigV2PipelineOverviewWidget"]
