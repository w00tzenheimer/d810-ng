"""Registered Extensions dialog (ticket d81-zijs).

Shaped after IDA's own "Registered Addons" box, but the rows come from
:meth:`d810.core.plugins.BackendRegistry.report`, so it can say something IDA's
list cannot: *why* an optional extension is not doing anything, and whether
d810 is silently running on a fallback.

Every decision about what to show lives in :mod:`d810.ui.extensions_logic`,
which is unit-tested; this module only builds widgets.
"""

from __future__ import annotations

from d810.qt_shim import QtCore, QtWidgets, qt_flag_or
from d810.ui.extensions_logic import (
    EXTENSION_COLUMNS,
    ExtensionRow,
    collect_extension_rows,
    summarize,
)

__all__ = ["ExtensionsDialog", "show_extensions_dialog"]


class ExtensionsDialog(QtWidgets.QDialog):
    """Read-only table of the registered backends and their status."""

    def __init__(self, rows: tuple[ExtensionRow, ...], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Registered Extensions")
        self.setModal(True)
        self.setMinimumSize(720, 280)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        table = QtWidgets.QTableWidget(len(rows), len(EXTENSION_COLUMNS))
        table.setHorizontalHeaderLabels(list(EXTENSION_COLUMNS))
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.setAlternatingRowColors(True)

        read_only = qt_flag_or(QtCore.Qt.ItemIsSelectable, QtCore.Qt.ItemIsEnabled)
        for row_index, row in enumerate(rows):
            for column, text in enumerate(row.cells()):
                item = QtWidgets.QTableWidgetItem(text)
                item.setFlags(read_only)
                if row.is_defect:
                    # A defect is someone's bug, not a deployment fact; the
                    # registry draws that line and the table keeps it visible.
                    item.setToolTip(row.detail or row.status)
                table.setItem(row_index, column, item)

        header = table.horizontalHeader()
        header.setStretchLastSection(True)
        table.resizeColumnsToContents()
        layout.addWidget(table)

        layout.addWidget(QtWidgets.QLabel(summarize(rows)))

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


def show_extensions_dialog(parent=None) -> None:
    """Build and run the Extensions dialog for the live registry."""
    ExtensionsDialog(collect_extension_rows(), parent).exec_()
