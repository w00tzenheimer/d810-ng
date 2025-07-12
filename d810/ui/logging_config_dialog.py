from __future__ import annotations

"""Logging configuration dialog for D-810.

This small utility window allows the user to inspect all registered
`logging.Logger` instances whose name starts with a given *module prefix*
(e.g. ``D810``) and interactively change their log-level via a drop-down
list.  The changes take effect immediately and persist for the lifetime of
this IDA session (the regular persistence mechanism already serialises the
chosen level on reload).

The dialog relies on :pymod:`PyQt5` for the UI layer and the existing
:class:`~d810.conf.loggers.LoggerConfigurator` helper for the heavy
lifting.
"""

import logging
from typing import Final

from d810.conf.loggers import LoggerConfigurator
from PyQt5 import QtCore, QtWidgets

LOG_LEVELS: Final[list[str]] = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class LoggingConfigDialog(QtWidgets.QDialog):
    """Modal window that lets the user tweak logger levels on the fly."""

    def __init__(self, module_prefix: str, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(f"Logging for {module_prefix}…")
        self.resize(500, 400)

        self.module_prefix = module_prefix
        self._logger_mgr = LoggerConfigurator

        # UI setup ---------------------------------------------------------
        vbox = QtWidgets.QVBoxLayout(self)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(2)
        self.tree.setHeaderLabels(["Logger", "Level"])
        self.tree.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        self.tree.header().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeToContents
        )
        vbox.addWidget(self.tree)

        btn_box = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        btn_box.rejected.connect(self.reject)
        vbox.addWidget(btn_box, alignment=QtCore.Qt.AlignRight)

        self._populate()

    # ---------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------
    def _populate(self) -> None:
        """Fill the tree with one row per logger under *module_prefix*."""
        self.tree.clear()
        for name in self._logger_mgr.available_loggers(self.module_prefix):
            lvl_num = logging.getLogger(name).getEffectiveLevel()
            lvl_name = logging.getLevelName(lvl_num)

            item = QtWidgets.QTreeWidgetItem([name, ""])
            self.tree.addTopLevelItem(item)

            combo = QtWidgets.QComboBox(self.tree)
            combo.addItems(LOG_LEVELS)
            combo.setCurrentText(lvl_name)
            combo.currentTextChanged.connect(
                lambda new_level, n=name: self._on_level_changed(n, new_level)
            )
            self.tree.setItemWidget(item, 1, combo)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------
    def _on_level_changed(self, logger_name: str, new_level: str) -> None:
        """Slot triggered when the user selects a new level from the drop-down."""
        try:
            self._logger_mgr.set_level(logger_name, new_level)
        except ValueError as exc:
            QtWidgets.QMessageBox.critical(self, "Error", str(exc))
            return

        QtWidgets.QMessageBox.information(
            self,
            "Logging Level Updated",
            f"{logger_name} → {new_level}",
        )
