"""Acknowledgement dialog (ticket d81-zijs).

Split out of About so that box stays identity-only -- product, version, links,
authors. The credits are the longest content by far, and inlining them made
About tall and dense next to IDA's compact one.

Content comes from :data:`d810.ui.about_logic.ACKNOWLEDGEMENTS`, kept verbatim
from the README so the two cannot drift; :func:`~d810.ui.about_logic.render_html`
turns its single markdown-link source into anchors.
"""

from __future__ import annotations

from d810.qt_shim import QtCore, QtWidgets, qt_flag_or
from d810.ui.about_logic import render_html

__all__ = ["AcknowledgementsDialog", "show_acknowledgements_dialog"]


class AcknowledgementsDialog(QtWidgets.QDialog):
    """Read-only credits, one wrapped paragraph per entry."""

    def __init__(self, entries: tuple[str, ...], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Acknowledgement")
        self.setModal(True)
        # The prose word-wraps; without a floor Qt makes this narrow and tall.
        self.setMinimumWidth(560)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        for entry in entries:
            paragraph = QtWidgets.QLabel(render_html(entry))
            paragraph.setWordWrap(True)
            paragraph.setOpenExternalLinks(True)
            paragraph.setTextInteractionFlags(
                qt_flag_or(
                    QtCore.Qt.TextBrowserInteraction,
                    QtCore.Qt.TextSelectableByMouse,
                )
            )
            layout.addWidget(paragraph)

        layout.addStretch(1)

        buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)


def show_acknowledgements_dialog(entries: tuple[str, ...], parent=None) -> None:
    """Build and run the Acknowledgement dialog."""
    AcknowledgementsDialog(entries, parent).exec_()
