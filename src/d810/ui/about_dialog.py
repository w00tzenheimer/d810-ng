"""The ``[?]`` About dialog (ticket d81-zijs).

A thin renderer over :func:`d810.ui.about_logic.about_model` -- every decision
about *what* is shown lives in that pure module, which is unit-tested. This file
only turns the model into widgets.

Links are plain ``QLabel`` anchors with ``setOpenExternalLinks(True)`` so Qt
hands them to the system browser; that avoids depending on ``QDesktopServices``
being present in :mod:`d810.qt_shim` proxy mode.
"""

from __future__ import annotations

from d810.core.logging import getLogger
from d810.qt_shim import QtCore, QtWidgets, qt_flag_or
from d810.ui.about_logic import AboutModel, about_model
from d810.ui.acknowledgements_dialog import show_acknowledgements_dialog
from d810.ui.extensions_dialog import show_extensions_dialog
from d810.ui.icon_assets import bundled_logo_pixmap

logger = getLogger("d810.ui")

#: Logo edge length. Big enough to read, small enough that the dialog stays
#: dense -- IDA's own About uses a similar square beside the text.
_LOGO_PX = 96

__all__ = ["AboutDialog", "show_about_dialog"]


def _logo_label():
    """A scaled logo label, or ``None`` when the asset cannot be loaded."""
    pixmap = bundled_logo_pixmap(_LOGO_PX)
    if pixmap is None:
        return None
    label = QtWidgets.QLabel()
    label.setPixmap(pixmap)
    # Fixed to the SCALED size: the source is 3:2, so a square would squash it.
    label.setFixedSize(pixmap.width(), pixmap.height())
    return label


class AboutDialog(QtWidgets.QDialog):
    """Modal About box: product, version, and the project links."""

    def __init__(self, model: AboutModel, parent=None) -> None:
        super().__init__(parent)
        self._model = model
        self.setWindowTitle(model.title)
        self.setModal(True)
        # The acknowledgement prose word-wraps; without a floor Qt makes the
        # dialog narrow and very tall.
        self.setMinimumWidth(560)

        # Density matches the config panel: 4px margins, 6px spacing, one bold
        # heading and no group frames. A dialog that reads like the panel it
        # opens from costs the user nothing to parse.
        outer = QtWidgets.QHBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(14)

        logo = _logo_label()
        if logo is not None:
            outer.addWidget(logo, 0, qt_flag_or(QtCore.Qt.AlignLeft, QtCore.Qt.AlignTop))

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        outer.addLayout(layout, 1)

        heading = QtWidgets.QLabel(f"{model.product} {model.version}")
        font = heading.font()
        font.setBold(True)
        heading.setFont(font)
        heading.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        layout.addWidget(heading)

        grid = QtWidgets.QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(5)
        grid.setColumnStretch(1, 1)
        label_align = qt_flag_or(QtCore.Qt.AlignLeft, QtCore.Qt.AlignTop)
        for row, (label, url) in enumerate(model.links):
            name = QtWidgets.QLabel(label)
            link = QtWidgets.QLabel(f'<a href="{url}">{url}</a>')
            link.setOpenExternalLinks(True)
            # qt_flag_or, not ``|``: PySide6 enum flags need ``.value`` for
            # bitwise ops, and a bare ``|`` only works via a PyQt5 shim feature.
            link.setTextInteractionFlags(
                qt_flag_or(
                    QtCore.Qt.TextBrowserInteraction,
                    QtCore.Qt.TextSelectableByMouse,
                )
            )
            grid.addWidget(name, row, 0, label_align)
            grid.addWidget(link, row, 1)

        authors = QtWidgets.QLabel(
            ", ".join(f'<a href="{url}">{name}</a>' for name, url in model.authors)
        )
        authors.setOpenExternalLinks(True)
        grid.addWidget(QtWidgets.QLabel("Authors"), len(model.links), 0, label_align)
        grid.addWidget(authors, len(model.links), 1)
        layout.addLayout(grid)

        layout.addStretch(1)

        # Grouped right with OK last and default, the way IDA's own About row
        # reads. QDialogButtonBox would otherwise push ActionRole buttons to the
        # far left by platform convention, splitting the row across the dialog.
        button_row = QtWidgets.QHBoxLayout()
        button_row.setSpacing(6)
        button_row.addStretch(1)

        acknowledgements = QtWidgets.QPushButton("Acknowledgement...")
        acknowledgements.setToolTip("Projects and people this plugin builds on")
        acknowledgements.clicked.connect(self._show_acknowledgements)
        button_row.addWidget(acknowledgements)

        extensions = QtWidgets.QPushButton("Extensions...")
        extensions.setToolTip("Show registered backends and their status")
        extensions.clicked.connect(self._show_extensions)
        button_row.addWidget(extensions)

        ok = QtWidgets.QPushButton("OK")
        ok.setDefault(True)
        ok.clicked.connect(self.accept)
        button_row.addWidget(ok)

        layout.addLayout(button_row)

    def _show_acknowledgements(self) -> None:
        """Open the credits, never raising into the Qt slot."""
        try:
            show_acknowledgements_dialog(self._model.acknowledgements, self)
        except Exception:  # noqa: BLE001 - credits must not kill About
            logger.warning("Could not open the Acknowledgement dialog", exc_info=True)

    def _show_extensions(self) -> None:
        """Open the Extensions listing, never raising into the Qt slot."""
        try:
            show_extensions_dialog(self)
        except Exception:  # noqa: BLE001 - a listing must not kill About
            logger.warning("Could not open the Extensions dialog", exc_info=True)


def show_about_dialog(parent=None) -> None:
    """Build and run the About dialog for the running build."""
    AboutDialog(about_model(), parent).exec_()
