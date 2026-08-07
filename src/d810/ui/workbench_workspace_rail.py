"""Compact collapsible rails for the native Build workspace."""

from __future__ import annotations

from d810.core import typing
from d810.qt_shim import QT_GRAPHICS_AVAILABLE, QtGui, QtWidgets
from d810.ui.workbench_workspace_layout_logic import COLLAPSED_RAIL_WIDTH


if QT_GRAPHICS_AVAILABLE:

    def _hamburger_icon(button: typing.Any) -> typing.Any:
        """Return a palette-aware icon without relying on a Unicode glyph."""

        pixmap = QtGui.QPixmap(14, 14)
        pixmap.fill(QtGui.QColor(0, 0, 0, 0))
        painter = QtGui.QPainter(pixmap)
        try:
            button_text_role = QtGui.QPalette.ColorRole.ButtonText
        except AttributeError:
            button_text_role = QtGui.QPalette.ButtonText
        pen = QtGui.QPen(button.palette().color(button_text_role))
        pen.setWidth(2)
        painter.setPen(pen)
        for y_position in (3, 7, 11):
            painter.drawLine(2, y_position, 12, y_position)
        painter.end()
        return QtGui.QIcon(pixmap)

    class CollapsibleWorkspaceRail(QtWidgets.QWidget):
        """Keep a named rail available as a small tab when it is collapsed."""

        def __init__(
            self,
            title: str,
            content: typing.Any,
            *,
            minimum_width: int,
            preferred_width: int,
            on_expanded_changed: typing.Callable[[bool, int], None] | None = None,
            parent: typing.Any = None,
        ) -> None:
            super().__init__(parent)
            self._title = title
            self._content = content
            self._minimum_width = minimum_width
            self._expanded_width = preferred_width
            self._expanded = True
            self._on_expanded_changed = on_expanded_changed

            layout = QtWidgets.QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(2)
            header = QtWidgets.QHBoxLayout()
            header.setContentsMargins(2, 0, 2, 0)
            self._title_label = QtWidgets.QLabel(title)
            header.addWidget(self._title_label)
            header.addStretch(1)
            self._toggle_button = QtWidgets.QToolButton()
            self._toggle_button.setAutoRaise(True)
            self._toggle_button.setFixedSize(22, 22)
            self._toggle_button.clicked.connect(self.toggle)
            header.addWidget(self._toggle_button)
            layout.addLayout(header)
            layout.addWidget(content, stretch=1)
            self.setMinimumWidth(minimum_width)
            self._sync_presentation()

        @property
        def expanded(self) -> bool:
            return self._expanded

        @property
        def expanded_width(self) -> int:
            return self._expanded_width

        def remember_width(self, width: int) -> None:
            if self._expanded and width > COLLAPSED_RAIL_WIDTH:
                self._expanded_width = max(self._minimum_width, width)

        def set_preferred_width(self, width: int) -> None:
            self._expanded_width = max(self._minimum_width, width)

        def toggle(self, checked: bool = False) -> None:
            del checked
            self.set_expanded(not self._expanded)

        def set_expanded(self, expanded: bool) -> None:
            if self._expanded == expanded:
                return
            if not expanded:
                self.remember_width(self.width())
            self._expanded = expanded
            self._sync_presentation()
            if self._on_expanded_changed is not None:
                self._on_expanded_changed(self._expanded, self._expanded_width)

        def _sync_presentation(self) -> None:
            self._toggle_button.setText("")
            self._toggle_button.setIcon(_hamburger_icon(self._toggle_button))
            if self._expanded:
                self._title_label.show()
                self._content.show()
                self.setMinimumWidth(self._minimum_width)
                self.setMaximumWidth(16_777_215)
                self._toggle_button.setToolTip(f"Collapse {self._title} rail")
            else:
                self._title_label.hide()
                self._content.hide()
                self.setFixedWidth(COLLAPSED_RAIL_WIDTH)
                self._toggle_button.setToolTip(f"Expand {self._title} rail")


else:

    class CollapsibleWorkspaceRail:
        """Unavailable native rail placeholder for headless imports."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise RuntimeError("Workspace rails require IDA GUI graphics support")


__all__ = ["CollapsibleWorkspaceRail"]
