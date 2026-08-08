"""Qt tree for stable public passes, transforms, and execution stages."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from d810.core import getLogger
from d810.qt_shim import QHeaderView, QPalette, QtCore, QtWidgets, qt_flag_or
from d810.ui.pass_tree_logic import PassTreeNodeKind, project_pass_tree

logger = getLogger("D810.ui.pass_tree")

# Plain ASCII markers rather than glyphs: the panel is hosted by IDA on
# platforms whose fonts silently substitute for box and check characters.
_ENABLED_MARKER = "[*] "
_DISABLED_MARKER = "[ ] "


class PassTreeWidget(QtWidgets.QWidget):
    """Display the public execution model without private optimizer objects."""

    pass_selected = QtCore.pyqtSignal(str)
    edit_requested = QtCore.pyqtSignal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._catalog: tuple[object, ...] = ()
        self._enabled_pass_ids: tuple[str, ...] = ()
        self._read_only = True

        self._filter = QtWidgets.QLineEdit(self)
        self._filter.setPlaceholderText("Filter passes, transforms, or stages...")
        self._tree = QtWidgets.QTreeWidget(self)
        # Kind is recoverable from indent depth and the child label prefix, so
        # the column is spent on the label instead.
        self._tree.setColumnCount(2)
        self._tree.setHeaderLabels(("Pass / child", "State"))
        self._tree.setRootIsDecorated(True)
        self._tree.setUniformRowHeights(True)
        self._tree.setAlternatingRowColors(True)
        header = self._tree.header()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._tree.headerItem().setTextAlignment(
            1, qt_flag_or(QtCore.Qt.AlignRight, QtCore.Qt.AlignVCenter)
        )
        self._disabled_brush = self.palette().brush(
            QPalette.Disabled, QPalette.WindowText
        )

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._filter)
        layout.addWidget(self._tree, 1)

        self._filter.textChanged.connect(self._rebuild)
        self._tree.currentItemChanged.connect(self._selection_changed)
        self._tree.itemDoubleClicked.connect(self._double_clicked)

    def set_passes(
        self,
        catalog: Sequence[object],
        enabled_pass_ids: Iterable[str],
    ) -> None:
        self._catalog = tuple(catalog)
        self._enabled_pass_ids = tuple(str(value) for value in enabled_pass_ids)
        self._rebuild()

    def set_read_only(self, read_only: bool) -> None:
        self._read_only = bool(read_only)

    def set_filter_visible(self, visible: bool) -> None:
        """Show or hide the filter field, preserving whatever it holds."""
        self._filter.setVisible(bool(visible))

    def filter_has_text(self) -> bool:
        return bool(self._filter.text().strip())

    def row_height(self) -> int:
        """Height of one tree row, or 0 before the view has been laid out."""
        model = self._tree.model()
        if model is None or model.rowCount() == 0:
            return 0
        return int(self._tree.rowHeight(model.index(0, 0)))

    def select_pass(self, pass_id: str) -> None:
        for index in range(self._tree.topLevelItemCount()):
            item = self._tree.topLevelItem(index)
            if item.data(0, QtCore.Qt.UserRole) == pass_id:
                self._tree.setCurrentItem(item)
                return

    def _rebuild(self, *_args) -> None:
        query = self._filter.text().strip().casefold()
        self._tree.clear()
        for row in project_pass_tree(self._catalog, self._enabled_pass_ids):
            searchable = " ".join(
                (row.parent.label, *(child.label for child in row.children))
            ).casefold()
            if query and query not in searchable:
                continue
            marker = _ENABLED_MARKER if row.parent.enabled else _DISABLED_MARKER
            parent = QtWidgets.QTreeWidgetItem(
                (
                    f"{marker}{row.parent.label}",
                    "active" if row.parent.enabled else "available",
                )
            )
            parent.setData(0, QtCore.Qt.UserRole, row.parent.pass_id)
            self._style_row(parent, enabled=row.parent.enabled)
            self._tree.addTopLevelItem(parent)
            for child in row.children:
                label = child.label
                if child.kind is PassTreeNodeKind.STAGE:
                    label = f"Stage: {label}"
                elif child.kind is PassTreeNodeKind.TRANSFORM:
                    label = f"Transform: {label}"
                item = QtWidgets.QTreeWidgetItem(
                    (label, "owned" if child.enabled else "available")
                )
                item.setData(0, QtCore.Qt.UserRole, child.pass_id)
                self._style_row(item, enabled=child.enabled)
                parent.addChild(item)
            parent.setExpanded(row.parent.enabled)

    def _style_row(self, item, *, enabled: bool) -> None:
        """Right-align the state column and dim rows that are not in effect."""
        item.setTextAlignment(
            1, qt_flag_or(QtCore.Qt.AlignRight, QtCore.Qt.AlignVCenter)
        )
        if enabled:
            return
        for column in (0, 1):
            item.setForeground(column, self._disabled_brush)

    def _selection_changed(self, current, _previous) -> None:
        if current is None:
            return
        pass_id = current.data(0, QtCore.Qt.UserRole)
        if pass_id:
            self.pass_selected.emit(str(pass_id))

    def _double_clicked(self, item, _column: int) -> None:
        if self._read_only or item is None:
            return
        pass_id = item.data(0, QtCore.Qt.UserRole)
        if pass_id:
            self.edit_requested.emit(str(pass_id))


__all__ = ["PassTreeWidget"]
