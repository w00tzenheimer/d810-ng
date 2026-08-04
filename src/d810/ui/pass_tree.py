"""Qt tree for stable public passes, transforms, and execution stages."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from d810.core import getLogger
from d810.qt_shim import QtCore, QtWidgets
from d810.ui.pass_tree_logic import PassTreeNodeKind, project_pass_tree

logger = getLogger("D810.ui.pass_tree")


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
        self._tree.setColumnCount(3)
        self._tree.setHeaderLabels(("Pass / child", "Kind", "State"))
        self._tree.setRootIsDecorated(True)

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
            parent = QtWidgets.QTreeWidgetItem(
                (
                    row.parent.label,
                    row.parent.kind.value,
                    "active" if row.parent.enabled else "available",
                )
            )
            parent.setData(0, QtCore.Qt.UserRole, row.parent.pass_id)
            self._tree.addTopLevelItem(parent)
            for child in row.children:
                label = child.label
                if child.kind is PassTreeNodeKind.STAGE:
                    label = f"Stage: {label}"
                elif child.kind is PassTreeNodeKind.TRANSFORM:
                    label = f"Transform: {label}"
                item = QtWidgets.QTreeWidgetItem(
                    (label, child.kind.value, "owned" if child.enabled else "available")
                )
                item.setData(0, QtCore.Qt.UserRole, child.pass_id)
                parent.addChild(item)
            parent.setExpanded(row.parent.enabled)
        self._tree.resizeColumnToContents(0)

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
