"""Qt rendering for immutable Workbench preparation projections."""

from __future__ import annotations

from d810.core import typing

try:
    import ida_kernwin  # noqa: F401

    from d810.qt_shim import QtCore, QtWidgets

    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


if IDA_AVAILABLE:

    def _user_role() -> int:
        try:
            return int(QtCore.Qt.ItemDataRole.UserRole)
        except AttributeError:
            return int(QtCore.Qt.UserRole)

    class PreparationWorkbenchWidget(QtWidgets.QGroupBox):
        """Render scripts and durable transactions; emit no IDA writes."""

        def __init__(
            self,
            *,
            preview: typing.Callable[[], None],
            prepare_only: typing.Callable[[], None],
            prepare_and_decompile: typing.Callable[[], None],
            restore: typing.Callable[[], None],
            parent: typing.Any = None,
        ) -> None:
            super().__init__("IDB preparation", parent)
            self._summary: typing.Any = None
            self._states: dict[str, typing.Any] = {}

            self.summary_label = QtWidgets.QLabel("Preparation is unavailable")
            self.summary_label.setWordWrap(True)
            self.script_tree = QtWidgets.QTreeWidget()
            self.script_tree.setHeaderLabels(["Order", "Script", "Status", "Source"])
            self.transaction_tree = QtWidgets.QTreeWidget()
            self.transaction_tree.setHeaderLabels(
                ["State", "Script", "Changes", "Restore"]
            )

            self.buttons: dict[str, typing.Any] = {}
            actions = QtWidgets.QHBoxLayout()
            for action_id, label, callback in (
                ("preview_preparation", "Preview", preview),
                ("prepare_only", "Prepare only", prepare_only),
                (
                    "prepare_and_decompile",
                    "Prepare & Decompile",
                    prepare_and_decompile,
                ),
                ("restore_preparation", "Restore", restore),
            ):
                button = QtWidgets.QPushButton(label)
                button.clicked.connect(callback)
                self.buttons[action_id] = button
                actions.addWidget(button)
            actions.addStretch(1)

            layout = QtWidgets.QVBoxLayout(self)
            layout.setContentsMargins(4, 4, 4, 4)
            layout.addWidget(self.summary_label)
            layout.addWidget(self.script_tree)
            layout.addWidget(self.transaction_tree)
            layout.addLayout(actions)
            self.transaction_tree.itemSelectionChanged.connect(
                self._render_action_states
            )

        @property
        def selected_transaction_id(self) -> str | None:
            selected = self.transaction_tree.selectedItems()
            if not selected:
                return None
            value = selected[0].data(0, _user_role())
            return str(value) if value else None

        def set_projection(
            self,
            summary: typing.Any,
            states: tuple[typing.Any, ...],
        ) -> None:
            selected_id = self.selected_transaction_id
            self._summary = summary
            self._states = {state.action_id: state for state in states}
            self.script_tree.clear()
            self.transaction_tree.clear()
            if summary.database_identity is None:
                self.summary_label.setText("Preparation is unavailable")
            else:
                self.summary_label.setText(
                    f"{len(summary.scripts)} scripts; "
                    f"{len(summary.transactions)} durable transactions; "
                    f"database {summary.database_identity}"
                )
            for ordinal, script in enumerate(summary.scripts, start=1):
                status = (
                    "attested" if script.source_hash_matches else "changed/unavailable"
                )
                source = "portable" if script.portable else "absolute"
                item = QtWidgets.QTreeWidgetItem(
                    [str(ordinal), script.display_name, status, source]
                )
                item.setToolTip(1, script.path)
                self.script_tree.addTopLevelItem(item)
            role = _user_role()
            for transaction in summary.transactions:
                changes = (
                    f"{transaction.bytes_changed} bytes; "
                    f"{transaction.type_annotations} types"
                )
                restore = (
                    "available"
                    if transaction.restore_allowed
                    else transaction.restore_blocker
                )
                item = QtWidgets.QTreeWidgetItem(
                    [transaction.state, transaction.script_id, changes, restore]
                )
                item.setData(0, role, transaction.transaction_id)
                self.transaction_tree.addTopLevelItem(item)
                if transaction.transaction_id == selected_id:
                    item.setSelected(True)
            for tree in (self.script_tree, self.transaction_tree):
                for column in range(tree.columnCount()):
                    tree.resizeColumnToContents(column)
            self._render_action_states()

        def _render_action_states(self) -> None:
            for action_id, button in self.buttons.items():
                state = self._states.get(action_id)
                if state is None:
                    button.setEnabled(False)
                    button.setToolTip("")
                    continue
                if action_id == "restore_preparation":
                    selected = self.selected_transaction_id
                    transaction = next(
                        (
                            item
                            for item in self._summary.transactions
                            if item.transaction_id == selected
                        ),
                        None,
                    )
                    enabled = bool(
                        transaction is not None and transaction.restore_allowed
                    )
                    reason = (
                        "Select an applied preparation transaction."
                        if transaction is None
                        else transaction.restore_blocker
                    )
                else:
                    enabled = state.enabled
                    reason = state.reason
                button.setText(state.label)
                button.setEnabled(enabled)
                button.setToolTip(reason)


else:

    class PreparationWorkbenchWidget:
        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("PreparationWorkbenchWidget requires IDA Pro")


__all__ = ["IDA_AVAILABLE", "PreparationWorkbenchWidget"]
