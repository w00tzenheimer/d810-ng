"""Thin dockable Qt adapter for the diagnostics explorer and cleaner."""

from __future__ import annotations

import datetime

from d810.core import typing
from d810.core.logging import getLogger
from d810.ui.workbench_diagnostics_logic import (
    DatabaseSort,
    SnapshotSort,
    cleanup_confirmation_matches,
    diagnostic_action_states,
    filter_databases,
    filter_records,
    filter_snapshots,
    latest_database_for_function,
    latest_snapshot_for_function,
    project_cleanup_plan,
    project_cleanup_result,
    project_record_rows,
    record_jump_ea,
    sort_databases,
    sort_snapshots,
)

logger = getLogger("D810.ui")

try:
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
    ida_kernwin = None  # type: ignore[assignment]
    IDA_AVAILABLE = False


if IDA_AVAILABLE:
    from d810.qt_shim import QtCore, QtGui, QtWidgets

    WOPN_NOT_CLOSED_BY_ESC = getattr(ida_kernwin, "WOPN_NOT_CLOSED_BY_ESC", 0x100)

    def _user_role() -> int:
        try:
            return int(QtCore.Qt.ItemDataRole.UserRole)
        except AttributeError:
            return int(QtCore.Qt.UserRole)

    def _extended_selection() -> typing.Any:
        try:
            return QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection
        except AttributeError:
            return QtWidgets.QAbstractItemView.ExtendedSelection

    def _select_rows() -> typing.Any:
        try:
            return QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows
        except AttributeError:
            return QtWidgets.QAbstractItemView.SelectRows

    def _no_edits() -> typing.Any:
        try:
            return QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers
        except AttributeError:
            return QtWidgets.QAbstractItemView.NoEditTriggers

    def _ignore_size_hint(
        widget: typing.Any,
        *,
        horizontal: bool = False,
        vertical: bool = False,
    ) -> None:
        policy = widget.sizePolicy()
        try:
            ignored = QtWidgets.QSizePolicy.Policy.Ignored
        except AttributeError:
            ignored = QtWidgets.QSizePolicy.Ignored
        if horizontal:
            policy.setHorizontalPolicy(ignored)
        if vertical:
            policy.setVerticalPolicy(ignored)
        widget.setSizePolicy(policy)

    def _timestamp(value: float | None) -> str:
        if value is None:
            return "unavailable"
        return datetime.datetime.fromtimestamp(float(value)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    def _size(value: int) -> str:
        size = float(value)
        for suffix in ("B", "KiB", "MiB", "GiB"):
            if size < 1024.0 or suffix == "GiB":
                return (
                    f"{size:.0f} {suffix}" if suffix == "B" else f"{size:.1f} {suffix}"
                )
            size /= 1024.0
        return f"{value} B"

    _Signal = getattr(QtCore, "Signal", getattr(QtCore, "pyqtSignal", None))

    class _InventorySignals(QtCore.QObject):
        completed = _Signal(int, object, object)

    class _InventoryWorker(QtCore.QRunnable):
        def __init__(self, adapter: typing.Any, generation: int) -> None:
            super().__init__()
            self._adapter = adapter
            self._generation = generation
            self.signals = _InventorySignals()

        def run(self) -> None:
            try:
                values = tuple(self._adapter.databases())
                error = None
            except Exception as exc:
                values = ()
                error = str(exc)
            self.signals.completed.emit(self._generation, values, error)

    class WorkbenchDiagnosticsPanel(ida_kernwin.PluginForm):
        """Read-only explorer with separately planned destructive actions."""

        TITLE = "d810-ng Diagnostics Explorer"
        _VIEW_LABELS = (
            ("Blocks", "blocks"),
            ("Instructions", "instructions"),
            ("State machine", "state_machine"),
            ("Modifications", "modifications"),
            ("Facts", "facts"),
            ("Conflicts", "conflicts"),
            ("Provenance", "provenance"),
            ("Rendered programs", "rendered_programs"),
        )

        def __init__(
            self,
            adapter: typing.Any,
            *,
            function_ea: int | None = None,
            function_name: str | None = None,
            graph_controller: typing.Any = None,
        ) -> None:
            ida_kernwin.PluginForm.__init__(self)
            self._adapter = adapter
            self._function_ea = None if function_ea is None else int(function_ea)
            self._function_name = function_name
            self._graph_controller = graph_controller
            self._databases: tuple[typing.Any, ...] = ()
            self._database_rows: tuple[typing.Any, ...] = ()
            self._snapshots: tuple[typing.Any, ...] = ()
            self._snapshot_rows: tuple[typing.Any, ...] = ()
            self._snapshot_database_path: str | None = None
            self._records: tuple[typing.Any, ...] = ()
            self._record_rows: tuple[typing.Any, ...] = ()
            self._record_identity: tuple[str, int, str] | None = None
            self._cleanup_plan: typing.Any = None
            self._closed = False
            self._rendering = False
            self._inventory_generation = 0
            self._inventory_workers: dict[int, typing.Any] = {}
            self._pending_inventory_path: dict[int, str | None] = {}
            self.parent: typing.Any = None

            self.context_label = QtWidgets.QLabel()
            self.inventory_label = QtWidgets.QLabel("No inventory loaded")
            self.mode_label = QtWidgets.QLabel(
                "Read-only browsing; cleanup requires a separate exact plan"
            )

            self.database_filter = QtWidgets.QLineEdit()
            self.database_filter.setPlaceholderText("Filter database or function EA")
            self.database_sort = QtWidgets.QComboBox()
            for label, value in (
                ("Newest first", "newest"),
                ("Oldest first", "oldest"),
                ("File size (largest)", "file_size"),
                ("Snapshot count (largest)", "snapshot_count"),
                ("Function EA", "function"),
                ("Path", "path"),
            ):
                self.database_sort.addItem(label, value)
            self.database_model = QtGui.QStandardItemModel()
            self.database_model.setHorizontalHeaderLabels(
                ["Last run", "State", "Snapshots", "Rows", "Size", "Functions", "Path"]
            )
            self.database_tree = self._tree(self.database_model, multi=True)

            self.snapshot_filter = QtWidgets.QLineEdit()
            self.snapshot_filter.setPlaceholderText(
                "Filter snapshot, function, maturity, stage, or outcome"
            )
            self.snapshot_sort = QtWidgets.QComboBox()
            for label, value in (
                ("Newest first", "newest"),
                ("Oldest first", "oldest"),
                ("Maturity", "maturity"),
                ("Stage", "phase"),
                ("Block count", "block_count"),
                ("Row count", "row_count"),
            ):
                self.snapshot_sort.addItem(label, value)
            self.snapshot_model = QtGui.QStandardItemModel()
            self.snapshot_model.setHorizontalHeaderLabels(
                [
                    "ID",
                    "Recorded",
                    "Function",
                    "Maturity",
                    "Stage",
                    "Outcome",
                    "Blocks",
                    "Rows",
                ]
            )
            self.snapshot_tree = self._tree(self.snapshot_model, multi=True)

            self.view_combo = QtWidgets.QComboBox()
            for label, value in self._VIEW_LABELS:
                self.view_combo.addItem(label, value)
            self.record_filter = QtWidgets.QLineEdit()
            self.record_filter.setPlaceholderText("Filter structured fields or outcome")
            self.record_model = QtGui.QStandardItemModel()
            self.record_model.setHorizontalHeaderLabels(
                ["Table", "Record", "Anchor", "Structured summary"]
            )
            self.record_tree = self._tree(self.record_model, multi=False)
            self.record_detail = QtWidgets.QPlainTextEdit()
            self.record_detail.setReadOnly(True)
            self.record_detail.setPlaceholderText(
                "Select a structured diagnostic record"
            )
            self.jump_function_button = QtWidgets.QPushButton("Jump to function")
            self.jump_record_button = QtWidgets.QPushButton("Jump to record anchor")
            self.open_graph_button = QtWidgets.QPushButton("Open graph")
            self.open_graph_button.setEnabled(False)

            self.cleanup_buttons: dict[str, typing.Any] = {}
            for action_id, label in (
                ("delete_selected_snapshots", "Delete selected snapshots"),
                ("delete_all_snapshots", "Delete all snapshots in DB"),
                ("keep_latest", "Keep latest N"),
                ("older_than", "Delete older than Unix time"),
                ("delete_selected_databases", "Quarantine selected DBs"),
                ("delete_all_closed_databases", "Delete all closed DBs"),
                ("vacuum_selected_databases", "Vacuum selected DBs"),
            ):
                self.cleanup_buttons[action_id] = QtWidgets.QPushButton(label)
            self.keep_latest_spin = QtWidgets.QSpinBox()
            self.keep_latest_spin.setRange(0, 1_000_000)
            self.keep_latest_spin.setValue(10)
            self.keep_latest_spin.setPrefix("N = ")
            self.older_than_edit = QtWidgets.QLineEdit()
            self.older_than_edit.setPlaceholderText("Unix timestamp")
            self.cleanup_plan_view = QtWidgets.QPlainTextEdit()
            self.cleanup_plan_view.setReadOnly(True)
            self.cleanup_plan_view.setMaximumHeight(150)
            self.cleanup_plan_view.setPlaceholderText(
                "Choose a cleaner action to inspect its exact plan"
            )
            self.cleanup_result_view = QtWidgets.QPlainTextEdit()
            self.cleanup_result_view.setReadOnly(True)
            self.cleanup_result_view.setMaximumHeight(150)
            self.cleanup_result_view.setVisible(False)
            self.reviewed_checkbox = QtWidgets.QCheckBox("I reviewed the exact plan")
            self.confirmation_edit = QtWidgets.QLineEdit()
            self.confirmation_edit.setPlaceholderText(
                "Typed confirmation appears here when required"
            )
            self.checkpoint_checkbox = QtWidgets.QCheckBox("Checkpoint WAL")
            self.checkpoint_checkbox.setChecked(True)
            self.vacuum_after_checkbox = QtWidgets.QCheckBox(
                "Vacuum after snapshot cleanup"
            )
            self.execute_button = QtWidgets.QPushButton("Execute confirmed plan")
            self.execute_button.setEnabled(False)
            self.refresh_button = QtWidgets.QPushButton("Refresh read-only inventory")

            self.database_filter.textChanged.connect(self._refilter_databases)
            self.database_sort.currentIndexChanged.connect(self._refilter_databases)
            self.snapshot_filter.textChanged.connect(self._refilter_snapshots)
            self.snapshot_sort.currentIndexChanged.connect(self._refilter_snapshots)
            self.view_combo.currentIndexChanged.connect(self._load_records)
            self.record_filter.textChanged.connect(self._refilter_records)
            self.database_tree.selectionModel().currentChanged.connect(
                self._database_changed
            )
            self.database_tree.selectionModel().selectionChanged.connect(
                self._selection_changed
            )
            self.snapshot_tree.selectionModel().currentChanged.connect(
                self._snapshot_changed
            )
            self.snapshot_tree.selectionModel().selectionChanged.connect(
                self._selection_changed
            )
            self.record_tree.selectionModel().currentChanged.connect(
                self._record_changed
            )
            self.jump_function_button.clicked.connect(self._jump_to_function)
            self.jump_record_button.clicked.connect(self._jump_to_record)
            self.open_graph_button.clicked.connect(self._open_graph)
            self.refresh_button.clicked.connect(self.refresh)
            for action_id, button in self.cleanup_buttons.items():

                def _plan(checked: bool = False, *, action_id: str = action_id) -> None:
                    del checked
                    self._plan_cleanup(action_id)

                button.clicked.connect(_plan)
            self.reviewed_checkbox.stateChanged.connect(self._update_execute_enabled)
            self.confirmation_edit.textChanged.connect(self._update_execute_enabled)
            self.execute_button.clicked.connect(self._execute_cleanup)

        @staticmethod
        def _tree(model: typing.Any, *, multi: bool) -> typing.Any:
            tree = QtWidgets.QTreeView()
            tree.setModel(model)
            tree.setRootIsDecorated(False)
            tree.setUniformRowHeights(True)
            tree.setSortingEnabled(False)
            tree.setSelectionBehavior(_select_rows())
            tree.setSelectionMode(
                _extended_selection()
                if multi
                else QtWidgets.QAbstractItemView.SelectionMode.SingleSelection
            )
            tree.setEditTriggers(_no_edits())
            return tree

        def OnCreate(self, form: typing.Any) -> None:
            self.parent = self.FormToPyQtWidget(form)

            context_group = QtWidgets.QGroupBox("Diagnostics", self.parent)
            context_layout = QtWidgets.QFormLayout(context_group)
            context_layout.setContentsMargins(4, 4, 4, 4)
            context_layout.setSpacing(4)
            context_layout.addRow("Function:", self.context_label)
            context_layout.addRow("Inventory:", self.inventory_label)
            context_layout.addRow("Safety:", self.mode_label)

            database_group = QtWidgets.QGroupBox("Databases")
            database_layout = QtWidgets.QVBoxLayout(database_group)
            database_layout.setContentsMargins(4, 4, 4, 4)
            database_layout.setSpacing(4)
            database_controls = QtWidgets.QHBoxLayout()
            database_controls.addWidget(self.database_filter)
            database_controls.addWidget(self.database_sort)
            database_layout.addLayout(database_controls)
            database_layout.addWidget(self.database_tree)

            snapshot_group = QtWidgets.QGroupBox("Snapshots")
            snapshot_layout = QtWidgets.QVBoxLayout(snapshot_group)
            snapshot_layout.setContentsMargins(4, 4, 4, 4)
            snapshot_layout.setSpacing(4)
            snapshot_controls = QtWidgets.QHBoxLayout()
            snapshot_controls.addWidget(self.snapshot_filter)
            snapshot_controls.addWidget(self.snapshot_sort)
            snapshot_layout.addLayout(snapshot_controls)
            snapshot_layout.addWidget(self.snapshot_tree)

            record_group = QtWidgets.QGroupBox("Structured records (no SQL console)")
            record_layout = QtWidgets.QVBoxLayout(record_group)
            record_layout.setContentsMargins(4, 4, 4, 4)
            record_layout.setSpacing(4)
            record_controls = QtWidgets.QHBoxLayout()
            record_controls.addWidget(self.record_filter)
            record_controls.addWidget(self.view_combo)
            record_layout.addLayout(record_controls)
            record_layout.addWidget(self.record_tree, stretch=3)
            record_layout.addWidget(self.record_detail, stretch=2)
            jump_row = QtWidgets.QHBoxLayout()
            jump_row.addWidget(self.jump_function_button)
            jump_row.addWidget(self.jump_record_button)
            jump_row.addWidget(self.open_graph_button)
            jump_row.addStretch(1)
            record_layout.addLayout(jump_row)

            cleaner_group = QtWidgets.QGroupBox("Cleaner - plan first, execute second")
            cleaner_layout = QtWidgets.QVBoxLayout(cleaner_group)
            cleaner_layout.setContentsMargins(4, 4, 4, 4)
            cleaner_layout.setSpacing(4)
            cleanup_actions = QtWidgets.QGridLayout()
            cleanup_actions.addWidget(
                self.cleanup_buttons["delete_selected_snapshots"], 0, 0
            )
            cleanup_actions.addWidget(
                self.cleanup_buttons["delete_all_snapshots"], 0, 1
            )
            cleanup_actions.addWidget(
                self.cleanup_buttons["delete_selected_databases"], 0, 2
            )
            cleanup_actions.addWidget(
                self.cleanup_buttons["delete_all_closed_databases"], 0, 3
            )
            cleanup_actions.addWidget(self.cleanup_buttons["keep_latest"], 1, 0)
            cleanup_actions.addWidget(self.keep_latest_spin, 1, 1)
            cleanup_actions.addWidget(self.cleanup_buttons["older_than"], 1, 2)
            cleanup_actions.addWidget(self.older_than_edit, 1, 3)
            cleanup_actions.addWidget(
                self.cleanup_buttons["vacuum_selected_databases"], 2, 0, 1, 2
            )
            cleanup_actions.addWidget(self.refresh_button, 2, 2, 1, 2)
            cleanup_actions.setHorizontalSpacing(4)
            cleanup_actions.setVerticalSpacing(4)
            cleaner_layout.addLayout(cleanup_actions)

            self._plan_splitter = QtWidgets.QSplitter()
            try:
                self._plan_splitter.setOrientation(QtCore.Qt.Orientation.Vertical)
            except AttributeError:
                self._plan_splitter.setOrientation(QtCore.Qt.Vertical)
            self._plan_splitter.addWidget(self.cleanup_plan_view)
            self._plan_splitter.addWidget(self.cleanup_result_view)
            self._plan_splitter.setStretchFactor(0, 1)
            self._plan_splitter.setStretchFactor(1, 1)
            cleaner_layout.addWidget(self._plan_splitter, stretch=1)

            confirmation_controls = QtWidgets.QGridLayout()
            confirmation_controls.addWidget(self.reviewed_checkbox, 0, 0)
            confirmation_controls.addWidget(self.confirmation_edit, 0, 1, 1, 3)
            confirmation_controls.addWidget(self.checkpoint_checkbox, 1, 0)
            confirmation_controls.addWidget(self.vacuum_after_checkbox, 1, 1)
            confirmation_controls.addWidget(self.execute_button, 1, 2, 1, 2)
            confirmation_controls.setHorizontalSpacing(4)
            confirmation_controls.setVerticalSpacing(4)
            cleaner_layout.addLayout(confirmation_controls)

            self._browser_splitter = QtWidgets.QSplitter()
            try:
                self._browser_splitter.setOrientation(QtCore.Qt.Orientation.Horizontal)
            except AttributeError:
                self._browser_splitter.setOrientation(QtCore.Qt.Horizontal)
            self._browser_splitter.addWidget(database_group)
            self._browser_splitter.addWidget(snapshot_group)
            _ignore_size_hint(database_group, horizontal=True)
            _ignore_size_hint(snapshot_group, horizontal=True)
            self._browser_splitter.setStretchFactor(0, 1)
            self._browser_splitter.setStretchFactor(1, 1)
            self._browser_splitter.setSizes([1_000, 1_000])

            self._left_splitter = QtWidgets.QSplitter()
            try:
                self._left_splitter.setOrientation(QtCore.Qt.Orientation.Vertical)
            except AttributeError:
                self._left_splitter.setOrientation(QtCore.Qt.Vertical)
            self._left_splitter.addWidget(self._browser_splitter)
            self._left_splitter.addWidget(cleaner_group)
            _ignore_size_hint(self._left_splitter, horizontal=True)
            _ignore_size_hint(cleaner_group, vertical=True)
            self._left_splitter.setStretchFactor(0, 3)
            self._left_splitter.setStretchFactor(1, 2)
            self._left_splitter.setSizes([3_000, 2_000])

            self._outer_splitter = QtWidgets.QSplitter()
            try:
                self._outer_splitter.setOrientation(QtCore.Qt.Orientation.Horizontal)
            except AttributeError:
                self._outer_splitter.setOrientation(QtCore.Qt.Horizontal)
            self._outer_splitter.addWidget(self._left_splitter)
            self._outer_splitter.addWidget(record_group)
            self._outer_splitter.setStretchFactor(0, 1)
            self._outer_splitter.setStretchFactor(1, 1)
            self._outer_splitter.setSizes([1_000, 1_000])

            layout = QtWidgets.QVBoxLayout(self.parent)
            layout.setContentsMargins(4, 4, 4, 4)
            layout.setSpacing(6)
            layout.addWidget(context_group)
            layout.addWidget(self._outer_splitter, stretch=1)

        def OnClose(self, form: typing.Any) -> None:
            del form
            self._closed = True
            if self._graph_controller is not None:
                self._graph_controller.close()
            self._inventory_generation += 1
            self._inventory_workers.clear()
            self._pending_inventory_path.clear()
            self.parent = None

        def close(self) -> None:
            if self._closed:
                return
            self._closed = True
            if self.GetWidget() is not None:
                self.Close(ida_kernwin.PluginForm.WCLS_SAVE)

        def show(self) -> bool:
            shown = ida_kernwin.PluginForm.Show(
                self,
                self.TITLE,
                options=ida_kernwin.PluginForm.WOPN_PERSIST,
            )
            if shown:
                ida_kernwin.display_widget(
                    self.GetWidget(), WOPN_NOT_CLOSED_BY_ESC, None
                )
                ida_kernwin.set_dock_pos(
                    self.TITLE,
                    "d810-ng Deobfuscation Workbench",
                    ida_kernwin.DP_TAB,
                )
                self.refresh()
            return shown

        @staticmethod
        def _sort_database_rows(
            values: tuple[typing.Any, ...], value: str
        ) -> tuple[typing.Any, ...]:
            if value == "newest":
                return sort_databases(values)
            if value == "oldest":
                return sort_databases(values, descending=False)
            if value == "file_size":
                return sort_databases(values, DatabaseSort.FILE_SIZE, descending=True)
            if value == "snapshot_count":
                return sort_databases(
                    values, DatabaseSort.SNAPSHOT_COUNT, descending=True
                )
            if value == "function":
                return sort_databases(values, DatabaseSort.FUNCTION)
            return sort_databases(values, DatabaseSort.PATH)

        @staticmethod
        def _sort_snapshot_rows(
            values: tuple[typing.Any, ...], value: str
        ) -> tuple[typing.Any, ...]:
            if value == "newest":
                return sort_snapshots(values)
            if value == "oldest":
                return sort_snapshots(values, descending=False)
            mapping = {
                "maturity": SnapshotSort.MATURITY,
                "phase": SnapshotSort.PHASE,
                "block_count": SnapshotSort.BLOCK_COUNT,
                "row_count": SnapshotSort.ROW_COUNT,
            }
            return sort_snapshots(values, mapping[value])

        def refresh(self, *args: typing.Any) -> None:
            del args
            if self._rendering or self._closed:
                return
            current_path = self._current_database_path()
            self._snapshot_database_path = None
            self._record_identity = None
            self._inventory_generation += 1
            generation = self._inventory_generation
            worker = _InventoryWorker(self._adapter, generation)
            worker.signals.completed.connect(self._inventory_ready)
            self._inventory_workers[generation] = worker
            self._pending_inventory_path[generation] = current_path
            self.inventory_label.setText("Loading exact read-only inventory...")
            self.refresh_button.setEnabled(False)
            QtCore.QThreadPool.globalInstance().start(worker)

        def _inventory_ready(
            self,
            generation: int,
            values: object,
            error: object,
        ) -> None:
            current_path = self._pending_inventory_path.pop(generation, None)
            self._inventory_workers.pop(generation, None)
            if self._closed or generation != self._inventory_generation:
                return
            self.refresh_button.setEnabled(True)
            if error is not None:
                logger.warning("Diagnostic inventory failed: %s", error)
                self.cleanup_result_view.setPlainText(f"Inventory failed: {error}")
                self.cleanup_result_view.setVisible(True)
                self.inventory_label.setText("Inventory failed")
                return
            try:
                self._databases = tuple(values)  # type: ignore[arg-type]
            except TypeError:
                self._databases = ()
            self._apply_database_projection(current_path)

        def _refilter_databases(self, *args: typing.Any) -> None:
            del args
            if self._rendering:
                return
            self._apply_database_projection(self._current_database_path())

        def _apply_database_projection(self, current_path: str | None) -> None:
            sort_value = str(self.database_sort.currentData() or "newest")
            filtered = filter_databases(self._databases, self.database_filter.text())
            self._database_rows = self._sort_database_rows(filtered, sort_value)
            if current_path is None and self._function_ea is not None:
                current = latest_database_for_function(
                    self._database_rows, self._function_ea
                )
                current_path = None if current is None else current.path
            self._render_databases(current_path)
            self.inventory_label.setText(
                f"{len(self._database_rows)} shown / {len(self._databases)} discovered"
            )
            if self._function_ea is None:
                self.context_label.setText(
                    "No current function; showing all diagnostics"
                )
            else:
                self.context_label.setText(f"0x{self._function_ea:X}")
            self._load_snapshots()
            self._render_action_states()

        def _render_databases(self, current_path: str | None) -> None:
            self._rendering = True
            try:
                self.database_model.removeRows(0, self.database_model.rowCount())
                selected_row = 0 if self._database_rows else -1
                for row_number, item in enumerate(self._database_rows):
                    state = (
                        "active"
                        if item.active
                        else ("closed" if item.readable else "unreadable")
                    )
                    functions = ", ".join(f"0x{ea:X}" for ea in item.function_eas)
                    values = (
                        _timestamp(item.recorded_at),
                        state,
                        str(item.snapshot_count),
                        str(item.row_count),
                        _size(item.size_bytes),
                        functions,
                        item.path,
                    )
                    model_items = [QtGui.QStandardItem(value) for value in values]
                    for model_item in model_items:
                        model_item.setEditable(False)
                        model_item.setData(item.path, _user_role())
                        model_item.setToolTip(item.error or item.path)
                    self.database_model.appendRow(model_items)
                    if item.path == current_path:
                        selected_row = row_number
                if selected_row >= 0:
                    self.database_tree.setCurrentIndex(
                        self.database_model.index(selected_row, 0)
                    )
                for column in range(self.database_model.columnCount()):
                    self.database_tree.resizeColumnToContents(column)
            finally:
                self._rendering = False

        def _database_changed(self, *args: typing.Any) -> None:
            del args
            if not self._rendering:
                self._load_snapshots()

        def _selection_changed(self, *args: typing.Any) -> None:
            del args
            if not self._rendering:
                self._render_action_states()

        def _load_snapshots(self, *args: typing.Any) -> None:
            del args
            if self._rendering:
                return
            database = self._current_database()
            current_id = self._current_snapshot_id()
            database_path = None if database is None else str(database.path)
            if (
                database_path is not None
                and database_path == self._snapshot_database_path
            ):
                self._refilter_snapshots()
                return
            self._snapshot_database_path = database_path
            self._record_identity = None
            self._snapshots = ()
            if database is not None and database.readable:
                try:
                    self._snapshots = tuple(self._adapter.snapshots(database.path))
                except Exception as exc:
                    logger.warning("Diagnostic snapshot inventory failed: %s", exc)
                    self.record_detail.setPlainText(f"Snapshot inventory failed: {exc}")
            filtered = filter_snapshots(self._snapshots, self.snapshot_filter.text())
            self._apply_snapshot_projection(filtered, current_id)

        def _refilter_snapshots(self, *args: typing.Any) -> None:
            del args
            if self._rendering:
                return
            filtered = filter_snapshots(self._snapshots, self.snapshot_filter.text())
            self._apply_snapshot_projection(filtered, self._current_snapshot_id())

        def _apply_snapshot_projection(
            self,
            filtered: tuple[typing.Any, ...],
            current_id: int | None,
        ) -> None:
            sort_value = str(self.snapshot_sort.currentData() or "newest")
            self._snapshot_rows = self._sort_snapshot_rows(filtered, sort_value)
            if current_id is None and self._function_ea is not None:
                current = latest_snapshot_for_function(
                    self._snapshot_rows, self._function_ea
                )
                current_id = None if current is None else current.snapshot_id
            self._render_snapshots(current_id)
            self._load_records()
            self._render_action_states()

        def _render_snapshots(self, current_id: int | None) -> None:
            self._rendering = True
            try:
                self.snapshot_model.removeRows(0, self.snapshot_model.rowCount())
                selected_row = 0 if self._snapshot_rows else -1
                for row_number, item in enumerate(self._snapshot_rows):
                    values = (
                        str(item.snapshot_id),
                        _timestamp(item.recorded_at),
                        f"0x{item.function_ea:X}",
                        item.maturity,
                        item.phase,
                        item.label,
                        str(item.block_count),
                        str(item.row_count),
                    )
                    model_items = [QtGui.QStandardItem(value) for value in values]
                    for model_item in model_items:
                        model_item.setEditable(False)
                        model_item.setData(int(item.snapshot_id), _user_role())
                        model_item.setToolTip(item.label)
                    self.snapshot_model.appendRow(model_items)
                    if item.snapshot_id == current_id:
                        selected_row = row_number
                if selected_row >= 0:
                    self.snapshot_tree.setCurrentIndex(
                        self.snapshot_model.index(selected_row, 0)
                    )
                for column in range(self.snapshot_model.columnCount()):
                    self.snapshot_tree.resizeColumnToContents(column)
            finally:
                self._rendering = False

        def _snapshot_changed(self, *args: typing.Any) -> None:
            del args
            if not self._rendering:
                self._load_records()

        def _load_records(self, *args: typing.Any) -> None:
            del args
            if self._rendering:
                return
            database = self._current_database()
            snapshot = self._current_snapshot()
            kind = str(self.view_combo.currentData() or "blocks")
            identity = (
                None
                if database is None or snapshot is None
                else (str(database.path), int(snapshot.snapshot_id), kind)
            )
            if identity is not None and identity == self._record_identity:
                self._refilter_records()
                return
            self._record_identity = identity
            self._records = ()
            if database is not None and snapshot is not None:
                try:
                    self._records = tuple(
                        self._adapter.records(
                            database.path,
                            snapshot.snapshot_id,
                            kind,
                        )
                    )
                except Exception as exc:
                    logger.warning("Diagnostic structured view failed: %s", exc)
                    self.record_detail.setPlainText(f"Structured view failed: {exc}")
            filtered = filter_records(self._records, self.record_filter.text())
            self._apply_record_projection(filtered)
            self._publish_graph_context()

        def _refilter_records(self, *args: typing.Any) -> None:
            del args
            if self._rendering:
                return
            filtered = filter_records(self._records, self.record_filter.text())
            self._apply_record_projection(filtered)

        def _apply_record_projection(
            self,
            filtered: tuple[typing.Any, ...],
        ) -> None:
            self._record_rows = project_record_rows(filtered)
            self._render_records()
            self._render_action_states()

        def _render_records(self) -> None:
            self._rendering = True
            try:
                self.record_model.removeRows(0, self.record_model.rowCount())
                for row_number, item in enumerate(self._record_rows):
                    values = (
                        item.source_table,
                        str(item.ordinal),
                        item.anchor,
                        item.summary,
                    )
                    model_items = [QtGui.QStandardItem(value) for value in values]
                    for model_item in model_items:
                        model_item.setEditable(False)
                        model_item.setData(row_number, _user_role())
                        model_item.setToolTip(item.summary)
                    self.record_model.appendRow(model_items)
                if self._record_rows:
                    self.record_tree.setCurrentIndex(self.record_model.index(0, 0))
                    self.record_detail.setPlainText(self._record_rows[0].detail)
                else:
                    self.record_detail.setPlainText("")
                for column in range(self.record_model.columnCount()):
                    self.record_tree.resizeColumnToContents(column)
            finally:
                self._rendering = False

        def _record_changed(self, *args: typing.Any) -> None:
            del args
            row = self._current_record_row()
            self.record_detail.setPlainText("" if row is None else row.detail)
            if self._graph_controller is not None:
                self._graph_controller.select_record(
                    None if row is None else row.record
                )
            self._render_action_states()

        def _graph_context(self) -> typing.Any:
            controller = self._graph_controller
            database = self._current_database()
            snapshot = self._current_snapshot()
            if (
                controller is None
                or database is None
                or not database.readable
                or snapshot is None
            ):
                return None
            return controller.context_for_explorer(
                database_path=str(database.path),
                snapshot_id=int(snapshot.snapshot_id),
                function_ea=int(snapshot.function_ea),
                function_name=self._function_name,
                view_value=str(self.view_combo.currentData() or ""),
            )

        def _open_graph(self, checked: bool = False) -> None:
            del checked
            context = self._graph_context()
            if self._graph_controller is None or context is None:
                self.open_graph_button.setEnabled(False)
                self.record_detail.setPlainText(
                    "Select a readable database, snapshot, and supported view "
                    "before opening a graph"
                )
                return
            self._graph_controller.open(context)

        def _publish_graph_context(self) -> None:
            context = self._graph_context()
            self.open_graph_button.setEnabled(context is not None)
            if self._graph_controller is None:
                return
            if context is None:
                self._graph_controller.clear_for_unsupported_view()
                return
            self._graph_controller.update_context(context)

        def _selected_rows(self, tree: typing.Any) -> tuple[int, ...]:
            return tuple(
                sorted(
                    {int(index.row()) for index in tree.selectionModel().selectedRows()}
                )
            )

        def _selected_database_paths(self) -> tuple[str, ...]:
            return tuple(
                self._database_rows[row].path
                for row in self._selected_rows(self.database_tree)
                if 0 <= row < len(self._database_rows)
            )

        def _selected_snapshot_ids(self) -> tuple[int, ...]:
            return tuple(
                int(self._snapshot_rows[row].snapshot_id)
                for row in self._selected_rows(self.snapshot_tree)
                if 0 <= row < len(self._snapshot_rows)
            )

        def _current_database_path(self) -> str | None:
            database = self._current_database()
            return None if database is None else str(database.path)

        def _current_database(self) -> typing.Any:
            row = int(self.database_tree.currentIndex().row())
            return (
                self._database_rows[row]
                if 0 <= row < len(self._database_rows)
                else None
            )

        def _current_snapshot_id(self) -> int | None:
            snapshot = self._current_snapshot()
            return None if snapshot is None else int(snapshot.snapshot_id)

        def _current_snapshot(self) -> typing.Any:
            row = int(self.snapshot_tree.currentIndex().row())
            return (
                self._snapshot_rows[row]
                if 0 <= row < len(self._snapshot_rows)
                else None
            )

        def _current_record_row(self) -> typing.Any:
            row = int(self.record_tree.currentIndex().row())
            return self._record_rows[row] if 0 <= row < len(self._record_rows) else None

        def _render_action_states(self) -> None:
            selected_paths = set(self._selected_database_paths())
            selected = tuple(
                item for item in self._databases if item.path in selected_paths
            )
            states = {
                item.action_id: item
                for item in diagnostic_action_states(
                    selected,
                    selected_snapshot_ids=self._selected_snapshot_ids(),
                    all_databases=self._databases,
                )
            }
            for action_id, button in self.cleanup_buttons.items():
                state = states.get(action_id)
                button.setEnabled(bool(state and state.enabled))
                button.setToolTip("" if state is None else state.reason)
            snapshot = self._current_snapshot()
            record = self._current_record_row()
            self.jump_function_button.setEnabled(snapshot is not None)
            self.jump_record_button.setEnabled(
                record is not None and record_jump_ea(record.record) is not None
            )

        def _clear_plan(self) -> None:
            self._cleanup_plan = None
            self.cleanup_plan_view.setPlainText("")
            self.reviewed_checkbox.setChecked(False)
            self.confirmation_edit.clear()
            self.confirmation_edit.setPlaceholderText(
                "Typed confirmation appears here when required"
            )
            self.execute_button.setEnabled(False)

        def _plan_cleanup(self, action_id: str) -> None:
            self._clear_plan()
            database = self._current_database()
            path = None if database is None else database.path
            selected_paths = self._selected_database_paths()
            all_paths = tuple(item.path for item in self._databases)
            paths = (
                all_paths
                if action_id == "delete_all_closed_databases"
                else selected_paths
            )
            try:
                recorded_before = float(self.older_than_edit.text().strip() or "0")
                plan = self._adapter.plan(
                    action_id,
                    path=path,
                    paths=paths,
                    snapshot_ids=self._selected_snapshot_ids(),
                    keep=int(self.keep_latest_spin.value()),
                    recorded_before=recorded_before,
                )
                view = project_cleanup_plan(plan)
            except Exception as exc:
                logger.warning("Diagnostic cleanup plan failed: %s", exc)
                self.cleanup_plan_view.setPlainText(f"Plan failed: {exc}")
                return
            self._cleanup_plan = plan
            self.cleanup_plan_view.setPlainText(view.text)
            if view.required_phrase:
                self.confirmation_edit.setPlaceholderText(
                    f"Type {view.required_phrase} exactly"
                )
            self._update_execute_enabled()

        def _update_execute_enabled(self, *args: typing.Any) -> None:
            del args
            plan = self._cleanup_plan
            if plan is None:
                self.execute_button.setEnabled(False)
                return
            view = project_cleanup_plan(plan)
            confirmed = cleanup_confirmation_matches(
                plan, self.confirmation_edit.text()
            )
            self.execute_button.setEnabled(
                bool(view.target_count)
                and self.reviewed_checkbox.isChecked()
                and confirmed
            )

        def _execute_cleanup(self, checked: bool = False) -> None:
            del checked
            plan = self._cleanup_plan
            if plan is None or not self.reviewed_checkbox.isChecked():
                return
            if not cleanup_confirmation_matches(plan, self.confirmation_edit.text()):
                return
            try:
                result = self._adapter.execute(
                    plan,
                    checkpoint_wal=self.checkpoint_checkbox.isChecked(),
                    vacuum_after=self.vacuum_after_checkbox.isChecked(),
                )
                text = project_cleanup_result(result)
            except Exception as exc:
                logger.warning("Diagnostic cleanup failed: %s", exc)
                text = f"Cleanup execution failed: {exc}"
            self.cleanup_result_view.setPlainText(text)
            self.cleanup_result_view.setVisible(True)
            self._clear_plan()
            self.refresh()

        def _jump_to_function(self, checked: bool = False) -> None:
            del checked
            snapshot = self._current_snapshot()
            if snapshot is not None:
                self._adapter.navigate(int(snapshot.function_ea))

        def _jump_to_record(self, checked: bool = False) -> None:
            del checked
            row = self._current_record_row()
            if row is None:
                return
            ea = record_jump_ea(row.record)
            if ea is not None:
                self._adapter.navigate(ea)

else:

    class WorkbenchDiagnosticsPanel:
        """Import-safe stub used outside IDA."""

        def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
            del args, kwargs
            raise ImportError("WorkbenchDiagnosticsPanel requires IDA Pro")


__all__ = ["WorkbenchDiagnosticsPanel", "IDA_AVAILABLE"]
