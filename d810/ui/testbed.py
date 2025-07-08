import importlib
import logging
import os
import pkgutil
import unittest
from typing import Iterable

from PyQt5 import QtCore, QtGui, QtWidgets

import ida_kernwin

LOGGER = logging.getLogger(__name__)
print("logger name", __name__)


class IDATestLoader(unittest.TestLoader):
    """Custom `unittest` loader that discovers tests under *packages/d810/tests*.

    This loader works similarly to :pyclass:`unittest.TestLoader` but ignores
    sub-packages named ``data`` or ``__pycache__`` to avoid importing binary
    fixtures or compiled artefacts.
    """

    IGNORED_SUBPKGS = {"data", "__pycache__"}

    def discover(
        self,
        start_dir: str | None = None,
        pattern: str = "test*.py",
        top_level_dir: str | None = None,
    ):
        LOGGER.debug("Discovering tests in %s with pattern %s", start_dir, pattern)
        return super().discover(
            start_dir or __package__.replace(".", "/"), pattern, top_level_dir
        )

    def _match_path(
        self, path: str, full_path: str, pattern: str
    ) -> bool:  # noqa: N802 – override camelCase name
        # Skip ignored sub-packages
        for token in path.split("/"):
            if token in self.IGNORED_SUBPKGS:
                return False
        return super()._match_path(path, full_path, pattern)


class IDATestRunner:
    """Small wrapper around :pyclass:`unittest.TextTestRunner` that collects
    results for programmatic access (e.g. GUI widgets).
    """

    def __init__(self):
        self.loader = IDATestLoader()
        # self.stream = types.SimpleNamespace(write=lambda _: None, flush=lambda: None)  # type: ignore[attr-defined]
        self.runner = unittest.TextTestRunner(verbosity=2)
        self.last_result: unittest.TestResult | None = None

    # ---------------------------------------------------------------------
    # Discovery helpers
    # ---------------------------------------------------------------------

    @staticmethod
    def _iter_modules(package_name: str) -> Iterable[str]:
        """Yield fully-qualified module names contained in *package_name*."""
        package = importlib.import_module(package_name)
        if not hasattr(package, "__path__"):
            return
        for mod_info in pkgutil.walk_packages(
            package.__path__, prefix=f"{package_name}."
        ):
            if not mod_info.ispkg:
                yield mod_info.name

    def discover_tests(self, package: str = "d810.tests.system") -> unittest.TestSuite:
        """Discover test cases under *package* using unittest.TestLoader.discover."""
        LOGGER.debug("Discovering tests under package %s", package)
        pkg = importlib.import_module(package)
        if not hasattr(pkg, "__path__"):
            raise ValueError(f"{package} is not a package")
        start_dir = pkg.__path__[0]
        top_level_dir = os.path.dirname(os.path.dirname(start_dir))
        LOGGER.debug(f"start_dir={start_dir}, top_level_dir={top_level_dir}")
        suite = self.loader.discover(
            start_dir=start_dir, pattern="test*.py", top_level_dir=top_level_dir
        )
        return suite

    # ------------------------------------------------------------------
    # Execution helpers
    # ------------------------------------------------------------------

    def run(self, suite: unittest.TestSuite | None = None) -> unittest.TestResult:
        LOGGER.info("Starting IDA unit test run …")
        if suite is None:
            suite = self.discover_tests()
        self.last_result = self.runner.run(suite)
        LOGGER.info(
            "Tests run: %d, failures: %d, errors: %d, skipped: %d",
            self.last_result.testsRun,
            len(self.last_result.failures),
            len(self.last_result.errors),
            len(self.last_result.skipped),
        )
        return self.last_result

    # ------------------------------------------------------------------
    # Convenience API
    # ------------------------------------------------------------------

    def run_all(self) -> unittest.TestResult:
        """Discover and execute every test under *d810.tests*."""
        return self.run()


class TestRunnerForm(ida_kernwin.PluginForm):
    """Qt-based GUI for executing IDA unit tests and displaying results."""

    def __init__(self, runner: IDATestRunner):
        super().__init__()
        self.runner = runner
        self.text_edit = None  # Will be assigned in _populate
        self.run_button = None

    # ------------------------------------------------------------------
    # Qt helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_qt_modules():
        """Return a tuple *(QtWidgets, QtCore)* for the active Qt binding."""
        # future proofing, PySide6/pyqt6 looks like it's coming in a later version of IDA
        # and is not _CURRENTLY_ supported by IDA
        for binding in ("PyQt5", "PySide6", "PyQt6"):
            try:
                qt_widgets = importlib.import_module(f"{binding}.QtWidgets")
                qt_core = importlib.import_module(f"{binding}.QtCore")
                return qt_widgets, qt_core
            except ModuleNotFoundError:  # pragma: no cover – depends on IDA's build
                continue
        raise RuntimeError("No compatible Qt binding found in IDA environment")

    # ------------------------------------------------------------------
    # PluginForm overrides
    # ------------------------------------------------------------------

    def _populate(self, ctx):  # noqa: D401 – IDA callback naming
        QtWidgets, QtCore = self._get_qt_modules()

        # Root widget provided by IDA – we must wrap it with Qt
        layout = QtWidgets.QVBoxLayout()

        # Tree widget to display test hierarchy and status
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(2)
        self.tree.setHeaderLabels(["Test", "Status"])
        self.tree.setRootIsDecorated(True)
        self.tree.setIndentation(20)
        self.tree.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self.tree)

        self.run_button = QtWidgets.QPushButton("Run tests")
        self.run_button.clicked.connect(self._on_run_clicked)  # type: ignore[attr-defined]
        layout.addWidget(self.run_button)

        # Apply layout to the parent widget
        self.parent_widget = self.FormToPyQtWidget(ctx)  # type: ignore[attr-defined]
        self.parent_widget.setLayout(layout)
        self.parent_widget.setWindowTitle("D810 Test Runner")
        self.parent_widget.resize(600, 400)

    def OnCreate(self, ctx):  # pylint: disable=invalid-name
        self._populate(ctx)

    # Context menu for tree widget
    def _show_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        if not item or not item.data(0, QtCore.Qt.UserRole):
            return
        menu = QtWidgets.QMenu()
        run_action = menu.addAction("Run Test")
        action = menu.exec_(self.tree.viewport().mapToGlobal(pos))
        if action == run_action:
            test_name = item.data(0, QtCore.Qt.UserRole)
            self._run_single_test(test_name)

    def _run_single_test(self, test_name):
        suite = unittest.TestSuite()
        suite.addTest(self.runner.loader.loadTestsFromName(test_name))
        result = self.runner.runner.run(suite)
        self._populate_tree(suite, result)

    def _iter_tests(self, suite):
        for test in suite:
            if isinstance(test, unittest.TestSuite):
                yield from self._iter_tests(test)
            elif test is not None:
                yield test

    def _populate_tree(self, suite, result):
        # Debug: log discovered tests
        # tests = list(self._iter_tests(suite))
        # print(
        #     "Populating tree: discovered %d tests: %s",
        #     len(tests),
        #     [t.id() for t in tests],
        # )
        self.tree.clear()
        tests = list(self._iter_tests(suite))
        print(
            "Populating tree: discovered %d tests: %s",
            len(tests),
            [t.id() for t in tests],
        )
        if not tests:
            # Show placeholder if no tests found
            QtWidgets.QTreeWidgetItem(self.tree, ["<No tests found>", ""])
            return
        # Group tests by class name
        groups: dict[str, list[tuple[unittest.TestCase, str]]] = {}
        for test in tests:
            test_id = test.id()
            parts = test_id.split(".")
            cls_name = parts[-2]
            method_name = parts[-1]
            groups.setdefault(cls_name, []).append((test, method_name))
        # Populate tree
        for cls_name, tests in groups.items():
            parent = QtWidgets.QTreeWidgetItem(self.tree, [cls_name])
            for test, method in tests:
                item = QtWidgets.QTreeWidgetItem(parent, [method, ""])
                # Determine status
                failed = any(f[0] is test for f in result.failures + result.errors)
                status = "Failed" if failed else "Passed"
                brush = QtGui.QBrush(QtGui.QColor("red" if failed else "green"))
                item.setText(1, status)
                item.setForeground(0, brush)
                item.setForeground(1, brush)
                # Store full test id for re-running
                item.setData(0, QtCore.Qt.UserRole, test.id())
        self.tree.expandAll()

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_run_clicked(self):
        self.tree.clear()
        suite = self.runner.discover_tests()
        result = self.runner.runner.run(suite)
        self._populate_tree(suite, result)


# ----------------------------------------------------------------------
# Convenience helper
# ----------------------------------------------------------------------


def show_gui():
    """Launch or focus the D810 test runner GUI inside IDA Pro."""
    runner = IDATestRunner()
    form = TestRunnerForm(runner)
    form.Show("D810 Test Runner", options=ida_kernwin.PluginForm.WOPN_TAB)
