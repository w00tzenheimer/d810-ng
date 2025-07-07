import importlib
import inspect
import logging
import pkgutil
import types
import unittest
from typing import Iterable, List, Type

import ida_hexrays  # noqa: F401 – required so tests can rely on Hex-Rays being loaded
import ida_kernwin
import idaapi

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
        self.stream = types.SimpleNamespace(write=lambda _: None, flush=lambda: None)  # type: ignore[attr-defined]
        self.runner = unittest.TextTestRunner(stream=self.stream, verbosity=2)
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
        """Discover test cases located under *package* and return a suite."""
        LOGGER.debug("Discovering tests under package %s", package)
        modules = list(self._iter_modules(package))
        for mod_name in modules:
            LOGGER.debug("Importing test module %s", mod_name)
            importlib.import_module(mod_name)
        return self.loader.loadTestsFromNames(modules)

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
        for binding in ("PyQt5", "PySide2", "PySide6", "PyQt6"):
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

        self.text_edit = QtWidgets.QTextEdit()
        self.text_edit.setReadOnly(True)
        font = self.text_edit.font()
        font.setFamily("monospace")
        self.text_edit.setFont(font)
        layout.addWidget(self.text_edit)

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

    def _append_output(self, text: str):
        if self.text_edit is None:
            return
        self.text_edit.append(text)
        self.text_edit.ensureCursorVisible()

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _on_run_clicked(self):
        self._append_output("Running tests …\n")
        result = self.runner.run_all()
        summary = (
            f"Ran {result.testsRun} test(s) – "
            f"Failures: {len(result.failures)}, "
            f"Errors: {len(result.errors)}, "
            f"Skipped: {len(result.skipped)}"
        )
        self._append_output(summary + "\n")
        if result.failures or result.errors:
            self._append_output("\nDetails:\n")
            for test_case, err in result.failures + result.errors:
                self._append_output(f"{test_case}:\n{err}\n")


# ----------------------------------------------------------------------
# Convenience helper
# ----------------------------------------------------------------------


def show_gui():
    """Launch or focus the D810 test runner GUI inside IDA Pro."""
    runner = IDATestRunner()
    form = TestRunnerForm(runner)
    form.Show("D810 Test Runner", options=ida_kernwin.PluginForm.WOPN_TAB)
