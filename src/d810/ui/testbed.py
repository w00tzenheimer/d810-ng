import collections
import importlib
import logging
import os
import re
import sys
import time
import weakref

# Added for easier path manipulations
from pathlib import Path
from typing import TextIO
from unittest import loader, runner, suite

from PyQt5 import QtCore, QtGui, QtWidgets

import ida_kernwin

# Configure a logger for the script
LOGGER = logging.getLogger(__name__)
# Set a basic configuration if one is not already set
if not logging.root.handlers:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )


# --- Test Results ---
TEST_RESULT_NONE = 0
TEST_RESULT_RUNNING = 1
TEST_RESULT_SKIP = 2
TEST_RESULT_PASS = 3
TEST_RESULT_EXPECTED_FAIL = 4
TEST_RESULT_UNEXPECTED_PASS = 5
TEST_RESULT_FAIL = 6
TEST_RESULT_ERROR = 7

# --- Partial Run Modes ---
RUN_TEST_SETUP_ONLY = 0
RUN_TEST_NO_TEAR_DOWN = 1
RUN_TEST_FULL = 2

# --- Tree Item Categories ---
ITEM_CATEGORY_ALL = 0
ITEM_CATEGORY_PACKAGE = 1
ITEM_CATEGORY_MODULE = 2
ITEM_CATEGORY_SUITE = 3
ITEM_CATEGORY_TEST = 4

# --- UI Log Colors ---
LOG_COLOR_INFORMATION = QtGui.QColor(200, 200, 200)
LOG_COLOR_ERROR = QtGui.QColor(234, 52, 95)
LOG_COLOR_FAILED = QtGui.QColor(234, 52, 95)
LOG_COLOR_WARNING = QtGui.QColor(220, 206, 135)
LOG_COLOR_SUCCESS = QtGui.QColor(138, 211, 11)


def make_main_layout(host_widget=None):
    _lay = QtWidgets.QVBoxLayout(host_widget)
    _lay.setContentsMargins(6, 6, 6, 6)
    _lay.setSpacing(3)
    return _lay


def make_minor_horizontal_layout():
    _layout = QtWidgets.QHBoxLayout()
    _layout.setSpacing(3)
    _layout.setContentsMargins(0, 0, 0, 0)
    return _layout


def make_icon_button(icon=None, parent=None):
    btn = QtWidgets.QPushButton("", parent)
    if icon:
        btn.setIcon(icon)
    btn.setFlat(True)
    btn.setIconSize(QtCore.QSize(20, 20))
    btn.setFixedSize(QtCore.QSize(24, 24))
    return btn


def make_menu_tool_button(icon=None, tool_tip="", parent=None):
    btn = QtWidgets.QToolButton(parent)
    if icon:
        btn.setIcon(icon)
    btn.setToolTip(tool_tip)
    btn.setContentsMargins(0, 0, 0, 0)
    btn.setIconSize(QtCore.QSize(20, 20))
    btn.setPopupMode(btn.InstantPopup)
    menu = QtWidgets.QMenu(btn)
    btn.setMenu(menu)
    return (btn, menu)


def is_path(path):
    return "/" in path or "\\" in path


def object_from_dot_path(dot_path, silent=False):
    if not dot_path:
        return None

    def try_import_closest_module(paths):
        module = None
        while paths:
            try:
                module_name = ".".join(paths)
                # Use importlib for cleaner imports
                if module_name in sys.modules:
                    module = importlib.reload(sys.modules[module_name])
                else:
                    module = importlib.import_module(module_name)
                break
            except ImportError:
                del paths[-1]
                if not paths:
                    return None
        return module

    parts = dot_path.split(".")
    module = try_import_closest_module(parts[:])
    if not module:
        if not silent:
            LOGGER.error("No module found from %s", dot_path)
        return None

    obj = module
    for part in parts[1:]:
        try:
            obj = getattr(obj, part)
        except AttributeError:
            if not silent:
                LOGGER.exception("Error importing the module at path %s", dot_path)
            return None
    return obj


def parse_parameterized_test_id(test_id):
    is_parameterized = ":" in test_id
    return (
        (is_parameterized, test_id.split(":")[0])
        if is_parameterized
        else (is_parameterized, test_id)
    )


class TestRunInfo(object):
    def __init__(self):
        self.reset()

    def reset(self):
        self.run_test_ids = []
        self.run_count = 0
        self.failed_test_id = None
        self.success_count = 0
        self.failed_count = 0
        self.error_count = 0
        self.skip_count = 0
        self.expected_failure_count = 0
        self.unexpected_success_count = 0
        self._session_start_time = 0.0
        self.session_run_time = 0.0
        self._test_start_times = {}
        self.single_test_run_time = 0


class TestManager:
    def __init__(self, ui, start_dir_or_module, top_dir=None):
        self._ui = ui
        self._start_dir_or_module = start_dir_or_module or ""
        self._top_dir = top_dir or ""
        self._stop_on_error = False
        self._runner = PyUnitRunner(self)
        self.set_dirs(start_dir_or_module, top_dir)

    def set_dirs(self, start_dir_or_module, top_dir=None):
        self._start_dir_or_module = start_dir_or_module or ""
        self._top_dir = top_dir or ""
        if self._start_dir_or_module and not self._top_dir:
            if os.path.isdir(self._start_dir_or_module):
                self._top_dir = os.path.dirname(self._start_dir_or_module)

    def start_dir_or_module(self):
        return self._start_dir_or_module

    def top_dir(self):
        return self._top_dir

    def set_stop_on_error(self, stop):
        self._stop_on_error = stop

    def reload_test_modules(self):
        """
        Reload all previously imported test modules under the current start_dir.
        """
        start_dir = self._start_dir_or_module
        top_dir = self._top_dir
        if not start_dir or not top_dir:
            return
        # Ensure tests are importable
        if top_dir not in sys.path:
            sys.path.insert(0, top_dir)
        # Compute package name from start_dir relative to top_dir
        relpath = os.path.relpath(start_dir, top_dir)
        package_name = relpath.replace(os.sep, ".")
        # Reload modules matching the test package
        for module_name, module in list(sys.modules.items()):
            if module_name == package_name or module_name.startswith(
                package_name + "."
            ):
                try:
                    importlib.reload(module)
                    LOGGER.info("Reloaded test module %s", module_name)
                except Exception:
                    LOGGER.exception("Failed to reload test module %s", module_name)

    def stop_on_error(self):
        """
        Return whether to stop on the first error.
        """
        return self._stop_on_error

    def run_tests(self, *tests):
        # Reload test modules so changes are picked up
        self.reload_test_modules()
        self._runner.run_tests(*tests)

    def iter_all_test_ids(self):
        yield from self._runner.iter_all_test_ids()

    def run_all_tests(self):
        tests = list(self.iter_all_test_ids())
        if not tests:
            LOGGER.warning("No tests found to run.")
            return
        self.run_tests(*tests)

    def run_single_test_partially(self, test_id, partial_mode):
        self._runner.run_single_test_partially(test_id, partial_mode)

    def has_last_lister_error(self):
        return self._runner.has_last_lister_error()

    def last_run_test_ids(self):
        return self._runner.last_run_test_ids()

    def last_run_info(self):
        return self._runner.last_run_info()

    def last_failed_test_id(self):
        return self._runner.last_failed_test_id()


class UiStream(TextIO):
    _test_main_window = None
    _log_browser = None
    _url_template = "<a href='?{1}={2}'>{0}</a>"
    _trace_exp = None

    @classmethod
    def set_ui(cls, wgt):
        cls._test_main_window = weakref.ref(wgt)
        cls._log_browser = cls.call_ui_method("get_log_browser_widget")

    @classmethod
    def unset_ui(cls, wgt):
        if cls._test_main_window and cls._test_main_window() == wgt:
            cls._test_main_window = None

    @classmethod
    def log_browser(cls):
        return cls._log_browser

    def __init__(self):
        if not self.__class__._trace_exp:
            self.__class__._trace_exp = re.compile(r'File "(.*?)", line (\d+),')
        self._test_result = None

    def set_result(self, result=None):
        self._test_result = result

    def write(self, msg):
        report_ui = self.log_browser()
        if not report_ui:
            sys.stdout.write(msg)  # Fallback
            return

        if self._test_result == TEST_RESULT_ERROR:
            report_ui.log_error(msg)
        elif self._test_result == TEST_RESULT_FAIL:
            report_ui.log_failed(msg)
        elif self._test_result == TEST_RESULT_SKIP:
            report_ui.log_warning(msg)
        elif self._test_result == TEST_RESULT_PASS:
            report_ui.log_success(msg)
        else:
            report_ui.log_information(msg)

    def writeln(self, msg=None):
        if msg:
            self.write(msg)
        self.write("<br>")

    def flush(self):
        pass

    @classmethod
    def call_ui_method(cls, method_name, *args, **kwargs):
        if not cls._test_main_window:
            return
        ui = cls._test_main_window()
        if ui:
            method = getattr(ui, method_name, None)
            if method:
                return method(*args, **kwargs)


class LogHandler(logging.Handler):
    def emit(self, record):
        report_ui = UiStream.log_browser()
        if not report_ui:
            return
        msg = self.format(record)
        if record.levelno >= logging.ERROR:
            report_ui.log_failed(msg)
        elif record.levelno >= logging.WARNING:
            report_ui.log_warning(msg)
        else:
            report_ui.log_information(msg)


class PyUnitUiMixin(object):
    last_run_info = TestRunInfo()
    _original_std_out = sys.stdout
    _original_std_err = sys.stderr

    def __init__(self, stream: UiStream):
        self.stream: UiStream = stream
        self.log_handler = LogHandler()
        self.std_out_capturer = None  # Will be created on demand
        self.std_err_capturer = None  # Will be created on demand

    @classmethod
    def reset_last_data(cls):
        cls.last_run_info.reset()

    def _call_ui_method(self, method, *args, **kwargs):
        UiStream.call_ui_method(method, *args, **kwargs)

    @classmethod
    def _record_last_failed_test_id(cls, test_id):
        if not cls.last_run_info.failed_test_id:
            cls.last_run_info.failed_test_id = test_id

    def _at_outcome_available(self, test_id, result_code):
        cls = type(self)
        if result_code == TEST_RESULT_ERROR:
            cls.last_run_info.error_count += 1
            self._record_last_failed_test_id(test_id)
        elif result_code == TEST_RESULT_FAIL:
            cls.last_run_info.failed_count += 1
            self._record_last_failed_test_id(test_id)
        elif result_code == TEST_RESULT_EXPECTED_FAIL:
            cls.last_run_info.expected_failure_count += 1
        elif result_code == TEST_RESULT_UNEXPECTED_PASS:
            cls.last_run_info.unexpected_success_count += 1
        elif result_code == TEST_RESULT_SKIP:
            cls.last_run_info.skip_count += 1
        elif result_code == TEST_RESULT_PASS:
            cls.last_run_info.success_count += 1

        self._call_ui_method("show_result_on_item_by_test_id", test_id, result_code)
        self._stop_log_processors()

    def _at_start_test_run(self):
        self._call_ui_method("repaint_ui")
        cls = type(self)
        cls.last_run_info.reset()
        cls.last_run_info._session_start_time = time.time()
        self._call_ui_method("on_test_running_session_start")

    def _start_log_processors(self):
        logging.getLogger().addHandler(self.log_handler)
        sys.stdout = self.stream
        sys.stderr = self.stream

    def _stop_log_processors(self):
        logging.getLogger().removeHandler(self.log_handler)
        sys.stdout = self._original_std_out
        sys.stderr = self._original_std_err

    def _at_start_test(self, test):
        cls = type(self)
        cls.last_run_info.run_count += 1
        original_test_id = test.id()
        _, test_id = parse_parameterized_test_id(original_test_id)
        if test_id not in cls.last_run_info.run_test_ids:
            test_start_time = time.time()
            cls.last_run_info._test_start_times[test_id] = test_start_time
            cls.last_run_info.run_test_ids.append(test_id)
            self._call_ui_method("on_single_test_start", test_id, test_start_time)

    def _at_stop_test(self, test):
        original_test_id = test.id()
        _, test_id = parse_parameterized_test_id(original_test_id)
        stop_time = time.time()
        cls = type(self)
        test_start_time = cls.last_run_info._test_start_times.get(
            test_id, cls.last_run_info._session_start_time
        )
        cls.last_run_info.single_test_run_time = stop_time - test_start_time
        self._call_ui_method("on_single_test_stop", test_id, stop_time)
        self._call_ui_method("repaint_ui")

    def _at_stop_test_run(self):
        cls = type(self)
        cls.last_run_info.session_run_time = (
            time.time() - cls.last_run_info._session_start_time
        )
        self._call_ui_method("on_all_tests_finished")
        # Ensure that standard output/error streams and the root logger are
        # restored to their original state when the complete test run
        # finishes.  Without this call, further logging performed outside the
        # testbed session would continue to be redirected to the UI log
        # browser instead of the console.
        self._stop_log_processors()


class PyUnitTestRunnerWrapper(runner.TextTestRunner):
    def __init__(self, verbosity=2, failfast=False, partial_mode=RUN_TEST_FULL):
        self.stream = UiStream()
        self._partial_mode = partial_mode

        # Call the parent constructor without explicitly passing our custom
        # ``resultclass``.  This avoids mypy’s type-checking complaint that
        # ``PyUnitTestResult`` expects a ``UiStream`` rather than a ``TextIO``.
        super().__init__(
            stream=self.stream,
            verbosity=verbosity,
            failfast=failfast,
        )

        # Now that the base class is initialized we can safely set the
        # desired result class.  The ``type: ignore`` suppresses the
        # mismatch warning between ``UiStream`` and ``TextIO`` in stubs.
        self.resultclass = PyUnitTestResult  # type: ignore[assignment]

    @staticmethod
    def _dummy_function(*_, **__):
        pass

    def run(self, test):
        if self._partial_mode != RUN_TEST_FULL:
            test_case = test
            while isinstance(test_case, suite.TestSuite):
                test_case = next(iter(test_case), None)

            if test_case:
                print(type(test_case))
                if hasattr(test_case, "tearDown"):
                    test_case.tearDown = self._dummy_function
                if self._partial_mode == RUN_TEST_SETUP_ONLY:
                    method_name = test_case.id().split(".")[-1]
                    if hasattr(test_case, method_name):
                        setattr(test_case, method_name, self._dummy_function)
                    LOGGER.info("Run %s.setUp() only:", test_case.__class__.__name__)
                elif self._partial_mode == RUN_TEST_NO_TEAR_DOWN:
                    LOGGER.info("Skipped %s.tearDown():", test_case.__class__.__name__)
        return super().run(test)


class PyUnitTestResult(runner.TextTestResult, PyUnitUiMixin):

    def __init__(self, stream: UiStream, descriptions: bool, verbosity: int):
        self.Cls = self.__class__
        super().__init__(stream, descriptions, verbosity)
        self.stream: UiStream = stream
        PyUnitUiMixin.__init__(self, stream)

    def startTestRun(self):
        self._at_start_test_run()
        super().startTestRun()

    def startTest(self, test):
        self._at_start_test(test)
        super().startTest(test)
        self._start_log_processors()

    def stopTest(self, test):
        super().stopTest(test)
        self._at_stop_test(test)

    def stopTestRun(self):
        super().stopTestRun()
        self._at_stop_test_run()
        self.stream.set_result(
            TEST_RESULT_PASS if self.wasSuccessful() else TEST_RESULT_ERROR
        )

    def addSuccess(self, test):
        self.stream.set_result(TEST_RESULT_PASS)
        super().addSuccess(test)
        self._at_outcome_available(test.id(), TEST_RESULT_PASS)

    def addError(self, test, err):
        self.stream.set_result(TEST_RESULT_ERROR)
        super().addError(test, err)
        self._at_outcome_available(test.id(), TEST_RESULT_ERROR)

    def addFailure(self, test, err):
        self.stream.set_result(TEST_RESULT_FAIL)
        super().addFailure(test, err)
        self._at_outcome_available(test.id(), TEST_RESULT_FAIL)

    def addSkip(self, test, reason):
        self.stream.set_result(TEST_RESULT_SKIP)
        super().addSkip(test, reason)
        self._at_outcome_available(test.id(), TEST_RESULT_SKIP)

    def addExpectedFailure(self, test, err):
        self.stream.set_result(TEST_RESULT_EXPECTED_FAIL)
        super().addExpectedFailure(test, err)
        self._at_outcome_available(test.id(), TEST_RESULT_EXPECTED_FAIL)

    def addUnexpectedSuccess(self, test):
        self.stream.set_result(TEST_RESULT_UNEXPECTED_PASS)
        super().addUnexpectedSuccess(test)
        self._at_outcome_available(test.id(), TEST_RESULT_UNEXPECTED_PASS)


class BaseTestRunner:
    def __init__(self, manager: TestManager):
        self._manager: TestManager = manager

    def run_tests(self, *test_ids):
        raise NotImplementedError

    def iter_all_test_ids(self):
        raise NotImplementedError

    def run_single_test_partially(self, test_id, partial_mode):
        raise NotImplementedError

    @classmethod
    def last_run_info(cls):
        return TestRunInfo()

    @classmethod
    def last_run_test_ids(cls):
        return cls.last_run_info().run_test_ids

    @classmethod
    def last_failed_test_id(cls):
        return cls.last_run_info().failed_test_id

    @classmethod
    def has_last_lister_error(cls):
        return False


class PyUnitRunner(BaseTestRunner):
    _got_error = False

    def run_tests(self, *test_ids):
        self._run_tests(RUN_TEST_FULL, *test_ids)

    def _run_tests(self, partial_mode=RUN_TEST_FULL, *test_ids):
        failfast = self._manager.stop_on_error()
        PyUnitTestResult.reset_last_data()
        test_runner = PyUnitTestRunnerWrapper(
            failfast=failfast, partial_mode=partial_mode, verbosity=2
        )
        # Create a suite from the test IDs
        suite = loader.defaultTestLoader.loadTestsFromNames(test_ids)
        test_runner.run(suite)

    def run_single_test_partially(self, test_id, partial_mode):
        self._run_tests(partial_mode, test_id)

    def _collect_all_paths(self, tests):
        if isinstance(tests, suite.TestSuite):
            for t in tests:
                yield from self._collect_all_paths(t)
        else:
            yield tests.id()

    def iter_all_test_ids(self):
        self.__class__._got_error = False
        start_dir = self._manager.start_dir_or_module()
        top_dir = self._manager.top_dir()
        if not start_dir or not os.path.isdir(start_dir):
            LOGGER.warning("Start directory is not a valid directory: %s", start_dir)
            return iter([])

        if not top_dir or not os.path.isdir(top_dir):
            top_dir = os.path.dirname(start_dir)
            LOGGER.info("Top level directory not set, defaulting to: %s", top_dir)

        try:
            # Add top_dir to sys.path to ensure imports work correctly
            if top_dir not in sys.path:
                sys.path.insert(0, top_dir)
            tests = loader.defaultTestLoader.discover(start_dir, top_level_dir=top_dir)
            yield from self._collect_all_paths(tests)
        except Exception:
            self.__class__._got_error = True
            LOGGER.exception("Unable to load tests from %s", start_dir)

    @classmethod
    def has_last_lister_error(cls):
        return cls._got_error

    @classmethod
    def last_run_info(cls):
        return PyUnitTestResult.last_run_info


class InlineButtonLineEdit(QtWidgets.QLineEdit):
    def __init__(self, with_clear_button=False, parent=None):
        super().__init__(parent)
        self._buttons = collections.OrderedDict()
        self._init_margins = self.getTextMargins()
        if with_clear_button:
            self.add_clear_button()

    def add_button(self, btn_id, button):
        button.setFixedSize(QtCore.QSize(20, 20))
        button.setParent(self)
        button.setStyleSheet("QAbstractButton{background:transparent; border: none;}")
        self._buttons[btn_id] = button
        self._refresh_buttons()
        return button

    def add_clear_button(self):
        btn = make_icon_button(
            self.style().standardIcon(QtWidgets.QStyle.SP_LineEditClearButton), self
        )
        btn.setToolTip("Clear")
        btn.setVisible(False)
        btn.clicked.connect(self.clear)
        self.textChanged.connect(lambda txt: btn.setVisible(bool(txt)))
        return self.add_button("__clear__", btn)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._refresh_buttons()

    def _refresh_buttons(self):
        # Use initial text margins captured at creation
        init_left, init_top, init_right, init_bottom = self._init_margins
        right_margin = 0
        for btn in reversed(list(self._buttons.values())):
            if btn.isVisible():
                btn.move(
                    self.width() - right_margin - btn.width() - 2,
                    (self.height() - btn.height()) // 2,
                )
                right_margin += btn.width() + 2
        total_right = init_right + right_margin
        self.setTextMargins(init_left, init_top, total_right, init_bottom)


class RootPathEdit(InlineButtonLineEdit):
    root_path_changed = QtCore.pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(with_clear_button=False, parent=parent)
        self.editingFinished.connect(self.on_edit_finished)
        self._init_path = None

    def set_initial_path(self, path):
        self._init_path = path

    def setText(self, txt):
        super().setText(txt)
        self.set_initial_path(txt)

    def on_edit_finished(self):
        txt = str(self.text())
        if txt != self._init_path:
            self.set_initial_path(txt)
            self.root_path_changed.emit(txt, "")

    def _on_browse_tests_root_dir(self):
        dir_path = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Pick the Test Root Directory"
        )
        if dir_path:
            self.setText(dir_path)
            self.on_edit_finished()


class LogBrowser(QtWidgets.QTextBrowser):
    def __init__(self, parent=None):
        super().__init__(parent)
        fn = self.font()
        fn.setFamily("Courier New")
        fn.setPointSize(10)
        self.setFont(fn)
        self.setReadOnly(True)
        self.setOpenLinks(False)

    def log_with_color(self, msg, color, *args):
        self.moveCursor(QtGui.QTextCursor.End)
        self.setTextColor(color)
        msg_formatted = msg if not args else (msg % args)
        self.insertPlainText(msg_formatted)
        self.moveCursor(QtGui.QTextCursor.End)

    def log_separator(self):
        self.log_warning("\n" + ">" * 70 + "\n")

    def log_information(self, msg, *args):
        self.log_with_color(msg, LOG_COLOR_INFORMATION, *args)

    def log_success(self, msg, *args):
        self.log_with_color(msg, LOG_COLOR_SUCCESS, *args)

    def log_failed(self, msg, *args):
        self.log_with_color(msg, LOG_COLOR_FAILED, *args)

    def log_error(self, msg, *args):
        self.log_with_color(msg, LOG_COLOR_ERROR, *args)

    def log_warning(self, msg, *args):
        self.log_with_color(msg, LOG_COLOR_WARNING, *args)


class StatusLabel(QtWidgets.QLabel):
    def __init__(self, parent):
        super().__init__(parent)
        self.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self._test_manager: TestManager

    def set_test_manager(self, manager):
        self._test_manager = manager

    def update_report(self):
        if not self._test_manager:
            return
        run_info = self._test_manager.last_run_info()
        test_lbl = "tests" if run_info.run_count != 1 else "test"
        msgs = [
            f"{run_info.run_count} {test_lbl} run in {run_info.session_run_time:.3f} sec"
        ]
        if run_info.failed_count:
            msgs.append(
                f'<font color="{LOG_COLOR_FAILED.name()}">{run_info.failed_count} failed</font>'
            )
        if run_info.error_count:
            msgs.append(
                f'<font color="{LOG_COLOR_ERROR.name()}">{run_info.error_count} errors</font>'
            )
        if run_info.skip_count:
            msgs.append(
                f'<font color="{LOG_COLOR_WARNING.name()}">{run_info.skip_count} skipped</font>'
            )
        self.setText(", ".join(msgs))

    def report_test_count(self, test_count):
        self.setText(f"{test_count} tests found.")

    def start_collecting_tests(self):
        self.setText("Loading tests...")
        self.repaint()


class UnitTestTreeView(QtWidgets.QTreeWidget):
    run_all_tests = QtCore.pyqtSignal()
    run_tests = QtCore.pyqtSignal(tuple)
    run_setup_only = QtCore.pyqtSignal(str)
    run_without_tear_down = QtCore.pyqtSignal(str)

    def __init__(self, parent):
        super().__init__(parent)
        self.setColumnCount(2)
        self.setHeaderLabels(["Test", "Time (s)"])
        self.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        self.header().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        self.setAlternatingRowColors(True)
        self.setExpandsOnDoubleClick(False)
        self.setSelectionMode(self.ExtendedSelection)
        self.itemDoubleClicked.connect(
            lambda item, col: self.on_item_double_clicked(item)
        )
        self.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._make_context_menu)

        self._test_manager: TestManager
        self._all_items_id_map = {}
        self._test_cases = []
        self._root_test_item: QtWidgets.QTreeWidgetItem

    def set_test_manager(self, manager):
        self._test_manager = manager

    def on_item_double_clicked(self, item):
        if item is self._root_test_item:
            self.run_all_tests.emit()
        else:
            self.run_tests.emit((self.test_id_of_item(item),))

    def reload(self):
        self.clear()
        self._all_items_id_map.clear()
        self._test_cases.clear()

        start_dir = self._test_manager.start_dir_or_module()
        if not start_dir:
            self._root_test_item = QtWidgets.QTreeWidgetItem(
                self, ["No directory selected."]
            )
            return 0

        self._root_test_item = QtWidgets.QTreeWidgetItem(self, [start_dir])
        self._root_test_item.setData(
            0, QtCore.Qt.UserRole, (ITEM_CATEGORY_ALL, start_dir)
        )
        self._set_item_icon_state(self._root_test_item, TEST_RESULT_NONE)
        self.addTopLevelItem(self._root_test_item)
        self._all_items_id_map[start_dir] = self._root_test_item

        test_count = 0
        for test_id in self._test_manager.iter_all_test_ids():
            test_count += 1
            self._add_test_to_tree(test_id)

        self.expandAll()
        self.header().resizeSections(QtWidgets.QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        return test_count

    def _add_test_to_tree(self, test_id):
        parts = test_id.split(".")
        current_parent = self._root_test_item
        path_so_far = []
        # Build or reuse each segment node
        for part in parts[:-1]:
            path_so_far.append(part)
            new_path = ".".join(path_so_far)
            if new_path in self._all_items_id_map:
                current_parent = self._all_items_id_map[new_path]
            else:
                child = QtWidgets.QTreeWidgetItem(current_parent, [part])
                child.setData(0, QtCore.Qt.UserRole, (ITEM_CATEGORY_MODULE, new_path))
                self._set_item_icon_state(child, TEST_RESULT_NONE)
                self._all_items_id_map[new_path] = child
                current_parent = child
        # Add the actual test method as a leaf
        method_name = parts[-1]
        test_item = QtWidgets.QTreeWidgetItem(current_parent, [method_name])
        test_item.setData(0, QtCore.Qt.UserRole, (ITEM_CATEGORY_TEST, test_id))
        self._set_item_icon_state(test_item, TEST_RESULT_NONE)
        self._all_items_id_map[test_id] = test_item
        self._test_cases.append(test_item)

    def _set_item_icon_state(self, item, state):
        colors = {
            TEST_RESULT_NONE: QtGui.QColor("black"),
            TEST_RESULT_RUNNING: QtGui.QColor("blue"),
            TEST_RESULT_PASS: QtGui.QColor("darkGreen"),
            TEST_RESULT_FAIL: QtGui.QColor("red"),
            TEST_RESULT_ERROR: QtGui.QColor("darkRed"),
            TEST_RESULT_SKIP: QtGui.QColor("gray"),
        }
        color = colors.get(state, QtGui.QColor("black"))
        item.setForeground(0, QtGui.QBrush(color))
        item.setData(0, QtCore.Qt.UserRole + 1, state)

    def _update_ancestors_state(self, item):
        parent = item.parent()
        if not parent:
            return

        max_state = TEST_RESULT_NONE
        for i in range(parent.childCount()):
            child_state = parent.child(i).data(0, QtCore.Qt.UserRole + 1)
            if child_state is not None and child_state > max_state:
                max_state = child_state

        self._set_item_icon_state(parent, max_state)
        self._update_ancestors_state(parent)

    def test_id_of_item(self, item):
        data = item.data(0, QtCore.Qt.UserRole)
        return data[1] if data and len(data) > 1 else None

    def on_single_test_start(self, test_id, start_time):
        item = self._all_items_id_map.get(test_id)
        if item:
            self._set_item_icon_state(item, TEST_RESULT_RUNNING)
            item.setText(1, "running...")
            self._update_ancestors_state(item)

    def on_single_test_stop(self, test_id, end_time):
        item = self._all_items_id_map.get(test_id)
        if item:
            run_info = self._test_manager.last_run_info()
            item.setText(1, f"{run_info.single_test_run_time:.3f}")

    def show_result_on_item_by_test_id(self, test_id, state):
        item = self._all_items_id_map.get(test_id)
        if item:
            self._set_item_icon_state(item, state)
            self._update_ancestors_state(item)

    def on_all_tests_finished(self):
        pass

    def _make_context_menu(self, pos):
        item = self.itemAt(pos)
        if not item:
            return

        menu = QtWidgets.QMenu()
        test_id = self.test_id_of_item(item)
        if not test_id:
            return

        run_action = menu.addAction("Run Test(s)")
        run_action.triggered.connect(lambda: self.run_tests.emit((test_id,)))

        menu.addSeparator()

        setup_action = menu.addAction("Run setUp() only")
        setup_action.triggered.connect(lambda: self.run_setup_only.emit(test_id))

        no_teardown_action = menu.addAction("Run without tearDown()")
        no_teardown_action.triggered.connect(
            lambda: self.run_without_tear_down.emit(test_id)
        )

        is_test_case = item.data(0, QtCore.Qt.UserRole)[0] == ITEM_CATEGORY_TEST
        setup_action.setEnabled(is_test_case)
        no_teardown_action.setEnabled(is_test_case)

        menu.exec_(self.viewport().mapToGlobal(pos))


# =============================================================================
# MAIN APPLICATION FORM
# =============================================================================


class TestRunnerForm(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self._test_manager: TestManager
        self._view: UnitTestTreeView
        self._log_browser: LogBrowser
        self._status_lbl: StatusLabel
        self._run_all_btn: QtWidgets.QPushButton
        self._run_selected_btn: QtWidgets.QPushButton
        self._stop_on_error_cb: QtWidgets.QCheckBox
        self._root_dir_le: RootPathEdit

    def OnCreate(self, ctx):
        self.parent_widget: QtWidgets.QWidget = self.FormToPyQtWidget(ctx)
        self.parent_widget.setWindowTitle("IDA System Tests Runner")
        self.parent_widget.resize(900, 700)

        # Automatically detect the repository-level "tests" directory.
        # We walk up from this file until we find a sibling directory named
        # "tests" and use that as the default root for unit discovery.
        default_root: str | None = None
        try:
            current_path = Path(__file__).resolve()
            for parent in current_path.parents:
                tests_dir = parent / "tests/system"
                if tests_dir.is_dir():
                    default_root = str(tests_dir)
                    break

            if default_root is None:
                LOGGER.warning(
                    "Could not locate a top-level 'tests' directory."
                    " Please select it manually."
                )
        except Exception:
            # Unexpected failure - log but continue with no default.
            LOGGER.exception("Error while searching for default tests directory")

        self._test_manager = TestManager(
            self, start_dir_or_module=default_root, top_dir=None
        )

        main_lay = make_main_layout(self.parent_widget)

        dir_layout = make_minor_horizontal_layout()
        label = QtWidgets.QLabel("Test Root:")
        dir_layout.addWidget(label)
        # add a little extra space before the separator
        dir_layout.addSpacing(6)
        # Add a vertical separator for visual spacing
        separator = QtWidgets.QFrame(self.parent_widget)
        separator.setFrameShape(QtWidgets.QFrame.VLine)
        separator.setFrameShadow(QtWidgets.QFrame.Sunken)
        dir_layout.addWidget(separator)
        # Increase spacing between elements
        dir_layout.setSpacing(8)
        self._root_dir_le = RootPathEdit(self.parent_widget)
        self._root_dir_le.root_path_changed.connect(self._on_test_root_changed)
        # Ensure the path field expands
        self._root_dir_le.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed
        )
        dir_layout.addWidget(self._root_dir_le, 1)
        # External browse button next to the line edit
        browse_btn = QtWidgets.QPushButton(self.parent_widget)
        browse_btn.setIcon(
            self.parent_widget.style().standardIcon(QtWidgets.QStyle.SP_DirOpenIcon)
        )
        browse_btn.setToolTip("Browse")
        browse_btn.clicked.connect(self._root_dir_le._on_browse_tests_root_dir)
        dir_layout.addWidget(browse_btn)
        self._stop_on_error_cb = QtWidgets.QCheckBox("Stop on Error")
        self._stop_on_error_cb.toggled.connect(self._test_manager.set_stop_on_error)
        dir_layout.addWidget(self._stop_on_error_cb)
        main_lay.addLayout(dir_layout)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical, self.parent_widget)
        main_lay.addWidget(splitter, 1)

        tree_widget = QtWidgets.QWidget()
        tree_layout = QtWidgets.QVBoxLayout(tree_widget)
        tree_layout.setContentsMargins(0, 0, 0, 0)
        self._view = UnitTestTreeView(tree_widget)
        self._view.set_test_manager(self._test_manager)
        tree_layout.addWidget(self._view)
        splitter.addWidget(tree_widget)

        log_widget = QtWidgets.QWidget()
        log_layout = QtWidgets.QVBoxLayout(log_widget)
        log_layout.setContentsMargins(0, 0, 0, 0)
        log_layout.addWidget(QtWidgets.QLabel("Log Output"))
        self._log_browser = LogBrowser(log_widget)
        log_layout.addWidget(self._log_browser)
        splitter.addWidget(log_widget)

        splitter.setSizes([400, 300])

        self._status_lbl = StatusLabel(self.parent_widget)
        self._status_lbl.set_test_manager(self._test_manager)
        main_lay.addWidget(self._status_lbl)

        btn_layout = make_minor_horizontal_layout()
        # Add buttons: Reload Tests, Run Selected, Run All
        btn_layout.addStretch(1)
        self._reload_btn = QtWidgets.QPushButton("Reload Tests")
        self._reload_btn.clicked.connect(self.reload_tests)
        btn_layout.addWidget(self._reload_btn)
        self._run_selected_btn = QtWidgets.QPushButton("Run Selected")
        self._run_selected_btn.clicked.connect(self._run_view_selected_tests)
        btn_layout.addWidget(self._run_selected_btn)
        self._run_all_btn = QtWidgets.QPushButton("Run All")
        self._run_all_btn.clicked.connect(self._run_all_tests)
        btn_layout.addWidget(self._run_all_btn)
        main_lay.addLayout(btn_layout)

        self._view.run_all_tests.connect(self._run_all_tests)
        self._view.run_tests.connect(self._run_tests)
        self._view.run_setup_only.connect(self._run_test_setup_only)
        self._view.run_without_tear_down.connect(self._run_test_without_tear_down)

        UiStream.set_ui(self)

        # Prepopulate the root path selector and load tests
        try:
            default_root = self._test_manager.start_dir_or_module()
            if default_root:
                self._root_dir_le.setText(default_root)
                self._root_dir_le.set_initial_path(default_root)
                self.reload_tests()
        except Exception:
            LOGGER.exception("Failed to set initial test view")

    def OnClose(self, form):
        UiStream.unset_ui(self)

    def _on_test_root_changed(self, start_dir, top_dir):
        self._test_manager.set_dirs(start_dir, top_dir)
        self.reload_tests()

    def reload_tests(self):
        self._status_lbl.start_collecting_tests()
        self._test_manager.reload_test_modules()
        test_count = self._view.reload()
        self.repaint_ui()
        self._status_lbl.report_test_count(test_count)

    def _run_all_tests(self):
        self._before_running_tests()
        self._test_manager.run_all_tests()

    def _run_tests(self, test_ids):
        if not test_ids:
            return
        self._before_running_tests()
        self._test_manager.run_tests(*test_ids)

    def _run_view_selected_tests(self):
        selected_ids = [
            self._view.test_id_of_item(item) for item in self._view.selectedItems()
        ]
        if selected_ids:
            self._run_tests(tuple(filter(None, selected_ids)))

    def _run_test_setup_only(self, test_id):
        self._before_running_tests()
        self._test_manager.run_single_test_partially(test_id, RUN_TEST_SETUP_ONLY)

    def _run_test_without_tear_down(self, test_id):
        self._before_running_tests()
        self._test_manager.run_single_test_partially(test_id, RUN_TEST_NO_TEAR_DOWN)

    def _before_running_tests(self):
        self._log_browser.clear()
        self._log_browser.log_separator()

    def get_log_browser_widget(self):
        return self._log_browser

    def on_test_running_session_start(self):
        self._status_lbl.setText("Running tests...")

    def on_all_tests_finished(self):
        self._status_lbl.update_report()
        self._view.on_all_tests_finished()

    def on_single_test_start(self, test_id, start_time):
        self._view.on_single_test_start(test_id, start_time)

    def on_single_test_stop(self, test_id, end_time):
        self._view.on_single_test_stop(test_id, end_time)
        self._status_lbl.update_report()

    def show_result_on_item_by_test_id(self, test_id, state):
        self._view.show_result_on_item_by_test_id(test_id, state)

    def repaint_ui(self):
        QtWidgets.QApplication.processEvents(QtCore.QEventLoop.ExcludeUserInputEvents)


# =============================================================================
# CONVENIENCE HELPER
# =============================================================================


def show_gui():
    """Launch or focus the IDA test runner GUI."""
    form_title = "IDA Unit Test Runner"
    form = ida_kernwin.find_widget(form_title)
    if form:
        ida_kernwin.activate_widget(form, True)
    else:
        form = TestRunnerForm()
        form.Show(
            form_title,
            options=ida_kernwin.PluginForm.WOPN_TAB
            | ida_kernwin.PluginForm.WCLS_CLOSE_LATER,
        )


# Example of how to run this in IDA
if __name__ == "__main__":
    show_gui()
