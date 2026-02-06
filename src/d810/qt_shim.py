"""
Qt Compatibility Shim for PyQt5 and PySide6

This module provides a compatibility layer between PyQt5 (Qt5) and PySide6 (Qt6),
similar to Python's 'six' module. It automatically detects and imports the
appropriate Qt binding and provides a unified API.

Inspired by Python's six module (https://github.com/benjaminp/six).

Usage:
    from qt_shim import Qt, QApplication, QWidget, QT5, QT6, QT_VERSION, QT_BINDING

    # Use Qt enums and classes normally
    widget = QWidget()
    widget.setWindowTitle("Test")

    # Check version using boolean constants (similar to six.PY2, six.PY3)
    if QT6:
        # Qt6-specific code
        pass

    # Or check version number
    if QT_VERSION == 6:
        # Qt6-specific code
        pass

    # Or check binding name
    if QT_BINDING == "PySide6":
        # PySide6-specific code
        pass
"""

from __future__ import annotations

import pathlib
import sys
from typing import Any, Literal, Union, cast


def _is_ida_gui_available() -> bool:
    """Check if we're running in IDA GUI mode where Qt is available.

    Returns True if:
    - Running inside IDA Pro GUI (ida64/ida32, not idat64/idat32)
    - Qt bindings should be importable

    Returns False if:
    - Running in headless IDA (idat64/idat32)
    - Running via idalib/idapro module
    - Running in pytest or other non-GUI environment
    """
    exec_name = pathlib.Path(sys.executable).name.lower()

    # Check if we're in IDA at all
    in_ida = exec_name.startswith("ida")
    if in_ida:
        try:
            import idaapi
        except ImportError:
            return False

    return idaapi.is_idaq() if in_ida else False


# Skip Qt imports entirely if not in GUI mode
_QT_AVAILABLE = _is_ida_gui_available()


# Version detection constants (similar to six.PY2, six.PY3)
# Initialize with defaults, will be reassigned based on available Qt binding
QT5: bool = False
QT6: bool = False
QT_VERSION: Literal[5, 6] = 5  # type: ignore[assignment]
QT_BINDING: Literal["PyQt5", "PySide6"] = "PyQt5"  # type: ignore[assignment]

# Skip Qt imports if not in GUI mode - prevents errors in headless/idalib mode
if not _QT_AVAILABLE:
    # Create stub classes/values that will fail gracefully if used
    class ProxyClass: ...

    class ProxyNamespace: ...

    class QtCore(ProxyNamespace):
        class Qt(ProxyNamespace):
            # ItemDataRole enum values
            UserRole: int = ...  # type: ignore[assignment]

            # TextInteractionFlag enum values
            TextSelectableByMouse: int = ...  # type: ignore[assignment]

            # ContextMenuPolicy enum values
            CustomContextMenu: int = ...  # type: ignore[assignment]

            # Orientation enum values
            Vertical: int = ...  # type: ignore[assignment]

        class QSize(ProxyClass):
            def __init__(self, w: int, h: int) -> None: ...

        class QEventLoop(ProxyNamespace):
            # ProcessEventsFlag enum values
            ExcludeUserInputEvents: int = ...  # type: ignore[assignment]

        class QMetaObject(ProxyClass):
            @classmethod
            def connectSlotsByName(cls, *args) -> None: ...

        class QEvent(ProxyClass): ...

        class QObject(ProxyClass):
            flags: Any

            def metaObject(self): ...
            def objectName(self): ...

        class QTimer(ProxyClass): ...

        # Signal/Slot compatibility (will be set up by _setup_compatibility)
        def pyqtSignal(*args, **kwargs): ...  # type: ignore[misc]

    class QtGui(ProxyNamespace):
        class QColor(ProxyClass):
            def __init__(self, *args) -> None: ...
            def name(self) -> str: ...

        class QTextCursor(ProxyNamespace):
            # MoveOperation enum values
            End: int = ...  # type: ignore[assignment]

        class QBrush(ProxyClass):
            def __init__(self, color: Any) -> None: ...

        class QIcon(ProxyClass):
            class fromTheme(ProxyClass): ...

        class QConicalGradient(ProxyClass): ...

        class QLinearGradient(ProxyClass): ...

        class QRadialGradient(ProxyClass): ...

        class QPainter(ProxyClass): ...

        class QPalette(ProxyClass): ...

        class QFont(ProxyClass): ...

        class QFontDatabase(ProxyClass): ...

        class QCursor(ProxyClass): ...

        class QKeyEvent(ProxyClass): ...

        class QKeySequence(ProxyClass): ...

        class QPixmap(ProxyClass): ...

        class QShortcut(ProxyClass): ...

        class QAction(QtCore.QObject): ...

        class QActionGroup(QtCore.QObject): ...

    class QtWidgets(ProxyNamespace):
        class QApplication(QtCore.QObject):
            @staticmethod
            def translate(uiname, text, disambig): ...
            @staticmethod
            def processEvents(flags: int = ...) -> None: ...
            @staticmethod
            def setAttribute(attribute: int, on: bool = ...) -> None: ...

        class QSpacerItem(ProxyClass): ...

        class QSizePolicy(ProxyClass):
            Expanding: int = ...  # type: ignore[assignment]
            Fixed: int = ...  # type: ignore[assignment]

        class QButtonGroup(QtCore.QObject): ...

        class QLayout(QtCore.QObject):
            def addWidget(self, widget: Any, stretch: int = ...) -> None: ...
            def setContentsMargins(
                self, left: int, top: int, right: int, bottom: int
            ) -> None: ...
            def setSpacing(self, spacing: int) -> None: ...

        class QGridLayout(QLayout): ...

        class QBoxLayout(QLayout): ...

        class QHBoxLayout(QBoxLayout):
            def __init__(self, parent: Any = ...) -> None: ...
            def addSpacing(self, size: int) -> None: ...

        class QVBoxLayout(QBoxLayout):
            def __init__(self, parent: Any = ...) -> None: ...

        class QFormLayout(QLayout): ...

        class QWidget(QtCore.QObject):
            def __init__(self, parent: Any = ...) -> None: ...
            def font(self): ...
            def minimumSizeHint(self): ...
            def sizePolicy(self): ...
            def style(self): ...
            def width(self) -> int: ...
            def height(self) -> int: ...
            def resize(self, w: int, h: int) -> None: ...
            def setWindowTitle(self, title: str) -> None: ...

        class QDialog(QWidget): ...

        class QColorDialog(QDialog): ...

        class QAbstractItemView(QWidget): ...

        class QComboBox(QWidget): ...

        class QMainWindow(QWidget): ...

        class QMessageBox(QWidget): ...

        class QStatusBar(QWidget): ...

        class QStyleFactory(ProxyClass): ...

        class QTabWidget(QWidget): ...

        class QTextEdit(QWidget): ...

        class QPushButton(QWidget):
            def __init__(self, text: str = ..., parent: Any = ...) -> None: ...
            def setIcon(self, icon: Any) -> None: ...
            def setFlat(self, flat: bool) -> None: ...
            def setIconSize(self, size: Any) -> None: ...
            def setFixedSize(self, size: Any) -> None: ...
            def setToolTip(self, tip: str) -> None: ...
            def clicked(self): ...  # Signal

        class QToolButton(QWidget):
            def __init__(self, parent: Any = ...) -> None: ...
            def setIcon(self, icon: Any) -> None: ...
            def setToolTip(self, tip: str) -> None: ...
            def setContentsMargins(
                self, left: int, top: int, right: int, bottom: int
            ) -> None: ...
            def setIconSize(self, size: Any) -> None: ...
            def setPopupMode(self, mode: int) -> None: ...
            def setMenu(self, menu: Any) -> None: ...
            def clicked(self): ...  # Signal

        class QMenu(QWidget):
            def __init__(self, parent: Any = ...) -> None: ...
            def addAction(self, text: str) -> Any: ...
            def addSeparator(self) -> Any: ...
            def exec_(self, pos: Any) -> Any: ...

        class QLineEdit(QWidget):
            def __init__(self, parent: Any = ...) -> None: ...
            def text(self) -> str: ...
            def setText(self, text: str) -> None: ...
            def textMargins(self) -> Any: ...
            def setTextMargins(
                self, left: int, top: int, right: int, bottom: int
            ) -> None: ...
            def textChanged(self): ...  # Signal
            def editingFinished(self): ...  # Signal
            def clear(self) -> None: ...
            def resizeEvent(self, event: Any) -> None: ...

        class QTextBrowser(QWidget):
            def __init__(self, parent: Any = ...) -> None: ...
            def font(self): ...
            def setFont(self, font: Any) -> None: ...
            def setReadOnly(self, readonly: bool) -> None: ...
            def setOpenLinks(self, open: bool) -> None: ...
            def moveCursor(self, operation: int, mode: int = ...) -> None: ...
            def setTextColor(self, color: Any) -> None: ...
            def insertPlainText(self, text: str) -> None: ...
            def clear(self) -> None: ...

        class QLabel(QWidget):
            def __init__(self, text: str = ..., parent: Any = ...) -> None: ...
            def setText(self, text: str) -> None: ...
            def setTextInteractionFlags(self, flags: int) -> None: ...
            def repaint(self) -> None: ...

        class QTreeWidget(QWidget):
            def __init__(self, parent: Any = ...) -> None: ...
            def setColumnCount(self, columns: int) -> None: ...
            def setHeaderLabels(self, labels: list[str]) -> None: ...
            def header(self) -> Any: ...
            def setAlternatingRowColors(self, enable: bool) -> None: ...
            def setExpandsOnDoubleClick(self, enable: bool) -> None: ...
            def setSelectionMode(self, mode: int) -> None: ...
            def itemDoubleClicked(self): ...  # Signal
            def setContextMenuPolicy(self, policy: int) -> None: ...
            def customContextMenuRequested(self): ...  # Signal
            def clear(self) -> None: ...
            def addTopLevelItem(self, item: Any) -> None: ...
            def expandAll(self) -> None: ...
            def selectedItems(self) -> list[Any]: ...
            def itemAt(self, pos: Any) -> Any: ...
            def viewport(self) -> Any: ...

            ExtendedSelection: int = ...  # type: ignore[assignment]

        class QTreeWidgetItem:
            def __init__(self, parent: Any = ..., strings: list[str] = ...) -> None: ...
            def setData(self, column: int, role: int, value: Any) -> None: ...
            def data(self, column: int, role: int) -> Any: ...
            def setForeground(self, column: int, brush: Any) -> None: ...
            def setText(self, column: int, text: str) -> None: ...
            def text(self, column: int) -> str: ...
            def parent(self) -> Any: ...
            def childCount(self) -> int: ...
            def child(self, index: int) -> Any: ...

        class QFileDialog:
            @staticmethod
            def getExistingDirectory(
                parent: Any = ..., caption: str = ..., directory: str = ...
            ) -> str: ...

        class QCheckBox(QWidget):
            def __init__(self, text: str = ..., parent: Any = ...) -> None: ...
            def toggled(self): ...  # Signal

        class QSplitter(QWidget):
            def __init__(self, orientation: int = ..., parent: Any = ...) -> None: ...
            def addWidget(self, widget: Any) -> None: ...
            def setSizes(self, sizes: list[int]) -> None: ...

        class QFrame(QWidget):
            def __init__(self, parent: Any = ...) -> None: ...
            def setFrameShape(self, shape: int) -> None: ...
            def setFrameShadow(self, shadow: int) -> None: ...

            VLine: int = ...  # type: ignore[assignment]
            Sunken: int = ...  # type: ignore[assignment]

        class QHeaderView:
            Stretch: int = ...  # type: ignore[assignment]
            ResizeToContents: int = ...  # type: ignore[assignment]

            def setSectionResizeMode(self, logicalIndex: int, mode: int) -> None: ...
            def resizeSections(self, mode: int) -> None: ...

        class QStyle:
            SP_LineEditClearButton: int = ...  # type: ignore[assignment]
            SP_DirOpenIcon: int = ...  # type: ignore[assignment]

            def standardIcon(self, standardIcon: int) -> Any: ...

    # Type aliases for convenience imports - reference the classes from namespaces
    Qt = QtCore.Qt
    QEvent = QtCore.QEvent
    QEventLoop = QtCore.QEventLoop
    QObject = QtCore.QObject
    QSize = QtCore.QSize
    QTimer = QtCore.QTimer
    QBrush = QtGui.QBrush
    QColor = QtGui.QColor
    QCursor = QtGui.QCursor
    QFont = QtGui.QFont
    QIcon = QtGui.QIcon
    QKeyEvent = QtGui.QKeyEvent
    QKeySequence = QtGui.QKeySequence
    QPalette = QtGui.QPalette
    QPixmap = QtGui.QPixmap
    QShortcut = QtGui.QShortcut
    QTextCursor = QtGui.QTextCursor
    QAbstractItemView = QtWidgets.QAbstractItemView
    QApplication = QtWidgets.QApplication
    QCheckBox = QtWidgets.QCheckBox
    QComboBox = QtWidgets.QComboBox
    QDialog = QtWidgets.QDialog
    QFileDialog = QtWidgets.QFileDialog
    QFrame = QtWidgets.QFrame
    QHBoxLayout = QtWidgets.QHBoxLayout
    QHeaderView = QtWidgets.QHeaderView
    QLabel = QtWidgets.QLabel
    QLineEdit = QtWidgets.QLineEdit
    QMainWindow = QtWidgets.QMainWindow
    QMenu = QtWidgets.QMenu
    QMessageBox = QtWidgets.QMessageBox
    QPushButton = QtWidgets.QPushButton
    QSizePolicy = QtWidgets.QSizePolicy
    QSplitter = QtWidgets.QSplitter
    QStatusBar = QtWidgets.QStatusBar
    QStyle = QtWidgets.QStyle
    QStyleFactory = QtWidgets.QStyleFactory
    QTabWidget = QtWidgets.QTabWidget
    QTextBrowser = QtWidgets.QTextBrowser
    QTextEdit = QtWidgets.QTextEdit
    QToolButton = QtWidgets.QToolButton
    QTreeWidget = QtWidgets.QTreeWidget
    QTreeWidgetItem = QtWidgets.QTreeWidgetItem
    QVBoxLayout = QtWidgets.QVBoxLayout
    QWidget = QtWidgets.QWidget
    _QT_MODULE = None
# Try PySide6 first (IDA 9.2+, Qt6)
else:
    try:
        from PySide6 import QtCore, QtGui, QtWidgets
        from PySide6.QtCore import QEvent, QObject, Qt, QTimer
        from PySide6.QtGui import (
            QColor,
            QCursor,
            QFont,
            QIcon,
            QKeyEvent,
            QKeySequence,
            QPalette,
            QPixmap,
            QShortcut,
            QTextCursor,
        )
        from PySide6.QtWidgets import (
            QAbstractItemView,
            QApplication,
            QCheckBox,
            QComboBox,
            QDialog,
            QFileDialog,
            QHBoxLayout,
            QHeaderView,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMenu,
            QMessageBox,
            QPushButton,
            QSizePolicy,
            QSplitter,
            QStatusBar,
            QStyleFactory,
            QTabWidget,
            QTextEdit,
            QTreeWidget,
            QTreeWidgetItem,
            QVBoxLayout,
            QWidget,
        )

        QT_VERSION = 6  # type: ignore[assignment]
        QT_BINDING = "PySide6"  # type: ignore[assignment]
        QT5 = False
        QT6 = True
        _QT_MODULE = "PySide6"
    except ImportError:
        # Fall back to PyQt5 (IDA 9.1, Qt5)
        try:
            from PyQt5 import QtCore, QtGui, QtWidgets, sip
            from PyQt5.QtCore import QEvent, QObject, Qt, QTimer
            from PyQt5.QtGui import (
                QColor,
                QCursor,
                QFont,
                QIcon,
                QKeyEvent,
                QKeySequence,
                QPalette,
                QTextCursor,
            )
            from PyQt5.QtWidgets import (
                QAbstractItemView,
                QApplication,
                QCheckBox,
                QComboBox,
                QDialog,
                QFileDialog,
                QHBoxLayout,
                QHeaderView,
                QLabel,
                QLineEdit,
                QMainWindow,
                QMenu,
                QMessageBox,
                QPixmap,
                QPushButton,
                QShortcut,
                QSizePolicy,
                QSplitter,
                QStatusBar,
                QStyleFactory,
                QTabWidget,
                QTextEdit,
                QTreeWidget,
                QTreeWidgetItem,
                QVBoxLayout,
                QWidget,
            )

            QT_VERSION = 5  # type: ignore[assignment]
            QT_BINDING = "PyQt5"  # type: ignore[assignment]
            QT5 = True
            QT6 = False
            _QT_MODULE = "PyQt5"
        except ImportError:
            raise ImportError(
                "Neither PySide6 nor PyQt5 could be imported. "
                "Please ensure one of them is installed."
            ) from None
    else:
        # shiboken6 is only needed for PySide6
        try:
            import shiboken6  # import shiboken6 for PySide6 only
        except ImportError:
            print(
                "shiboken6 could not be imported. Please ensure it is installed.",
                file=sys.stderr,
                flush=True,
            )
            shiboken6 = None


def _setup_compatibility() -> None:
    """
    Set up compatibility shims for API differences between PyQt5 and PySide6.

    This function handles:
    - exec_() vs exec() method naming differences
    - Keyboard modifier enum access patterns
    - pyqtSignal/pyqtSlot aliases for PySide6
    """
    if not _QT_AVAILABLE:
        return
    if not QT_VERSION or QT_VERSION != 6:
        return

    # PySide6 uses exec() instead of exec_()
    # Create exec_ alias for backward compatibility
    if not hasattr(QMessageBox, "exec_"):
        QMessageBox.exec_ = QMessageBox.exec  # type: ignore[method-assign]
    if not hasattr(QMenu, "exec_"):
        QMenu.exec_ = QMenu.exec  # type: ignore[method-assign]

    # PySide6 uses Signal/Slot, but PyQt5 uses pyqtSignal/pyqtSlot
    # Create aliases for backward compatibility
    if not hasattr(QtCore, "pyqtSignal"):
        QtCore.pyqtSignal = QtCore.Signal  # type: ignore[attr-defined]
    if not hasattr(QtCore, "pyqtSlot"):
        QtCore.pyqtSlot = QtCore.Slot  # type: ignore[attr-defined]

    # Ensure keyboard modifier shortcuts work (Qt.CTRL, Qt.ALT, etc.)
    # PySide6 may use different enum access patterns
    if not hasattr(Qt, "CTRL"):
        if hasattr(Qt, "KeyboardModifier"):
            Qt.CTRL = Qt.KeyboardModifier.ControlModifier  # type: ignore[attr-defined]
        elif hasattr(Qt, "ControlModifier"):
            Qt.CTRL = Qt.ControlModifier  # type: ignore[attr-defined]
    if not hasattr(Qt, "ALT"):
        if hasattr(Qt, "KeyboardModifier"):
            Qt.ALT = Qt.KeyboardModifier.AltModifier  # type: ignore[attr-defined]
        elif hasattr(Qt, "AltModifier"):
            Qt.ALT = Qt.AltModifier  # type: ignore[attr-defined]
    if not hasattr(Qt, "SHIFT"):
        if hasattr(Qt, "KeyboardModifier"):
            Qt.SHIFT = Qt.KeyboardModifier.ShiftModifier  # type: ignore[attr-defined]
        elif hasattr(Qt, "ShiftModifier"):
            Qt.SHIFT = Qt.ShiftModifier  # type: ignore[attr-defined]

    # QTreeWidget selection mode compatibility
    # PySide6 uses QAbstractItemView.SelectionMode.ExtendedSelection
    # PyQt5 uses QTreeWidget.ExtendedSelection
    # Add compatibility attributes to QTreeWidget for PySide6
    # In PySide6, SelectionMode enum exists but hasattr returns False
    # Try direct access - it may work even though hasattr returns False
    try:
        # Direct access to enum values (works even if hasattr returns False)
        QTreeWidget.ExtendedSelection = QAbstractItemView.SelectionMode.ExtendedSelection  # type: ignore[attr-defined]
        QTreeWidget.SingleSelection = QAbstractItemView.SelectionMode.SingleSelection  # type: ignore[attr-defined]
        QTreeWidget.MultiSelection = QAbstractItemView.SelectionMode.MultiSelection  # type: ignore[attr-defined]
        QTreeWidget.NoSelection = QAbstractItemView.SelectionMode.NoSelection  # type: ignore[attr-defined]
        QTreeWidget.ContiguousSelection = QAbstractItemView.SelectionMode.ContiguousSelection  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        # Fallback: try QTreeWidget.SelectionMode (shouldn't happen in PySide6)
        try:
            QTreeWidget.ExtendedSelection = QTreeWidget.SelectionMode.ExtendedSelection  # type: ignore[attr-defined]
            QTreeWidget.SingleSelection = QTreeWidget.SelectionMode.SingleSelection  # type: ignore[attr-defined]
            QTreeWidget.MultiSelection = QTreeWidget.SelectionMode.MultiSelection  # type: ignore[attr-defined]
            QTreeWidget.NoSelection = QTreeWidget.SelectionMode.NoSelection  # type: ignore[attr-defined]
            QTreeWidget.ContiguousSelection = QTreeWidget.SelectionMode.ContiguousSelection  # type: ignore[attr-defined]
        except (AttributeError, TypeError):
            # If both fail, we can't set up the compatibility shim
            # This should not happen in normal circumstances
            pass


def set_high_dpi_attributes() -> None:
    """
    Set High DPI scaling attributes appropriate for the Qt version.

    In Qt5, we need to explicitly enable High DPI scaling.
    In Qt6, High DPI scaling is enabled by default, but we can set rounding policy.

    This function should be called before creating the QApplication instance
    for best results.
    """
    if not _QT_AVAILABLE or QApplication is None:
        return
    if QT_VERSION == 5:
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)  # type: ignore[attr-defined]
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)  # type: ignore[attr-defined]
    elif QT_VERSION == 6:
        # Qt6: High DPI scaling is always enabled, but we can set rounding policy
        try:
            QApplication.setAttribute(
                Qt.HighDpiScaleFactorRoundingPolicy.PassThrough, True  # type: ignore[attr-defined]
            )
        except AttributeError:
            # Attribute might not exist in all Qt6 versions
            pass


def get_text_margins_as_tuple(line_edit: "QLineEdit") -> tuple[int, int, int, int]:
    """
    Get text margins from a QLineEdit as a tuple, compatible with both Qt5 and Qt6.

    In both Qt5 and Qt6, textMargins() returns a QMargins object.
    This function converts it to a tuple for easier use.

    Args:
        line_edit: The QLineEdit widget to get margins from.

    Returns:
        A tuple (left, top, right, bottom) of margin values.
    """
    # QLineEdit uses textMargins() method, not getTextMargins()
    margins = line_edit.textMargins()
    # QMargins object has left(), top(), right(), bottom() methods
    if hasattr(margins, "left"):
        # QMargins object (both Qt5 and Qt6)
        return (margins.left(), margins.top(), margins.right(), margins.bottom())
    else:
        # Fallback: if it's already a tuple, return as-is
        return margins


def qt_flag_or(*flags) -> Union[int, "Qt.ItemFlag"]:  # type: ignore[valid-type]
    """
    Helper function to combine Qt flags that works with both PyQt5 and PySide6.

    In PySide6, enum flags need to use .value for bitwise operations, and the result
    must be converted back to the enum type using Qt.ItemFlag.
    In PyQt5, flags can be used directly as integers.

    Args:
        *flags: Variable number of Qt flag enum values to combine.

    Returns:
        Combined flags as an integer (PyQt5) or ItemFlag enum type (PySide6).
    """
    if not flags:
        return 0

    result = 0
    for flag in flags:
        # PySide6: use .value, PyQt5: flags are already integers
        flag_value = flag.value if hasattr(flag, "value") else int(flag)
        result |= flag_value

    # In PySide6, convert the integer result back to Qt.ItemFlag enum type
    if QT6:
        try:
            # Use Qt.ItemFlag to construct the enum from the combined integer value
            item_flag = Qt.ItemFlag(result)  # type: ignore[call-overload]
            return cast("Qt.ItemFlag", item_flag)
        except (ValueError, TypeError, AttributeError):
            # If conversion fails, return int (fallback)
            return result

    # PyQt5: Attempt to return Qt.ItemFlags object to satisfy strict type checks
    # Some bindings (like IDA's) are strict about types and don't accept raw ints
    try:
        return Qt.ItemFlags(result)  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        return result


def wrapinstance(ptr: int, base) -> object:
    """
    Wrap a C++ pointer as a Python Qt object, compatible with both PyQt5 and PySide6.

    In PyQt5, this is sip.wrapinstance().
    In PySide6, this is shiboken6.wrapInstance() (note the capital I).

    Args:
        ptr: Integer pointer value to wrap.
        base: Base class type (e.g., QWidget, QMenu).

    Returns:
        Wrapped Qt object instance.
    """
    if QT6:
        return shiboken6.wrapInstance(ptr, base)  # type: ignore[name-defined]
    else:
        return sip.wrapinstance(ptr, base)  # type: ignore[name-defined]


# Set up compatibility shims immediately upon import
_setup_compatibility()

# Export all Qt classes and constants for easy importing
__all__ = [
    # Version constants (similar to six.PY2, six.PY3)
    "QT5",
    "QT6",
    "QT_VERSION",
    "QT_BINDING",
    # Qt modules (for module-style imports)
    "QtCore",
    "QtGui",
    "QtWidgets",
    # Qt Core
    "Qt",
    "QEvent",
    "QEventLoop",
    "QObject",
    "QSize",
    "QTimer",
    # Qt Gui
    "QBrush",
    "QCursor",
    "QFont",
    "QKeyEvent",
    "QKeySequence",
    "QPalette",
    "QPixmap",
    "QColor",
    "QIcon",
    "QTextCursor",
    # Qt Widgets
    "QAbstractItemView",
    "QApplication",
    "QCheckBox",
    "QComboBox",
    "QDialog",
    "QFileDialog",
    "QFrame",
    "QHBoxLayout",
    "QHeaderView",
    "QLabel",
    "QLineEdit",
    "QMainWindow",
    "QMenu",
    "QMessageBox",
    "QPushButton",
    "QShortcut",
    "QSplitter",
    "QStatusBar",
    "QStyle",
    "QStyleFactory",
    "QTabWidget",
    "QTextBrowser",
    "QTextEdit",
    "QToolButton",
    "QTreeWidget",
    "QTreeWidgetItem",
    "QVBoxLayout",
    "QWidget",
    "QSizePolicy",
    # Utility functions
    "set_high_dpi_attributes",
    "get_text_margins_as_tuple",
    "qt_flag_or",
    "wrapinstance",
]
