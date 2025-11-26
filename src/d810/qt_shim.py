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

import sys
from typing import TYPE_CHECKING, Literal, Union, cast

if TYPE_CHECKING:
    # Type stubs for Qt classes - these are only used for type checking
    # The actual imports happen at runtime below
    pass


# Version detection constants (similar to six.PY2, six.PY3)
# Initialize with defaults, will be reassigned based on available Qt binding
QT5: bool = False
QT6: bool = False
QT_VERSION: Literal[5, 6] = 5  # type: ignore[assignment]
QT_BINDING: Literal["PyQt5", "PySide6"] = "PyQt5"  # type: ignore[assignment]

# Try PySide6 first (IDA 9.2+, Qt6)
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
            QPixmap,
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
            QPushButton,
            QSizePolicy,
            QShortcut,
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


def get_text_margins_as_tuple(line_edit: QLineEdit) -> tuple[int, int, int, int]:
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
    "QObject",
    "QTimer",
    # Qt Gui
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
    "QHBoxLayout",
    "QLabel",
    "QLineEdit",
    "QMainWindow",
    "QMenu",
    "QMessageBox",
    "QPushButton",
    "QShortcut",
    "QSplitter",
    "QStatusBar",
    "QStyleFactory",
    "QTabWidget",
    "QTextEdit",
    "QTreeWidget",
    "QTreeWidgetItem",
    "QVBoxLayout",
    "QWidget",
    "QSizePolicy",
    "QHeaderView",
    # Utility functions
    "set_high_dpi_attributes",
    "get_text_margins_as_tuple",
    "qt_flag_or",
    "wrapinstance",
]
