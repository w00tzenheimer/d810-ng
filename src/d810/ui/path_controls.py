"""Reusable Qt path controls with one directory-selection policy."""

from __future__ import annotations

from d810.qt_shim import QtWidgets, qt_flag_or
from d810.ui.path_controls_logic import (
    directory_chooser_initial_path,
    file_chooser_initial_path,
)


class DirectoryPathField(QtWidgets.QWidget):
    """Editable directory path with the shared native directory chooser."""

    def __init__(
        self,
        *,
        path: str = "",
        dialog_title: str = "Choose directory",
        parent: object | None = None,
    ) -> None:
        super().__init__(parent)
        self._dialog_title = dialog_title
        self.line_edit = QtWidgets.QLineEdit(self)
        self.line_edit.setText(str(path))
        self.choose_button = QtWidgets.QPushButton("Choose...", self)
        self.choose_button.setToolTip("Choose an existing directory")
        self.choose_button.clicked.connect(self.choose_directory)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(self.line_edit, 1)
        layout.addWidget(self.choose_button)

    def path(self) -> str:
        return self.line_edit.text().strip()

    def set_path(self, path: str) -> None:
        self.line_edit.setText(str(path))

    def choose_directory(self, _checked: bool = False) -> None:
        selected = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            self._dialog_title,
            directory_chooser_initial_path(self.path()),
            qt_flag_or(
                QtWidgets.QFileDialog.ShowDirsOnly,
                QtWidgets.QFileDialog.DontResolveSymlinks,
            ),
        )
        if selected:
            self.set_path(selected)


class FilePathField(QtWidgets.QWidget):
    """Editable save-file path with the shared native file chooser."""

    def __init__(
        self,
        *,
        path: str = "",
        dialog_title: str = "Choose output file",
        file_filter: str = "All files (*)",
        suggested_filename: str = "",
        parent: object | None = None,
    ) -> None:
        super().__init__(parent)
        self._dialog_title = dialog_title
        self._file_filter = file_filter
        self._suggested_filename = suggested_filename
        self.line_edit = QtWidgets.QLineEdit(self)
        self.line_edit.setText(str(path))
        self.choose_button = QtWidgets.QPushButton("Choose...", self)
        self.choose_button.setToolTip("Choose an output file")
        self.choose_button.clicked.connect(self.choose_file)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(self.line_edit, 1)
        layout.addWidget(self.choose_button)

    def path(self) -> str:
        return self.line_edit.text().strip()

    def set_path(self, path: str) -> None:
        self.line_edit.setText(str(path))

    def choose_file(self, _checked: bool = False) -> None:
        selected, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            self._dialog_title,
            file_chooser_initial_path(
                self.path(),
                suggested_filename=self._suggested_filename,
            ),
            self._file_filter,
        )
        if selected:
            self.set_path(selected)


class CopyPathButton(QtWidgets.QToolButton):
    """Compact, explicit clipboard action for a resolved local path."""

    def __init__(
        self,
        label: str,
        *,
        parent: object | None = None,
    ) -> None:
        super().__init__(parent)
        self._label = label
        self._path = ""
        self.setText("Copy")
        self.setToolTip(f"Copy {label.lower()} path")
        self.clicked.connect(self.copy_path)
        self.setEnabled(False)

    def set_path(self, path: str) -> None:
        self._path = str(path)
        self.setEnabled(bool(self._path))

    def copy_path(self, _checked: bool = False) -> None:
        if not self._path:
            return
        clipboard = QtWidgets.QApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(self._path)


__all__ = ["CopyPathButton", "DirectoryPathField", "FilePathField"]
