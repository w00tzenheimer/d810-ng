"""Export disassembly to various formats (ASM/LST/MAP/IDC).

Export the current function's disassembly using IDA's native exporters.
Available from disassembly view.
"""
from __future__ import annotations

import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

# ---------------------------------------------------------------------------
# IDA imports -- optional so unit tests can import without IDA present.
# ---------------------------------------------------------------------------
try:
    import ida_funcs
    import ida_kernwin
    import ida_loader
    import ida_fpro
    import idaapi

    IDA_AVAILABLE = True
except ImportError:
    ida_funcs = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
    ida_loader = None  # type: ignore[assignment]
    ida_fpro = None  # type: ignore[assignment]
    idaapi = None  # type: ignore[assignment]
    IDA_AVAILABLE = False

# ---------------------------------------------------------------------------
# Qt imports -- optional, will fail gracefully if not in GUI mode
# ---------------------------------------------------------------------------
try:
    from d810.qt_shim import (
        QDialog,
        QVBoxLayout,
        QHBoxLayout,
        QLabel,
        QComboBox,
        QCheckBox,
        QPushButton,
        QLineEdit,
    )

    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False


class ExportDisassemblyDialog(QDialog if QT_AVAILABLE else object):  # type: ignore[misc]
    """Dialog for configuring disassembly export options."""

    def __init__(self, func_name: str, parent=None):
        """Initialize the export disassembly dialog.

        Args:
            func_name: Name of the function being exported (for default filename)
            parent: Parent widget
        """
        super().__init__(parent)
        self.func_name = func_name
        self.setWindowTitle("Export Disassembly")
        self.setup_ui()

    def setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout()

        # Format selection
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))
        self.format_combo = QComboBox()
        self.format_combo.addItems(["ASM", "LST", "MAP", "IDC"])
        format_layout.addWidget(self.format_combo)
        layout.addLayout(format_layout)

        # Options checkboxes
        self.include_headers_check = QCheckBox("Include segment headers")
        self.include_headers_check.setChecked(True)
        layout.addWidget(self.include_headers_check)

        # Output file selection
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Output file:"))
        self.file_edit = QLineEdit()
        self.file_edit.setText(f"{self.func_name}.asm")
        file_layout.addWidget(self.file_edit)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_btn)
        layout.addLayout(file_layout)

        # Buttons
        button_layout = QHBoxLayout()
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(ok_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def browse_file(self):
        """Show file browser dialog."""
        if ida_kernwin is None:
            return

        file_path = ida_kernwin.ask_file(1, self.file_edit.text(), "Save disassembly as...")
        if file_path:
            self.file_edit.setText(file_path)

    def get_settings(self) -> dict:
        """Get the configured export settings.

        Returns:
            Dictionary with format, include_headers, output_path
        """
        format_str = self.format_combo.currentText()
        return {
            "format": format_str,
            "include_headers": self.include_headers_check.isChecked(),
            "output_path": self.file_edit.text(),
        }


class ExportDisassembly(D810ActionHandler):
    """Export the current function's disassembly to various formats."""

    ACTION_ID = "d810ng:export_disasm"
    ACTION_TEXT = "Export disassembly..."
    ACTION_TOOLTIP = "Export function disassembly as ASM/LST/MAP/IDC"
    SUPPORTED_VIEWS = frozenset({"disasm"})
    MENU_ORDER = 71
    REQUIRES_STARTED = False

    def execute(self, ctx: typing.Any) -> int:
        """Execute the export disassembly action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        if not IDA_AVAILABLE or not QT_AVAILABLE:
            return 0

        # Get current function EA
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if func is None:
            logger.warning("ExportDisassembly: no function at cursor")
            ida_kernwin.warning("No function at cursor")
            return 0

        func_name = ida_funcs.get_func_name(func.start_ea)
        if not func_name:
            func_name = f"sub_{func.start_ea:X}"

        # Show dialog
        dialog = ExportDisassemblyDialog(func_name)
        if dialog.exec() != QDialog.Accepted:
            logger.info("Export disassembly cancelled by user")
            return 0

        settings = dialog.get_settings()

        # Map format string to ida_loader constants
        format_map = {
            "ASM": ida_loader.OFILE_ASM,
            "LST": ida_loader.OFILE_LST,
            "MAP": ida_loader.OFILE_MAP,
            "IDC": ida_loader.OFILE_IDC,
        }
        format_type = format_map.get(settings["format"], ida_loader.OFILE_ASM)

        # Build flags
        flags = 0
        if settings["include_headers"]:
            flags |= ida_loader.GENFLG_ASMTYPE  # type: ignore[attr-defined]

        output_path = settings["output_path"]
        if not output_path:
            ida_kernwin.warning("No output file specified")
            return 0

        try:
            # Open qfile_t on the output path
            qf = ida_fpro.qfile_t()
            if not qf.open(output_path, "w"):
                logger.error("Failed to open output file: %s", output_path)
                ida_kernwin.warning(f"Failed to open output file:\n{output_path}")
                return 0

            # Use ida_loader.gen_file to export
            # We need to export a range from function start to end
            success = ida_loader.gen_file(
                format_type,
                qf,
                func.start_ea,
                func.end_ea,
                flags,
            )
            qf.close()

            if success:
                logger.info("Exported disassembly to %s", output_path)
                ida_kernwin.info(f"Disassembly exported to:\n{output_path}")
                return 1
            else:
                logger.error("Failed to export disassembly")
                ida_kernwin.warning("Failed to export disassembly")
                return 0

        except Exception as exc:
            logger.error("Failed to export disassembly: %s", exc)
            ida_kernwin.warning(f"Failed to export disassembly:\n{exc}")
            return 0

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in disassembly view with a function at cursor
        """
        if not IDA_AVAILABLE or idaapi is None or ida_kernwin is None or ida_funcs is None:
            return False

        # Check if we're in disassembly view
        widget_type = idaapi.get_widget_type(ctx.widget)
        if widget_type != idaapi.BWN_DISASM:
            return False

        # Check if there's a function at cursor
        ea = ida_kernwin.get_screen_ea()
        func = ida_funcs.get_func(ea)
        return func is not None
