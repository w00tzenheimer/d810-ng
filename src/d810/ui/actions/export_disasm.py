"""Export disassembly to various formats (ASM/LST/MAP/IDC).

Export the current function's disassembly using IDA's native exporters.
Available from disassembly view.
"""
from __future__ import annotations

import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler
from d810.ui.actions.export_disasm_logic import (
    DisasmExportSettings,
    to_ida_flags_with_loader,
    to_ida_format_int_with_loader,
)

logger = getLogger("D810.ui")

ida_funcs = None
ida_kernwin = None
ida_loader = None
ida_fpro = None
idaapi = None

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

    def __init__(
        self,
        func_name: str,
        parent=None,
        ida_kernwin_module: typing.Any | None = None,
    ):
        """Initialize the export disassembly dialog.

        Args:
            func_name: Name of the function being exported (for default filename)
            parent: Parent widget
        """
        super().__init__(parent)
        self.func_name = func_name
        self._ida_kernwin = ida_kernwin_module
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
        if self._ida_kernwin is None:
            return

        file_path = self._ida_kernwin.ask_file(1, self.file_edit.text(), "Save disassembly as...")
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
        ida_kernwin_mod = self.ida_module("ida_kernwin", ida_kernwin)
        ida_funcs_mod = self.ida_module("ida_funcs", ida_funcs)
        ida_loader_mod = self.ida_module("ida_loader", ida_loader)
        ida_fpro_mod = self.ida_module("ida_fpro", ida_fpro)

        if (
            not QT_AVAILABLE
            or ida_kernwin_mod is None
            or ida_funcs_mod is None
            or ida_loader_mod is None
            or ida_fpro_mod is None
        ):
            return 0

        # Get current function EA
        ea = ida_kernwin_mod.get_screen_ea()
        func = ida_funcs_mod.get_func(ea)
        if func is None:
            logger.warning("ExportDisassembly: no function at cursor")
            ida_kernwin_mod.warning("No function at cursor")
            return 0

        func_name = ida_funcs_mod.get_func_name(func.start_ea)
        if not func_name:
            func_name = f"sub_{func.start_ea:X}"

        # Show dialog
        dialog = ExportDisassemblyDialog(
            func_name,
            ida_kernwin_module=ida_kernwin_mod,
        )
        if dialog.exec_() != QDialog.Accepted:
            logger.info("Export disassembly cancelled by user")
            return 0

        settings = dialog.get_settings()

        logic_settings = DisasmExportSettings(
            format=settings["format"],
            include_headers=settings["include_headers"],
            include_segments=False,  # Dialog currently exposes header toggle only
            output_path=settings["output_path"],
        )
        format_type = to_ida_format_int_with_loader(
            logic_settings.format, loader=ida_loader_mod
        )
        flags = to_ida_flags_with_loader(logic_settings, loader=ida_loader_mod)

        output_path = settings["output_path"]
        if not output_path:
            ida_kernwin_mod.warning("No output file specified")
            return 0

        try:
            # Open qfile_t on the output path
            qf = ida_fpro_mod.qfile_t()
            if not qf.open(output_path, "w"):
                logger.error("Failed to open output file: %s", output_path)
                ida_kernwin_mod.warning(f"Failed to open output file:\n{output_path}")
                return 0

            # Use ida_loader.gen_file to export
            # We need to export a range from function start to end
            success = ida_loader_mod.gen_file(
                format_type,
                qf,
                func.start_ea,
                func.end_ea,
                flags,
            )
            qf.close()

            if success:
                logger.info("Exported disassembly to %s", output_path)
                ida_kernwin_mod.info(f"Disassembly exported to:\n{output_path}")
                return 1
            else:
                logger.error("Failed to export disassembly")
                ida_kernwin_mod.warning("Failed to export disassembly")
                return 0

        except Exception as exc:
            logger.error("Failed to export disassembly: %s", exc)
            ida_kernwin_mod.warning(f"Failed to export disassembly:\n{exc}")
            return 0

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in disassembly view with a function at cursor
        """
        idaapi_mod = self.ida_module("idaapi", idaapi)
        ida_kernwin_mod = self.ida_module("ida_kernwin", ida_kernwin)
        ida_funcs_mod = self.ida_module("ida_funcs", ida_funcs)

        if idaapi_mod is None or ida_kernwin_mod is None or ida_funcs_mod is None:
            return False

        # Check if we're in disassembly view
        widget_type = idaapi_mod.get_widget_type(ctx.widget)
        if widget_type != idaapi_mod.BWN_DISASM:
            return False

        # Check if there's a function at cursor
        ea = ida_kernwin_mod.get_screen_ea()
        func = ida_funcs_mod.get_func(ea)
        return func is not None
