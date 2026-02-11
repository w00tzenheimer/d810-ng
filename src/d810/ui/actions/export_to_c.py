"""Export function to C file action.

Export the decompiled function as a compilable C source file with metadata.
Available from both pseudocode and disassembly views.
"""
from __future__ import annotations

import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler
from d810.ui.actions.export_to_c_logic import format_c_output, suggest_filename
from d810.ui.actions_logic import get_deobfuscation_stats

logger = getLogger("D810.ui")

# ---------------------------------------------------------------------------
# IDA imports -- optional so unit tests can import without IDA present.
# ---------------------------------------------------------------------------
try:
    import ida_funcs
    import ida_hexrays
    import ida_kernwin
    import ida_lines
    import idaapi

    IDA_AVAILABLE = True
except ImportError:
    ida_funcs = None  # type: ignore[assignment]
    ida_hexrays = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
    ida_lines = None  # type: ignore[assignment]
    idaapi = None  # type: ignore[assignment]
    IDA_AVAILABLE = False

# ---------------------------------------------------------------------------
# Qt imports -- optional, will fail gracefully if not in GUI mode
# ---------------------------------------------------------------------------
try:
    from d810.qt_shim import (
        QtCore,
        QtWidgets,
        QDialog,
        QVBoxLayout,
        QHBoxLayout,
        QLabel,
        QComboBox,
        QCheckBox,
        QPushButton,
        QLineEdit,
        QSpinBox,
    )

    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False


def _get_current_func_ea(ctx: typing.Any) -> int | None:
    """Extract the entry-point EA of the function from the context.

    Works in both pseudocode and disassembly views.

    Args:
        ctx: IDA action context

    Returns:
        Function entry EA, or None if not in a function
    """
    if ida_hexrays is None or ida_kernwin is None or ida_funcs is None:
        return None

    # Try pseudocode view first
    vdui = ida_hexrays.get_widget_vdui(ctx.widget)
    if vdui is not None:
        return vdui.cfunc.entry_ea

    # Fall back to disassembly view
    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if func is not None:
        return func.start_ea

    return None


def _decompile_function(func_ea: int) -> tuple[str, list[str]] | None:
    """Decompile a function and return its pseudocode.

    Args:
        func_ea: Function entry address

    Returns:
        Tuple of (function_name, pseudocode_lines), or None on failure
    """
    if ida_hexrays is None or ida_funcs is None or ida_lines is None:
        return None

    try:
        # Initialize decompiler if needed
        if not ida_hexrays.init_hexrays_plugin():
            logger.error("Hex-Rays decompiler is not available")
            return None

        # Decompile the function
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc is None:
            logger.error("Failed to decompile function at %s", hex(func_ea))
            return None

        # Get function name
        func_name = ida_funcs.get_func_name(func_ea)
        if not func_name:
            func_name = f"sub_{func_ea:X}"

        # Get pseudocode as text and clean IDA color tags
        pseudocode = str(cfunc)
        clean_code = ida_lines.tag_remove(pseudocode)
        lines = clean_code.splitlines()

        return func_name, lines

    except Exception as exc:
        logger.error("Failed to decompile function at %s: %s", hex(func_ea), exc)
        return None


def _save_c_file(content: str, suggested_name: str) -> bool:
    """Prompt user for file location and save C source.

    Args:
        content: The C source content to save
        suggested_name: Suggested filename

    Returns:
        True if saved successfully, False otherwise
    """
    if ida_kernwin is None:
        return False

    # Ask user for save location
    file_path = ida_kernwin.ask_file(1, suggested_name, "Save C source as...")
    if not file_path:
        logger.info("Export to C cancelled by user")
        return False

    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("Exported C source to %s", file_path)
        ida_kernwin.info(f"Function exported to:\n{file_path}")
        return True
    except Exception as exc:
        logger.error("Failed to write C file: %s", exc)
        ida_kernwin.warning(f"Failed to save file:\n{exc}")
        return False


class ExportToCDialog(QDialog if QT_AVAILABLE else object):  # type: ignore[misc]
    """Dialog for configuring C export options."""

    def __init__(self, func_name: str, parent=None):
        """Initialize the export to C dialog.

        Args:
            func_name: Name of the function being exported (for default filename)
            parent: Parent widget
        """
        super().__init__(parent)
        self.func_name = func_name
        self.setWindowTitle("Export to C")
        self.setup_ui()

    def setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout()

        # Format selection
        format_layout = QVBoxLayout()
        format_layout.addWidget(QLabel("Output format:"))
        self.normal_radio = QtWidgets.QRadioButton("Normal C (standard decompilation)")
        self.normal_radio.setChecked(True)
        self.sample_radio = QtWidgets.QRadioButton("Sample-compatible C (for recompilation)")
        format_layout.addWidget(self.normal_radio)
        format_layout.addWidget(self.sample_radio)
        layout.addLayout(format_layout)

        # Recursion depth
        recursion_layout = QHBoxLayout()
        recursion_layout.addWidget(QLabel("Recursion depth (0=current function only):"))
        self.recursion_spin = QSpinBox()
        self.recursion_spin.setRange(0, 5)
        self.recursion_spin.setValue(0)
        recursion_layout.addWidget(self.recursion_spin)
        layout.addLayout(recursion_layout)

        # Export globals checkbox
        self.export_globals_check = QCheckBox("Export referenced global variables")
        self.export_globals_check.setChecked(False)
        layout.addLayout(QHBoxLayout())  # spacing
        layout.addWidget(self.export_globals_check)

        # Output file selection
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Output file:"))
        self.file_edit = QLineEdit()
        self.file_edit.setText(f"{self.func_name}.c")
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

        file_path = ida_kernwin.ask_file(1, self.file_edit.text(), "Save C source as...")
        if file_path:
            self.file_edit.setText(file_path)

    def get_settings(self) -> dict:
        """Get the configured export settings.

        Returns:
            Dictionary with sample_compatible, recursion_depth, export_globals, output_path
        """
        return {
            "sample_compatible": self.sample_radio.isChecked(),
            "recursion_depth": self.recursion_spin.value(),
            "export_globals": self.export_globals_check.isChecked(),
            "output_path": self.file_edit.text(),
        }



class ExportFunctionToC(D810ActionHandler):
    """Export the current function as a compilable C source file."""

    ACTION_ID = "d810ng:export_to_c"
    ACTION_TEXT = "Export function to C file"
    ACTION_TOOLTIP = "Export decompiled function as compilable C source"
    SUPPORTED_VIEWS = frozenset({"pseudocode", "disasm"})
    MENU_ORDER = 70
    REQUIRES_STARTED = False

    def execute(self, ctx: typing.Any) -> int:
        """Execute the export to C action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        if not IDA_AVAILABLE or ida_kernwin is None:
            return 0

        # Get current function EA
        func_ea = _get_current_func_ea(ctx)
        if func_ea is None:
            logger.warning("ExportFunctionToC: could not determine function EA")
            ida_kernwin.warning("No function at cursor")
            return 0

        # Decompile the function
        result = _decompile_function(func_ea)
        if result is None:
            ida_kernwin.warning("Failed to decompile function")
            return 0

        func_name, pseudocode_lines = result

        # Show dialog if Qt available, otherwise use simple file dialog
        if QT_AVAILABLE:
            dialog = ExportToCDialog(func_name)
            if dialog.exec() != QDialog.Accepted:
                logger.info("Export to C cancelled by user")
                return 0
            settings = dialog.get_settings()
        else:
            # Fallback to simple file dialog
            settings = {
                "sample_compatible": False,
                "recursion_depth": 0,
                "export_globals": False,
                "output_path": suggest_filename(func_name),
            }

        output_path = settings.get("output_path")
        if not output_path:
            ida_kernwin.warning("No output file specified")
            return 0

        # Get d810ng deobfuscation stats if available
        metadata = None
        if hasattr(self._state, "manager") and self._state.manager is not None:
            try:
                metadata = get_deobfuscation_stats(self._state.manager)
            except Exception as exc:
                logger.warning("Could not retrieve deobfuscation stats: %s", exc)

        # Format C output based on mode
        if settings.get("sample_compatible", False):
            # Import sample-compatible formatter from logic layer
            try:
                from d810.ui.actions.export_to_c_logic import format_sample_compatible_c

                # Collect global declarations if requested
                # TODO: implement global variable extraction from IDA
                global_decls = None
                if settings.get("export_globals", False):
                    # Placeholder: global extraction not yet implemented
                    global_decls = []

                c_source = format_sample_compatible_c(
                    func_name=func_name,
                    func_ea=func_ea,
                    pseudocode_lines=pseudocode_lines,
                    metadata=metadata,
                    global_declarations=global_decls,
                )
            except ImportError:
                logger.warning("Sample-compatible formatter not yet implemented, using normal format")
                c_source = format_c_output(
                    func_name=func_name,
                    func_ea=func_ea,
                    pseudocode_lines=pseudocode_lines,
                    metadata=metadata,
                )
        else:
            # Normal C format
            c_source = format_c_output(
                func_name=func_name,
                func_ea=func_ea,
                pseudocode_lines=pseudocode_lines,
                metadata=metadata,
            )

        # TODO: Handle recursion_depth > 0 (recursively decompile called functions)
        recursion_depth = settings.get("recursion_depth", 0)
        if recursion_depth > 0:
            logger.warning("Recursion depth > 0 not yet implemented, exporting only current function")

        # Save to file
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(c_source)
            logger.info("Exported C source to %s", output_path)
            ida_kernwin.info(f"Function exported to:\n{output_path}")
            return 1
        except Exception as exc:
            logger.error("Failed to write C file: %s", exc)
            ida_kernwin.warning(f"Failed to save file:\n{exc}")
            return 0

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in a supported view with a function at cursor
        """
        if (
            ida_hexrays is None
            or ida_kernwin is None
            or ida_funcs is None
            or idaapi is None
        ):
            return False

        # Check if we're in pseudocode view
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if vdui is not None:
            return True

        # Check if we're in disassembly view with a function at cursor
        widget_type = idaapi.get_widget_type(ctx.widget)
        if widget_type == idaapi.BWN_DISASM:
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)
            return func is not None

        return False
