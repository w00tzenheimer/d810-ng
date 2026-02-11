"""Export microcode to JSON format.

Export the current function's microcode at a specific maturity level,
with optional pre-deobfuscation snapshot capability.
Available from pseudocode view.
"""
from __future__ import annotations

import json
import typing

from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

# ---------------------------------------------------------------------------
# IDA imports -- optional so unit tests can import without IDA present.
# ---------------------------------------------------------------------------
try:
    import ida_funcs
    import ida_hexrays
    import ida_kernwin

    IDA_AVAILABLE = True
except ImportError:
    ida_funcs = None  # type: ignore[assignment]
    ida_hexrays = None  # type: ignore[assignment]
    ida_kernwin = None  # type: ignore[assignment]
    IDA_AVAILABLE = False

# ---------------------------------------------------------------------------
# Qt imports -- optional, will fail gracefully if not in GUI mode
# ---------------------------------------------------------------------------
try:
    from d810.qt_shim import (
        QtWidgets,
        QDialog,
        QVBoxLayout,
        QHBoxLayout,
        QLabel,
        QComboBox,
        QPushButton,
        QLineEdit,
    )

    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False

# Maturity level choices (name, IDA constant value, description)
MATURITY_CHOICES = [
    ("GENERATED", 0, "Immediately after generation"),
    ("PREOPTIMIZED", 1, "Pre-optimized microcode"),
    ("LOCOPT", 2, "After local optimizations"),
    ("CALLS", 3, "After call analysis"),
    ("GLBOPT1", 4, "After first global optimization"),
    ("GLBOPT2", 5, "After second global optimization"),
    ("GLBOPT3", 6, "After third global optimization"),
    ("LVARS", 7, "Final with local variables"),
]


class ExportMicrocodeDialog(QDialog if QT_AVAILABLE else object):  # type: ignore[misc]
    """Dialog for configuring microcode export options."""

    def __init__(self, func_name: str, parent=None):
        """Initialize the export microcode dialog.

        Args:
            func_name: Name of the function being exported (for default filename)
            parent: Parent widget
        """
        super().__init__(parent)
        self.func_name = func_name
        self.setWindowTitle("Export Microcode")
        self.setup_ui()

    def setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout()

        # Maturity level selection
        maturity_layout = QHBoxLayout()
        maturity_layout.addWidget(QLabel("Maturity level:"))
        self.maturity_combo = QComboBox()
        for name, _, description in MATURITY_CHOICES:
            self.maturity_combo.addItem(f"{name} - {description}", name)
        # Default to LVARS (final)
        self.maturity_combo.setCurrentIndex(7)
        maturity_layout.addWidget(self.maturity_combo)
        layout.addLayout(maturity_layout)

        # Pre/post deobfuscation radio buttons
        deobf_layout = QHBoxLayout()
        deobf_layout.addWidget(QLabel("Capture:"))
        self.post_deobf_radio = QtWidgets.QRadioButton("Post-deobfuscation (d810ng applied)")
        self.post_deobf_radio.setChecked(True)
        self.pre_deobf_radio = QtWidgets.QRadioButton("Pre-deobfuscation (d810ng suppressed)")
        deobf_layout.addWidget(self.post_deobf_radio)
        deobf_layout.addWidget(self.pre_deobf_radio)
        layout.addLayout(deobf_layout)

        # Output file selection
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Output file:"))
        self.file_edit = QLineEdit()
        self.file_edit.setText(f"{self.func_name}_microcode.json")
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

        file_path = ida_kernwin.ask_file(1, self.file_edit.text(), "Save microcode as...")
        if file_path:
            self.file_edit.setText(file_path)

    def get_settings(self) -> dict:
        """Get the configured export settings.

        Returns:
            Dictionary with maturity_name, maturity_value, pre_deobfuscation, output_path
        """
        idx = self.maturity_combo.currentIndex()
        maturity_name, maturity_value, _ = MATURITY_CHOICES[idx]

        return {
            "maturity_name": maturity_name,
            "maturity_value": maturity_value,
            "pre_deobfuscation": self.pre_deobf_radio.isChecked(),
            "output_path": self.file_edit.text(),
        }


class ExportMicrocode(D810ActionHandler):
    """Export the current function's microcode as JSON."""

    ACTION_ID = "d810ng:export_microcode"
    ACTION_TEXT = "Export microcode..."
    ACTION_TOOLTIP = "Export function microcode at specific maturity level"
    SUPPORTED_VIEWS = frozenset({"pseudocode"})
    MENU_ORDER = 72
    REQUIRES_STARTED = False

    def execute(self, ctx: typing.Any) -> int:
        """Execute the export microcode action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        if not IDA_AVAILABLE or not QT_AVAILABLE:
            return 0

        # Get current function EA from pseudocode context
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        if vdui is None:
            logger.warning("ExportMicrocode: not in pseudocode view")
            ida_kernwin.warning("Not in pseudocode view")
            return 0

        func_ea = vdui.cfunc.entry_ea
        func_name = ida_funcs.get_func_name(func_ea)
        if not func_name:
            func_name = f"sub_{func_ea:X}"

        # Show dialog
        dialog = ExportMicrocodeDialog(func_name)
        if dialog.exec() != QDialog.Accepted:
            logger.info("Export microcode cancelled by user")
            return 0

        settings = dialog.get_settings()
        output_path = settings["output_path"]
        if not output_path:
            ida_kernwin.warning("No output file specified")
            return 0

        maturity_value = settings["maturity_value"]
        pre_deobfuscation = settings["pre_deobfuscation"]

        try:
            # Import microcode dump utility
            from d810.hexrays.microcode_dump import dump_function_microcode

            # If pre-deobfuscation requested and d810ng is running, suppress hooks
            if pre_deobfuscation and hasattr(self._state, "manager") and self._state.manager.started:
                from d810.manager import d810_hooks_suppressed

                with d810_hooks_suppressed(self._state.manager):
                    microcode_data = dump_function_microcode(func_ea, maturity=maturity_value)
            else:
                # Normal export (post-deobfuscation or d810ng not running)
                microcode_data = dump_function_microcode(func_ea, maturity=maturity_value)

            # Write JSON to file
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(microcode_data, f, indent=2, ensure_ascii=False)

            logger.info("Exported microcode to %s", output_path)
            ida_kernwin.info(f"Microcode exported to:\n{output_path}")
            return 1

        except Exception as exc:
            logger.error("Failed to export microcode: %s", exc, exc_info=True)
            ida_kernwin.warning(f"Failed to export microcode:\n{exc}")
            return 0

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in pseudocode view
        """
        if not IDA_AVAILABLE or ida_hexrays is None:
            return False

        # Check if we're in pseudocode view
        vdui = ida_hexrays.get_widget_vdui(ctx.widget)
        return vdui is not None
