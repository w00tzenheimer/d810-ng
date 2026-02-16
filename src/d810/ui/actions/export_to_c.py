"""Export function to C file action.

Export the decompiled function as a compilable C source file with metadata.
Available from both pseudocode and disassembly views.
"""

from __future__ import annotations

import os
import re
from d810.core import typing
from contextlib import contextmanager

from d810.core.config import DEFAULT_IDA_USER_DIR
from d810.core.logging import getLogger
from d810.ui.actions.base import D810ActionHandler
from d810.ui.actions.export_to_c_logic import (
    format_c_output,
    get_forward_declaration_names,
    get_imported_function_names,
    suggest_filename,
)
from d810.ui.actions_logic import get_deobfuscation_stats

logger = getLogger("D810.ui")

ida_funcs = None
ida_hexrays = None
ida_kernwin = None
ida_lines = None
ida_name = None
ida_bytes = None
ida_nalt = None
ida_typeinf = None
idaapi = None

# ---------------------------------------------------------------------------
# Qt imports -- optional, will fail gracefully if not in GUI mode
# ---------------------------------------------------------------------------
try:
    from d810.qt_shim import (
        QApplication,
        QCheckBox,
        QDialog,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QPushButton,
        QSpinBox,
        QtWidgets,
        QVBoxLayout,
    )

    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False

_GLOBAL_NAME_RE = re.compile(
    r"\b((?:byte|word|dword|qword|xmmword|ymmword|zmmword|off|unk|asc|flt|dbl)_[0-9A-Fa-f]+)\b"
)

_GLOBAL_TYPE_BY_PREFIX = {
    "byte": "unsigned __int8",
    "word": "unsigned __int16",
    "dword": "unsigned __int32",
    "qword": "unsigned __int64",
    "xmmword": "__int128",
    "ymmword": "__int128",
    "zmmword": "__int128",
    "off": "unsigned __int64",
    "unk": "unsigned __int64",
    "asc": "char",
    "flt": "float",
    "dbl": "double",
}


def _get_collapse_lvars_restore_directive() -> str:
    """Resolve preferred COLLAPSE_LVARS restore directive from user config."""
    cfg_path = DEFAULT_IDA_USER_DIR / "cfg" / "hexrays.cfg"
    try:
        with open(cfg_path, encoding="utf-8") as cfg_file:
            for line in cfg_file:
                match = re.match(
                    r"^\s*COLLAPSE_LVARS\s*=\s*(YES|NO)\b", line, re.IGNORECASE
                )
                if match:
                    return f"COLLAPSE_LVARS = {match.group(1).upper()}"
    except OSError:
        pass
    return "COLLAPSE_LVARS = YES"


@contextmanager
def _temporary_hexrays_config(
    idaapi_mod: typing.Any | None,
    set_directive: str,
    restore_directive: str | None = None,
):
    """Temporarily override a Hex-Rays config directive and restore after use."""
    if idaapi_mod is None or not hasattr(idaapi_mod, "change_hexrays_config"):
        yield
        return

    effective_restore = restore_directive or _get_collapse_lvars_restore_directive()
    applied = False
    try:
        idaapi_mod.change_hexrays_config(set_directive)
        applied = True
    except Exception as exc:
        logger.debug("Could not apply Hex-Rays config '%s': %s", set_directive, exc)

    try:
        yield
    finally:
        if not applied:
            return
        try:
            idaapi_mod.change_hexrays_config(effective_restore)
        except Exception as exc:
            logger.debug(
                "Could not restore Hex-Rays config '%s' after '%s': %s",
                effective_restore,
                set_directive,
                exc,
            )


def _get_qt_parent_for_dialog(
    ctx: typing.Any, ida_kernwin_mod: typing.Any
) -> typing.Any:
    """Get a Qt parent widget from the action context so dialogs display properly in IDA."""
    import sys

    # 1. Try converting ctx.widget (TWidget) to QWidget via IDA's converter
    if (
        ctx is not None
        and ida_kernwin_mod is not None
        and getattr(ctx, "widget", None) is not None
    ):
        plugin_form = getattr(ida_kernwin_mod, "PluginForm", None)
        if plugin_form is not None:
            # Pass our module as ctx so converter finds Qt bindings (PySide6/PyQt5)
            qt_ctx = sys.modules.get("d810.ui.actions.export_to_c") or sys.modules.get(
                "__main__"
            )
            for method_name in (
                "FormToPySideWidget",
                "FormToPyQtWidget",
                "TWidgetToPySideWidget",
                "TWidgetToQtPythonWidget",
            ):
                converter = getattr(plugin_form, method_name, None)
                if converter is not None:
                    try:
                        parent = (
                            converter(ctx.widget, qt_ctx)
                            if qt_ctx
                            else converter(ctx.widget)
                        )
                        if parent is not None:
                            return parent
                    except Exception:
                        try:
                            parent = converter(ctx.widget)
                            if parent is not None:
                                return parent
                        except Exception:
                            pass

    # 2. Fallback: use QApplication.activeWindow() or first top-level widget
    if QT_AVAILABLE and QApplication is not None:
        try:
            app = QApplication.instance()
            if app is not None:
                active = app.activeWindow()
                if active is not None:
                    return active
                # activeWindow can be None when e.g. context menu has focus
                for w in (app.topLevelWidgets() or [])[:3]:
                    if w is not None and w.isVisible():
                        return w
        except Exception:
            pass

    return None


def _get_default_export_dir(idaapi_mod: typing.Any | None) -> str:
    """Return a sensible default directory for C export (input file dir or cwd)."""
    if idaapi_mod is not None and hasattr(idaapi_mod, "get_input_file_path"):
        try:
            path = idaapi_mod.get_input_file_path()
            if path:
                return os.path.dirname(path)
        except Exception:
            pass
    return os.getcwd()


def _get_current_func_ea(
    ctx: typing.Any,
    ida_hexrays_mod: typing.Any,
    ida_kernwin_mod: typing.Any,
    ida_funcs_mod: typing.Any,
) -> int | None:
    """Extract the entry-point EA of the function from the context.

    Works in both pseudocode and disassembly views.

    Args:
        ctx: IDA action context

    Returns:
        Function entry EA, or None if not in a function
    """
    # Try pseudocode view first
    vdui = ida_hexrays_mod.get_widget_vdui(ctx.widget)
    if vdui is not None:
        return vdui.cfunc.entry_ea

    # Fall back to disassembly view
    ea = ida_kernwin_mod.get_screen_ea()
    func = ida_funcs_mod.get_func(ea)
    if func is not None:
        return func.start_ea

    return None


def _decompile_function(
    func_ea: int,
    ida_hexrays_mod: typing.Any,
    ida_funcs_mod: typing.Any,
    ida_lines_mod: typing.Any,
    idaapi_mod: typing.Any | None = None,
) -> tuple[str, list[str]] | None:
    """Decompile a function and return its pseudocode.

    Args:
        func_ea: Function entry address

    Returns:
        Tuple of (function_name, pseudocode_lines), or None on failure
    """
    try:
        # Initialize decompiler if needed
        if not ida_hexrays_mod.init_hexrays_plugin():
            logger.error("Hex-Rays decompiler is not available")
            return None

        with _temporary_hexrays_config(idaapi_mod, "COLLAPSE_LVARS = NO"):
            # Decompile the function
            cfunc = ida_hexrays_mod.decompile(func_ea)
            if cfunc is None:
                logger.error("Failed to decompile function at %s", hex(func_ea))
                return None

            # Get function name
            func_name = ida_funcs_mod.get_func_name(func_ea)
            if not func_name:
                func_name = f"sub_{func_ea:X}"

            # Get pseudocode as text and clean IDA color tags
            pseudocode = str(cfunc)
            clean_code = ida_lines_mod.tag_remove(pseudocode)
            lines = clean_code.splitlines()

            return func_name, lines

    except Exception as exc:
        logger.error("Failed to decompile function at %s: %s", hex(func_ea), exc)
        return None


def _extract_global_symbol_names(pseudocode_lines: list[str]) -> list[str]:
    """Extract IDA-generated global symbol names from pseudocode text."""
    code = "\n".join(pseudocode_lines)
    return sorted(set(_GLOBAL_NAME_RE.findall(code)))


def _guess_global_type(symbol_name: str) -> str:
    """Guess C type from an IDA-style symbol name."""
    prefix = symbol_name.split("_", 1)[0].lower()
    return _GLOBAL_TYPE_BY_PREFIX.get(prefix, "unsigned __int64")


def _format_initializer(
    symbol_name: str,
    ea: int,
    ida_bytes_mod: typing.Any,
) -> str | None:
    """Read current IDB value and return an initializer literal when possible."""
    prefix = symbol_name.split("_", 1)[0].lower()
    if prefix == "byte":
        val = ida_bytes_mod.get_byte(ea)
        return f"0x{val:02X}u"
    if prefix == "word":
        val = ida_bytes_mod.get_word(ea)
        return f"0x{val:04X}u"
    if prefix == "dword":
        val = ida_bytes_mod.get_dword(ea)
        return f"0x{val:08X}u"
    if prefix in {"xmmword", "ymmword", "zmmword"}:
        raw = ida_bytes_mod.get_bytes(ea, 16)
        if raw is not None and len(raw) == 16:
            val = int.from_bytes(raw, "little")
            return f"0x{val:032X}LL"
        val = ida_bytes_mod.get_qword(ea)
        return f"0x{val:016X}uLL"
    if prefix in {"qword", "off", "unk"}:
        val = ida_bytes_mod.get_qword(ea)
        return f"0x{val:016X}uLL"
    return None


def _get_type_str(
    ea: int,
    idaapi_mod: typing.Any,
    ida_nalt_mod: typing.Any = None,
    ida_typeinf_mod: typing.Any = None,
) -> str | None:
    """Get type declaration string for address using idaapi (ida_nalt + ida_typeinf).

    Uses ida_nalt.get_tinfo + ida_typeinf.print_type/print_tinfo when available;
    falls back to idc.get_type otherwise.
    """
    nalt = ida_nalt_mod if ida_nalt_mod is not None else ida_nalt
    tinf = ida_typeinf_mod if ida_typeinf_mod is not None else ida_typeinf

    # 1. idaapi.get_type (idaapi often exposes get_type)
    if idaapi_mod is not None:
        get_type = getattr(idaapi_mod, "get_type", None)
        if callable(get_type):
            try:
                t = get_type(ea)
                if t and str(t).strip():
                    return str(t)
            except Exception:
                pass

    # 2. ida_nalt + ida_typeinf (no idc)
    if nalt is not None and tinf is not None:
        try:
            tif = tinf.tinfo_t()
            if nalt.get_tinfo(tif, ea):
                qstring_cls = getattr(tinf, "qstring", None)
                if qstring_cls is not None:
                    out = qstring_cls()
                    if getattr(tinf, "print_type", lambda *a: False)(out, ea, 0):
                        s = str(out)
                        if s:
                            return s
                    out = qstring_cls()
                    if getattr(tinf, "print_tinfo", lambda *a: False)(
                        out, "", 0, 0, 0, tif, "", ""
                    ):
                        s = str(out)
                        if s:
                            return s
        except Exception:
            pass

    # 3. Fallback: idc.get_type
    idc_mod = getattr(idaapi_mod, "idc", None) if idaapi_mod else None
    if idc_mod is None:
        try:
            idc_mod = __import__("idc")
        except ImportError:
            return None
    get_type = getattr(idc_mod, "get_type", None)
    if callable(get_type):
        try:
            return get_type(ea) or None
        except Exception:
            pass
    return None


def _get_typed_forward_declarations_from_ida(
    func_name: str,
    pseudocode_lines: list[str],
    ida_name_mod: typing.Any,
    idaapi_mod: typing.Any,
    ida_nalt_mod: typing.Any = None,
    ida_typeinf_mod: typing.Any = None,
) -> list[str] | None:
    """Build forward declarations using IDA type info when available.

    Returns list of full signatures (e.g. __int64 __fastcall sub_xxx(_QWORD, _QWORD);)
    or None if type info is not available.
    """
    callee_names = get_forward_declaration_names(func_name, pseudocode_lines)
    badaddr = idaapi_mod.BADADDR if idaapi_mod else 0xFFFFFFFFFFFFFFFF
    declarations: list[str] = []
    for name in sorted(callee_names):
        ea = ida_name_mod.get_name_ea(badaddr, name)
        if ea == badaddr:
            continue
        type_str = _get_type_str(
            ea, idaapi_mod, ida_nalt_mod=ida_nalt_mod, ida_typeinf_mod=ida_typeinf_mod
        )
        if not type_str or not type_str.strip():
            continue
        s = type_str.strip()
        # Type string has no symbol name; insert name before '('
        paren = s.find("(")
        if paren >= 0:
            s = s[:paren].rstrip() + " " + name + s[paren:]
        if not s.startswith("extern "):
            s = "extern " + s
        if not s.endswith(";"):
            s += ";"
        declarations.append(s)

    return declarations if declarations else None


def _get_imported_function_declarations_from_ida(
    pseudocode_lines: list[str],
    ida_name_mod: typing.Any,
    idaapi_mod: typing.Any,
    ida_nalt_mod: typing.Any = None,
    ida_typeinf_mod: typing.Any = None,
) -> list[str] | None:
    """Build function-pointer declarations for imported/API functions.

    Returns list like IDA's Data declarations: e.g.
    LPVOID (__stdcall *ConvertThreadToFiber)(LPVOID lpParameter);
    """
    names = get_imported_function_names(pseudocode_lines)
    if not names:
        return None

    badaddr = idaapi_mod.BADADDR if idaapi_mod else 0xFFFFFFFFFFFFFFFF
    declarations: list[str] = []

    for name in names:
        ea = ida_name_mod.get_name_ea(badaddr, name)
        if ea == badaddr:
            continue
        type_str = _get_type_str(
            ea, idaapi_mod, ida_nalt_mod=ida_nalt_mod, ida_typeinf_mod=ida_typeinf_mod
        )
        if not type_str or not type_str.strip():
            continue
        s = type_str.strip()
        if not s.startswith("extern "):
            s = "extern " + s
        if not s.endswith(";"):
            s += ";"
        declarations.append(s)

    return declarations if declarations else None


def _build_global_declarations_from_ida(
    symbol_names: list[str],
    ida_name_mod: typing.Any,
    ida_bytes_mod: typing.Any,
    idaapi_mod: typing.Any,
    ida_nalt_mod: typing.Any = None,
    ida_typeinf_mod: typing.Any = None,
) -> list[str]:
    """Build global declarations with initializers when IDA can resolve them."""
    declarations: list[str] = []
    badaddr = idaapi_mod.BADADDR

    for name in symbol_names:
        c_type = _guess_global_type(name)
        ea = ida_name_mod.get_name_ea(badaddr, name)
        if ea == badaddr:
            declarations.append(f"extern volatile {c_type} {name};")
            continue

        # xmmword/ymmword/zmmword are always __int128 regardless of IDA type
        prefix = name.split("_", 1)[0].lower()
        if prefix not in {"xmmword", "ymmword", "zmmword"}:
            ida_type = _get_type_str(
                ea,
                idaapi_mod,
                ida_nalt_mod=ida_nalt_mod,
                ida_typeinf_mod=ida_typeinf_mod,
            )
            if ida_type and ida_type.strip():
                c_type = ida_type.strip()

        initializer = _format_initializer(name, ea, ida_bytes_mod)
        if initializer is None:
            declarations.append(f"extern volatile {c_type} {name};")
        else:
            declarations.append(f"volatile {c_type} {name} = {initializer};")

    return declarations


class ExportToCDialog(QDialog if QT_AVAILABLE else object):  # type: ignore[misc]
    """Dialog for configuring C export options."""

    def __init__(
        self,
        func_name: str,
        parent=None,
        ida_kernwin_module: typing.Any | None = None,
        default_output_path: str | None = None,
    ):
        """Initialize the export to C dialog.

        Args:
            func_name: Name of the function being exported (for default filename)
            parent: Parent widget
            default_output_path: Full path for default output file (used when provided)
        """
        super().__init__(parent)
        self.func_name = func_name
        self._ida_kernwin = ida_kernwin_module
        self._default_output_path = default_output_path
        self.setWindowTitle("Export to C")
        self.setup_ui()

    def setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout()

        # Format selection
        format_layout = QVBoxLayout()
        format_layout.addWidget(QLabel("Output format:"))
        self.normal_radio = QtWidgets.QRadioButton("Normal C (standard decompilation)")
        self.normal_radio.setChecked(False)
        self.sample_radio = QtWidgets.QRadioButton(
            "Sample-compatible C (for recompilation)"
        )
        self.sample_radio.setChecked(True)
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
        self.export_globals_check.setChecked(True)
        layout.addLayout(QHBoxLayout())  # spacing
        layout.addWidget(self.export_globals_check)

        # Output file selection
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Output file:"))
        self.file_edit = QLineEdit()
        self.file_edit.setText(
            self._default_output_path
            if self._default_output_path
            else f"{self.func_name}.c"
        )
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

        file_path = self._ida_kernwin.ask_file(
            1, self.file_edit.text(), "Save C source as..."
        )
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

        def _ensure_mod(name: str, default: typing.Any) -> typing.Any:
            m = self.ida_module(name, default)
            if m is None:
                try:
                    return __import__(name)
                except ImportError:
                    return None
            return m

        ida_hexrays_mod = _ensure_mod("ida_hexrays", ida_hexrays)
        ida_kernwin_mod = _ensure_mod("ida_kernwin", ida_kernwin)
        ida_funcs_mod = _ensure_mod("ida_funcs", ida_funcs)
        ida_lines_mod = _ensure_mod("ida_lines", ida_lines)
        ida_name_mod = _ensure_mod("ida_name", ida_name)
        ida_bytes_mod = _ensure_mod("ida_bytes", ida_bytes)
        idaapi_mod = _ensure_mod("idaapi", idaapi)
        ida_nalt_mod = _ensure_mod("ida_nalt", ida_nalt)
        ida_typeinf_mod = _ensure_mod("ida_typeinf", ida_typeinf)
        if (
            ida_hexrays_mod is None
            or ida_kernwin_mod is None
            or ida_funcs_mod is None
            or ida_lines_mod is None
        ):
            msg = "Export to C: missing IDA modules (hexrays, kernwin, funcs, or lines)"
            logger.warning(msg)
            if ida_kernwin_mod:
                ida_kernwin_mod.warning(msg)
            return 0

        # Get current function EA
        func_ea = _get_current_func_ea(
            ctx, ida_hexrays_mod, ida_kernwin_mod, ida_funcs_mod
        )
        if func_ea is None:
            logger.warning("ExportFunctionToC: could not determine function EA")
            ida_kernwin_mod.warning("No function at cursor")
            return 0

        func_name = ida_funcs_mod.get_func_name(func_ea) or f"sub_{func_ea:X}"
        default_dir = _get_default_export_dir(idaapi_mod)
        default_output_path = os.path.join(default_dir, suggest_filename(func_name))

        parent_widget = _get_qt_parent_for_dialog(ctx, ida_kernwin_mod)
        if QT_AVAILABLE and parent_widget is not None:
            dialog = ExportToCDialog(
                func_name,
                parent=parent_widget,
                ida_kernwin_module=ida_kernwin_mod,
                default_output_path=default_output_path,
            )
            if dialog.exec_() != QDialog.Accepted:
                logger.info("Export to C cancelled by user")
                return 0
            settings = dialog.get_settings()
        else:
            save_path = ida_kernwin_mod.ask_file(
                1, default_output_path, "Save C source as..."
            )
            if not save_path:
                logger.info("Export to C cancelled by user")
                return 0
            settings = {
                "sample_compatible": True,
                "recursion_depth": 0,
                "export_globals": True,
                "output_path": save_path,
            }

        # Normal C = IDA's native Produce C file dialog
        if not settings.get("sample_compatible", True):
            ida_kernwin_mod.jumpto(func_ea, -1, 0)
            ok = ida_kernwin_mod.process_ui_action("hx:CreateCFile", 0)
            if ok:
                logger.info("Invoked IDA Produce C file dialog")
                return 1
            logger.warning("Failed to invoke hx:CreateCFile")
            ida_kernwin_mod.warning("Could not open Produce C file dialog. Ensure Hex-Rays decompiler is loaded.")
            return 0

        output_path = settings.get("output_path")
        if not output_path:
            ida_kernwin_mod.warning("No output file specified")
            return 0

        # Resolve to absolute path so the file is written to an explicit location
        if not os.path.isabs(output_path):
            output_path = os.path.join(default_dir, output_path)
        output_path = os.path.normpath(os.path.abspath(output_path))

        # Sample-compatible: decompile and write our format
        # Decompile the function (deferred until we know Sample mode is selected)
        result = _decompile_function(
            func_ea,
            ida_hexrays_mod,
            ida_funcs_mod,
            ida_lines_mod,
            idaapi_mod,
        )
        if result is None:
            ida_kernwin_mod.warning("Failed to decompile function")
            return 0

        func_name, pseudocode_lines = result

        # Get d810ng deobfuscation stats if available
        metadata = None
        if hasattr(self._state, "manager") and self._state.manager is not None:
            try:
                metadata = get_deobfuscation_stats(self._state.manager)
            except Exception as exc:
                logger.warning("Could not retrieve deobfuscation stats: %s", exc)

        # Import sample-compatible formatter from logic layer
        try:
            from d810.ui.actions.export_to_c_logic import format_sample_compatible_c

            # Collect global declarations if requested
            global_decls = None
            if (
                settings.get("export_globals", False)
                and ida_name_mod is not None
                and ida_bytes_mod is not None
                and idaapi_mod is not None
            ):
                global_symbols = _extract_global_symbol_names(pseudocode_lines)
                global_decls = _build_global_declarations_from_ida(
                    symbol_names=global_symbols,
                    ida_name_mod=ida_name_mod,
                    ida_bytes_mod=ida_bytes_mod,
                    idaapi_mod=idaapi_mod,
                    ida_nalt_mod=ida_nalt_mod,
                    ida_typeinf_mod=ida_typeinf_mod,
                )

            # Use IDA type info for forward declarations when available
            forward_decls = None
            if ida_name_mod is not None and idaapi_mod is not None:
                forward_decls = _get_typed_forward_declarations_from_ida(
                    func_name=func_name,
                    pseudocode_lines=pseudocode_lines,
                    ida_name_mod=ida_name_mod,
                    idaapi_mod=idaapi_mod,
                    ida_nalt_mod=ida_nalt_mod,
                    ida_typeinf_mod=ida_typeinf_mod,
                )

            # Imported function pointers (ConvertThreadToFiber, TlsGetValue, etc.)
            imported_decls = None
            if ida_name_mod is not None and idaapi_mod is not None:
                imported_decls = _get_imported_function_declarations_from_ida(
                    pseudocode_lines=pseudocode_lines,
                    ida_name_mod=ida_name_mod,
                    idaapi_mod=idaapi_mod,
                    ida_nalt_mod=ida_nalt_mod,
                    ida_typeinf_mod=ida_typeinf_mod,
                )

            c_source = format_sample_compatible_c(
                func_name=func_name,
                func_ea=func_ea,
                pseudocode_lines=pseudocode_lines,
                metadata=metadata,
                global_declarations=global_decls,
                forward_declarations=forward_decls,
                imported_function_declarations=imported_decls,
            )
        except ImportError:
            logger.warning(
                "Sample-compatible formatter not yet implemented, using normal format"
            )
            c_source = format_c_output(
                func_name=func_name,
                func_ea=func_ea,
                pseudocode_lines=pseudocode_lines,
                metadata=metadata,
            )

        # TODO: Handle recursion_depth > 0 (recursively decompile called functions)
        recursion_depth = settings.get("recursion_depth", 0)
        if recursion_depth > 0:
            logger.warning(
                "Recursion depth > 0 not yet implemented, exporting only current function"
            )

        # Post-process with clang to apply fixits and improve compilability
        try:
            from d810.ui.actions.export_to_c_clang import make_compilable
            c_source = make_compilable(c_source)
        except Exception as exc:
            logger.debug("Clang post-process skipped: %s", exc)

        # Save to file
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(c_source)
            logger.info("Exported C source to %s", output_path)
            ida_kernwin_mod.info(f"Function exported to:\n{output_path}")
            return 1
        except Exception as exc:
            logger.error("Failed to write C file: %s", exc)
            ida_kernwin_mod.warning(f"Failed to save file:\n{exc}")
            return 0

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in a supported view with a function at cursor
        """
        ida_hexrays_mod = self.ida_module("ida_hexrays", ida_hexrays)
        ida_kernwin_mod = self.ida_module("ida_kernwin", ida_kernwin)
        ida_funcs_mod = self.ida_module("ida_funcs", ida_funcs)
        idaapi_mod = self.ida_module("idaapi", idaapi)
        if (
            ida_hexrays_mod is None
            or ida_kernwin_mod is None
            or ida_funcs_mod is None
            or idaapi_mod is None
        ):
            return False

        # Check if we're in pseudocode view
        vdui = ida_hexrays_mod.get_widget_vdui(ctx.widget)
        if vdui is not None:
            return True

        # Check if we're in disassembly view with a function at cursor
        widget_type = idaapi_mod.get_widget_type(ctx.widget)
        if widget_type == idaapi_mod.BWN_DISASM:
            ea = ida_kernwin_mod.get_screen_ea()
            func = ida_funcs_mod.get_func(ea)
            return func is not None

        return False
