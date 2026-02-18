# -*- coding: utf-8 -*-
"""Auto-generated config editor panel for a selected optimization rule.

Reads the rule's ``CONFIG_SCHEMA`` (a tuple of :class:`ConfigParam`) and
builds the appropriate Qt editor widgets for each parameter type.
"""
from __future__ import annotations

import html
import json
import logging
from d810.core import typing

from d810.qt_shim import QtCore, QtWidgets

if typing.TYPE_CHECKING:
    from d810.optimizers.microcode.handler import ConfigParam, OptimizationRule

logger = logging.getLogger("D810.ui.rule_detail")


class RuleDetailPanel(QtWidgets.QWidget):
    """Detail panel showing a rule's metadata and auto-generated config editors.

    Signals
    -------
    config_changed(str, object)
        Emitted when the user changes a config parameter value.
        Payload is ``(param_name, new_value)``.
    """

    config_changed = QtCore.pyqtSignal(str, object)

    def __init__(
        self,
        parent: QtWidgets.QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self._current_rule: OptimizationRule | None = None
        self._editor_widgets: dict[str, QtWidgets.QWidget] = {}
        self._read_only: bool = False

        # --- Layout -----------------------------------------------------------
        # Outer layout holds the compact header browser + expanding scroll area
        self._outer_layout = QtWidgets.QVBoxLayout(self)
        self._outer_layout.setContentsMargins(2, 2, 2, 2)
        self._outer_layout.setSpacing(2)

        # Single compact header browser for all metadata
        self._header_browser = QtWidgets.QTextBrowser()
        self._header_browser.setReadOnly(True)
        self._header_browser.setOpenLinks(False)  # Prevent link navigation
        self._header_browser.setFrameShape(QtWidgets.QFrame.NoFrame)  # Seamless look
        self._header_browser.setStyleSheet("QTextBrowser { background: transparent; border: none; }")
        self._header_browser.viewport().setAutoFillBackground(False)
        self._header_browser.document().setDocumentMargin(4)
        self._header_browser.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self._header_browser.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        # Set size policy to prevent vertical expansion
        self._header_browser.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,   # horizontal: fill width
            QtWidgets.QSizePolicy.Fixed         # vertical: stay at fixed height
        )
        # Add with stretch=0 and AlignTop alignment
        self._outer_layout.addWidget(self._header_browser, stretch=0, alignment=QtCore.Qt.AlignTop)

        # Scroll area for config editors gets all remaining space
        self._scroll = QtWidgets.QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self._scroll.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        self._outer_layout.addWidget(self._scroll, 1)  # stretch=1 to fill remaining vertical space

        # Inner widget for the scroll area
        self._config_widget = QtWidgets.QWidget()
        self._config_layout = QtWidgets.QFormLayout(self._config_widget)
        self._config_layout.setContentsMargins(0, 0, 0, 0)
        self._config_layout.setSpacing(6)
        self._config_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)
        self._scroll.setWidget(self._config_widget)

    # --- Public API ---------------------------------------------------------

    def _adjust_header_height(self) -> None:
        """Resize header browser to fit content exactly."""
        doc = self._header_browser.document()
        doc.setTextWidth(self._header_browser.viewport().width())
        doc_height = doc.size().height()
        # Use fallback if document not yet laid out
        if doc_height < 10:  # Not yet laid out
            doc_height = 80  # Reasonable default
        # Add small padding, cap at reasonable max
        target = min(int(doc_height) + 8, 200)
        self._header_browser.setFixedHeight(target)

    def set_rule(self, rule: OptimizationRule | None) -> None:
        """Display details for *rule* (or clear the panel if None)."""
        self._current_rule = rule
        self._clear_config_editors()

        if rule is None:
            self._header_browser.setHtml("<i>(no rule selected)</i>")
            self._adjust_header_height()  # immediate
            QtCore.QTimer.singleShot(0, self._adjust_header_height)  # deferred for accurate width
            self._scroll.setVisible(False)
            return

        # Build HTML for the header browser
        html_parts = []

        # Rule name (bold, larger font)
        html_parts.append(f'<b style="font-size: 14px;">{html.escape(rule.name)}</b>')

        # Description with WARNING/backtick processing
        # _process_description() already returns HTML, so don't escape it
        desc_html = self._process_description(rule.description)
        html_parts.append(f'<p>{desc_html}</p>')

        # Maturities
        mat_names = self._format_maturities(rule)
        if mat_names:
            html_parts.append(f'<p style="color: #888;">Maturities: {html.escape(mat_names)}</p>')

        # Separator and config header
        html_parts.append('<hr>')
        html_parts.append('<b>Configuration</b>')

        self._header_browser.setHtml("".join(html_parts))
        # Adjust height after content is set (immediate + deferred)
        self._adjust_header_height()  # immediate
        QtCore.QTimer.singleShot(0, self._adjust_header_height)  # deferred for accurate width

        # Build config editors
        schema = getattr(rule, "CONFIG_SCHEMA", ())
        if schema:
            self._scroll.setVisible(True)
            self._build_config_editors(rule, schema)
        else:
            self._scroll.setVisible(False)

    def set_read_only(self, read_only: bool) -> None:
        """Set read-only mode for the detail panel.

        When enabled, all editor widgets (text inputs, combo boxes, etc.)
        are disabled, preventing user edits. The panel itself remains visible
        and interactive for viewing.

        Parameters
        ----------
        read_only:
            If True, disable all config editor widgets.
        """
        self._read_only = read_only
        # Apply to all editor widgets
        for widget in self._editor_widgets.values():
            widget.setEnabled(not read_only)

    # --- Internal -----------------------------------------------------------

    def _clear_config_editors(self) -> None:
        """Remove all dynamically created editor widgets."""
        self._editor_widgets.clear()
        # Clear the form layout
        while self._config_layout.rowCount() > 0:
            self._config_layout.removeRow(0)

    def _build_config_editors(
        self,
        rule: OptimizationRule,
        schema: tuple[ConfigParam, ...],
    ) -> None:
        """Create one editor widget per ConfigParam in *schema*."""
        for param in schema:
            # Current value from rule.config, falling back to attribute, then default
            current_value = rule.config.get(param.name)
            if current_value is None:
                # Try to read from the rule's attribute directly
                current_value = getattr(rule, param.name, param.default)
            widget = self._create_editor(param, current_value)
            if widget is not None:
                label = QtWidgets.QLabel(param.name)
                label.setToolTip(param.description)
                widget.setToolTip(param.description)
                widget.setEnabled(not self._read_only)  # Apply read-only state
                self._config_layout.addRow(label, widget)
                self._editor_widgets[param.name] = widget

    def _create_editor(
        self,
        param: ConfigParam,
        current_value: typing.Any,
    ) -> QtWidgets.QWidget | None:
        """Return the appropriate editor widget for *param*."""
        # List with choices -> multi-select toggle buttons
        if param.type is list and param.choices is not None:
            return self._make_multi_select_buttons(param, current_value)

        # Choices override -> combo box
        if param.choices is not None:
            return self._make_combo(param, current_value)

        if param.type is bool:
            return self._make_checkbox(param, current_value)
        if param.type is int:
            return self._make_spinbox(param, current_value)
        if param.type is float:
            return self._make_double_spinbox(param, current_value)
        if param.type is str:
            return self._make_line_edit(param, current_value)
        if param.type is list:
            return self._make_list_edit(param, current_value)
        if param.type is dict:
            return self._make_json_edit(param, current_value)

        # Fallback: generic line edit with string representation
        return self._make_line_edit(param, str(current_value) if current_value else "")

    # --- Widget factories ---------------------------------------------------

    def _make_checkbox(
        self, param: ConfigParam, value: typing.Any
    ) -> QtWidgets.QCheckBox:
        cb = QtWidgets.QCheckBox()
        cb.setChecked(bool(value))
        cb.toggled.connect(
            lambda checked, name=param.name: self._emit_change(name, checked)
        )
        return cb

    def _make_spinbox(
        self, param: ConfigParam, value: typing.Any
    ) -> QtWidgets.QSpinBox:
        sb = QtWidgets.QSpinBox()
        sb.setRange(-(2**31), 2**31 - 1)
        try:
            sb.setValue(int(value))
        except (TypeError, ValueError):
            sb.setValue(int(param.default) if param.default else 0)
        sb.valueChanged.connect(
            lambda v, name=param.name: self._emit_change(name, v)
        )
        return sb

    def _make_double_spinbox(
        self, param: ConfigParam, value: typing.Any
    ) -> QtWidgets.QDoubleSpinBox:
        dsb = QtWidgets.QDoubleSpinBox()
        dsb.setRange(-1e15, 1e15)
        dsb.setDecimals(6)
        try:
            dsb.setValue(float(value))
        except (TypeError, ValueError):
            dsb.setValue(float(param.default) if param.default else 0.0)
        dsb.valueChanged.connect(
            lambda v, name=param.name: self._emit_change(name, v)
        )
        return dsb

    def _make_line_edit(
        self, param: ConfigParam, value: typing.Any
    ) -> QtWidgets.QLineEdit:
        le = QtWidgets.QLineEdit()
        le.setText(str(value) if value is not None else "")
        le.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        le.editingFinished.connect(
            lambda name=param.name, w=le: self._emit_change(name, w.text())
        )
        return le

    def _make_combo(
        self, param: ConfigParam, value: typing.Any
    ) -> QtWidgets.QComboBox:
        cb = QtWidgets.QComboBox()
        cb.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        for choice in param.choices:
            cb.addItem(str(choice), choice)
        # Set current value
        idx = cb.findData(value)
        if idx >= 0:
            cb.setCurrentIndex(idx)
        cb.currentIndexChanged.connect(
            lambda _idx, name=param.name, w=cb: self._emit_change(
                name, w.currentData()
            )
        )
        return cb

    def _make_multi_select_buttons(
        self, param: ConfigParam, value: typing.Any
    ) -> QtWidgets.QWidget:
        """Multi-select toggle buttons for list types with choices."""
        container = QtWidgets.QWidget()
        container.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)

        # Use grid layout with 4 columns for a flow-like appearance
        layout = QtWidgets.QGridLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        current_values = value if isinstance(value, list) else []
        buttons = []

        # Convert current values to strings for comparison (handles both enum ints and strings)
        current_values_as_strings = set()
        for v in current_values:
            if isinstance(v, int):
                # It's likely a maturity enum value - convert to string
                try:
                    from d810.hexrays.hexrays_formatters import maturity_to_string
                    current_values_as_strings.add(maturity_to_string(v))
                except ImportError:
                    current_values_as_strings.add(str(v))
            else:
                current_values_as_strings.add(str(v))

        for idx, choice in enumerate(param.choices):
            btn = QtWidgets.QPushButton(str(choice))
            btn.setCheckable(True)
            btn.setChecked(str(choice) in current_values_as_strings)
            btn.setMinimumWidth(60)

            # Use palette-based styling for dark/light mode compatibility
            btn.setStyleSheet("""
                QPushButton {
                    padding: 4px 8px;
                    border: 1px solid palette(mid);
                    border-radius: 3px;
                    background: palette(button);
                }
                QPushButton:checked {
                    background: palette(highlight);
                    color: palette(highlighted-text);
                    border-color: palette(highlight);
                }
                QPushButton:hover {
                    border-color: palette(highlight);
                }
            """)

            btn.toggled.connect(lambda checked, p=param.name: self._on_button_toggled(p))
            buttons.append(btn)

            # Layout in grid: 4 columns
            row = idx // 4
            col = idx % 4
            layout.addWidget(btn, row, col)

        # Store references for later access
        container._buttons = buttons  # type: ignore
        container._param_name = param.name  # type: ignore

        return container

    def _make_list_edit(
        self, param: ConfigParam, value: typing.Any
    ) -> QtWidgets.QLineEdit:
        """Comma-separated list editor."""
        le = QtWidgets.QLineEdit()
        if isinstance(value, list):
            le.setText(", ".join(str(v) for v in value))
        else:
            le.setText(str(value) if value else "")
        le.setPlaceholderText("comma-separated values")
        le.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        le.editingFinished.connect(
            lambda name=param.name, w=le: self._emit_change(
                name,
                [v.strip() for v in w.text().split(",") if v.strip()],
            )
        )
        return le

    def _make_json_edit(
        self, param: ConfigParam, value: typing.Any
    ) -> QtWidgets.QTextEdit:
        """JSON dict editor."""
        te = QtWidgets.QTextEdit()
        te.setMaximumHeight(120)
        te.setAcceptRichText(False)
        try:
            te.setPlainText(json.dumps(value, indent=2))
        except (TypeError, ValueError):
            te.setPlainText("{}")
        # Emit on focus-out (not every keystroke)
        te.setToolTip(f"{param.description}\n(JSON format)")

        # We use a helper to debounce and emit on text change loss of focus.
        # QTextEdit does not have editingFinished, so we use focusOutEvent
        # via an event filter.
        te.installEventFilter(self)
        te.setProperty("_param_name", param.name)
        return te

    def eventFilter(
        self, obj: QtCore.QObject, event: QtCore.QEvent
    ) -> bool:
        """Intercept focus-out on JSON QTextEdits to emit changes."""
        if (
            isinstance(event, QtCore.QEvent)
            and event.type() == QtCore.QEvent.FocusOut
            and isinstance(obj, QtWidgets.QTextEdit)
        ):
            param_name = obj.property("_param_name")
            if param_name:
                raw = obj.toPlainText()
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    parsed = raw  # let the rule handle invalid JSON
                self._emit_change(param_name, parsed)
        return super().eventFilter(obj, event)

    # --- Helpers ------------------------------------------------------------

    def _process_description(self, desc: str) -> str:
        """Process description text to add HTML formatting.

        Handles:
        - HTML escaping for safety
        - Backtick-wrapped code: `code` -> <code>...</code>
        - Warning keywords: WARNING/CAUTION/DANGER -> red styled span

        Returns
        -------
        str
            HTML-formatted description text.
        """
        import re

        # FIRST: Escape HTML special characters to prevent injection
        desc_html = html.escape(desc)

        # Replace backtick-wrapped text with inline code
        # Pattern: `some code` -> <code>some code</code>
        # Note: Content is already HTML-escaped, so safe to wrap
        backtick_pattern = re.compile(r'`([^`]+)`')
        desc_html = backtick_pattern.sub(
            r'<code style="background: #e0e0e0; padding: 1px 4px; border-radius: 2px; font-family: monospace;">\1</code>',
            desc_html
        )

        # Replace warning keywords with red-styled HTML
        # Note: Keywords are already HTML-escaped, safe to wrap
        if any(keyword in desc.upper() for keyword in ["WARNING:", "CAUTION:", "DANGER:"]):
            for keyword in ["WARNING:", "CAUTION:", "DANGER:"]:
                # Case-insensitive replacement
                # Escape the keyword for pattern matching (already escaped in desc_html)
                escaped_keyword = html.escape(keyword)
                pattern = re.compile(re.escape(escaped_keyword), re.IGNORECASE)
                desc_html = pattern.sub(
                    f'<span style="color: #D32F2F; font-weight: bold;">\u26a0 {escaped_keyword}</span>',
                    desc_html
                )

        return desc_html

    def _on_button_toggled(self, param_name: str) -> None:
        """Handle toggle button changes for multi-select button groups."""
        # Find the container widget for this parameter
        container = self._editor_widgets.get(param_name)
        if container is None or not hasattr(container, "_buttons"):
            return

        # Collect all checked button labels
        selected = []
        for btn in container._buttons:  # type: ignore
            if btn.isChecked():
                selected.append(btn.text())

        self._emit_change(param_name, selected)

    def _emit_change(self, param_name: str, value: typing.Any) -> None:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Config param changed: %s = %s", param_name, value
            )
        self.config_changed.emit(param_name, value)

    @staticmethod
    def _format_maturities(rule: OptimizationRule) -> str:
        """Return a human-readable string of the rule's configured maturities."""
        maturities = getattr(rule, "maturities", [])
        if not maturities:
            return ""
        try:
            from d810.hexrays.hexrays_formatters import maturity_to_string

            return ", ".join(maturity_to_string(m) for m in maturities)
        except ImportError:
            return ", ".join(str(m) for m in maturities)
