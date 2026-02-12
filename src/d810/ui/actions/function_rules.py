"""Function rules action.

Show and edit function-scoped rule overrides for the current pseudocode function.
"""
from __future__ import annotations

import typing

from d810.core.logging import getLogger
from d810.core.persistence import FunctionRuleConfig
from d810.ui.rule_tree import RuleTreeWidget
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

# ---------------------------------------------------------------------------
# Qt imports -- optional, will fail gracefully if not in GUI mode
# ---------------------------------------------------------------------------
try:
    from d810.qt_shim import (
        QDialog,
        QLabel,
        QPushButton,
        QTextEdit,
        QVBoxLayout,
        QHBoxLayout,
        QTimer,
    )

    QT_AVAILABLE = True
except ImportError:
    QT_AVAILABLE = False


def _get_current_func_ea(ctx: typing.Any, ida_hexrays_mod: typing.Any) -> int | None:
    vdui = ida_hexrays_mod.get_widget_vdui(ctx.widget)
    if vdui is None or getattr(vdui, "cfunc", None) is None:
        return None
    return int(vdui.cfunc.entry_ea)


def _collect_available_rules(state: typing.Any) -> list[typing.Any]:
    rules = list(getattr(state, "current_ins_rules", [])) + list(
        getattr(state, "current_blk_rules", [])
    )
    if not rules:
        rules = list(getattr(state, "known_ins_rules", [])) + list(
            getattr(state, "known_blk_rules", [])
        )
    dedup: dict[str, typing.Any] = {}
    for rule in rules:
        rule_name = str(getattr(rule, "name", ""))
        if not rule_name:
            continue
        dedup.setdefault(rule_name, rule)
    return list(dedup.values())


def _resolve_initial_enabled_rule_names(
    all_rule_names: set[str],
    override: FunctionRuleConfig | None,
) -> set[str]:
    if not all_rule_names:
        return set()
    if override is None:
        return set(all_rule_names)

    enabled = set(override.enabled_rules)
    disabled = set(override.disabled_rules)
    if enabled:
        return {name for name in all_rule_names if name in enabled and name not in disabled}
    return set(all_rule_names) - disabled


def _build_override_sets(
    all_rule_names: set[str],
    enabled_rule_names: set[str],
) -> tuple[set[str], set[str]]:
    selected = set(enabled_rule_names) & set(all_rule_names)
    if selected == all_rule_names:
        return set(), set()
    if not selected:
        return set(), set(all_rule_names)

    disabled = set(all_rule_names) - selected
    # Prefer the smaller representation to keep persisted overlays compact.
    if len(disabled) <= len(selected):
        return set(), disabled
    return selected, set()


class FunctionRulesDialog(QDialog if QT_AVAILABLE else object):  # type: ignore[misc]
    def __init__(
        self,
        *,
        func_name: str,
        func_ea: int,
        available_rules: list[typing.Any],
        initial_enabled_rule_names: set[str],
        initial_notes: str,
        parent: typing.Any = None,
    ) -> None:
        super().__init__(parent)
        self._available_rules = available_rules
        self._all_rule_names = {
            str(getattr(rule, "name", "")) for rule in available_rules if getattr(rule, "name", "")
        }
        self.setWindowTitle(f"Function Rules: {func_name}")

        layout = QVBoxLayout()

        self._summary_label = QLabel()
        layout.addWidget(self._summary_label)

        self._details_label = QLabel(
            f"Function: {func_name} @ 0x{func_ea:X}"
        )
        layout.addWidget(self._details_label)

        self._rule_tree = RuleTreeWidget(self)
        self._rule_tree.set_rules(available_rules, enabled_names=initial_enabled_rule_names)
        self._rule_tree.set_read_only(False)
        self._rule_tree.rule_toggled.connect(self._on_rule_toggled)
        layout.addWidget(self._rule_tree)

        layout.addWidget(QLabel("Notes:"))
        self._notes_edit = QTextEdit(self)
        self._notes_edit.setPlainText(initial_notes or "")
        layout.addWidget(self._notes_edit)

        button_layout = QHBoxLayout()
        self._reset_button = QPushButton("Enable All")
        self._reset_button.clicked.connect(self._on_enable_all)
        button_layout.addWidget(self._reset_button)

        button_layout.addStretch(1)

        self._save_button = QPushButton("Save")
        self._save_button.clicked.connect(self.accept)
        button_layout.addWidget(self._save_button)

        self._cancel_button = QPushButton("Cancel")
        self._cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self._cancel_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)
        self._refresh_summary()

    def selected_rule_names(self) -> set[str]:
        return self._rule_tree.get_enabled_rule_names()

    def notes_text(self) -> str:
        return str(self._notes_edit.toPlainText()).strip()

    def _on_enable_all(self) -> None:
        self._rule_tree.set_enabled_rules(set(self._all_rule_names))
        self._refresh_summary()

    def _on_rule_toggled(self, _rule: typing.Any, _enabled: bool) -> None:
        self._refresh_summary()

    def _refresh_summary(self) -> None:
        selected = self.selected_rule_names()
        total = len(self._all_rule_names)
        self._summary_label.setText(f"Enabled for this function: {len(selected)}/{total}")


class FunctionRules(D810ActionHandler):
    """Show / edit function-scoped rule overrides for the current function."""

    ACTION_ID = "d810ng:function_rules"
    ACTION_TEXT = "Function rules..."
    ACTION_TOOLTIP = "View or edit rule overrides for this function"
    SUPPORTED_VIEWS = frozenset({"pseudocode"})
    MENU_ORDER = 30

    def execute(self, ctx: typing.Any) -> int:
        """Execute the function rules action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        ida_kernwin_mod = self.ida_module("ida_kernwin")
        ida_hexrays_mod = self.ida_module("ida_hexrays")
        if ida_kernwin_mod is None or ida_hexrays_mod is None or not QT_AVAILABLE:
            return 0

        func_ea = _get_current_func_ea(ctx, ida_hexrays_mod)
        if func_ea is None:
            ida_kernwin_mod.warning("d810-ng: no function available in current context.")
            return 0

        vdui = ida_hexrays_mod.get_widget_vdui(ctx.widget)
        func_name = f"sub_{func_ea:X}"
        try:
            if vdui is not None and getattr(vdui, "cfunc", None) is not None:
                cfunc_name = str(getattr(vdui.cfunc, "name", "")).strip()
                if cfunc_name:
                    func_name = cfunc_name
        except Exception:
            pass

        available_rules = _collect_available_rules(self._state)
        if not available_rules:
            ida_kernwin_mod.warning("d810-ng: no rules available for function override.")
            return 0

        manager = getattr(self._state, "manager", None)
        if manager is None:
            ida_kernwin_mod.warning("d810-ng manager is not initialized.")
            return 0

        override = None
        if hasattr(manager, "get_function_rule_override"):
            override = manager.get_function_rule_override(func_ea)

        all_rule_names = {
            str(getattr(rule, "name", "")) for rule in available_rules if getattr(rule, "name", "")
        }
        initial_enabled = _resolve_initial_enabled_rule_names(all_rule_names, override)
        initial_notes = override.notes if override is not None else ""

        dialog = FunctionRulesDialog(
            func_name=func_name,
            func_ea=func_ea,
            available_rules=available_rules,
            initial_enabled_rule_names=initial_enabled,
            initial_notes=initial_notes,
        )
        if dialog.exec() != QDialog.Accepted:
            return 0

        enabled_names = dialog.selected_rule_names()
        enabled_rules, disabled_rules = _build_override_sets(all_rule_names, enabled_names)
        notes = dialog.notes_text()

        def _apply_override() -> None:
            manager.set_function_rule_override(
                function_addr=func_ea,
                enabled_rules=enabled_rules,
                disabled_rules=disabled_rules,
                notes=notes,
            )
            if vdui is not None:
                vdui.refresh_view(True)
            ida_kernwin_mod.msg(
                f"d810-ng: Saved function rule override for {func_name} "
                f"(enabled={len(enabled_names)}/{len(all_rule_names)})\n"
            )

        QTimer.singleShot(0, _apply_override)
        return 1

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in pseudocode view, False otherwise
        """
        ida_hexrays_mod = self.ida_module("ida_hexrays")
        if ida_hexrays_mod is None:
            return False

        return ida_hexrays_mod.get_widget_vdui(ctx.widget) is not None
