from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from d810.ui.project_config_logic import (
    config_v2_user_destination,
    resolve_config_v2_focus_target,
)
from d810.ui.rule_tree_logic import (
    RuleTreeContextAction,
    RuleTreeContextTarget,
    RuleTreeTargetKind,
    apply_context_action,
    context_action_for,
)


def _leaf(*, enabled: bool) -> RuleTreeContextTarget:
    return RuleTreeContextTarget(
        kind=RuleTreeTargetKind.RULE,
        rule_names=("Add_Xor_Rule_1",),
        enabled_count=int(enabled),
        total_count=1,
        rule_name="Add_Xor_Rule_1",
        optimizer_type="Instruction Optimizers",
    )


def _group(enabled: int, total: int) -> RuleTreeContextTarget:
    return RuleTreeContextTarget(
        kind=RuleTreeTargetKind.GROUP,
        rule_names=tuple(f"Rule_{index}" for index in range(total)),
        enabled_count=enabled,
        total_count=total,
    )


def test_disabled_leaf_requests_enable() -> None:
    assert context_action_for(_leaf(enabled=False)) is RuleTreeContextAction.ENABLE


def test_enabled_leaf_requests_disable() -> None:
    assert context_action_for(_leaf(enabled=True)) is RuleTreeContextAction.DISABLE


def test_partial_or_empty_group_requests_enable_all() -> None:
    assert context_action_for(_group(0, 7)) is RuleTreeContextAction.ENABLE_ALL
    assert context_action_for(_group(3, 7)) is RuleTreeContextAction.ENABLE_ALL


def test_full_group_requests_disable_all_and_empty_group_has_no_action() -> None:
    assert context_action_for(_group(7, 7)) is RuleTreeContextAction.DISABLE_ALL
    assert context_action_for(_group(0, 0)) is None


def test_apply_context_action_returns_new_legacy_draft_set() -> None:
    initial = {"Rule_0", "unrelated"}
    target = _group(1, 3)

    enabled = apply_context_action(
        initial,
        target,
        RuleTreeContextAction.ENABLE_ALL,
    )
    disabled = apply_context_action(
        initial,
        target,
        RuleTreeContextAction.DISABLE_ALL,
    )

    assert initial == {"Rule_0", "unrelated"}
    assert enabled == {"Rule_0", "Rule_1", "Rule_2", "unrelated"}
    assert disabled == {"unrelated"}


def test_mba_instruction_rule_focus_is_unique() -> None:
    target = _leaf(enabled=False)
    catalog = (
        SimpleNamespace(
            pass_id="mba-simplify",
            owned_rules=(),
            transforms=(),
        ),
    )

    focus = resolve_config_v2_focus_target(
        target,
        ("mba-simplify", "jump-fixer"),
        catalog,
    )

    assert focus.unambiguous is True
    assert focus.pass_id == "mba-simplify"
    assert focus.rule_name == "Add_Xor_Rule_1"


def test_catalog_transform_focus_is_unique() -> None:
    target = RuleTreeContextTarget(
        kind=RuleTreeTargetKind.RULE,
        rule_names=("JumpFixer",),
        enabled_count=1,
        total_count=1,
        rule_name="JumpFixer",
        optimizer_type="Block Optimizers",
    )
    catalog = (
        SimpleNamespace(
            pass_id="jump-fixer",
            owned_rules=(),
            transforms=("JumpFixer",),
        ),
    )

    focus = resolve_config_v2_focus_target(target, ("jump-fixer",), catalog)

    assert focus.unambiguous is True
    assert focus.pass_id == "jump-fixer"


def test_ambiguous_or_unowned_focus_does_not_guess() -> None:
    target = RuleTreeContextTarget(
        kind=RuleTreeTargetKind.RULE,
        rule_names=("SharedRule",),
        enabled_count=1,
        total_count=1,
        rule_name="SharedRule",
        optimizer_type="Block Optimizers",
    )
    catalog = (
        SimpleNamespace(pass_id="first", owned_rules=("SharedRule",), transforms=()),
        SimpleNamespace(pass_id="second", owned_rules=("SharedRule",), transforms=()),
    )

    ambiguous = resolve_config_v2_focus_target(
        target, ("first", "second"), catalog
    )
    unowned = resolve_config_v2_focus_target(
        target, ("other",), catalog
    )

    assert ambiguous.unambiguous is False
    assert ambiguous.pass_id is None
    assert "multiple" in ambiguous.message.lower()
    assert unowned.unambiguous is False
    assert unowned.pass_id is None
    assert "no configured" in unowned.message.lower()


def test_config_v2_user_destination_uses_same_basename_for_bundled_runtime() -> None:
    config_dir = Path("/ida-user/cfg/d810")
    runtime = Path("/plugin/d810/conf/runtime.json")

    assert config_v2_user_destination(config_dir, runtime) == (
        config_dir / "runtime.json"
    )
    assert config_v2_user_destination(config_dir, config_dir / "runtime.json") == (
        config_dir / "runtime.json"
    )
