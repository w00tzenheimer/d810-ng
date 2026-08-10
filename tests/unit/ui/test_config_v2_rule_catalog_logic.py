"""Rule-catalog projections stay typed, grouped, and selection-safe."""

from __future__ import annotations

import pytest

from d810.passes.hook_transform_passes import JUMP_FIXER_RULE_SPECS


def _logic_module() -> object:
    from d810.ui import config_v2_editing_logic

    return config_v2_editing_logic


def test_rule_catalog_groups_explicit_families_and_subfamilies() -> None:
    logic = _logic_module()
    from d810.core.pass_editor_spec import PassEditorSpec

    view = logic.project_rule_catalog(
        PassEditorSpec.rule_catalog(JUMP_FIXER_RULE_SPECS),
        {"JnzRule1", "JmpRuleFlagsOpaquePredicate"},
        query="opaque",
    )

    assert [family.family_id for family in view.families] == ["opaque-predicates"]
    assert view.families[0].visible_count == 13
    assert view.families[0].selected_count == 2
    assert {subfamily.subfamily_id for subfamily in view.families[0].subfamilies} == {
        "flags-register",
        "boolean-identities",
        "modulo-parity",
    }


def test_visible_rule_action_only_changes_the_current_filtered_scope() -> None:
    logic = _logic_module()
    from d810.core.pass_editor_spec import PassEditorSpec

    view = logic.project_rule_catalog(
        PassEditorSpec.rule_catalog(JUMP_FIXER_RULE_SPECS),
        {"CompareConstantRule1"},
        query="opaque",
    )

    assert logic.apply_rule_catalog_selection(
        view,
        {"CompareConstantRule1"},
        target_id="visible",
        selected=True,
    ) == (
        "CompareConstantRule1",
        "JmpRuleFlagsOpaquePredicate",
        "JnzRule1",
        "JnzRule2",
        "JnzRule3",
        "JnzRule4",
        "JnzRule5",
        "JnzRule6",
        "JnzRule7",
        "JnzRule8",
        "JnzRuleModIdentity",
        "JnzRuleSmodSubIdentity",
        "JnzRuleUmodAddIdentity",
        "JnzRuleUmodSubIdentity",
    )


def test_rule_group_actions_apply_to_all_registered_descendants() -> None:
    logic = _logic_module()
    from d810.core.pass_editor_spec import PassEditorSpec

    jump_fixer_spec = PassEditorSpec.rule_catalog(JUMP_FIXER_RULE_SPECS)
    filtered = logic.project_rule_catalog(
        jump_fixer_spec,
        selected_ids=frozenset(),
        query="compare constant 1",
    )

    assert logic.apply_rule_catalog_selection(
        filtered,
        frozenset(),
        target_id="family:comparison-rewrites",
        selected=True,
    ) == (
        "CompareConstantRule1",
        "CompareConstantRule2",
        "CompareConstantRule3",
        "CompareConstantRule4",
        "JaeRule1",
        "JbRule1",
    )
    assert logic.apply_rule_catalog_selection(
        filtered,
        frozenset(),
        target_id="subfamily:comparison-rewrites:masked-constants",
        selected=True,
    ) == (
        "CompareConstantRule1",
        "CompareConstantRule2",
        "CompareConstantRule3",
        "CompareConstantRule4",
    )
    assert logic.apply_rule_catalog_selection(
        filtered,
        frozenset(),
        target_id="visible",
        selected=True,
    ) == ("CompareConstantRule1",)
    assert logic.apply_rule_catalog_selection(
        filtered,
        frozenset(),
        target_id="CompareConstantRule1",
        selected=True,
    ) == ("CompareConstantRule1",)

    assert logic.apply_rule_catalog_selection(
        filtered,
        filtered.all_rule_ids,
        target_id="subfamily:comparison-rewrites:masked-constants",
        selected=False,
    ) == (
        "JaeRule1",
        "JbRule1",
        "JmpRuleFlagsOpaquePredicate",
        "JmpRuleReachingConst",
        "JmpRuleZ3Const",
        "JnzRule1",
        "JnzRule2",
        "JnzRule3",
        "JnzRule4",
        "JnzRule5",
        "JnzRule6",
        "JnzRule7",
        "JnzRule8",
        "JnzRuleModIdentity",
        "JnzRuleSmodSubIdentity",
        "JnzRuleUmodAddIdentity",
        "JnzRuleUmodSubIdentity",
    )


def test_rule_catalog_selection_rejects_unknown_targets() -> None:
    logic = _logic_module()
    from d810.core.pass_editor_spec import PassEditorSpec

    view = logic.project_rule_catalog(
        PassEditorSpec.rule_catalog(JUMP_FIXER_RULE_SPECS),
        selected_ids=frozenset(),
        query="compare constant 1",
    )

    with pytest.raises(ValueError):
        logic.apply_rule_catalog_selection(
            view,
            frozenset(),
            target_id="family:not-registered",
            selected=True,
        )
    with pytest.raises(ValueError):
        logic.apply_rule_catalog_selection(
            view,
            frozenset(),
            target_id="subfamily:comparison-rewrites:not-registered",
            selected=True,
        )
    with pytest.raises(ValueError):
        logic.apply_rule_catalog_selection(
            view,
            frozenset(),
            target_id="NotARegisteredRule",
            selected=True,
        )


def test_rule_projection_keeps_experimental_warning_metadata_visible() -> None:
    logic = _logic_module()
    from d810.core.pass_editor_spec import PassEditorSpec

    view = logic.project_rule_catalog(
        PassEditorSpec.rule_catalog(JUMP_FIXER_RULE_SPECS),
        set(),
        query="flags",
    )
    flags_rule = view.families[0].subfamilies[0].rules[0]

    assert flags_rule.rule_id == "JmpRuleFlagsOpaquePredicate"
    assert flags_rule.experimental is True
    assert flags_rule.experimental_reason


def test_rule_catalog_selection_updates_only_its_declared_option_path() -> None:
    logic = _logic_module()
    from d810.core.pass_editor_spec import PassEditorSpec

    spec = PassEditorSpec.rule_catalog(
        JUMP_FIXER_RULE_SPECS,
        option_path=("rule_selection", "enabled"),
    )

    assert logic.apply_rule_catalog_selection_to_options(
        {"keep": True, "rule_selection": {"other": "preserved"}},
        spec,
        ("JnzRule1", "JmpRuleFlagsOpaquePredicate"),
    ) == {
        "keep": True,
        "rule_selection": {
            "other": "preserved",
            "enabled": ["JnzRule1", "JmpRuleFlagsOpaquePredicate"],
        },
    }
