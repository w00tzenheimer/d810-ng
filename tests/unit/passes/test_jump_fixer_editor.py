"""jump-fixer must expose its rule selection in the workbench.

The pass shipped with PassEditorKind.SUMMARY and no fields, so none of its rules
were visible or toggleable from the UI -- `enabled_rules` was JSON-only. That
hid every jump rule, not just newly added ones.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from d810.passes.hook_transform_passes import (
    JUMP_FIXER_PASS_ID,
    JUMP_FIXER_RULE_NAMES,
    JUMP_FIXER_RULE_SPECS,
    hook_transform_pass_registry,
)


@pytest.fixture(scope="module")
def spec():
    return hook_transform_pass_registry().editor_spec_for(JUMP_FIXER_PASS_ID)


def test_jump_fixer_rules_use_a_typed_rule_catalog(spec):
    assert spec.kind.name == "RULE_CATALOG"
    assert spec.rule_option_path == ("enabled_rules",)
    assert spec.rules == JUMP_FIXER_RULE_SPECS


def test_every_declared_rule_is_offered_as_a_choice(spec):
    assert {item.rule_id for item in spec.rules} == set(JUMP_FIXER_RULE_NAMES)
    assert all(item.family_id and item.family_label for item in spec.rules)
    assert all(item.description for item in spec.rules)


def test_the_flags_opaque_predicate_rule_is_offered():
    """The rule that motivated this: previously invisible in the UI."""
    rule = next(
        item
        for item in JUMP_FIXER_RULE_SPECS
        if item.rule_id == "JmpRuleFlagsOpaquePredicate"
    )

    assert rule.experimental is True
    assert rule.experimental_reason
    assert rule.default_selected is False


@pytest.mark.parametrize(
    "known",
    ["JnzRule1", "JmpRuleZ3Const", "CompareConstantRule1", "JmpRuleReachingConst"],
)
def test_preexisting_rules_are_offered_too(known):
    """This gap hid all of them, so the fix must not be scoped to one rule."""
    assert known in JUMP_FIXER_RULE_NAMES


def test_rule_names_are_unique_and_sorted():
    assert len(JUMP_FIXER_RULE_NAMES) == len(set(JUMP_FIXER_RULE_NAMES))
    assert list(JUMP_FIXER_RULE_NAMES) == sorted(JUMP_FIXER_RULE_NAMES)


def test_every_public_runtime_jump_rule_has_explicit_editor_metadata() -> None:
    """A new optimizer rule cannot become selectable only through JSON.

    The pass layer must not import Hex-Rays optimizer modules, so this test
    inspects their class hierarchy syntactically.  It follows local subclasses
    (the modulo identities inherit a private helper) and intentionally omits
    only underscored implementation bases, never public concrete rules.
    """
    jumps_dir = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "d810"
        / "optimizers"
        / "microcode"
        / "flow"
        / "jumps"
    )
    bases_by_class: dict[str, set[str]] = {}
    for source in jumps_dir.glob("*.py"):
        module = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(module):
            if not isinstance(node, ast.ClassDef):
                continue
            bases_by_class.setdefault(node.name, set()).update(
                base.id
                for base in node.bases
                if isinstance(base, ast.Name)
            )

    jump_rule_classes = {"JumpOptimizationRule"}
    changed = True
    while changed:
        changed = False
        for class_name, bases in bases_by_class.items():
            if class_name in jump_rule_classes or not bases.intersection(jump_rule_classes):
                continue
            jump_rule_classes.add(class_name)
            changed = True

    runtime_rule_names = {
        class_name
        for class_name in jump_rule_classes
        if class_name != "JumpOptimizationRule" and not class_name.startswith("_")
    }

    assert runtime_rule_names == set(JUMP_FIXER_RULE_NAMES)


def test_template_seeds_enabled_rules_so_the_control_renders_populated(spec):
    template = hook_transform_pass_registry().config_template_for(JUMP_FIXER_PASS_ID)
    assert "enabled_rules" in template.options
    assert template.options == spec.default_options()


def test_every_public_hook_pass_seeds_its_typed_editor_defaults():
    """The fixed editor, rather than JSON, defines each public hook default."""
    registry = hook_transform_pass_registry()

    for pass_id in registry.public_pass_ids():
        editor = registry.editor_spec_for(pass_id)
        template = registry.config_template_for(pass_id)

        assert editor is not None
        assert template.options == editor.default_options()
