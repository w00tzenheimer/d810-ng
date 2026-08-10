"""jump-fixer must expose its rule selection in the workbench.

The pass shipped with PassEditorKind.SUMMARY and no fields, so none of its rules
were visible or toggleable from the UI -- `enabled_rules` was JSON-only. That
hid every jump rule, not just newly added ones.
"""

from __future__ import annotations

import pytest

from d810.passes.hook_transform_passes import (
    JUMP_FIXER_PASS_ID,
    JUMP_FIXER_RULE_NAMES,
    hook_transform_pass_registry,
)


@pytest.fixture(scope="module")
def spec():
    return hook_transform_pass_registry().editor_spec_for(JUMP_FIXER_PASS_ID)


def _field(spec, field_id):
    return {f.field_id: f for f in spec.fields}[field_id]


def test_jump_fixer_is_no_longer_summary_only(spec):
    assert spec.kind.name == "FIELDS"
    assert spec.fields


def test_enabled_rules_is_editable_as_a_list(spec):
    field = _field(spec, "enabled_rules")
    assert field.control.name == "STRING_LIST"
    assert field.path == ("enabled_rules",)
    assert field.label
    assert field.description


def test_every_declared_rule_is_offered_as_a_choice(spec):
    field = _field(spec, "enabled_rules")
    assert set(field.choices) == set(JUMP_FIXER_RULE_NAMES)


def test_the_flags_opaque_predicate_rule_is_offered():
    """The rule that motivated this: previously invisible in the UI."""
    assert "JmpRuleFlagsOpaquePredicate" in JUMP_FIXER_RULE_NAMES


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


def test_template_seeds_enabled_rules_so_the_control_renders_populated():
    template = hook_transform_pass_registry().config_template_for(JUMP_FIXER_PASS_ID)
    assert "enabled_rules" in template.options
    assert set(template.options["enabled_rules"]) <= set(JUMP_FIXER_RULE_NAMES)


def test_other_hook_transform_passes_keep_their_summary_editor():
    """Only jump-fixer gains fields; the rest are untouched."""
    registry = hook_transform_pass_registry()
    other = registry.editor_spec_for("identity-call-resolver")
    assert other.kind.name == "SUMMARY"
