"""The third constant-simplification option: rva_guard (lpccp-suvl).

It decides HOW the pointer-like veto is answered, independently of
``memory_policy``, which decides WHICH memory may be folded at all.
"""

from __future__ import annotations

import pytest

from d810.passes.constant_simplification import (
    AGGRESSIVE_MEMORY_POLICY,
    CONSTANT_SIMPLIFICATION_PASS_ID,
    STRICT_MEMORY_POLICY,
    build_constant_simplification_pass,
    constant_simplification_hook_rules,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError


def _config(**options: object) -> PipelineConfig:
    return PipelineConfig(
        pass_id=CONSTANT_SIMPLIFICATION_PASS_ID, options=dict(options)
    )


def _fold_rule_options(config: PipelineConfig) -> dict[str, object]:
    rules = constant_simplification_hook_rules(config)
    for rule in rules.instruction_rules:
        if rule.name == "FoldReadonlyDataRule":
            return dict(rule.config)
    raise AssertionError("FoldReadonlyDataRule is not among the instruction rules")


# --------------------------------------------------------------------------- #
# parsing / validation                                                        #
# --------------------------------------------------------------------------- #


def test_rva_guard_defaults_to_true():
    """Default must preserve today's veto rather than loosen folding."""
    built = build_constant_simplification_pass(_config())
    assert built.options.rva_guard is True


@pytest.mark.parametrize("value", [True, False])
def test_rva_guard_accepts_booleans(value):
    built = build_constant_simplification_pass(_config(rva_guard=value))
    assert built.options.rva_guard is value


@pytest.mark.parametrize("value", ["true", 1, 0, None, "yes"])
def test_rva_guard_rejects_non_boolean(value):
    with pytest.raises(PipelineConfigError, match="rva_guard"):
        build_constant_simplification_pass(_config(rva_guard=value))


def test_rva_guard_is_a_known_option():
    """It must not trip the unknown-option guard."""
    build_constant_simplification_pass(_config(rva_guard=False))


# --------------------------------------------------------------------------- #
# plumbing into the private rule                                              #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", [True, False])
def test_rva_guard_reaches_the_fold_rule(value):
    options = _fold_rule_options(_config(rva_guard=value))
    assert options["rva_guard"] is value


def test_rva_guard_present_in_rule_options_by_default():
    options = _fold_rule_options(_config())
    assert options["rva_guard"] is True


# --------------------------------------------------------------------------- #
# orthogonality to memory_policy                                              #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("policy", "expect_writable"),
    [(STRICT_MEMORY_POLICY, False), (AGGRESSIVE_MEMORY_POLICY, True)],
)
@pytest.mark.parametrize("guard", [True, False])
def test_rva_guard_does_not_alter_memory_policy(policy, expect_writable, guard):
    options = _fold_rule_options(_config(memory_policy=policy, rva_guard=guard))
    assert options.get("fold_writable_constants", False) is expect_writable
    assert options["rva_guard"] is guard


def test_memory_policy_does_not_alter_rva_guard():
    strict = _fold_rule_options(_config(memory_policy=STRICT_MEMORY_POLICY))
    aggressive = _fold_rule_options(_config(memory_policy=AGGRESSIVE_MEMORY_POLICY))
    assert strict["rva_guard"] == aggressive["rva_guard"] is True


# --------------------------------------------------------------------------- #
# the option must be reachable from the UI, not just from JSON                 #
# --------------------------------------------------------------------------- #


def _editor_fields():
    from d810.passes.constant_simplification import (
        register_constant_simplification_pass,
    )
    from d810.passes.registry import PassRegistry

    registry = register_constant_simplification_pass(PassRegistry())
    spec = registry.editor_spec_for(CONSTANT_SIMPLIFICATION_PASS_ID)
    return {f.field_id: f for f in spec.fields}


def test_rva_guard_is_exposed_in_the_pass_editor():
    """Without this the option works from JSON but the UI cannot show it."""
    assert "rva_guard" in _editor_fields()


def test_rva_guard_editor_field_is_a_boolean_bound_to_the_option():
    field = _editor_fields()["rva_guard"]
    assert field.path == ("rva_guard",)
    assert field.control.name == "BOOLEAN"
    assert field.label
    assert field.description


def test_every_parsed_option_has_an_editor_field():
    """Guards the class of bug this test file was extended for: an option added
    to parsing but never surfaced in the editor."""
    from d810.passes.constant_simplification import ConstantSimplificationOptions
    import dataclasses

    parsed = {f.name for f in dataclasses.fields(ConstantSimplificationOptions)}
    assert parsed <= set(_editor_fields())


def test_config_template_seeds_rva_guard_with_its_real_default():
    """An absent template entry renders as an unchecked box, i.e. false --
    the opposite of the effective default."""
    from d810.passes.constant_simplification import (
        register_constant_simplification_pass,
    )
    from d810.passes.registry import PassRegistry

    registry = register_constant_simplification_pass(PassRegistry())
    template = registry.config_template_for(CONSTANT_SIMPLIFICATION_PASS_ID)

    assert template.options["rva_guard"] is True
    assert (
        template.options["rva_guard"]
        is build_constant_simplification_pass(_config()).options.rva_guard
    )
