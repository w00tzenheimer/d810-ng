"""Test adjacent-product modulo opaque predicate rules."""
from __future__ import annotations

import importlib

import pytest

# Test will import IDA modules only if available
try:
    import ida_hexrays
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


@pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")
def test_jnz_rule_mod_identity_exists():
    """Test that JnzRuleModIdentity class exists."""
    from d810.optimizers.microcode.flow.jumps.opaque import JnzRuleModIdentity
    
    rule = JnzRuleModIdentity()
    assert rule is not None
    assert hasattr(rule, 'ORIGINAL_JUMP_OPCODES')
    assert hasattr(rule, 'LEFT_PATTERN')
    assert hasattr(rule, 'RIGHT_PATTERN')
    assert hasattr(rule, 'check_candidate')


@pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")
@pytest.mark.parametrize(
    ("rule_name", "mod_opcode_name", "step_opcode_name"),
    (
        ("JnzRuleModIdentity", "m_smod", "m_add"),
        ("JnzRuleSmodSubIdentity", "m_smod", "m_sub"),
        ("JnzRuleUmodAddIdentity", "m_umod", "m_add"),
        ("JnzRuleUmodSubIdentity", "m_umod", "m_sub"),
    ),
)
def test_jnz_rule_mod_identity_variant_pattern_structure(
    rule_name,
    mod_opcode_name,
    step_opcode_name,
):
    """Test each adjacent-product variant matches the intended modulo shape."""
    opaque = importlib.import_module("d810.optimizers.microcode.flow.jumps.opaque")

    rule = getattr(opaque, rule_name)()

    mod_opcode = getattr(ida_hexrays, mod_opcode_name)
    step_opcode = getattr(ida_hexrays, step_opcode_name)
    assert rule.LEFT_PATTERN.opcode == mod_opcode
    assert rule.LEFT_PATTERN.left.opcode == ida_hexrays.m_mul
    assert rule.LEFT_PATTERN.left.right.opcode == step_opcode
    assert rule.LEFT_PATTERN.right.value == 2
    assert rule.RIGHT_PATTERN.value == 0


@pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")
@pytest.mark.parametrize(
    "rule_name",
    (
        "JnzRuleModIdentity",
        "JnzRuleSmodSubIdentity",
        "JnzRuleUmodAddIdentity",
        "JnzRuleUmodSubIdentity",
    ),
)
def test_jnz_rule_mod_identity_check_candidate_jnz(rule_name):
    """Test check_candidate selects fallthrough for jnz (left==right => NOT taken)."""
    opaque = importlib.import_module("d810.optimizers.microcode.flow.jumps.opaque")

    rule = getattr(opaque, rule_name)()
    rule.jump_original_block_serial = 100
    rule.direct_block_serial = 200

    # For jnz (jump if NOT equal), condition left==right is FALSE, so jump NOT taken (fallthrough)
    result = rule.check_candidate(ida_hexrays.m_jnz, {}, {})
    assert result is True
    assert rule.jump_replacement_block_serial == 200, "Should fallthrough for jnz when left==right"


@pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")
@pytest.mark.parametrize(
    "rule_name",
    (
        "JnzRuleModIdentity",
        "JnzRuleSmodSubIdentity",
        "JnzRuleUmodAddIdentity",
        "JnzRuleUmodSubIdentity",
    ),
)
def test_jnz_rule_mod_identity_check_candidate_jz(rule_name):
    """Test check_candidate selects jump target for jz (left==right => jump taken)."""
    opaque = importlib.import_module("d810.optimizers.microcode.flow.jumps.opaque")

    rule = getattr(opaque, rule_name)()
    rule.jump_original_block_serial = 100
    rule.direct_block_serial = 200

    # For jz (jump if equal), condition left==right is TRUE, so jump IS taken
    result = rule.check_candidate(ida_hexrays.m_jz, {}, {})
    assert result is True
    assert rule.jump_replacement_block_serial == 100, "Should take jump for jz when left==right"
