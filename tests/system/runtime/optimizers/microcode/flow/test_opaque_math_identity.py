"""Test for x*(x+1)%2==0 opaque predicate rule."""
from __future__ import annotations

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
def test_jnz_rule_mod_identity_pattern_structure():
    """Test the pattern has correct structure for smod/umod."""
    from d810.optimizers.microcode.flow.jumps.opaque import JnzRuleModIdentity
    from d810.expr.ast import AstNode
    
    rule = JnzRuleModIdentity()
    
    # LEFT_PATTERN should be a choice between smod and umod
    assert hasattr(rule.LEFT_PATTERN, 'choice_list') or rule.LEFT_PATTERN.opcode in [ida_hexrays.m_smod, ida_hexrays.m_umod]


@pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")
def test_jnz_rule_mod_identity_check_candidate_jnz():
    """Test check_candidate selects fallthrough for jnz (left==right => NOT taken)."""
    from d810.optimizers.microcode.flow.jumps.opaque import JnzRuleModIdentity

    rule = JnzRuleModIdentity()
    rule.jump_original_block_serial = 100
    rule.direct_block_serial = 200

    # For jnz (jump if NOT equal), condition left==right is FALSE, so jump NOT taken (fallthrough)
    result = rule.check_candidate(ida_hexrays.m_jnz, {}, {})
    assert result is True
    assert rule.jump_replacement_block_serial == 200, "Should fallthrough for jnz when left==right"


@pytest.mark.skipif(not IDA_AVAILABLE, reason="IDA not available")
def test_jnz_rule_mod_identity_check_candidate_jz():
    """Test check_candidate selects jump target for jz (left==right => jump taken)."""
    from d810.optimizers.microcode.flow.jumps.opaque import JnzRuleModIdentity

    rule = JnzRuleModIdentity()
    rule.jump_original_block_serial = 100
    rule.direct_block_serial = 200

    # For jz (jump if equal), condition left==right is TRUE, so jump IS taken
    result = rule.check_candidate(ida_hexrays.m_jz, {}, {})
    assert result is True
    assert rule.jump_replacement_block_serial == 100, "Should take jump for jz when left==right"
