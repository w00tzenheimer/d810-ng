"""Unit tests for graph_modification module (backend-agnostic CFG modification intents).

Test coverage:
- Construction of each modification type
- Frozen/immutability enforcement
- Hash and equality semantics
- Type discrimination via isinstance and match
- Tuple field enforcement
"""
from __future__ import annotations

import pytest

from d810.hexrays.graph_modification import (
    RedirectEdge,
    ConvertToGoto,
    InsertBlock,
    RemoveEdge,
    NopInstructions,
    GraphModification,
)
from d810.hexrays.portable_cfg import InsnSnapshot
from d810.hexrays.mop_snapshot import MopSnapshot


# ============================================================================
# Construction Tests
# ============================================================================


def test_redirect_edge_construction():
    """Test RedirectEdge construction and field access."""
    mod = RedirectEdge(from_serial=10, old_target=20, new_target=30)
    assert mod.from_serial == 10
    assert mod.old_target == 20
    assert mod.new_target == 30


def test_convert_to_goto_construction():
    """Test ConvertToGoto construction and field access."""
    mod = ConvertToGoto(block_serial=15, goto_target=25)
    assert mod.block_serial == 15
    assert mod.goto_target == 25


def test_insert_block_construction():
    """Test InsertBlock construction with instruction snapshots."""
    insn1 = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
    insn2 = InsnSnapshot(opcode=0x02, ea=0x1004, operands=())
    mod = InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn1, insn2))

    assert mod.pred_serial == 5
    assert mod.succ_serial == 10
    assert len(mod.instructions) == 2
    assert mod.instructions[0] == insn1
    assert mod.instructions[1] == insn2


def test_insert_block_empty_instructions():
    """Test InsertBlock with empty instruction tuple."""
    mod = InsertBlock(pred_serial=5, succ_serial=10, instructions=())
    assert mod.pred_serial == 5
    assert mod.succ_serial == 10
    assert len(mod.instructions) == 0
    assert mod.instructions == ()


def test_remove_edge_construction():
    """Test RemoveEdge construction and field access."""
    mod = RemoveEdge(from_serial=10, to_serial=20)
    assert mod.from_serial == 10
    assert mod.to_serial == 20


def test_nop_instructions_construction():
    """Test NopInstructions construction with EA tuple."""
    mod = NopInstructions(block_serial=10, insn_eas=(0x1000, 0x1004, 0x1008))
    assert mod.block_serial == 10
    assert len(mod.insn_eas) == 3
    assert mod.insn_eas[0] == 0x1000
    assert mod.insn_eas[1] == 0x1004
    assert mod.insn_eas[2] == 0x1008


def test_nop_instructions_empty_eas():
    """Test NopInstructions with empty EA tuple."""
    mod = NopInstructions(block_serial=10, insn_eas=())
    assert mod.block_serial == 10
    assert len(mod.insn_eas) == 0
    assert mod.insn_eas == ()


# ============================================================================
# Immutability Tests
# ============================================================================


def test_redirect_edge_frozen():
    """Test RedirectEdge is frozen (immutable)."""
    mod = RedirectEdge(from_serial=10, old_target=20, new_target=30)
    with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
        mod.from_serial = 99  # type: ignore


def test_convert_to_goto_frozen():
    """Test ConvertToGoto is frozen (immutable)."""
    mod = ConvertToGoto(block_serial=15, goto_target=25)
    with pytest.raises(Exception):
        mod.block_serial = 99  # type: ignore


def test_insert_block_frozen():
    """Test InsertBlock is frozen (immutable)."""
    mod = InsertBlock(pred_serial=5, succ_serial=10, instructions=())
    with pytest.raises(Exception):
        mod.pred_serial = 99  # type: ignore


def test_insert_block_instructions_immutable():
    """Test InsertBlock.instructions tuple is immutable."""
    insn1 = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
    mod = InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn1,))

    # Tuple itself is immutable
    with pytest.raises(Exception):  # TypeError or AttributeError
        mod.instructions[0] = InsnSnapshot(opcode=0xFF, ea=0xDEAD, operands=())  # type: ignore


def test_remove_edge_frozen():
    """Test RemoveEdge is frozen (immutable)."""
    mod = RemoveEdge(from_serial=10, to_serial=20)
    with pytest.raises(Exception):
        mod.from_serial = 99  # type: ignore


def test_nop_instructions_frozen():
    """Test NopInstructions is frozen (immutable)."""
    mod = NopInstructions(block_serial=10, insn_eas=(0x1000,))
    with pytest.raises(Exception):
        mod.block_serial = 99  # type: ignore


def test_nop_instructions_eas_immutable():
    """Test NopInstructions.insn_eas tuple is immutable."""
    mod = NopInstructions(block_serial=10, insn_eas=(0x1000, 0x1004))

    # Tuple itself is immutable
    with pytest.raises(Exception):
        mod.insn_eas[0] = 0xDEAD  # type: ignore


# ============================================================================
# Equality and Hashing Tests
# ============================================================================


def test_redirect_edge_equality():
    """Test RedirectEdge equality semantics."""
    mod1 = RedirectEdge(from_serial=10, old_target=20, new_target=30)
    mod2 = RedirectEdge(from_serial=10, old_target=20, new_target=30)
    mod3 = RedirectEdge(from_serial=10, old_target=20, new_target=99)

    assert mod1 == mod2
    assert mod1 != mod3
    assert hash(mod1) == hash(mod2)


def test_convert_to_goto_equality():
    """Test ConvertToGoto equality semantics."""
    mod1 = ConvertToGoto(block_serial=15, goto_target=25)
    mod2 = ConvertToGoto(block_serial=15, goto_target=25)
    mod3 = ConvertToGoto(block_serial=15, goto_target=99)

    assert mod1 == mod2
    assert mod1 != mod3
    assert hash(mod1) == hash(mod2)


def test_insert_block_equality():
    """Test InsertBlock equality semantics."""
    insn1 = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
    insn2 = InsnSnapshot(opcode=0x02, ea=0x1004, operands=())

    mod1 = InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn1, insn2))
    mod2 = InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn1, insn2))
    mod3 = InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn1,))

    assert mod1 == mod2
    assert mod1 != mod3
    assert hash(mod1) == hash(mod2)


def test_remove_edge_equality():
    """Test RemoveEdge equality semantics."""
    mod1 = RemoveEdge(from_serial=10, to_serial=20)
    mod2 = RemoveEdge(from_serial=10, to_serial=20)
    mod3 = RemoveEdge(from_serial=10, to_serial=99)

    assert mod1 == mod2
    assert mod1 != mod3
    assert hash(mod1) == hash(mod2)


def test_nop_instructions_equality():
    """Test NopInstructions equality semantics."""
    mod1 = NopInstructions(block_serial=10, insn_eas=(0x1000, 0x1004))
    mod2 = NopInstructions(block_serial=10, insn_eas=(0x1000, 0x1004))
    mod3 = NopInstructions(block_serial=10, insn_eas=(0x1000,))

    assert mod1 == mod2
    assert mod1 != mod3
    assert hash(mod1) == hash(mod2)


def test_cross_type_inequality():
    """Test that different modification types are not equal."""
    mod1 = RedirectEdge(from_serial=10, old_target=20, new_target=30)
    mod2 = ConvertToGoto(block_serial=10, goto_target=30)
    mod3 = RemoveEdge(from_serial=10, to_serial=20)

    assert mod1 != mod2
    assert mod1 != mod3
    assert mod2 != mod3


# ============================================================================
# Type Discrimination Tests (isinstance and match)
# ============================================================================


def test_isinstance_discrimination():
    """Test type discrimination via isinstance()."""
    redirect = RedirectEdge(from_serial=10, old_target=20, new_target=30)
    convert = ConvertToGoto(block_serial=15, goto_target=25)
    insert = InsertBlock(pred_serial=5, succ_serial=10, instructions=())
    remove = RemoveEdge(from_serial=10, to_serial=20)
    nop = NopInstructions(block_serial=10, insn_eas=(0x1000,))

    assert isinstance(redirect, RedirectEdge)
    assert isinstance(convert, ConvertToGoto)
    assert isinstance(insert, InsertBlock)
    assert isinstance(remove, RemoveEdge)
    assert isinstance(nop, NopInstructions)

    # Cross-type checks
    assert not isinstance(redirect, ConvertToGoto)
    assert not isinstance(convert, InsertBlock)


def test_match_statement_discrimination():
    """Test type discrimination via match statement (Python 3.10+)."""
    redirect = RedirectEdge(from_serial=10, old_target=20, new_target=30)
    convert = ConvertToGoto(block_serial=15, goto_target=25)
    insert = InsertBlock(pred_serial=5, succ_serial=10, instructions=())
    remove = RemoveEdge(from_serial=10, to_serial=20)
    nop = NopInstructions(block_serial=10, insn_eas=(0x1000,))

    def classify(mod: GraphModification) -> str:
        match mod:
            case RedirectEdge():
                return "redirect"
            case ConvertToGoto():
                return "convert"
            case InsertBlock():
                return "insert"
            case RemoveEdge():
                return "remove"
            case NopInstructions():
                return "nop"
            case _:
                return "unknown"

    assert classify(redirect) == "redirect"
    assert classify(convert) == "convert"
    assert classify(insert) == "insert"
    assert classify(remove) == "remove"
    assert classify(nop) == "nop"


def test_match_statement_field_extraction():
    """Test field extraction via match statement patterns."""
    mod = RedirectEdge(from_serial=10, old_target=20, new_target=30)

    match mod:
        case RedirectEdge(from_serial=src, new_target=dst):
            assert src == 10
            assert dst == 30
        case _:
            pytest.fail("Should match RedirectEdge pattern")


# ============================================================================
# Tuple Field Enforcement Tests
# ============================================================================


def test_insert_block_requires_tuple():
    """Test InsertBlock.instructions must be a tuple (enforced by type checker)."""
    # This test verifies the type system, but Python doesn't enforce it at runtime
    # Type checker (mypy) would catch this: InsertBlock(..., instructions=[...])

    # We can still construct with a list at runtime, but it violates the contract
    insn1 = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())

    # Valid: tuple
    mod = InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn1,))
    assert isinstance(mod.instructions, tuple)


def test_nop_instructions_requires_tuple():
    """Test NopInstructions.insn_eas must be a tuple (enforced by type checker)."""
    # Valid: tuple
    mod = NopInstructions(block_serial=10, insn_eas=(0x1000, 0x1004))
    assert isinstance(mod.insn_eas, tuple)


# ============================================================================
# Edge Cases
# ============================================================================


def test_insert_block_with_complex_operands():
    """Test InsertBlock with instructions containing complex operands."""
    # Create instruction with register operand (mop_r type)
    # MopSnapshot constructor signature: t, size, valnum, value, reg, ...
    reg_op = MopSnapshot(
        t=1,  # mop_r (register type, typically 1 in IDA)
        size=4,
        reg=0,  # register index
    )

    insn = InsnSnapshot(opcode=0x01, ea=0x1000, operands=(reg_op,))
    mod = InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn,))

    assert len(mod.instructions) == 1
    assert len(mod.instructions[0].operands) == 1
    assert mod.instructions[0].operands[0].t == 1
    assert mod.instructions[0].operands[0].reg == 0


def test_nop_instructions_ordering_preserved():
    """Test NopInstructions preserves EA ordering."""
    eas = (0x1000, 0x1004, 0x1008, 0x100C, 0x1010)
    mod = NopInstructions(block_serial=10, insn_eas=eas)

    assert mod.insn_eas == eas
    assert list(mod.insn_eas) == [0x1000, 0x1004, 0x1008, 0x100C, 0x1010]


def test_redirect_edge_self_loop():
    """Test RedirectEdge can represent self-loops (edge cases)."""
    # Self-loop: block points to itself
    mod = RedirectEdge(from_serial=10, old_target=20, new_target=10)
    assert mod.from_serial == mod.new_target


def test_redirect_edge_no_change():
    """Test RedirectEdge can represent no-op changes (old_target == new_target)."""
    # No-op redirect (should be filtered out by optimizer, but valid construction)
    mod = RedirectEdge(from_serial=10, old_target=20, new_target=20)
    assert mod.old_target == mod.new_target


# ============================================================================
# Repr and String Tests
# ============================================================================


def test_redirect_edge_repr():
    """Test RedirectEdge has useful repr."""
    mod = RedirectEdge(from_serial=10, old_target=20, new_target=30)
    repr_str = repr(mod)

    assert "RedirectEdge" in repr_str
    assert "from_serial=10" in repr_str
    assert "old_target=20" in repr_str
    assert "new_target=30" in repr_str


def test_insert_block_repr():
    """Test InsertBlock has useful repr."""
    insn1 = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
    mod = InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn1,))
    repr_str = repr(mod)

    assert "InsertBlock" in repr_str
    assert "pred_serial=5" in repr_str
    assert "succ_serial=10" in repr_str


def test_nop_instructions_repr():
    """Test NopInstructions has useful repr."""
    mod = NopInstructions(block_serial=10, insn_eas=(0x1000, 0x1004))
    repr_str = repr(mod)

    assert "NopInstructions" in repr_str
    assert "block_serial=10" in repr_str
