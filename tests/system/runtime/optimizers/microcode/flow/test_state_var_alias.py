"""Unit tests for state variable alias expansion.

Tests the iterative fixed-point algorithm that discovers all aliases
of a state variable by following assignment chains bidirectionally.

No IDA dependency - uses synthetic VarRef/Assignment data.
"""

import pytest

from d810.cfg.flow.state_var_alias import (
    Assignment,
    StateVarAliasExpander,
    VarRef,
)


class TestVarRef:
    """Test the VarRef abstraction."""

    def test_register_ref(self):
        """VarRef can represent a register."""
        rax = VarRef("reg", 0, 8)
        assert rax.kind == "reg"
        assert rax.identifier == 0
        assert rax.size == 8

    def test_stack_ref(self):
        """VarRef can represent a stack slot."""
        stack_var = VarRef("stack", -16, 4)
        assert stack_var.kind == "stack"
        assert stack_var.identifier == -16
        assert stack_var.size == 4

    def test_temp_ref(self):
        """VarRef can represent a temporary."""
        temp = VarRef("temp", 3, 8)
        assert temp.kind == "temp"
        assert temp.identifier == 3
        assert temp.size == 8

    def test_equality(self):
        """VarRef equality is based on kind, identifier, and size."""
        r0_8 = VarRef("reg", 0, 8)
        r0_8_copy = VarRef("reg", 0, 8)
        r0_4 = VarRef("reg", 0, 4)
        r1_8 = VarRef("reg", 1, 8)

        assert r0_8 == r0_8_copy
        assert r0_8 != r0_4  # Different size
        assert r0_8 != r1_8  # Different identifier

    def test_hashable(self):
        """VarRef can be used in sets and dicts."""
        r0 = VarRef("reg", 0, 8)
        r1 = VarRef("reg", 1, 8)
        alias_set = {r0, r1}
        assert r0 in alias_set
        assert r1 in alias_set

    def test_repr_formatting(self):
        """VarRef repr includes kind-specific formatting."""
        assert "reg=0" in repr(VarRef("reg", 0, 8))
        assert "stack=" in repr(VarRef("stack", -16, 4))
        assert "temp=3" in repr(VarRef("temp", 3, 8))


class TestAssignment:
    """Test the Assignment abstraction."""

    def test_var_to_var(self):
        """Assignment can represent variable-to-variable copy."""
        r0 = VarRef("reg", 0, 8)
        r1 = VarRef("reg", 1, 8)
        assign = Assignment(5, r0, r1)

        assert assign.block_serial == 5
        assert assign.target == r0
        assert assign.source == r1
        assert assign.is_var_to_var()
        assert not assign.is_constant_write()

    def test_constant_write(self):
        """Assignment can represent constant assignment."""
        r0 = VarRef("reg", 0, 8)
        assign = Assignment(7, r0, 0x42)

        assert assign.block_serial == 7
        assert assign.target == r0
        assert assign.source == 0x42
        assert assign.is_constant_write()
        assert not assign.is_var_to_var()


class TestStateVarAliasExpander:
    """Test the core alias expansion algorithm."""

    def test_no_aliases(self):
        """State var with only constant writes has no aliases."""
        state_var = VarRef("reg", 0, 8)
        assignments = [
            Assignment(5, state_var, 0x42),  # state_var = 0x42
            Assignment(7, state_var, 0x100), # state_var = 0x100
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        # Only the state var itself, no aliases
        assert aliases == frozenset([state_var])

    def test_single_alias(self):
        """Simple case: state_var = reg1 -> reg1 is alias."""
        state_var = VarRef("reg", 0, 8)
        reg1 = VarRef("reg", 1, 8)
        assignments = [
            Assignment(5, state_var, reg1),  # state_var = reg1
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        assert state_var in aliases
        assert reg1 in aliases
        assert len(aliases) == 2

    def test_chain_alias(self):
        """Transitive chain: state_var = reg1, reg1 = reg2 -> both are aliases."""
        state_var = VarRef("reg", 0, 8)
        reg1 = VarRef("reg", 1, 8)
        reg2 = VarRef("reg", 2, 8)
        assignments = [
            Assignment(5, state_var, reg1),  # state_var = reg1
            Assignment(7, reg1, reg2),       # reg1 = reg2
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        assert state_var in aliases
        assert reg1 in aliases
        assert reg2 in aliases
        assert len(aliases) == 3

    def test_bidirectional_alias(self):
        """Bidirectional: reg1 = state_var, state_var = reg1 -> reg1 is alias."""
        state_var = VarRef("reg", 0, 8)
        reg1 = VarRef("reg", 1, 8)
        assignments = [
            Assignment(5, reg1, state_var),  # reg1 = state_var (reverse)
            Assignment(7, state_var, reg1),  # state_var = reg1 (forward)
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        assert state_var in aliases
        assert reg1 in aliases
        assert len(aliases) == 2

    def test_stack_alias(self):
        """Stack slot can be an alias: state_var = stack_slot."""
        state_var = VarRef("reg", 0, 8)
        stack_slot = VarRef("stack", -16, 8)
        assignments = [
            Assignment(5, state_var, stack_slot),  # state_var = [rsp-16]
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        assert state_var in aliases
        assert stack_slot in aliases
        assert len(aliases) == 2

    def test_fixed_point_convergence(self):
        """Complex chain requiring multiple iterations."""
        # Chain: state_var = r1, r1 = r2, r2 = r3, r3 = r4
        # Requires 4 iterations to discover all aliases
        state_var = VarRef("reg", 0, 8)
        r1 = VarRef("reg", 1, 8)
        r2 = VarRef("reg", 2, 8)
        r3 = VarRef("reg", 3, 8)
        r4 = VarRef("reg", 4, 8)

        assignments = [
            Assignment(10, state_var, r1),  # state_var = r1
            Assignment(20, r1, r2),         # r1 = r2
            Assignment(30, r2, r3),         # r2 = r3
            Assignment(40, r3, r4),         # r3 = r4
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        # All variables in the chain should be aliases
        assert aliases == frozenset([state_var, r1, r2, r3, r4])

    def test_no_constant_alias(self):
        """Constants are not aliases (state_var = 0x42)."""
        state_var = VarRef("reg", 0, 8)
        reg1 = VarRef("reg", 1, 8)
        assignments = [
            Assignment(5, state_var, 0x42),  # state_var = 0x42 (constant)
            Assignment(7, state_var, reg1),  # state_var = reg1 (variable)
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        # 0x42 is not an alias, only reg1 is
        assert state_var in aliases
        assert reg1 in aliases
        assert len(aliases) == 2

    def test_multiple_blocks_same_alias(self):
        """Same alias can appear in multiple blocks."""
        state_var = VarRef("reg", 0, 8)
        reg1 = VarRef("reg", 1, 8)
        assignments = [
            Assignment(5, state_var, reg1),  # Block 5: state_var = reg1
            Assignment(7, state_var, reg1),  # Block 7: state_var = reg1 (again)
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        assert state_var in aliases
        assert reg1 in aliases
        assert len(aliases) == 2

    def test_diamond_pattern(self):
        """Diamond dependency: state_var = r1 and state_var = r2, r1 = r3, r2 = r3."""
        state_var = VarRef("reg", 0, 8)
        r1 = VarRef("reg", 1, 8)
        r2 = VarRef("reg", 2, 8)
        r3 = VarRef("reg", 3, 8)

        assignments = [
            Assignment(5, state_var, r1),  # state_var = r1
            Assignment(7, state_var, r2),  # state_var = r2
            Assignment(9, r1, r3),         # r1 = r3
            Assignment(11, r2, r3),        # r2 = r3
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        # All variables should be discovered as aliases
        assert aliases == frozenset([state_var, r1, r2, r3])

    def test_mixed_types_stack_and_reg(self):
        """Aliases can be a mix of registers and stack slots."""
        state_var = VarRef("reg", 0, 8)
        reg1 = VarRef("reg", 1, 8)
        stack_slot = VarRef("stack", -8, 8)

        assignments = [
            Assignment(5, state_var, reg1),       # state_var = reg1
            Assignment(7, reg1, stack_slot),      # reg1 = [rsp-8]
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        assert state_var in aliases
        assert reg1 in aliases
        assert stack_slot in aliases
        assert len(aliases) == 3

    def test_empty_assignments(self):
        """With no assignments, only the initial state var is an alias."""
        state_var = VarRef("reg", 0, 8)
        assignments = []

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        assert aliases == frozenset([state_var])

    def test_unrelated_assignments(self):
        """Assignments that don't involve the state var don't create aliases."""
        state_var = VarRef("reg", 0, 8)
        r1 = VarRef("reg", 1, 8)
        r2 = VarRef("reg", 2, 8)

        assignments = [
            Assignment(5, r1, r2),  # r1 = r2 (unrelated to state_var)
        ]

        aliases = StateVarAliasExpander.expand(assignments, state_var)

        # Only state_var, no aliases discovered
        assert aliases == frozenset([state_var])

    def test_self_assignment(self):
        """Self-assignment (state_var = state_var) adds no new aliases."""
        state_var = VarRef("reg", 0, 8)
        assignments = [Assignment(5, state_var, state_var)]
        aliases = StateVarAliasExpander.expand(assignments, state_var)
        assert aliases == frozenset([state_var])


class TestGetStateWrites:
    """Test extraction of constant writes to state variable aliases."""

    def test_constant_writes(self):
        """Blocks that write constants to state var aliases."""
        state_var = VarRef("reg", 0, 8)
        assignments = [
            Assignment(5, state_var, 0x42),   # Block 5 writes 0x42
            Assignment(7, state_var, 0x100),  # Block 7 writes 0x100
        ]
        aliases = frozenset([state_var])

        writes = StateVarAliasExpander.get_state_writes(assignments, aliases)

        assert writes[5] == [0x42]
        assert writes[7] == [0x100]
        assert len(writes) == 2

    def test_no_writes(self):
        """No constant writes to aliases."""
        state_var = VarRef("reg", 0, 8)
        reg1 = VarRef("reg", 1, 8)
        assignments = [
            Assignment(5, state_var, reg1),  # var-to-var (not constant)
        ]
        aliases = frozenset([state_var])

        writes = StateVarAliasExpander.get_state_writes(assignments, aliases)

        # No constant writes
        assert len(writes) == 0

    def test_writes_through_alias(self):
        """Constants written to an alias (not the original state var)."""
        state_var = VarRef("reg", 0, 8)
        reg1 = VarRef("reg", 1, 8)
        assignments = [
            Assignment(5, state_var, reg1),  # state_var = reg1 (reg1 is alias)
            Assignment(7, reg1, 0x42),       # reg1 = 0x42 (write through alias)
        ]
        aliases = frozenset([state_var, reg1])

        writes = StateVarAliasExpander.get_state_writes(assignments, aliases)

        # Block 7 writes 0x42 to the alias reg1
        assert writes[7] == [0x42]
        assert len(writes) == 1

    def test_multiple_writes_same_block(self):
        """Multiple constant writes in the same block."""
        state_var = VarRef("reg", 0, 8)
        assignments = [
            Assignment(5, state_var, 0x42),   # First write
            Assignment(5, state_var, 0x100),  # Second write (same block)
        ]
        aliases = frozenset([state_var])

        writes = StateVarAliasExpander.get_state_writes(assignments, aliases)

        # Both values should be recorded
        assert sorted(writes[5]) == [0x42, 0x100]

    def test_writes_to_non_alias_ignored(self):
        """Writes to non-alias variables are ignored."""
        state_var = VarRef("reg", 0, 8)
        other_var = VarRef("reg", 1, 8)
        assignments = [
            Assignment(5, state_var, 0x42),   # Write to alias
            Assignment(7, other_var, 0x100),  # Write to non-alias (ignored)
        ]
        aliases = frozenset([state_var])

        writes = StateVarAliasExpander.get_state_writes(assignments, aliases)

        # Only block 5's write is recorded
        assert writes[5] == [0x42]
        assert 7 not in writes
        assert len(writes) == 1

    def test_empty_aliases(self):
        """With no aliases, no writes are recorded."""
        state_var = VarRef("reg", 0, 8)
        assignments = [
            Assignment(5, state_var, 0x42),
        ]
        aliases = frozenset()  # Empty alias set

        writes = StateVarAliasExpander.get_state_writes(assignments, aliases)

        assert len(writes) == 0

    def test_empty_assignments(self):
        """With no assignments, no writes are recorded."""
        state_var = VarRef("reg", 0, 8)
        assignments = []
        aliases = frozenset([state_var])

        writes = StateVarAliasExpander.get_state_writes(assignments, aliases)

        assert len(writes) == 0

    def test_mixed_var_and_const_writes(self):
        """Blocks with both var-to-var and constant writes."""
        state_var = VarRef("reg", 0, 8)
        reg1 = VarRef("reg", 1, 8)
        assignments = [
            Assignment(5, state_var, reg1),  # var-to-var (ignored)
            Assignment(5, state_var, 0x42),  # constant write (recorded)
        ]
        aliases = frozenset([state_var, reg1])

        writes = StateVarAliasExpander.get_state_writes(assignments, aliases)

        # Only constant write is recorded
        assert writes[5] == [0x42]
