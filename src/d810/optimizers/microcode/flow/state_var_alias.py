"""State variable alias expansion for control-flow flattening.

This module implements the iterative fixed-point algorithm from cadecff's
`expand_state_var_aliases` (analysis.py:141-201). Given assignments across
blocks and an initial state variable, it discovers all variables that are
aliases of the state variable.

The core algorithm operates on abstract VarRef/Assignment types (no IDA
dependency) to enable unit testing with synthetic data. A future adapter
will convert IDA's mop_t to VarRef and extract assignments from microcode.

References:
    - CaDeCFF algorithm: ~/src/idapro/cadecff/src/cadecff/analysis.py:141-201
    - CaDeCFF integration plan: docs/plans/CaDeCFF-Integration.md section 3.3
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Literal

__all__ = ["VarRef", "Assignment", "StateVarAliasExpander"]

VarKind = Literal["reg", "stack", "temp"]


@dataclass(frozen=True)
class VarRef:
    """Abstract reference to a variable (register, stack slot, or temp).

    This is a portable representation — no IDA dependency. Enables unit
    testing the alias expansion algorithm without IDA runtime.

    Attributes:
        kind: Variable kind ("reg", "stack", "temp")
        identifier: Register number, stack offset, or temp index
        size: Operand size in bytes

    Examples:
        >>> # Register RAX (x86-64, register 0, 8 bytes)
        >>> rax = VarRef("reg", 0, 8)
        >>> # Stack slot at offset -16
        >>> stack_var = VarRef("stack", -16, 4)
        >>> # Temporary variable #3
        >>> temp = VarRef("temp", 3, 8)
    """

    kind: VarKind
    identifier: int
    size: int

    def __repr__(self) -> str:
        """Return a human-readable representation."""
        if self.kind == "reg":
            return f"VarRef(reg={self.identifier}, size={self.size})"
        elif self.kind == "stack":
            return f"VarRef(stack={self.identifier:+d}, size={self.size})"
        else:
            return f"VarRef(temp={self.identifier}, size={self.size})"


@dataclass(frozen=True)
class Assignment:
    """A single variable assignment observed in a block.

    Represents: target = source (in some block).

    Attributes:
        block_serial: Block serial number where this assignment occurs
        target: The variable being assigned to
        source: The source value (VarRef for var-to-var, int for constant)

    Examples:
        >>> # Block 5: reg0 = reg1 (var-to-var copy)
        >>> Assignment(5, VarRef("reg", 0, 8), VarRef("reg", 1, 8))
        >>> # Block 7: reg2 = 0x42 (constant assignment)
        >>> Assignment(7, VarRef("reg", 2, 4), 0x42)
    """

    block_serial: int
    target: VarRef
    source: VarRef | int

    def is_var_to_var(self) -> bool:
        """Return True if this is a variable-to-variable assignment."""
        return isinstance(self.source, VarRef)

    def is_constant_write(self) -> bool:
        """Return True if this is a constant assignment."""
        return isinstance(self.source, int)

    def __repr__(self) -> str:
        """Return a human-readable representation."""
        if self.is_constant_write():
            return f"Assignment(blk={self.block_serial}, {self.target} = 0x{self.source:x})"
        return f"Assignment(blk={self.block_serial}, {self.target} = {self.source})"


class StateVarAliasExpander:
    """Expand state variable aliases using iterative fixed-point analysis.

    This implements the cadecff algorithm (analysis.py:141-201) ported to
    work on abstract VarRef/Assignment types. The algorithm:

    1. Starts from a known state variable
    2. Iterative fixed-point: finds all blocks that write to any known alias
    3. For each write: if source is a variable, add it as a new alias
    4. Repeats until no new aliases are found (fixed point reached)

    The algorithm handles:
    - Simple copies: state_var = reg1 → reg1 is alias
    - Chains: state_var = reg1, reg1 = reg2 → reg1, reg2 are aliases
    - Bidirectional: reg1 = state_var, state_var = reg1 → reg1 is alias
    - Memory-backed: state_var = stack_slot → stack_slot is alias

    Example:
        >>> assignments = [
        ...     Assignment(5, VarRef("reg", 0, 8), VarRef("reg", 1, 8)),  # r0 = r1
        ...     Assignment(7, VarRef("reg", 1, 8), VarRef("reg", 2, 8)),  # r1 = r2
        ... ]
        >>> initial = VarRef("reg", 0, 8)
        >>> aliases = StateVarAliasExpander.expand(assignments, initial)
        >>> # aliases = {r0, r1, r2} (transitive closure)
    """

    @staticmethod
    def expand(
        assignments: list[Assignment],
        initial_state_var: VarRef,
    ) -> frozenset[VarRef]:
        """Find all aliases of the state variable.

        Uses iterative fixed-point: starts from initial_state_var,
        follows assignment chains bidirectionally (both target and source
        directions), and returns the complete alias set.

        Parameters
        ----------
        assignments : list of observed variable assignments across all blocks
        initial_state_var : the known state variable to expand aliases for

        Returns
        -------
        frozenset of VarRef including the initial_state_var and all its aliases

        Examples
        --------
        >>> # Simple alias: state_var = reg1
        >>> assignments = [Assignment(5, VarRef("reg", 0, 8), VarRef("reg", 1, 8))]
        >>> initial = VarRef("reg", 0, 8)
        >>> aliases = StateVarAliasExpander.expand(assignments, initial)
        >>> assert initial in aliases
        >>> assert VarRef("reg", 1, 8) in aliases

        >>> # No aliases: state_var = 0x42 (constant)
        >>> assignments = [Assignment(5, VarRef("reg", 0, 8), 0x42)]
        >>> aliases = StateVarAliasExpander.expand(assignments, VarRef("reg", 0, 8))
        >>> assert len(aliases) == 1  # Only the initial state var
        """
        # Start with the initial state variable
        aliases: set[VarRef] = {initial_state_var}
        changed = True

        # Iterative fixed-point: repeat until no new aliases are found
        while changed:
            changed = False

            # For each assignment in all blocks
            for assignment in assignments:
                # Skip non-var-to-var assignments (constants don't create aliases)
                if not assignment.is_var_to_var():
                    continue

                # Check bidirectional: target is alias OR source is alias
                target_is_alias = assignment.target in aliases
                source_is_alias = assignment.source in aliases

                # If target is an alias and source is new, add source as alias
                if target_is_alias and assignment.source not in aliases:
                    aliases.add(assignment.source)
                    changed = True

                # If source is an alias and target is new, add target as alias
                # This handles the bidirectional case: reg1 = state_var
                if source_is_alias and assignment.target not in aliases:
                    aliases.add(assignment.target)
                    changed = True

        return frozenset(aliases)

    @staticmethod
    def get_state_writes(
        assignments: list[Assignment],
        aliases: frozenset[VarRef],
    ) -> dict[int, list[int]]:
        """For each block, find constant values written to any alias.

        This extracts the dispatch table entries: blocks that write constants
        to state variable aliases. These constant writes determine which
        case block will execute next after returning to the dispatcher.

        Parameters
        ----------
        assignments : list of observed variable assignments across all blocks
        aliases : the complete alias set (from expand())

        Returns
        -------
        dict mapping block_serial → list of constant values written to
        state variable aliases in that block

        Examples
        --------
        >>> # Block 5 writes 0x42 to state var, block 7 writes 0x100
        >>> assignments = [
        ...     Assignment(5, VarRef("reg", 0, 8), 0x42),
        ...     Assignment(7, VarRef("reg", 0, 8), 0x100),
        ... ]
        >>> aliases = frozenset([VarRef("reg", 0, 8)])
        >>> writes = StateVarAliasExpander.get_state_writes(assignments, aliases)
        >>> assert writes[5] == [0x42]
        >>> assert writes[7] == [0x100]

        >>> # Block with multiple constant writes to the same alias
        >>> assignments = [
        ...     Assignment(5, VarRef("reg", 0, 8), 0x42),
        ...     Assignment(5, VarRef("reg", 0, 8), 0x100),  # Same block, new value
        ... ]
        >>> aliases = frozenset([VarRef("reg", 0, 8)])
        >>> writes = StateVarAliasExpander.get_state_writes(assignments, aliases)
        >>> assert sorted(writes[5]) == [0x42, 0x100]
        """
        # Map block_serial → list of constant values
        state_writes: dict[int, list[int]] = {}

        for assignment in assignments:
            # Only interested in constant writes
            if not assignment.is_constant_write():
                continue

            # Only interested in writes to known aliases
            if assignment.target not in aliases:
                continue

            # Add the constant value to this block's write list
            if assignment.block_serial not in state_writes:
                state_writes[assignment.block_serial] = []

            state_writes[assignment.block_serial].append(assignment.source)

        return state_writes
