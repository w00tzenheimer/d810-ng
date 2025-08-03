from __future__ import annotations

import logging

import ida_hexrays

from d810 import _compat
from d810.conf.loggers import getLogger
from d810.hexrays.hexrays_formatters import (
    format_mop_t,
    mop_tree,
    opcode_to_string,
    sanitize_ea,
)
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

logger = getLogger(__name__, default_level=logging.DEBUG)


class StackVariableConstantFoldingRule(PeepholeSimplificationRule):
    DESCRIPTION = "Fold stack variables that are assigned constant values across blocks"

    def __init__(self):
        super().__init__()
        # Map to track stack variable assignments: {var_name: (value, size)}
        self.stack_var_map = {}
        # Track the current function being processed
        self.current_func = None
        self.maturities = [ida_hexrays.MMAT_CALLS]

    @_compat.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        # Reset our tracking when we move to a new function
        if (
            blk is not None
            and blk.mba is not None
            and blk.mba.entry_ea != self.current_func
        ):
            self.stack_var_map = {}
            self.current_func = blk.mba.entry_ea

        if logger.debug_on:
            logger.debug(
                "[stack-var-fold] considering ea=%X, opcode=%s l=%s r=%s d=%s",
                sanitize_ea(ins.ea),
                opcode_to_string(ins.opcode),
                format_mop_t(ins.l),
                format_mop_t(ins.r),
                format_mop_t(ins.d),
            )

        # Process constant assignments to stack variables
        if self._is_constant_stack_assignment(ins):
            self._record_stack_assignment(ins)
            return None  # No change needed

        # Check if this instruction uses stack variables we can fold
        changed = False
        new_ins = ida_hexrays.minsn_t(ins)  # Create a copy to modify

        # Process all operands in the instruction
        for op_name in ("l", "r", "d"):
            op = getattr(new_ins, op_name, None)
            if op is not None:
                if self._process_operand(op):
                    changed = True

        if changed:
            if logger.debug_on:
                logger.debug(
                    "[stack-var-fold] folded instruction at ea=%X",
                    sanitize_ea(ins.ea),
                )
            return None
        return None

    def _is_constant_stack_assignment(self, ins: ida_hexrays.minsn_t) -> bool:
        """Check if instruction is a constant assignment to a stack variable."""
        # Handle mov instructions
        if ins.opcode == ida_hexrays.m_mov:
            # Check if left operand is a constant and right is a stack variable
            if (
                ins.l is not None
                and ins.l.t == ida_hexrays.mop_n
                and ins.d is not None
                and ins.d.t == ida_hexrays.mop_S
            ):
                return True

        # Handle stx instructions (store to memory)
        elif ins.opcode == ida_hexrays.m_stx:
            # Check if left operand is a constant
            if ins.l is not None and ins.l.t == ida_hexrays.mop_n:
                # Check if the destination is a stack variable
                if ins.d is not None and ins.d.t == ida_hexrays.mop_S:
                    return True
                # Check if the destination is a memory expression
                elif ins.d is not None and ins.d.t == ida_hexrays.mop_d:
                    # logger.debug("I GOT HERE DUDE! \n%s", mop_tree(ins.d))
                    # Look for expressions like (reg + offset) where reg could be a stack variable
                    if ins.d.d.opcode == ida_hexrays.m_add:
                        # Check if either operand is a stack variable or a register that might be a stack variable
                        if (
                            ins.d.d.l is not None
                            and (
                                ins.d.d.l.t == ida_hexrays.mop_S
                                or ins.d.d.l.t == ida_hexrays.mop_r
                            )
                        ) or (
                            ins.d.d.r is not None
                            and (
                                ins.d.d.r.t == ida_hexrays.mop_S
                                or ins.d.d.r.t == ida_hexrays.mop_r
                            )
                        ):
                            return True

        return False

    def _is_stack_var_register(self, mop: ida_hexrays.mop_t) -> bool:
        """Check if a register operand represents a stack variable."""
        if mop.t != ida_hexrays.mop_r:
            return False

        # Check if the register name indicates it's a stack variable
        # This depends on how IDA represents stack variables in registers
        # Common patterns include registers with names like "var_XX" or "s_XX"
        reg_name = ida_hexrays.get_mreg_name(mop.r, mop.size)

        if reg_name.startswith("%"):
            logger.warning("FYI - registry name starts with: %s", reg_name)
            reg_name = reg_name[1:]

        # Check if the register name suggests it's a stack variable
        if not reg_name.startswith(("var_", "s_", "stack_")):
            return True

        # Alternatively, check if the register's value indicates it's a stack variable
        # This might require additional context from the microcode analyzer

        return False

    def _record_stack_assignment(self, ins: ida_hexrays.minsn_t):
        """Record a constant assignment to a stack variable."""
        value = ins.l.nnn.value
        size = ins.l.size

        # For mov instructions
        if ins.opcode == ida_hexrays.m_mov:
            var_name = self._get_stack_var_name(ins.d)
            if var_name is not None:
                self.stack_var_map[var_name] = (value, size)
                if logger.debug_on:
                    logger.debug(
                        "[stack-var-fold] recorded assignment: %s = 0x%X (size=%d)",
                        var_name,
                        value,
                        size,
                    )

        # For stx instructions
        elif ins.opcode == ida_hexrays.m_stx:
            # Direct stack variable assignment
            if ins.d.t == ida_hexrays.mop_S:
                var_name = self._get_stack_var_name(ins.d)
                if var_name is not None:
                    self.stack_var_map[var_name] = (value, size)
                    if logger.debug_on:
                        logger.debug(
                            "[stack-var-fold] recorded stx assignment: %s = 0x%X (size=%d)",
                            var_name,
                            value,
                            size,
                        )

            # Memory expression involving stack variable
            elif (
                ins.d.t == ida_hexrays.mop_d
                and ins.d.d is not None
                and ins.d.d.opcode == ida_hexrays.m_add
            ):
                # Extract the stack variable and offset
                stack_var = None
                offset = 0
                stack_var_name = None

                # Check left operand
                if ins.d.d.l is not None:
                    stack_var = ins.d.d.l
                    if stack_var.t == ida_hexrays.mop_S:
                        stack_var_name = self._get_stack_var_name(stack_var)
                    elif stack_var.t == ida_hexrays.mop_r:
                        # Use the register name as the variable name
                        # stack_var_name = (
                        #     ins.d.d.l._regname()
                        #     if hasattr(ins.d.d.l, "_regname")
                        #     else f"reg_{ins.d.d.l.r:X}"
                        # )
                        stack_var_name = ida_hexrays.get_mreg_name(
                            stack_var.r, stack_var.size
                        )
                        stack_var_name += f".{stack_var.size}{{{stack_var.valnum}}}"
                        logger.debug(
                            "found var %s with register number: %s",
                            stack_var_name,
                            stack_var.r,
                        )

                    if ins.d.d.r is not None and ins.d.d.r.t == ida_hexrays.mop_n:
                        offset = ins.d.d.r.nnn.value

                # Check right operand
                elif ins.d.d.r is not None:
                    stack_var = ins.d.d.r
                    if stack_var.t == ida_hexrays.mop_S:
                        stack_var_name = self._get_stack_var_name(stack_var)
                    elif stack_var.t == ida_hexrays.mop_r:
                        # Use the register name as the variable name
                        stack_var_name = ida_hexrays.get_mreg_name(
                            stack_var.r, stack_var.size
                        )
                        stack_var_name += f".{stack_var.size}{{{stack_var.valnum}}}"
                        logger.debug(
                            "found var %s with register number: %s",
                            stack_var_name,
                            stack_var.r,
                        )
                    if ins.d.d.l is not None and ins.d.d.l.t == ida_hexrays.mop_n:
                        offset = ins.d.d.l.nnn.value

                # If we found a stack variable, record the assignment
                if stack_var_name is not None:
                    # Create a composite name including the offset
                    composite_name = f"{stack_var_name}+{offset:X}"
                    self.stack_var_map[composite_name] = (value, size)
                    if logger.debug_on:
                        logger.debug(
                            "[stack-var-fold] recorded stx assignment: %s = 0x%X (size=%d)",
                            composite_name,
                            value,
                            size,
                        )

    def _get_stack_var_name(self, mop: ida_hexrays.mop_t) -> str | None:
        """Get a unique identifier for a stack variable."""
        if mop.t == ida_hexrays.mop_S:
            # Use stack offset and size to uniquely identify the variable
            return f"var_{mop.s.off:X}.{mop.size}"
        return None

    def _process_operand(self, op: ida_hexrays.mop_t) -> bool:
        """Process an operand, replacing stack variables with constants.
        Returns True if any changes were made.
        """
        changed = False

        # If this is a stack variable we know about, replace it
        if op.t == ida_hexrays.mop_S:
            var_name = self._get_stack_var_name(op)
            if var_name is not None and var_name in self.stack_var_map:
                value, size = self.stack_var_map[var_name]
                op.make_number(value, size)
                changed = True

                if logger.debug_on:
                    logger.debug(
                        "[stack-var-fold] replaced %s with 0x%X (size=%d)",
                        var_name,
                        value,
                        size,
                    )

        # Handle memory reads from stack variables
        elif op.t == ida_hexrays.mop_d and op.d is not None:
            # Check if this is a memory read from a stack variable
            if op.d.opcode in (ida_hexrays.m_ldx, ida_hexrays.m_ldc):
                # Check if the address is a stack variable
                if op.d.l is not None and op.d.l.t == ida_hexrays.mop_S:
                    var_name = self._get_stack_var_name(op.d.l)
                    if var_name is not None and var_name in self.stack_var_map:
                        value, size = self.stack_var_map[var_name]
                        op.make_number(value, size)
                        changed = True

                        if logger.debug_on:
                            logger.debug(
                                "[stack-var-fold] replaced memory read from %s with 0x%X (size=%d)",
                                var_name,
                                value,
                                size,
                            )

                # Check if the address is an expression involving a stack variable
                elif (
                    op.d.l is not None
                    and op.d.l.t == ida_hexrays.mop_d
                    and op.d.l.d is not None
                ):
                    if op.d.l.d.opcode == ida_hexrays.m_add:
                        # Extract the stack variable and offset
                        stack_var = None
                        offset = 0

                        # Check left operand
                        if op.d.l.d.l is not None and op.d.l.d.l.t == ida_hexrays.mop_S:
                            stack_var = op.d.l.d.l
                            if (
                                op.d.l.d.r is not None
                                and op.d.l.d.r.t == ida_hexrays.mop_n
                            ):
                                offset = op.d.l.d.r.nnn.value

                        # Check right operand
                        elif (
                            op.d.l.d.r is not None and op.d.l.d.r.t == ida_hexrays.mop_S
                        ):
                            stack_var = op.d.l.d.r
                            if (
                                op.d.l.d.l is not None
                                and op.d.l.d.l.t == ida_hexrays.mop_n
                            ):
                                offset = op.d.l.d.l.nnn.value

                        # If we found a stack variable, check for a matching assignment
                        if stack_var is not None:
                            var_name = self._get_stack_var_name(stack_var)
                            if var_name is not None:
                                composite_name = f"{var_name}+{offset:X}"
                                if composite_name in self.stack_var_map:
                                    value, size = self.stack_var_map[composite_name]
                                    op.make_number(value, size)
                                    changed = True

                                    if logger.debug_on:
                                        logger.debug(
                                            "[stack-var-fold] replaced memory read from %s with 0x%X (size=%d)",
                                            composite_name,
                                            value,
                                            size,
                                        )

            # Process nested operands recursively
            else:
                # Process left operand
                if op.d.l is not None and self._process_operand(op.d.l):
                    changed = True

                # Process right operand
                if op.d.r is not None and self._process_operand(op.d.r):
                    changed = True

                # Process destination operand
                if op.d.d is not None and self._process_operand(op.d.d):
                    changed = True

        # If this is a function call (mop_f), process its arguments
        elif op.t == ida_hexrays.mop_f and op.f is not None:
            for arg in op.f.args:
                if arg is not None and self._process_operand(arg):
                    changed = True

        return changed


# class StackVariableConstantPropagationRule(PeepholeSimplificationRule):
#     """Propagate constant values of stack variables across basic blocks for constant folding.

#     This rule:
#     1. Tracks assignments to stack variables across basic blocks
#     2. Replaces stack variable references with their constant values when possible
#     3. Enables subsequent rules to further simplify expressions (like rotate helpers)

#     Example:
#         Block 8: mov #0x6EBCBAA1.4, %var_E4.4
#         Block 9: add (call !__ROL4__<fast:_DWORD (call !__ROL4__<fast:_DWORD %var_E4.4,char #4.1>.4+#0x6B9F6F9A.4),char #3.1>.4 ^ #0x770BB7B8.4), #0x33AC85C6.4, %var_E8.4
#     becomes:
#         Block 9: add (call !__ROL4__<fast:_DWORD (call !__ROL4__<fast:_DWORD 0x6EBCBAA1,char #4.1>.4+#0x6B9F6F9A.4),char #3.1>.4 ^ #0x770BB7B8.4), #0x33AC85C6.4, %var_E8.4
#     which can then be simplified to a single constant by other rules.
#     """

#     DESCRIPTION = "Propagate constant values of stack variables across basic blocks"
#     maturities = [ida_hexrays.MMAT_CALLS]  # Run at MMAT_CALLS maturity as requested

#     def __init__(self):
#         super().__init__()
#         # Cache for function analyses: func_ea -> {stack_offset: (value, size)}
#         self._function_cache = {}
#         # Current function being analyzed
#         self.current_func_ea = None
#         self.const_map = {}

#     def _is_stack_var(self, mop: ida_hexrays.mop_t) -> bool:
#         """Check if a mop_t represents a stack variable."""
#         return mop is not None and mop.t == ida_hexrays.mop_S

#     def _get_stack_var_offset(self, mop: ida_hexrays.mop_t) -> int | None:
#         """Get the offset of a stack variable from its mop_t."""
#         if not self._is_stack_var(mop):
#             return None
#         return mop.s.off

#     def _get_constant_value(self, mop: ida_hexrays.mop_t) -> tuple[int, int] | None:
#         """Extract constant value and size from a mop_t if possible."""
#         return (
#             _extract_literal_from_mop(mop)[0]
#             if _extract_literal_from_mop(mop)
#             else None
#         )

#     def _analyze_function(self, mba: ida_hexrays.mba_t):
#         """Analyze the function to build a constant propagation map for stack variables.

#         This is a simplified reaching definitions analysis that:
#         1. Processes blocks in reverse post-order
#         2. For each stack variable, tracks if it has a single constant value at each point
#         3. Only propagates constants when all paths give the same value
#         """
#         # Initialize the constant map
#         const_map = {}

#         # We'll use a simple approach: collect all constant assignments and assume
#         # they reach if there are no intervening assignments
#         # This is conservative but works for many cases

#         # First, collect all constant assignments in the function
#         all_assignments = {}
#         for blk_idx in range(mba.qty):
#             blk = mba.bbs[blk_idx]
#             for ins in blk:
#                 if ins.d is not None and self._is_stack_var(ins.d):
#                     offset = self._get_stack_var_offset(ins.d)
#                     if offset is None:
#                         continue

#                     const_val = self._get_constant_value(ins.l)
#                     if const_val is not None:
#                         # Track this assignment
#                         if offset not in all_assignments:
#                             all_assignments[offset] = []
#                         all_assignments[offset].append((blk_idx, ins.ea, const_val))

#         # Now determine which constants reach which blocks
#         for offset, assignments in all_assignments.items():
#             # For simplicity, if there's only one assignment to this variable,
#             # assume it reaches all uses after it
#             if len(assignments) == 1:
#                 blk_idx, _, const_val = assignments[0]
#                 # Record that this constant reaches all blocks after the assignment block
#                 for i in range(blk_idx, mba.qty):
#                     if i not in const_map:
#                         const_map[i] = {}
#                     const_map[i][offset] = const_val

#         return const_map

#     def _replace_stack_vars(self, mop: ida_hexrays.mop_t, const_map: dict) -> bool:
#         """Replace stack variables with their constant values if possible.
#         Returns True if any replacements were made."""
#         if mop is None:
#             return False

#         changed = False

#         # Check if this is a stack variable we can replace
#         if self._is_stack_var(mop):
#             offset = self._get_stack_var_offset(mop)
#             if offset is not None and offset in const_map:
#                 value, size = const_map[offset]
#                 new_mop = ida_hexrays.mop_t()
#                 new_mop.make_number(value, size)
#                 mop.assign(new_mop)
#                 changed = True

#         # Recursively check child operands
#         if mop.t == ida_hexrays.mop_d and mop.d is not None:
#             if self._replace_stack_vars(mop.d.l, const_map):
#                 changed = True
#             if self._replace_stack_vars(mop.d.r, const_map):
#                 changed = True
#             if self._replace_stack_vars(mop.d.d, const_map):
#                 changed = True

#         # Handle typed immediates (mop_f)
#         if mop.t == ida_hexrays.mop_f and hasattr(mop, "f") and mop.f is not None:
#             for i, arg in enumerate(mop.f.args):
#                 if self._replace_stack_vars(arg, const_map):
#                     changed = True

#         return changed

#     def _apply_constant_folding(
#         self, ins: ida_hexrays.minsn_t
#     ) -> ida_hexrays.minsn_t | None:
#         """Apply constant folding rules to the instruction after replacing stack variables."""
#         # # Try existing rules that can simplify the instruction
#         # rules_to_try = [
#         #     RotateHelperInlineRule(),
#         #     ConstantCallResultFoldRule(),
#         #     TypedImmediateCanonicaliseRule(),
#         # ]

#         # new_ins = ins
#         # for rule in rules_to_try:
#         #     # Check if the rule can simplify this instruction
#         #     simplified = rule.check_and_replace(None, new_ins)
#         #     if simplified is not None:
#         #         new_ins = simplified

#         # Only return a replacement if the instruction actually changed
#         # if new_ins == ins:
#         #     return None
#         # return new_ins

#     @_compat.override
#     def check_and_replace(
#         self, blk: ida_hexrays.mblock_t, ins: ida_hexrays.minsn_t
#     ) -> ida_hexrays.minsn_t | None:
#         """Check if the instruction uses stack variables with constant values and replace them."""
#         if logger.debug_on:
#             logger.debug(
#                 "[StackVarProp] considering ea=%X, opcode=%s l=%s r=%s d=%s",
#                 sanitize_ea(ins.ea),
#                 opcode_to_string(ins.opcode),
#                 format_mop_t(ins.l),
#                 format_mop_t(ins.r),
#                 format_mop_t(ins.d),
#             )

#         # Check if we need to analyze the current function
#         func_ea = blk.mba.entry_ea
#         if self.current_func_ea != func_ea:
#             # Check cache first
#             if func_ea in self._function_cache:
#                 self.const_map = self._function_cache[func_ea]
#             else:
#                 # Analyze the function
#                 self.const_map = self._analyze_function(blk.mba)
#                 self._function_cache[func_ea] = self.const_map
#             self.current_func_ea = func_ea

#         # Get the constant map for this block
#         block_const_map = self.const_map.get(blk.serial, {})

#         # Check if this instruction uses any stack variables we can replace
#         changed = False
#         if self._replace_stack_vars(ins.l, block_const_map):
#             changed = True
#         if self._replace_stack_vars(ins.r, block_const_map):
#             changed = True
#         if self._replace_stack_vars(ins.d, block_const_map):
#             changed = True

#         if not changed:
#             return None

#         if logger.debug_on:
#             logger.debug(
#                 "[StackVarProp] replaced stack variables for ea=%X, new l=%s r=%s d=%s",
#                 sanitize_ea(ins.ea),
#                 format_mop_t(ins.l),
#                 format_mop_t(ins.r),
#                 format_mop_t(ins.d),
#             )

#         # Apply constant folding to the simplified instruction
#         return self._apply_constant_folding(ins)
