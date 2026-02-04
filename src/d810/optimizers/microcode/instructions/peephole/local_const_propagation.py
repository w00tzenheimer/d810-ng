from __future__ import annotations

import ida_hexrays

from d810.core import typing
from d810.core import getLogger
from d810.hexrays.hexrays_formatters import format_mop_t, opcode_to_string, sanitize_ea
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

logger = getLogger(__name__)


class LocalizedConstantPropagationRule(PeepholeSimplificationRule):
    DESCRIPTION = "Propagate local constants within blocks with local stack variables"

    # ------------------------------------------------------------------
    #  Propagate constants only for an *allowlist* of micro-opcodes that are
    #  considered side-effect free with respect to control flow.  Anything
    #  not explicitly mentioned below is skipped (e.g. jumps, switch
    #  tables, etc.).  The list mirrors the one you provided.
    # ------------------------------------------------------------------
    ALLOW_PROPAGATION_OPCODES: set[int] = {
        ida_hexrays.m_stx,
        ida_hexrays.m_mov,
        ida_hexrays.m_neg,
        ida_hexrays.m_lnot,
        ida_hexrays.m_bnot,
        ida_hexrays.m_xds,
        ida_hexrays.m_xdu,
        ida_hexrays.m_low,
        ida_hexrays.m_high,
        ida_hexrays.m_add,
        ida_hexrays.m_sub,
        ida_hexrays.m_mul,
        ida_hexrays.m_udiv,
        ida_hexrays.m_sdiv,
        ida_hexrays.m_umod,
        ida_hexrays.m_smod,
        ida_hexrays.m_or,
        ida_hexrays.m_and,
        ida_hexrays.m_xor,
        ida_hexrays.m_shl,
        ida_hexrays.m_shr,
        ida_hexrays.m_sar,
        ida_hexrays.m_cfadd,
        ida_hexrays.m_ofadd,
        ida_hexrays.m_cfshl,
        ida_hexrays.m_cfshr,
        ida_hexrays.m_sets,
        ida_hexrays.m_seto,
        ida_hexrays.m_setp,
        ida_hexrays.m_setnz,
        ida_hexrays.m_setz,
        ida_hexrays.m_setae,
        ida_hexrays.m_setb,
        ida_hexrays.m_seta,
        ida_hexrays.m_setbe,
        ida_hexrays.m_setg,
        ida_hexrays.m_setge,
        ida_hexrays.m_setl,
        ida_hexrays.m_setle,
        ida_hexrays.m_call,
        ida_hexrays.m_icall,
        ida_hexrays.m_ret,
    }

    def __init__(self):
        super().__init__()
        # Map to track stack variable assignments: {var_name: (value, size)}
        self.stack_var_map = {}
        # Track the current function being processed
        self.current_func = None
        # self.maturities = [ida_hexrays.MMAT_CALLS]

    @typing.override
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
            # Dump current constant map for diagnostics
            if self.stack_var_map:
                logger.debug(
                    "[stack-var-fold] current constant map: %s", self.stack_var_map
                )
            else:
                logger.debug("[stack-var-fold] constant map is currently empty")

        # Record constant stack-variable assignments.  We always do this so
        #    that future instructions can benefit from the recorded mapping even
        #    if this particular instruction is not itself rewritten.--------
        if self._is_constant_stack_assignment(ins):
            self._record_stack_assignment(ins)
            return  # This instruction is just an assignment – nothing to fold

        if ins.opcode not in self.ALLOW_PROPAGATION_OPCODES:
            return  # Skip instructions outside the allow-list

        # Check if this instruction uses stack variables we can fold
        changed = False
        new_ins = ida_hexrays.minsn_t(ins)  # Create a copy to modify

        # Only process the left operand ('l') for all instructions; avoid modifying 'r' or 'd'
        op = getattr(new_ins, "l", None)
        if op is not None and self._process_operand(op):
            changed = True

        if not changed:
            return
        if logger.debug_on:
            logger.debug(
                "[stack-var-fold] folded instruction at ea=%X",
                sanitize_ea(ins.ea),
            )
        return new_ins

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
                        # Accept forms (reg + const) or (stack_var + const)
                        # We don't try to validate reg here; _record_stack_assignment will decide what to do.
                        l_t = ins.d.d.l.t if ins.d.d.l is not None else None
                        r_t = ins.d.d.r.t if ins.d.d.r is not None else None
                        if (
                            l_t in (ida_hexrays.mop_S, ida_hexrays.mop_r)
                            and r_t == ida_hexrays.mop_n
                        ) or (
                            r_t in (ida_hexrays.mop_S, ida_hexrays.mop_r)
                            and l_t == ida_hexrays.mop_n
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
        if reg_name.startswith(("var_", "s_", "stack_")):
            return True

        # Alternatively, additional heuristics could be added here if needed

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
                and (
                    (
                        ins.d.d.l.t in (ida_hexrays.mop_S, ida_hexrays.mop_r)
                        and ins.d.d.r.t == ida_hexrays.mop_n
                    )
                    or (
                        ins.d.d.r.t in (ida_hexrays.mop_S, ida_hexrays.mop_r)
                        and ins.d.d.l.t == ida_hexrays.mop_n
                    )
                )
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
                    # For true stack variables (mop_S) we keep track of the offset, but for
                    # register based references (mop_r) the immediate that appears in an
                    # expression like (rcx+#4) is not an offset into the *variable* – it's
                    # simply an arithmetic addition on a pointer register.  In that case we
                    # record the constant against the register itself so that later uses of
                    # the register (e.g. an `add rcx, #4`) can be folded correctly.
                    # Always include the offset when one is present so that later memory
                    # reads that use the same base + offset pattern can be matched.
                    composite_name = (
                        f"{stack_var_name}+{offset:X}"
                        if offset != 0
                        else stack_var_name
                    )

                    self.stack_var_map[composite_name] = (value, size)

                    if logger.debug_on:
                        logger.debug(
                            "[stack-var-fold] recorded stx assignment: %s = 0x%X (size=%d)",
                            composite_name,
                            value,
                            size,
                        )

    def _get_stack_var_name(self, mop: ida_hexrays.mop_t) -> str | None:
        """Get a unique identifier for a stack or memory location base."""
        base_name = None
        if mop.t == ida_hexrays.mop_S:
            # Try to derive the same human-readable name ("%var_18.4") that IDA prints without
            # resorting to the heavyweight `format_mop_t()` formatter.  The trick is that Hex-Rays
            # stores stack offsets in `mop.s.off` counting *up* from the bottom of the frame,
            # whereas the listing that users see shows the distance *down* from the base pointer
            # (i.e. a negative offset).  If we know the total frame size we can convert:
            #
            #     display_offset = frame_size - mop.s.off
            #
            # Various `mba_t` fields record the frame size depending on architecture / compiler
            # settings.  We probe a few of them and take the first non-zero value.
            mba = getattr(mop.s, "mba", None)
            frame_size = None
            candidate_offsets = []  # collect for diagnostics if we must fall back
            if mba is not None:
                # Prefer the smallest non-zero size that yields a non-negative display offset.
                for attr in ("minstkref", "stacksize", "frsize", "fullsize"):
                    val = getattr(mba, attr, None)
                    if not val:
                        continue
                    disp_off = val - mop.s.off
                    candidate_offsets.append((attr, val, disp_off))
                    if disp_off >= 0:
                        frame_size = val
                        break
            if frame_size is not None:
                disp_off = frame_size - mop.s.off
                base_name = f"%var_{disp_off:X}.{mop.size}"
            else:
                # Fallback to raw offset if frame size isn't available.
                if logger.debug_on and candidate_offsets:
                    for attr, val, disp in candidate_offsets:
                        logger.debug(
                            "[stack-var-fold] fallback raw-offset key: mba.%s=0x%X -> disp=0x%X (neg? %s)",
                            attr,
                            val,
                            disp & ((1 << 64) - 1),
                            disp < 0,
                        )
                base_name = f"stk_{mop.s.off:X}.{mop.size}"

            # Append the value number to distinguish SSA versions. This is the crucial fix.
            return f"{base_name}{{{mop.valnum}}}"

        elif mop.t == ida_hexrays.mop_r:
            # Register-based pointer (e.g. function argument passed in a register)
            # Use the same naming scheme we employ when recording assignments so that
            # look-ups succeed. Include the value number to distinguish SSA versions
            # of the same register and omit the "reg_" prefix for consistency with
            # the keys generated in _record_stack_assignment.
            base_name = ida_hexrays.get_mreg_name(mop.r, mop.size)
            return f"{base_name}.{mop.size}{{{mop.valnum}}}"
        return base_name

    def _process_operand(self, op: ida_hexrays.mop_t) -> bool:
        """Process an operand, replacing stack variables with constants.
        Returns True if any changes were made.
        """
        changed = False

        # If this is a stack variable we know about, replace it
        if op.t == ida_hexrays.mop_S:
            var_name = self._get_stack_var_name(op)
            if var_name is not None and var_name in self.stack_var_map:
                value, _ = self.stack_var_map[var_name]
                # Ensure we don't create a literal that is wider than the stack variable itself
                # IDA will raise an exception if the sizes are inconsistent.
                truncated_value = value & ((1 << (op.size * 8)) - 1)
                op.make_number(truncated_value, op.size)
                changed = True

                if logger.debug_on:
                    logger.debug(
                        "[stack-var-fold] replaced %s with 0x%X (size=%d)",
                        var_name,
                        value,
                        op.size,
                    )

        # If this is a register that represents a stack variable, try to replace it
        elif op.t == ida_hexrays.mop_r:
            if self._is_stack_var_register(op):
                reg_name = ida_hexrays.get_mreg_name(op.r, op.size)
                reg_name += f".{op.size}{{{op.valnum}}}"
                if reg_name in self.stack_var_map:
                    value, _ = self.stack_var_map[reg_name]
                    op.make_number(value, op.size)
                    changed = True

                    if logger.debug_on:
                        logger.debug(
                            "[stack-var-fold] replaced pseudo-register %s with 0x%X (size=%d)",
                            reg_name,
                            value,
                            op.size,
                        )

        # Handle memory reads from stack variables
        elif op.t == ida_hexrays.mop_d and op.d is not None:
            # Check if this is a memory read from a stack variable
            if op.d.opcode in (ida_hexrays.m_ldx, ida_hexrays.m_ldc):
                # The address operand for ldx/ldc is the *right* argument (op.d.r).
                addr = op.d.r if op.d.r is not None else op.d.l

                # Direct stack variable address
                if addr is not None and addr.t == ida_hexrays.mop_S:
                    var_name = self._get_stack_var_name(addr)
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

                # Address is an expression (e.g., base+offset)
                elif (
                    addr is not None
                    and addr.t == ida_hexrays.mop_d
                    and addr.d is not None
                    and addr.d.opcode == ida_hexrays.m_add
                ):
                    # Extract base and offset similarly to the store-handling logic
                    stack_var = None
                    offset = 0
                    if addr.d.l is not None and addr.d.l.t in (
                        ida_hexrays.mop_S,
                        ida_hexrays.mop_r,
                    ):
                        stack_var = addr.d.l
                        if addr.d.r is not None and addr.d.r.t == ida_hexrays.mop_n:
                            offset = addr.d.r.nnn.value
                    elif addr.d.r is not None and addr.d.r.t in (
                        ida_hexrays.mop_S,
                        ida_hexrays.mop_r,
                    ):
                        stack_var = addr.d.r
                        if addr.d.l is not None and addr.d.l.t == ida_hexrays.mop_n:
                            offset = addr.d.l.nnn.value

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
