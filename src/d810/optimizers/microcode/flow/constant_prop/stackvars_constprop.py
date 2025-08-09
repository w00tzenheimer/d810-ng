from __future__ import annotations

"""Global forward constant-propagation of stack / frame variables.

This pass is a *function-level* optimisation implemented as a
``FlowOptimizationRule`` (triggered by ``BlockOptimizerManager``).
It performs a forward data-flow analysis to discover stack variables
that hold a *unique* constant along every path and folds those
constants back into the micro-code.

Compared with the former peephole rule this implementation is
function-wide and therefore safe at control-flow merge points.
"""
import ida_hexrays

from d810 import _compat
from d810.conf.loggers import getLogger
from d810.hexrays.cfg_utils import (
    extract_base_and_offset,
    get_stack_var_name,
    safe_verify,
)
from d810.hexrays.hexrays_formatters import (
    format_minsn_t,
    format_mop_t,
    opcode_to_string,
    sanitize_ea,
)
from d810.hexrays.hexrays_helpers import AND_TABLE
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

logger = getLogger(__name__)

ConstMap = dict[str, tuple[int, int]]  # var  -> (value, size)


class StackVariableConstantPropagationRule(FlowOptimizationRule):
    """Forward constant propagation for stack variables (whole function)."""

    DESCRIPTION = "Fold stack variables that are assigned constant values across the whole function"

    # Opcodes whose *operands* we are willing to fold to constants.  The list is
    # **not** used for KILL/GEN decisions – those depend on the actual destination
    # operand, not on the opcode.
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
        ida_hexrays.m_ldx,
        ida_hexrays.m_ldc,
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
    }

    def __init__(self):
        super().__init__()
        self._done_funcs: set[tuple[int, int]] = set()
        # run when SSA names are fixed but before aggressive global opts
        self.maturities = [ida_hexrays.MMAT_CALLS]

    @_compat.override
    def optimize(self, blk: ida_hexrays.mblock_t):
        logger.debug("Optimizing block %d", blk.serial)
        if self.current_maturity not in self.maturities:
            logger.debug(
                "Skipping block %d, maturity %d", blk.serial, self.current_maturity
            )
            return 0
        mba = blk.mba
        if mba is None:
            return 0
        nb_changes = self._run_on_function(mba)
        return nb_changes

    def _run_on_function(self, mba: ida_hexrays.mba_t) -> int:
        """
        Performs dataflow analysis and then rewrites the function.

        This function uses a fixed-point iteration strategy for rewriting. This is
        the standard, safe way to handle optimizers that can delete or replace
        the instruction being worked on (e.g., via `optimize_solo`), which
        invalidates simple instruction list iterators.
        """
        # Phase A: Dataflow analysis to find where constants are known at the
        # start of each block.
        IN, _ = self._run_dataflow(mba)

        total_changes = 0
        # Phase B: Iterate over each block and apply optimizations until the
        # block is stable (reaches a fixed point).
        curr_blk: ida_hexrays.mblock_t = mba.get_mblock(0)
        while curr_blk:
            block_was_changed = False
            # Fixed-point loop for the current block.
            while True:
                # The local constant map MUST be re-initialized inside the
                # fixed-point loop. A destructive rewrite invalidates the
                # previous local dataflow analysis, so we must start fresh.
                consts: ConstMap = IN[curr_blk.serial].copy()
                if logger.debug_on and consts:
                    logger.debug(
                        "[stack-var-cprop] constant map before blk %d: %s",
                        curr_blk.serial,
                        consts,
                    )
                made_change_this_pass = False
                ins = curr_blk.head
                while ins:
                    # Attempt to rewrite the current instruction.
                    if self._rewrite_instruction(ins, consts) > 0:
                        total_changes += 1
                        made_change_this_pass = True
                        block_was_changed = True
                        # A destructive change was made. The instruction list
                        # is now potentially invalid. We must break this inner
                        # loop and restart the scan from the block's head.
                        break

                    # If no rewrite happened, update the local constant map
                    # with the effects of the current instruction.
                    self._transfer_single(ins, consts)
                    ins = ins.next

                if not made_change_this_pass:
                    # We completed a full pass over the block with no changes.
                    # The block is stable, so we can exit the fixed-point loop.
                    break

            # If any instruction in the block was changed, its use/def lists
            # are now invalid. We must mark them as dirty so the decompiler
            # knows to recompute them. This is the fix for INTERR 50873.
            if block_was_changed:
                curr_blk.mark_lists_dirty()

            curr_blk = curr_blk.nextb

        if total_changes > 0:
            mba.mark_chains_dirty()
            mba.optimize_local(0)
            safe_verify(mba, "rewriting", logger_func=logger.error)

        return total_changes

    # ------------------------------------------------------------------
    # Phase A – classic forward data-flow (GEN/KILL)
    # ------------------------------------------------------------------

    def _run_dataflow(self, mba: ida_hexrays.mba_t):
        nb = mba.qty
        IN: dict[int, ConstMap] = {i: {} for i in range(nb)}
        OUT: dict[int, ConstMap] = {i: {} for i in range(nb)}

        worklist: list[int] = list(range(nb))

        preds: dict[int, list[int]] = {}
        for i in range(nb):
            blk: ida_hexrays.mblock_t = mba.get_mblock(i)
            preds[i] = list(blk.predset)

        while worklist:
            idx = worklist.pop()
            inm = self._meet([OUT[p] for p in preds[idx]]) if preds[idx] else {}
            if inm != IN[idx]:
                IN[idx] = inm
            out_new = self._transfer_block(mba.get_mblock(idx), inm)
            if out_new != OUT[idx]:
                OUT[idx] = out_new
                for succ in mba.get_mblock(idx).succset:
                    if succ not in worklist:
                        worklist.append(succ)
        return IN, OUT

    # meet = intersection of keys where all values agree
    @staticmethod
    def _meet(pred_outs: list[ConstMap]) -> ConstMap:
        """
        Compute the meet (intersection) of constant maps coming from the
        predecessors.

        The previous implementation built *N* temporary ``set`` objects and an
        additional ``set`` for the intersection result on **every** call – on
        large functions with thousands of blocks this showed up as a hotspot in
        the profiler (≈250 ms of a 635 ms pass in the example trace).

        This optimised version avoids most of that overhead:
        1. Early-out when there are 0 or 1 predecessors.
        2. Iterate only over the keys of the *first* predecessor and compare the
           value in the remaining maps.  This replaces costly ``set``
           allocations with plain dictionary look-ups and short-circuiting.

        For functions with few predecessors per block (the common case) the
        runtime of ``_meet`` drops by roughly an order of magnitude.
        """
        if not pred_outs:
            return {}
        if len(pred_outs) == 1:
            # Fast-path: single predecessor – just copy its map.
            return dict(pred_outs[0])

        first = pred_outs[0]
        res: ConstMap = {}
        for k, v in first.items():
            for other in pred_outs[1:]:
                if other.get(k) != v:
                    break
            else:  # no ``break`` means all predecessors agree on (k, v)
                res[k] = v
        return res

    # transfer over whole block
    def _transfer_block(self, blk: ida_hexrays.mblock_t, in_map: ConstMap) -> ConstMap:
        env = dict(in_map)
        ins = blk.head
        while ins:
            self._transfer_single(ins, env)
            ins = ins.next
        return env

    # transfer for a single instruction (GEN/KILL)
    def _transfer_single(self, ins: ida_hexrays.minsn_t, env: ConstMap):
        # 1. Side-effects handling - for *imprecise* side-effecting instructions
        # (e.g. calls) we must drop every tracked constant.
        #
        # A plain store (stx) is a *precise* write that we interpret below,
        # so we exclude it from the blanket kill.
        if ins.has_side_effects() and ins.opcode != ida_hexrays.m_stx:
            if env and logger.debug_on:
                logger.debug(
                    "[stack-var-cprop] KILL-ALL at %X due to %s",
                    sanitize_ea(ins.ea),
                    opcode_to_string(ins.opcode),
                )
            env.clear()
            # Nothing more to learn from this instruction.
            return

        # 2. Determine written variable & apply precise KILL / GEN.
        written_var = self._get_written_var_name(ins)
        is_const_assign = self._is_constant_stack_assignment(ins)

        # KILL when variable overwritten by non-constant value
        if written_var and not is_const_assign and written_var in env:
            if logger.debug_on:
                logger.debug(
                    "[stack-var-cprop] KILL %s at %X via %s",
                    written_var,
                    sanitize_ea(ins.ea),
                    opcode_to_string(ins.opcode),
                )
            del env[written_var]

        # 3. GEN - introduce new constant
        if is_const_assign:
            res = self._extract_assignment(ins)
            if res:
                var, val_size = res
                if var:
                    env[var] = val_size
                    if logger.debug_on:
                        logger.debug(
                            "[stack-var-cprop] GEN %s = 0x%X at %X",
                            var,
                            val_size[0],
                            sanitize_ea(ins.ea),
                        )

    # ------------------------------------------------------------------
    # Phase B – rewrite helpers
    # ------------------------------------------------------------------

    def _rewrite_instruction(self, ins: ida_hexrays.minsn_t, env: ConstMap) -> int:
        if ins.opcode not in self.ALLOW_PROPAGATION_OPCODES:
            return 0

        # We must process one operand, and if it changes, optimize and exit
        # immediately. Calling `optimize_solo()` can invalidate the `ins`
        # object, so we cannot continue to access its other operands like
        # `ins.r`.

        changed = False
        # left operand
        if ins.l and self._process_operand(ins.l, env):
            changed = True
        # right operand for binary ops
        if ins.r and self._process_operand(ins.r, env):
            changed = True
        # stx destination address is also an input
        if (
            ins.opcode == ida_hexrays.m_stx
            and ins.d
            and self._process_operand(ins.d, env)
        ):
            changed = True

        if not changed:
            return 0

        # Ensure the instruction is internally consistent after we rewrote its operands.
        # An operand was changed to a constant. Let Hex-Rays recompute internal
        # metadata for this instruction.
        if logger.debug_on:
            old_repr = format_minsn_t(ins)
        ins.optimize_solo()
        if logger.debug_on:
            logger.debug(
                "[stack-var-cprop] optimized insn at %X: %s -> %s",
                sanitize_ea(ins.ea),
                old_repr,
                format_minsn_t(ins),
            )
        return 1

    # ------------------------------------------------------------------
    # Helper utilities
    # ------------------------------------------------------------------

    # conservative wiping helper
    def _kill_all_stack_vars(self, env: ConstMap, reason: str, ea: int):
        prefixes = ("%var_", "stk_", "rsp", "rbp", "esp", "ebp")
        to_del = [k for k in env if k.startswith(prefixes)]
        if to_del and logger.debug_on:
            logger.debug(
                "[stack-var-cprop] KILL-ALL at %X (%s): %s", ea, reason, to_del
            )
        for k in to_del:
            del env[k]

    # identify destination variable of an instruction (None if unknown)
    def _get_written_var_name(self, ins: ida_hexrays.minsn_t):
        if ins.d is None:
            return None
        if ins.d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            return get_stack_var_name(ins.d)
        if ins.opcode == ida_hexrays.m_stx:
            if ins.d.t == ida_hexrays.mop_S:
                return get_stack_var_name(ins.d)
            base, off = extract_base_and_offset(ins.d)
            if base is not None:
                base_name = get_stack_var_name(base)
                if base_name:
                    return f"{base_name}+{off:X}" if off else base_name
        return None

    # is instruction a constant store into stack?
    def _is_constant_stack_assignment(self, ins: ida_hexrays.minsn_t):
        if ins.l is None or ins.l.t != ida_hexrays.mop_n:
            return False
        if (
            ins.opcode == ida_hexrays.m_mov
            and ins.d
            and ins.d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}
        ):
            return True
        if ins.opcode == ida_hexrays.m_stx:
            if ins.d and ins.d.t == ida_hexrays.mop_S:
                return True
            base, _ = extract_base_and_offset(ins.d) if ins.d else (None, 0)
            return base is not None
        return False

    # extract (var,(value,size)) for constant assignment
    def _extract_assignment(self, ins: ida_hexrays.minsn_t):
        if not self._is_constant_stack_assignment(ins):
            return None
        value = ins.l.nnn.value  # type: ignore[attr-defined]
        size = ins.l.size  # type: ignore[attr-defined]
        if ins.opcode == ida_hexrays.m_mov:
            var = get_stack_var_name(ins.d)
            return var, (value, size)
        # stx / mov forms
        if ins.d.t == ida_hexrays.mop_S:
            var = get_stack_var_name(ins.d)
            return var, (value, size)
        if ins.d.t == ida_hexrays.mop_r:
            var = get_stack_var_name(ins.d)
            return var, (value, size)
        base, off = extract_base_and_offset(ins.d)
        if base is not None:
            var_base = get_stack_var_name(base)
            if var_base:
                comp = f"{var_base}+{off:X}" if off else var_base
                return comp, (value, size)
        return None

    def _process_operand(self, op: ida_hexrays.mop_t, consts: ConstMap):
        changed = False
        if op.t == ida_hexrays.mop_S:
            name = get_stack_var_name(op)
            if name and name in consts:
                val, _ = consts[name]
                op.make_number(val & ((1 << (op.size * 8)) - 1), op.size)
                return True
        elif op.t == ida_hexrays.mop_r:
            name = get_stack_var_name(op)
            if name and name in consts:
                val, _ = consts[name]
                op.make_number(val & ((1 << (op.size * 8)) - 1), op.size)
                return True
        elif op.t == ida_hexrays.mop_f and op.f is not None:
            for a in op.f.args:
                if a and self._process_operand(a, consts):
                    changed = True
        elif op.t == ida_hexrays.mop_d and op.d is not None:
            if logger.debug_on:
                logger.debug(
                    "[stack-var-cprop] mop_d: considering nested insn at ea=0x%X, opcode=%s, l=%s, r=%s, d=%s",
                    sanitize_ea(op.d.ea),
                    opcode_to_string(op.d.opcode),
                    format_mop_t(op.d.l) if op.d.l else "",
                    format_mop_t(op.d.r) if op.d.r else "",
                    format_mop_t(op.d.d) if op.d.d else "",
                )
            # If a nested instruction is a load from a known constant location,
            # replace the entire load operation (`mop_d`) with the constant value
            # itself (`mop_n`).
            if op.d.opcode == ida_hexrays.m_ldx:
                # For `ldx`, the address is in the right operand 'r'.
                addr = op.d.r
                if logger.debug_on:
                    logger.debug(
                        "[stack-var-cprop] mop_d: found load (ldx/ldc), addr=%s",
                        format_mop_t(addr),
                    )
                const_info = None
                name = None
                # Case 1: Direct stack variable access
                if addr and addr.t == ida_hexrays.mop_S:
                    name = get_stack_var_name(addr)
                    if logger.debug_on:
                        logger.debug(
                            "[stack-var-cprop] mop_d: direct stack var access, name=%s, in consts=%s",
                            name,
                            name in consts if name else None,
                        )
                    if name and name in consts:
                        const_info = consts[name]
                        if logger.debug_on:
                            logger.debug(
                                "[stack-var-cprop] mop_d: folding direct stack var '%s' to constant 0x%X (size=%d)",
                                name,
                                const_info[0],
                                const_info[1],
                            )
                else:
                    # Case 2: Base + offset access
                    base, off = extract_base_and_offset(addr)
                    if base is not None:
                        if logger.debug_on:
                            logger.debug(
                                "[stack-var-cprop] mop_d: base+off extraction: base=%s, off=%s",
                                format_mop_t(base),
                                off,
                            )
                        base_name = get_stack_var_name(base)
                        name = f"{base_name}+{off:X}" if off else base_name
                        if logger.debug_on:
                            logger.debug(
                                "[stack-var-cprop] mop_d: base+off access, comp=%s, in consts=%s",
                                name,
                                name in consts,
                            )
                        if name in consts:
                            const_info = consts[name]
                            if logger.debug_on:
                                logger.debug(
                                    "[stack-var-cprop] mop_d: folding base+off '%s' to constant 0x%X (size=%d)",
                                    name,
                                    const_info[0],
                                    const_info[1],
                                )
                if const_info:
                    val, _ = const_info
                    # The size of the operand is the size of the mop_d itself.
                    op_size = op.size

                    tmp = ida_hexrays.mop_t()
                    tmp.make_number(val & AND_TABLE[op_size], op_size)
                    op.assign(tmp)

                    if logger.debug_on:
                        logger.debug(
                            "[stack-var-cprop] mop_d: folded load '%s' -> #%X (size=%d): %s",
                            name,
                            val & AND_TABLE[op_size],
                            op_size,
                            format_mop_t(op),
                        )
                    return True

            # If the load couldn't be resolved, recurse into its children.
            changed = False
            for attr in ("l", "r"):
                sub = getattr(op.d, attr, None)
                if logger.debug_on:
                    logger.debug(
                        "[stack-var-cprop] mop_d: recursing into child attr '%s': %s",
                        attr,
                        format_mop_t(sub) if sub else "",
                    )
                if sub is not None and self._process_operand(sub, consts):
                    if logger.debug_on:
                        logger.debug(
                            "[stack-var-cprop] mop_d: child attr '%s' changed during recursion",
                            attr,
                        )
                    changed = True
            # ensure nested instruction is internally consistent after edits
            if changed and op.t == ida_hexrays.mop_d and op.d is not None:
                op.d.optimize_solo()
            if logger.debug_on:
                logger.debug(
                    "[stack-var-cprop] mop_d: finished recursion, changed=%s, insn=%s",
                    changed,
                    format_mop_t(op),
                )
            return changed
        return changed
