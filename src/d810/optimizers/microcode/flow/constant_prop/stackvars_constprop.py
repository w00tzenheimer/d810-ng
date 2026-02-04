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

from d810.core import typing
from d810.core import getLogger
from d810.hexrays.cfg_utils import (
    extract_base_and_offset,
    get_stack_var_name,
    safe_verify,
)
from d810.hexrays.hexrays_formatters import maturity_to_string
from d810.hexrays.hexrays_helpers import AND_TABLE
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

logger = getLogger(__name__)

ConstMap = dict[str, tuple[int, int]]  # var  -> (value, size)

import weakref


class StackVariableConstantPropagationRule(FlowOptimizationRule):
    """Forward constant propagation for stack variables (whole function)."""

    DESCRIPTION = "Fold stack variables that are assigned constant values across the whole function"

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
        self.maturities = [ida_hexrays.MMAT_CALLS]
        self.cython_enabled = True
        self._seen = weakref.WeakKeyDictionary()  # mba -> last_maturity_run

    @typing.override
    def configure(self, kwargs):
        super().configure(kwargs)
        self.cython_enabled = kwargs.get("cython_enabled", True)

    @typing.override
    def optimize(self, blk: ida_hexrays.mblock_t):
        if self.current_maturity not in self.maturities:
            if logger.debug_on:
                logger.debug(
                    "maturity is %s (%d), expecting one of: %s",
                    maturity_to_string(self.current_maturity),
                    self.current_maturity,
                    ", ".join(map(maturity_to_string, self.maturities)),
                )
            return 0
        mba = blk.mba
        if mba is None:
            if logger.debug_on:
                logger.debug("Block %d has no mba", blk.serial)
            return 0

        # Run once per function per maturity; only from block 0
        last = self._seen.get(mba)
        if last == self.current_maturity:
            if logger.debug_on:
                logger.debug(
                    "Skipping previous run of block %d, maturity %s (%d)",
                    blk.serial,
                    maturity_to_string(self.current_maturity),
                    self.current_maturity,
                )
            return 0
        if blk.serial != 1:
            if logger.debug_on:
                logger.debug(
                    "Skipping, this block serial is: %d, expecting 1, maturity %s (%d)",
                    blk.serial,
                    maturity_to_string(self.current_maturity),
                    self.current_maturity,
                )
            return 0
        if logger.debug_on:
            logger.debug(
                "Running %s analysis on block %d, maturity %s (%d)",
                self.__class__.__name__,
                blk.serial,
                maturity_to_string(self.current_maturity),
                self.current_maturity,
            )
        nb_changes = self._run_on_function(mba)
        self._seen[mba] = self.current_maturity  # remember we've run
        return nb_changes
        # if logger.debug_on:
        #     logger.debug("Running dataflow analysis on block %d", blk.serial)
        # nb_changes = self._run_on_function(mba)
        # if logger.debug_on:
        #     logger.debug("Block %d has %d changes", blk.serial, nb_changes)
        # return nb_changes

    def _run_on_function(self, mba: ida_hexrays.mba_t) -> int:
        """
        Performs dataflow analysis and then rewrites the function.
        This is a single call to a highly optimized Cython function.
        """
        if not self.cython_enabled:
            # Fallback to the slower, pure-Python implementation if Cython is disabled
            return self._slow_run_on_function(mba)

        try:
            from . import _fast_dataflow

            total_changes = _fast_dataflow.cy_run_full_pass(mba)
        except ImportError:
            logger.warning(
                "Cython module `_fast_dataflow` not found. Falling back to slow Python implementation."
            )
            self.cython_enabled = False
            return self._slow_run_on_function(mba)

        if total_changes > 0:
            safe_verify(mba, "rewriting", logger_func=logger.error)

        return total_changes

    def _run_dataflow(self, mba: ida_hexrays.mba_t):
        logger.debug("Running dataflow analysis")
        if self.cython_enabled:
            try:
                from . import _fast_dataflow

                return _fast_dataflow.run_dataflow_cython(mba)
            except ImportError:
                logger.warning(
                    "Cython module `_fast_dataflow` not found. Falling back to slow Python implementation."
                )
                self.cython_enabled = False
        return self._slow_dataflow(mba)

    def _slow_run_on_function(self, mba: ida_hexrays.mba_t) -> int:
        """The pure Python implementation of the analysis and rewrite pass."""
        IN, _ = self._slow_dataflow(mba)
        if not IN:
            return 0

        total_changes = 0
        curr_blk: ida_hexrays.mblock_t = mba.get_mblock(0)
        while curr_blk:
            block_was_changed = False
            while True:
                consts: ConstMap = IN[curr_blk.serial].copy()
                if logger.debug_on and consts:
                    logger.debug("[cprop] IN for blk %d: %s", curr_blk.serial, consts)

                made_change_this_pass = False
                ins = curr_blk.head
                while ins:
                    # FIX: Pass the 'mba' object down to the helper functions.
                    if self._slow_rewrite_instruction(mba, ins, consts) > 0:
                        total_changes += 1
                        made_change_this_pass = True
                        block_was_changed = True
                        break

                    # FIX: Pass the 'mba' object down to the helper functions.
                    self._slow_transfer_single(mba, ins, consts)
                    ins = ins.next

                if not made_change_this_pass:
                    break

            if block_was_changed:
                curr_blk.mark_lists_dirty()
            curr_blk = curr_blk.nextb

        if total_changes > 0:
            mba.mark_chains_dirty()
            mba.optimize_local(0)
        return total_changes

    def _rewrite_instruction(
        self, mba: ida_hexrays.mba_t, ins: ida_hexrays.minsn_t, env: ConstMap
    ) -> int:
        if self.cython_enabled:
            return self._fast_rewrite_instruction(mba, ins, env)
        else:
            return self._slow_rewrite_instruction(mba, ins, env)

    def _transfer_single(
        self, mba: ida_hexrays.mba_t, ins: ida_hexrays.minsn_t, env: ConstMap
    ):
        if self.cython_enabled:
            self._fast_transfer_single(mba, ins, env)
        else:
            self._slow_transfer_single(mba, ins, env)

    def _fast_rewrite_instruction(
        self, mba: ida_hexrays.mba_t, ins: ida_hexrays.minsn_t, env: ConstMap
    ) -> int:
        from . import _fast_dataflow

        if ins.opcode not in self.ALLOW_PROPAGATION_OPCODES:
            return 0

        return _fast_dataflow.cy_rewrite_instruction(ins, env)

    def _fast_transfer_single(
        self, mba: ida_hexrays.mba_t, ins: ida_hexrays.minsn_t, env: ConstMap
    ):
        from . import _fast_dataflow

        # if ins.has_side_effects() and ins.opcode != ida_hexrays.m_stx:
        #     env.clear()
        #     return
        if ins.is_unknown_call():  # or opcode-based check if needed
            env.clear()
            return
        written_var = _fast_dataflow.cy_get_written_var_name(ins)
        is_const_assign = _fast_dataflow.cy_is_constant_stack_assignment(ins)
        if written_var and not is_const_assign and written_var in env:
            del env[written_var]
        if is_const_assign:
            res = _fast_dataflow.cy_extract_assignment(ins)
            if res:
                var, val_size = res
                if var:
                    env[var] = val_size

    def _slow_dataflow(self, mba: ida_hexrays.mba_t):
        nb = mba.qty
        IN: dict[int, ConstMap] = {i: {} for i in range(nb)}
        OUT: dict[int, ConstMap] = {i: {} for i in range(nb)}
        worklist: list[int] = list(range(nb))
        preds: dict[int, list[int]] = {
            i: list(mba.get_mblock(i).predset) for i in range(nb)
        }
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

    @staticmethod
    def _meet(pred_outs: list[ConstMap]) -> ConstMap:
        if not pred_outs:
            return {}
        if len(pred_outs) == 1:
            return dict(pred_outs[0])
        first, res = pred_outs[0], {}
        for k, v in first.items():
            if all(other.get(k) == v for other in pred_outs[1:]):
                res[k] = v
        return res

    def _transfer_block(self, blk: ida_hexrays.mblock_t, in_map: ConstMap) -> ConstMap:
        env = dict(in_map)
        ins = blk.head
        # FIX: Pass the mba from the block down to the slow transfer function.
        mba = blk.mba
        while ins:
            self._slow_transfer_single(mba, ins, env)
            ins = ins.next
        return env

    def _slow_transfer_single(
        self, mba: ida_hexrays.mba_t, ins: ida_hexrays.minsn_t, env: ConstMap
    ):
        if ins.has_side_effects() and ins.opcode != ida_hexrays.m_stx:
            env.clear()
            return
        written_var = self._get_written_var_name(ins)
        is_const_assign = self._is_constant_stack_assignment(ins)
        if written_var and not is_const_assign and written_var in env:
            del env[written_var]
        if is_const_assign:
            res = self._extract_assignment(ins)
            if res and res[0]:
                env[res[0]] = res[1]

    def _slow_rewrite_instruction(
        self, mba: ida_hexrays.mba_t, ins: ida_hexrays.minsn_t, env: ConstMap
    ) -> int:
        if ins.opcode not in self.ALLOW_PROPAGATION_OPCODES:
            return 0
        changed = False
        if ins.l and self._slow_process_operand(ins.l, env):
            changed = True
        if ins.r and self._slow_process_operand(ins.r, env):
            changed = True
        if (
            ins.opcode == ida_hexrays.m_stx
            and ins.d
            and self._slow_process_operand(ins.d, env)
        ):
            changed = True
        if not changed:
            return 0
        ins.optimize_solo()
        return 1

    def _slow_process_operand(self, op: ida_hexrays.mop_t, consts: ConstMap) -> bool:
        changed = False
        if op.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            name = get_stack_var_name(op)
            if name and name in consts:
                val, _ = consts[name]
                op.make_number(val & ((1 << (op.size * 8)) - 1), op.size)
                return True
        elif op.t == ida_hexrays.mop_f and op.f is not None:
            for a in op.f.args:
                if a and self._slow_process_operand(a, consts):
                    changed = True
        elif op.t == ida_hexrays.mop_d and op.d is not None:
            if op.d.opcode == ida_hexrays.m_ldx:
                addr = op.d.r
                const_info, name = None, None
                if addr and addr.t == ida_hexrays.mop_S:
                    name = get_stack_var_name(addr)
                    if name and name in consts:
                        const_info = consts[name]
                else:
                    base, off = extract_base_and_offset(addr)
                    if base:
                        base_name = get_stack_var_name(base)
                        name = f"{base_name}+{off:X}" if off else base_name
                        if name in consts:
                            const_info = consts[name]
                if const_info:
                    val, _ = const_info
                    tmp = ida_hexrays.mop_t()
                    tmp.make_number(val & AND_TABLE[op.size], op.size)
                    op.assign(tmp)
                    return True
            for attr in ("l", "r"):
                sub = getattr(op.d, attr, None)
                if sub and self._slow_process_operand(sub, consts):
                    changed = True
            if changed:
                op.d.optimize_solo()
        return changed

    def _get_written_var_name(self, ins: ida_hexrays.minsn_t):
        d = ins.d
        if d is None:
            return None
        if d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            return get_stack_var_name(d)
        if ins.opcode != ida_hexrays.m_stx:
            return None
        if d.t == ida_hexrays.mop_S:
            return get_stack_var_name(d)
        base, off = extract_base_and_offset(d)
        if base and (base_name := get_stack_var_name(base)):
            return f"{base_name}+{off:X}" if off else base_name
        return None

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

    def _extract_assignment(self, ins: ida_hexrays.minsn_t):
        if not self._is_constant_stack_assignment(ins):
            return None
        value, size = ins.l.nnn.value, ins.l.size
        var = None
        if ins.opcode == ida_hexrays.m_mov:
            var = get_stack_var_name(ins.d)
        elif ins.d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            var = get_stack_var_name(ins.d)
        else:
            base, off = extract_base_and_offset(ins.d)
            if base and (base_name := get_stack_var_name(base)):
                var = f"{base_name}+{off:X}" if off else base_name
        return (var, (value, size)) if var else None
