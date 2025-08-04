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

import logging
from typing import Dict, List, Tuple

import ida_hexrays

from d810 import _compat
from d810.conf.loggers import getLogger
from d810.hexrays.cfg_utils import log_block_info
from d810.hexrays.hexrays_formatters import opcode_to_string, sanitize_ea
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule

logger = getLogger(__name__, default_level=logging.DEBUG)

# Typing helpers -------------------------------------------------------------
ConstMap = Dict[str, Tuple[int, int]]  # var  -> (value, size)


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

    # ---------------------------------------------------------------------
    # FlowOptimizationRule entry-point
    # ---------------------------------------------------------------------

    @_compat.override
    def optimize(self, blk: ida_hexrays.mblock_t):
        mba = blk.mba
        if mba is None:
            return 0
        key = (mba.entry_ea, mba.maturity)
        if key in self._done_funcs:
            return 0
        nb_changes = self._run_on_function(mba)
        self._done_funcs.add(key)
        return nb_changes

    # ---------------------------------------------------------------------
    # Full function processing (two phases)
    # ---------------------------------------------------------------------

    def _run_on_function(self, mba: ida_hexrays.mba_t) -> int:
        IN, _ = self._run_dataflow(mba)

        changes = 0
        curr_blk: ida_hexrays.mblock_t = mba.get_mblock(0)
        while curr_blk:
            consts: ConstMap = IN[curr_blk.serial].copy()
            if logger.debug_on and consts:
                logger.debug(
                    "[stack-var-cprop] constant map before blk %d: %s",
                    curr_blk.serial,
                    consts,
                )
            ins: ida_hexrays.minsn_t = curr_blk.head
            while ins:
                changes += self._rewrite_instruction(ins, consts)
                # update env with original instruction effects
                self._transfer_single(ins, consts)
                ins = ins.next
            curr_blk = curr_blk.nextb

        if changes:
            mba.mark_chains_dirty()
            mba.optimize_local(0)
            self._safe_verify(mba, "rewriting")
        return changes

    # ------------------------------------------------------------------
    # Phase A – classic forward data-flow (GEN/KILL)
    # ------------------------------------------------------------------

    def _run_dataflow(self, mba: ida_hexrays.mba_t):
        nb = mba.qty
        IN: Dict[int, ConstMap] = {i: {} for i in range(nb)}
        OUT: Dict[int, ConstMap] = {i: {} for i in range(nb)}

        worklist: List[int] = list(range(nb))

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
    def _meet(pred_outs: List[ConstMap]) -> ConstMap:
        if not pred_outs:
            return {}
        keys = set.intersection(*(set(m.keys()) for m in pred_outs))
        res: ConstMap = {}
        for k in keys:
            vals = {m[k] for m in pred_outs}
            if len(vals) == 1:
                res[k] = vals.pop()
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
        # -------------------------------------------------------------
        # 1. Side-effects handling
        # -------------------------------------------------------------
        # For *imprecise* side-effecting instructions (e.g. calls) we must drop
        # every tracked constant.  A plain store (stx) is a *precise* write that
        # we interpret below, so we exclude it from the blanket kill.
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

        # -------------------------------------------------------------
        # 2. Determine written variable & apply precise KILL / GEN.
        # -------------------------------------------------------------
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

        # GEN – introduce new constant
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
        if changed and logger.debug_on:
            logger.debug("[stack-var-cprop] folded at %X", sanitize_ea(ins.ea))
        return 1 if changed else 0

    # ------------------------------------------------------------------
    # Helper utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_base_and_offset(mop: ida_hexrays.mop_t):
        if (
            mop.t == ida_hexrays.mop_d
            and mop.d is not None
            and mop.d.opcode == ida_hexrays.m_add
        ):
            # (base + const)
            if mop.d.l and mop.d.l.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
                off = (
                    mop.d.r.nnn.value
                    if mop.d.r and mop.d.r.t == ida_hexrays.mop_n
                    else 0
                )
                return mop.d.l, off
            if mop.d.r and mop.d.r.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
                off = (
                    mop.d.l.nnn.value
                    if mop.d.l and mop.d.l.t == ida_hexrays.mop_n
                    else 0
                )
                return mop.d.r, off
        return None, 0

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
            return self._get_stack_var_name(ins.d)
        if ins.opcode == ida_hexrays.m_stx:
            if ins.d.t == ida_hexrays.mop_S:
                return self._get_stack_var_name(ins.d)
            base, off = self._extract_base_and_offset(ins.d)
            if base is not None:
                base_name = self._get_stack_var_name(base)
                if base_name:
                    return f"{base_name}+{off:X}" if off else base_name
        return None

    # is instruction a constant store into stack?
    def _is_constant_stack_assignment(self, ins: ida_hexrays.minsn_t):
        if ins.l is None or ins.l.t != ida_hexrays.mop_n:
            return False
        if ins.opcode == ida_hexrays.m_mov and ins.d and ins.d.t == ida_hexrays.mop_S:
            return True
        if ins.opcode == ida_hexrays.m_stx:
            if ins.d and ins.d.t == ida_hexrays.mop_S:
                return True
            base, _ = self._extract_base_and_offset(ins.d) if ins.d else (None, 0)
            return base is not None
        return False

    # extract (var,(value,size)) for constant assignment
    def _extract_assignment(self, ins: ida_hexrays.minsn_t):
        if not self._is_constant_stack_assignment(ins):
            return None
        value = ins.l.nnn.value  # type: ignore[attr-defined]
        size = ins.l.size  # type: ignore[attr-defined]
        if ins.opcode == ida_hexrays.m_mov:
            var = self._get_stack_var_name(ins.d)
            return var, (value, size)
        # stx forms
        if ins.d.t == ida_hexrays.mop_S:
            var = self._get_stack_var_name(ins.d)
            return var, (value, size)
        base, off = self._extract_base_and_offset(ins.d)
        if base is not None:
            var_base = self._get_stack_var_name(base)
            if var_base:
                comp = f"{var_base}+{off:X}" if off else var_base
                return comp, (value, size)
        return None

    # ------------------------------------------------------------------
    # Utility -----------------------------------------------------------------

    def _safe_verify(self, mba: ida_hexrays.mba_t, ctx: str):
        """Run mba.verify(True) and produce helpful diagnostics on failure."""
        try:
            mba.verify(True)
        except RuntimeError as e:
            logger.error("[stack-var-cprop] verify failed after %s: %s", ctx, e)
            # attempt to locate a problematic block: dump the last one
            try:
                last_blk = (
                    mba.get_mblock(mba.qty - 2) if mba.qty >= 2 else mba.get_mblock(0)
                )
                log_block_info(last_blk, logger.error)
            except Exception:  # pragma: no cover
                pass
            raise

    # Operand folding (recursive)
    # ------------------------------------------------------------------

    def _process_operand(self, op: ida_hexrays.mop_t, consts: ConstMap):
        changed = False
        if op.t == ida_hexrays.mop_S:
            name = self._get_stack_var_name(op)
            if name and name in consts:
                val, _ = consts[name]
                op.make_number(val & ((1 << (op.size * 8)) - 1), op.size)
                return True
        elif op.t == ida_hexrays.mop_r:
            name = self._get_stack_var_name(op)
            if name and name in consts:
                val, _ = consts[name]
                op.make_number(val & ((1 << (op.size * 8)) - 1), op.size)
                return True
        elif op.t == ida_hexrays.mop_d and op.d is not None:
            # ------------------------------------------------------------------
            # Case 1: the *value* of this mop_d is itself an address expression
            #         "(base + const)" that we have a constant for.  Fold the
            #         whole operand before peeking into nested instructions.
            # ------------------------------------------------------------------
            base, off = self._extract_base_and_offset(op)
            if base is not None:
                base_name = self._get_stack_var_name(base)
                if base_name:
                    key = f"{base_name}+{off:X}" if off else base_name
                    if key in consts:
                        val, _ = consts[key]
                        op.make_number(val & ((1 << (op.size * 8)) - 1), op.size)
                        return True
            if op.d.opcode in {ida_hexrays.m_ldx, ida_hexrays.m_ldc}:
                addr = op.d.l
                # direct stack var
                if addr and addr.t == ida_hexrays.mop_S:
                    name = self._get_stack_var_name(addr)
                    if name and name in consts:
                        val, sz = consts[name]
                        op.make_number(val & ((1 << (op.size * 8)) - 1), op.size)
                        return True
                # base+offset
                base, off = self._extract_base_and_offset(addr)
                if base is not None:
                    base_name = self._get_stack_var_name(base)
                    comp = f"{base_name}+{off:X}" if off else base_name
                    if comp in consts:
                        val, sz = consts[comp]
                        op.make_number(val & ((1 << (op.size * 8)) - 1), op.size)
                        return True
            # Recurse into *source* operands of the nested instruction.  Do NOT
            # touch its destination ('.d').
            if op.d.opcode == ida_hexrays.m_stx:
                return changed
            for attr in ("l", "r"):
                sub = getattr(op.d, attr, None)
                if sub is not None and self._process_operand(sub, consts):
                    changed = True
            # ensure nested instruction is internally consistent after edits
            if changed and op.t == ida_hexrays.mop_d and op.d is not None:
                op.d.optimize_solo()
        elif op.t == ida_hexrays.mop_f and op.f is not None:
            for a in op.f.args:
                if a and self._process_operand(a, consts):
                    changed = True
        return changed

    # ------------------------------------------------------------------
    # Variable naming (same as old peephole rule)
    # ------------------------------------------------------------------

    def _get_stack_var_name(self, mop: ida_hexrays.mop_t):
        if mop.t == ida_hexrays.mop_S:
            mba = getattr(mop.s, "mba", None)
            frame_size = None
            if mba:
                for att in ("minstkref", "stacksize", "frsize", "fullsize"):
                    val = getattr(mba, att, None)
                    if val:
                        disp = val - mop.s.off
                        if disp >= 0:
                            frame_size = val
                            break
            if frame_size is not None:
                disp = frame_size - mop.s.off
                base = f"%var_{disp:X}.{mop.size}"
            else:
                base = f"stk_{mop.s.off:X}.{mop.size}"
            return f"{base}{{{mop.valnum}}}"
        if mop.t == ida_hexrays.mop_r:
            base = ida_hexrays.get_mreg_name(mop.r, mop.size)
            return f"{base}.{mop.size}{{{mop.valnum}}}"
        return None
