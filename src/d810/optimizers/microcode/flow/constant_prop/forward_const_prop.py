from __future__ import annotations

"""Global forward constant-propagation of stack / frame variables and registers.

This pass is a *function-level* optimisation implemented as a
``FlowOptimizationRule`` (triggered by ``BlockOptimizerManager``).
It performs a forward data-flow analysis to discover stack variables
and registers that hold a *unique* constant along every path and folds
those constants back into the micro-code.

Compared with the former peephole rule this implementation is
function-wide and therefore safe at control-flow merge points.
"""
import weakref

import ida_hexrays
import ida_segment
import idaapi

from d810.core import CythonMode, getLogger, logging, typing
from d810.hexrays.cfg_utils import (
    _VALID_MOP_SIZES,
    extract_base_and_offset,
    get_stack_var_name,
    safe_make_number,
    safe_verify,
)
from d810.hexrays.hexrays_formatters import maturity_to_string
from d810.hexrays.hexrays_helpers import AND_TABLE
from d810.optimizers.microcode.handler import ConfigParam
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule, FlowRulePriority

logger = getLogger(__name__, logging.DEBUG)

from d810.optimizers.microcode.flow.constant_prop.lattice import (
    BOTTOM, TOP, Const, LatticeValue, LatticeEnv, LatticeMeet,
)

ConstMap = LatticeEnv  # backward-compat alias


# ---------------------------------------------------------------------------
# Module-level helpers for readonly-segment ldx resolution
# ---------------------------------------------------------------------------

def _ro_segment_is_read_only(addr: int) -> bool:
    """Return True if *addr* is in a readable, non-writable, non-executable segment.

    Guards all IDA API calls with try/except — segment queries can fail when
    the address is synthetic or outside any loaded segment.
    """
    try:
        seg = ida_segment.getseg(addr)
        if seg is None:
            return False
        perms = seg.perm
        has_read = bool(perms & idaapi.SEGPERM_READ)
        has_write = bool(perms & idaapi.SEGPERM_WRITE)
        has_exec = bool(perms & idaapi.SEGPERM_EXEC)
        return has_read and not has_write and not has_exec
    except Exception:
        return False


def _ro_fetch_constant(addr: int, size: int) -> typing.Optional[int]:
    """Read *size* bytes at *addr* and return as an integer, or None on failure."""
    try:
        if size == 1:
            val = idaapi.get_byte(addr)
        elif size == 2:
            val = idaapi.get_word(addr)
        elif size == 4:
            val = idaapi.get_dword(addr)
        elif size == 8:
            val = idaapi.get_qword(addr)
        else:
            return None
        return None if val == idaapi.BADADDR else val
    except Exception:
        return None


@typing.runtime_checkable
class MeetStrategy(typing.Protocol):
    """Strategy for combining predecessor OUT maps at CFG merge points."""

    def meet(self, pred_outs: list[ConstMap]) -> ConstMap:
        """Return the combined constant map for the given predecessor OUT maps."""
        ...


class IntersectionMeet:
    """Keep only vars where ALL predecessors agree on value. Sound."""

    __slots__ = ()

    def meet(self, pred_outs: list[ConstMap]) -> ConstMap:
        """Intersection meet: conservative, sound at all CFG merge points."""
        if not pred_outs:
            return {}
        if len(pred_outs) == 1:
            return dict(pred_outs[0])
        first = pred_outs[0]
        res = {}
        for k, v in first.items():
            if all(other.get(k) == v for other in pred_outs[1:]):
                res[k] = v
        return res


class UnionKillMeet:
    """Keep vars from ANY predecessor; kill only on value conflict.

    WARNING: Unsound with partial-state OUT maps — use only in
    post-apply context where linearized CFG makes it practically safe.
    """

    __slots__ = ()

    def meet(self, pred_outs: list[ConstMap]) -> ConstMap:
        """Union-kill meet: aggressive, safe only in post-apply linearized context."""
        if not pred_outs:
            return {}
        if len(pred_outs) == 1:
            return dict(pred_outs[0])
        candidates: dict[str, tuple[int, int] | None] = {}
        for out_map in pred_outs:
            for var, val in out_map.items():
                if var not in candidates:
                    candidates[var] = val
                elif candidates[var] is not None and candidates[var] != val:
                    candidates[var] = None
        return {var: val for var, val in candidates.items() if val is not None}


class ForwardConstantPropagationRule(FlowOptimizationRule):
    """Forward constant propagation for stack variables and registers (whole function)."""

    CATEGORY = "Constant Propagation"
    PRIORITY = FlowRulePriority.PREPARE_CONSTANTS
    CONFIG_SCHEMA = FlowOptimizationRule.CONFIG_SCHEMA + (
        ConfigParam("cython_enabled", bool, False, "Use Cython fast path for propagation"),
    )

    DESCRIPTION = "Fold stack variables and registers that are assigned constant values across the whole function"

    # Opcodes whose *operands* we are willing to fold to constants.  The list is
    # **not** used for KILL/GEN decisions - those depend on the actual destination
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
        ida_hexrays.m_call,
    }

    def __init__(self, meet_strategy: MeetStrategy | None = None):
        super().__init__()
        self.maturities = [
            ida_hexrays.MMAT_CALLS,
            getattr(ida_hexrays, "MMAT_GLBOPT3", ida_hexrays.MMAT_CALLS),
        ]
        self._seen: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()  # mba -> (maturity, generation)
        self.cython_enabled = CythonMode().is_enabled()
        self._meet_strategy: MeetStrategy = meet_strategy or IntersectionMeet()

    @typing.override
    def configure(self, kwargs):
        super().configure(kwargs)
        self.cython_enabled = kwargs.get("cython_enabled", CythonMode().is_enabled())

    @typing.override
    def optimize(self, blk: ida_hexrays.mblock_t):
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "[FCP] optimize() called at maturity=%d (%s) blk=%d",
                blk.mba.maturity if blk.mba else -1,
                maturity_to_string(blk.mba.maturity) if blk.mba else "?",
                blk.serial,
            )
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

        # Run once per function per (maturity, generation); only from block 0.
        # Using a (maturity, generation) key means the rule re-runs when the
        # generation counter advances (i.e. another rule patched the CFG),
        # allowing constant propagation to pick up newly reachable constants
        # after the unflattener reshapes control flow.
        last = self._seen.get(mba)
        if last == (self.current_maturity, self.current_generation):
            if logger.debug_on:
                logger.debug(
                    "Skipping previous run of block %d, maturity %s (%d), generation %d",
                    blk.serial,
                    maturity_to_string(self.current_maturity),
                    self.current_maturity,
                    self.current_generation,
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
        self._seen[mba] = (self.current_maturity, self.current_generation)  # remember we've run
        return nb_changes

    def _run_on_function(self, mba: ida_hexrays.mba_t) -> int:
        """
        Performs dataflow analysis and then rewrites the function.

        This function uses a fixed-point iteration strategy for rewriting. This is
        the standard, safe way to handle optimizers that can delete or replace
        the instruction being worked on (e.g., via `optimize_solo`), which
        invalidates simple instruction list iterators.

        If Cython is enabled and available, delegates to a highly optimized
        Cython implementation for better performance.
        """
        if not self.cython_enabled:
            # Fallback to the slower, pure-Python implementation if Cython is disabled
            return self._slow_run_on_function(mba)

        try:
            from . import _fast_dataflow

            total_changes = _fast_dataflow.cy_run_full_pass(mba)
        except (ImportError, AttributeError, TypeError):
            logger.warning(
                "Cython module `_fast_dataflow` not found. Falling back to slow Python implementation."
            )
            self.cython_enabled = False
            return self._slow_run_on_function(mba)

        if total_changes > 0:
            safe_verify(mba, "rewriting", logger_func=logger.error)

        return total_changes

    def _run_dataflow(self, mba: ida_hexrays.mba_t):
        """Phase A - classic forward data-flow (GEN/KILL)."""
        logger.debug("Running dataflow analysis")
        if self.cython_enabled:
            try:
                from . import _fast_dataflow

                return _fast_dataflow.run_dataflow_cython(mba)
            except (ImportError, AttributeError, TypeError):
                logger.warning(
                    "Cython module `_fast_dataflow` not found. Falling back to slow Python implementation."
                )
                self.cython_enabled = False
        return self._slow_dataflow(mba)

    def _slow_run_on_function(self, mba: ida_hexrays.mba_t) -> int:
        """The pure Python implementation of the analysis and rewrite pass.

        Phase A: Dataflow analysis to find where constants are known at the
        start of each block.

        Phase B: Iterate over each block and apply optimizations until the
        block is stable (reaches a fixed point).
        """
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "[FCP] _slow_run_on_function: %d blocks, maturity=%d (%s)",
                mba.qty,
                mba.maturity,
                maturity_to_string(mba.maturity),
            )
        IN, _ = self._slow_dataflow(mba)
        if not IN:
            return 0

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
                        "[forward-cprop] constant map before blk %d: %s",
                        curr_blk.serial,
                        consts,
                    )

                made_change_this_pass = False
                ins = curr_blk.head
                while ins:
                    # Attempt to rewrite the current instruction.
                    if self._slow_rewrite_instruction(mba, ins, consts) > 0:
                        total_changes += 1
                        made_change_this_pass = True
                        block_was_changed = True
                        # A destructive change was made. The instruction list
                        # is now potentially invalid. We must break this inner
                        # loop and restart the scan from the block's head.
                        break

                    # If no rewrite happened, update the local constant map
                    # with the effects of the current instruction.
                    self._slow_transfer_single(mba, ins, consts)
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
        return total_changes

    # ------------------------------------------------------------------
    # Phase B - rewrite helpers
    # ------------------------------------------------------------------

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
        """Transfer function for a single instruction (GEN/KILL)."""
        if self.cython_enabled:
            self._fast_transfer_single(mba, ins, env)
        else:
            self._slow_transfer_single(mba, ins, env)

    def _fast_rewrite_instruction(
        self, mba: ida_hexrays.mba_t, ins: ida_hexrays.minsn_t, env: ConstMap
    ) -> int:
        try:
            from . import _fast_dataflow

            if ins.opcode not in self.ALLOW_PROPAGATION_OPCODES:
                return 0

            return _fast_dataflow.cy_rewrite_instruction(ins, env)
        except (ImportError, AttributeError, TypeError):
            logger.warning(
                "Cython module `_fast_dataflow` not available. Falling back to slow rewrite."
            )
            self.cython_enabled = False
            return self._slow_rewrite_instruction(mba, ins, env)

    def _fast_transfer_single(
        self, mba: ida_hexrays.mba_t, ins: ida_hexrays.minsn_t, env: ConstMap
    ):
        try:
            from . import _fast_dataflow

            # Side-effects handling - for *imprecise* side-effecting instructions
            # (e.g. calls) we must drop every tracked constant.
            if ins.is_unknown_call():
                env.clear()
                return
            written_var = _fast_dataflow.cy_get_written_var_name(ins)
            is_const_assign = _fast_dataflow.cy_is_constant_stack_assignment(ins)
            # KILL when variable overwritten by non-constant value
            if written_var and not is_const_assign and written_var in env:
                del env[written_var]
            # GEN - introduce new constant
            if is_const_assign:
                res = _fast_dataflow.cy_extract_assignment(ins)
                if res:
                    var, val_size = res
                    if var:
                        env[var] = val_size
        except (ImportError, AttributeError, TypeError):
            logger.warning(
                "Cython module `_fast_dataflow` not available. Falling back to slow transfer."
            )
            self.cython_enabled = False
            self._slow_transfer_single(mba, ins, env)

    def _slow_dataflow(self, mba: ida_hexrays.mba_t):
        nb = mba.qty
        block_serials = list(range(nb))
        IN: dict[int, ConstMap] = {i: {} for i in block_serials}
        OUT: dict[int, ConstMap] = {i: {} for i in block_serials}

        # Collect universe: all variable names written anywhere in the function
        universe = self._collect_universe(mba)

        # Entry block IN: all TOP (unknown initial values at function entry)
        # All other blocks: empty (missing = BOTTOM = identity for meet)
        entry_serial = 0  # IDA entry block is always serial 0
        IN[entry_serial] = {var: TOP for var in universe}

        # Start worklist from entry only — unreachable blocks stay BOTTOM
        worklist: list[int] = [entry_serial]

        preds: dict[int, list[int]] = {
            i: list(mba.get_mblock(i).predset) for i in block_serials
        }
        iteration = 0
        while worklist:
            iteration += 1
            idx = worklist.pop()
            inm = self._meet([OUT[p] for p in preds[idx]]) if preds[idx] else {}
            if logger.isEnabledFor(logging.DEBUG):
                total_vars = sum(len(v) for v in IN.values())
                logger.debug(
                    "[FCP] dataflow iteration %d: worklist=%d blk=%d %d vars in constant map",
                    iteration,
                    len(worklist),
                    idx,
                    total_vars,
                )
            if inm != IN[idx]:
                IN[idx] = inm
            out_new = self._transfer_block(mba.get_mblock(idx), inm)
            if out_new != OUT[idx]:
                OUT[idx] = out_new
                for succ in mba.get_mblock(idx).succset:
                    if succ not in worklist:
                        worklist.append(succ)
        return IN, OUT

    # meet delegates to the injected MeetStrategy
    def _meet(self, pred_outs: list[ConstMap]) -> ConstMap:
        """Delegate meet computation to the configured MeetStrategy.

        The default strategy (IntersectionMeet) is sound at all CFG merge
        points.  Callers may inject UnionKillMeet for a more aggressive pass
        in post-apply contexts where the CFG is effectively linearized.
        """
        result = self._meet_strategy.meet(pred_outs)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "[FCP] meet: %d predecessors -> %d vars in result",
                len(pred_outs),
                len(result),
            )
        return result

    # transfer over whole block
    def _transfer_block(self, blk: ida_hexrays.mblock_t, in_map: ConstMap) -> ConstMap:
        env = dict(in_map)
        ins = blk.head
        mba = blk.mba
        while ins:
            self._slow_transfer_single(mba, ins, env)
            ins = ins.next
        return env

    # transfer for a single instruction (GEN/KILL)
    def _slow_transfer_single(
        self,
        mba: ida_hexrays.mba_t,
        ins: ida_hexrays.minsn_t,
        env: ConstMap,
    ):
        # 1. Side-effects handling - for *imprecise* side-effecting instructions
        # (e.g. calls) we must drop every tracked constant.
        #
        # A plain store (stx) is a *precise* write that we interpret below,
        # so we exclude it from the blanket kill.
        #
        # Known pure helpers (ROL/ROR) are m_call with mop_h operand but have
        # no observable side effects on memory/stack — skip the blanket kill.
        if (ins.opcode == ida_hexrays.m_call
                and ins.l is not None
                and ins.l.t == ida_hexrays.mop_h):
            helper_name: str = ins.l.helper
            if helper_name.startswith(("__ROL", "__ROR")):
                return  # pure helper — preserve env
        if ins.has_side_effects() and ins.opcode != ida_hexrays.m_stx:
            for k in list(env):
                env[k] = TOP
            # Nothing more to learn from this instruction.
            return

        # 2. ldx is a memory load — check if it loads from a readonly segment.
        # If so, GEN the constant value; otherwise KILL the destination.
        if ins.opcode == ida_hexrays.m_ldx:
            written_var = self._get_written_var_name(ins)
            readonly_val = self._try_resolve_readonly_ldx(ins)
            if readonly_val is not None and written_var:
                value, size = readonly_val
                env[written_var] = Const(value, size)  # GEN: readonly constant
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "[forward-cprop] readonly ldx at %#x -> %s = %r",
                        ins.ea, written_var, env[written_var],
                    )
                return
            # Writable or unresolvable: KILL
            if written_var:
                env[written_var] = TOP
            return

        # 3. Determine written variable & apply precise KILL / GEN.
        written_var = self._get_written_var_name(ins)
        is_const_assign = self._is_constant_stack_assignment(ins)

        # KILL stack var when overwritten by non-constant value
        if written_var and not is_const_assign:
            env[written_var] = TOP

        # 3. GEN stack var constant
        if is_const_assign:
            res = self._extract_assignment(ins)
            if res and res[0]:
                var_name, (value, size) = res[0], res[1]
                env[var_name] = Const(value, size)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "[FCP] transfer: blk=? ins_ea=0x%x gen %s = %r",
                        ins.ea,
                        var_name,
                        env[var_name],
                    )

    def _slow_rewrite_instruction(
        self,
        mba: ida_hexrays.mba_t,
        ins: ida_hexrays.minsn_t,
        env: ConstMap,
    ) -> int:
        if ins.opcode not in self.ALLOW_PROPAGATION_OPCODES:
            return 0
        # ldx is a memory load: we must NOT fold the address computation into
        # the destination as if it were the loaded value.  The address is an
        # *input* to the load, not the result.
        if ins.opcode == ida_hexrays.m_ldx:
            return 0

        # We must process one operand, and if it changes, optimize and exit
        # immediately. Calling `optimize_solo()` can invalidate the `ins`
        # object, so we cannot continue to access its other operands like
        # `ins.r`.
        changed = False
        # left operand
        if ins.l and self._slow_process_operand(ins.l, env):
            changed = True
        # right operand for binary ops
        if ins.r and self._slow_process_operand(ins.r, env):
            changed = True
        # stx destination address is also an input
        if (
            ins.opcode == ida_hexrays.m_stx
            and ins.d
            and self._slow_process_operand(ins.d, env)
        ):
            changed = True
        # m_call: args are in ins.d (mop_f); substitute constants into them
        if (
            ins.opcode == ida_hexrays.m_call
            and ins.d
            and self._slow_process_operand(ins.d, env)
        ):
            changed = True
        if not changed:
            return 0
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "[FCP] rewrite: ea=0x%x opcode=%d (substitution applied)",
                ins.ea,
                ins.opcode,
            )
        # Ensure the instruction is internally consistent after we rewrote its operands.
        ins.optimize_solo()
        return 1

    def _slow_process_operand(
        self, op: ida_hexrays.mop_t, consts: ConstMap
    ) -> bool:
        changed = False
        if op.t == ida_hexrays.mop_S:
            name = get_stack_var_name(op)
            if name:
                lv = consts.get(name, BOTTOM)
                if not isinstance(lv, Const):
                    return False  # skip TOP and BOTTOM
                val, size = lv.value, lv.size
                if op.size not in _VALID_MOP_SIZES:
                    logger.warning(
                        "Skipping constprop rewrite: invalid op.size %d for var %s",
                        op.size, name,
                    )
                    return False
                op.make_number(val & ((1 << (op.size * 8)) - 1), op.size)
                return True
        elif op.t == ida_hexrays.mop_f and op.f is not None:
            for a in op.f.args:
                if a and self._slow_process_operand(a, consts):
                    changed = True
        elif op.t == ida_hexrays.mop_d and op.d is not None:
            if op.d.opcode == ida_hexrays.m_ldx:
                addr = op.d.r
                lv_info: LatticeValue = BOTTOM
                if addr and addr.t == ida_hexrays.mop_S:
                    name = get_stack_var_name(addr)
                    if name:
                        lv_info = consts.get(name, BOTTOM)
                else:
                    base, off = extract_base_and_offset(addr)
                    if base:
                        base_name = get_stack_var_name(base)
                        name = f"{base_name}+{off:X}" if off else base_name
                        if name:
                            lv_info = consts.get(name, BOTTOM)
                if isinstance(lv_info, Const):
                    val = lv_info.value
                    if op.size not in _VALID_MOP_SIZES:
                        logger.warning(
                            "Skipping constprop ldx rewrite: invalid op.size %d",
                            op.size,
                        )
                        return False
                    tmp = ida_hexrays.mop_t()
                    tmp.make_number(val & AND_TABLE[op.size], op.size)
                    op.assign(tmp)
                    return True
            for attr in ("l", "r", "d"):
                sub = getattr(op.d, attr, None)
                if sub and self._slow_process_operand(sub, consts):
                    changed = True
            if changed:
                op.d.optimize_solo()
        return changed

    # ------------------------------------------------------------------
    # Helper utilities
    # ------------------------------------------------------------------

    def _try_resolve_readonly_ldx(
        self, ins: ida_hexrays.minsn_t
    ) -> typing.Optional[tuple[int, int]]:
        """Try to resolve an ldx instruction as a load from a readonly segment.

        Reconstructs the effective address from the ldx operands (supporting
        the same ``ldx  &sym, #off`` and ``ldx  $global_var, #off`` patterns
        as FoldReadonlyDataRule).  If the address falls in a read-only segment,
        reads the constant value there and returns ``(value, size)``.

        Returns None if the address cannot be determined, is not readonly, or
        the value cannot be read.
        """
        if ins.opcode != ida_hexrays.m_ldx:
            return None

        try:
            ea: typing.Optional[int] = None

            # Variant A: ldx  &sym , #off  (mop_S left, mop_n right)
            if ins.l.t == ida_hexrays.mop_S and ins.r.t == ida_hexrays.mop_n:
                base = ins.l.s.start_ea
                off = ins.r.nnn.value
                ea = base + off

            # Variant B: ldx  $global_var , #off  (mop_v left, mop_n right)
            elif ins.l.t == ida_hexrays.mop_v and ins.r.t == ida_hexrays.mop_n:
                base = ins.l.g
                off = ins.r.nnn.value
                ea = base + off

            # Variant C: ldx  $global_var , <pure-const-expr>
            elif ins.l.t == ida_hexrays.mop_v and ins.r.t == ida_hexrays.mop_d:
                from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
                    _try_eval_pure_const_mop,
                )
                off = _try_eval_pure_const_mop(ins.r)
                if off is not None:
                    ea = ins.l.g + off

            # Variant D: ldx  &sym , <pure-const-expr>
            elif ins.l.t == ida_hexrays.mop_S and ins.r.t == ida_hexrays.mop_d:
                from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
                    _try_eval_pure_const_mop,
                )
                off = _try_eval_pure_const_mop(ins.r)
                if off is not None:
                    ea = ins.l.s.start_ea + off

            if ea is None:
                return None

            if not _ro_segment_is_read_only(ea):
                return None

            size = ins.d.size if (ins.d and ins.d.size) else ins.l.size
            if not size:
                return None

            value = _ro_fetch_constant(ea, size)
            if value is None:
                return None

            return (value, size)

        except Exception:
            return None

    def _collect_universe(self, mba: ida_hexrays.mba_t) -> set[str]:
        """Collect all variable names that are written in any block.

        This defines the universe of tracked variables for the lattice.
        Only variables with at least one definition need tracking.
        """
        universe: set[str] = set()
        for blk_idx in range(mba.qty):
            blk = mba.get_mblock(blk_idx)
            ins = blk.head
            while ins:
                dest_name = self._get_written_var_name(ins)
                if dest_name is not None:
                    universe.add(dest_name)
                ins = ins.next
        return universe

    # identify destination variable of an instruction (None if unknown)
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


# Backwards-compatibility alias so existing configs that reference the old name
# still load without error during any transition period.
StackVariableConstantPropagationRule = ForwardConstantPropagationRule
