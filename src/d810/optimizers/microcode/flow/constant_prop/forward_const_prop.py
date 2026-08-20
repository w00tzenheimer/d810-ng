"""Global forward constant-propagation of stack / frame variables and registers.

This pass is a *function-level* optimisation implemented as a
``FlowOptimizationRule`` (triggered by ``BlockOptimizerManager``).
It performs a forward data-flow analysis to discover stack variables
and registers that hold a *unique* constant along every path and folds
those constants back into the micro-code.

Compared with the former peephole rule this implementation is
function-wide and therefore safe at control-flow merge points.
"""

from __future__ import annotations

import weakref

import idaapi
import ida_hexrays

from d810.core import CythonMode, getLogger, typing
from d810.evaluator.hexrays_microcode.forward_dataflow import (
    FixpointDidNotConverge,
    build_constant_entry_state,
    run_forward_fixpoint_on_mba,
)
from d810.evaluator.hexrays_microcode.dynamic_state_write_backend import (
    recognize_derived_xor_dispatcher_models,
)
from d810.hexrays.ir.mop_utils import _VALID_MOP_SIZES
from d810.hexrays.ir.mop_utils import extract_base_and_offset
from d810.hexrays.ir.mop_utils import constant_propagation_var_name
from d810.hexrays.ir.mop_utils import safe_make_number
from d810.hexrays.mutation.cfg_verify import safe_verify
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.optimizers.microcode.flow.handler import (
    FlowOptimizationRule,
    FlowRulePriority,
)
from d810.optimizers.microcode.handler import ConfigParam
from d810.ir.lattice import (
    BOTTOM,
    TOP,
    Const,
    LatticeEnv,
    LatticeMeet,
    LatticeValue,
)

logger = getLogger(__name__)

ConstMap = LatticeEnv  # backward-compat alias

# Opcodes where the right operand (shift amount) must be size == 1.
# Folding a constant into ins.r with a larger size triggers INTERR 50835.
_SHIFT_OPCODES = frozenset({ida_hexrays.m_shl, ida_hexrays.m_shr, ida_hexrays.m_sar})


@typing.runtime_checkable
class MeetStrategy(typing.Protocol):
    """Strategy for combining predecessor OUT maps at CFG merge points."""

    def meet(self, pred_outs: list[ConstMap]) -> ConstMap:
        """Return the combined constant map for the given predecessor OUT maps."""
        ...


class ForwardConstantPropagationRule(FlowOptimizationRule):
    """Forward constant propagation for stack variables and registers (whole function)."""

    CATEGORY = "Constant Propagation"
    PRIORITY = FlowRulePriority.PREPARE_CONSTANTS
    CONFIG_SCHEMA = FlowOptimizationRule.CONFIG_SCHEMA + (
        ConfigParam(
            "cython_enabled", bool, False, "Use Cython fast path for propagation"
        ),
        ConfigParam(
            "sccp_overlay",
            str,
            "auto",
            "SCCP overlay policy",
            choices=("on", "off", "auto"),
        ),
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
        # Conditional jumps read l/r as comparison operands.  Their d operand
        # is a block target and is deliberately never processed below.
        ida_hexrays.m_jnz,
        ida_hexrays.m_jz,
        ida_hexrays.m_call,
    }

    def __init__(self, meet_strategy: MeetStrategy | None = None):
        super().__init__()
        self.maturities = [
            ida_hexrays.MMAT_CALLS,
            getattr(ida_hexrays, "MMAT_GLBOPT1", ida_hexrays.MMAT_CALLS),
            getattr(ida_hexrays, "MMAT_GLBOPT2", ida_hexrays.MMAT_CALLS),
            ida_hexrays.MMAT_GLBOPT3,
        ]
        self._seen: weakref.WeakKeyDictionary = (
            weakref.WeakKeyDictionary()
        )  # mba -> (maturity, generation)
        self.cython_enabled = CythonMode().is_enabled()
        self.sccp_overlay = "auto"
        self._meet_strategy: MeetStrategy = meet_strategy or LatticeMeet(
            default_missing=TOP
        )
        self._derived_xor_owned_mbas: weakref.WeakKeyDictionary = (
            weakref.WeakKeyDictionary()
        )
        self._derived_xor_owned_functions: set[int] = set()

    @typing.override
    def configure(self, kwargs):
        super().configure(kwargs)
        self.cython_enabled = kwargs.get("cython_enabled", CythonMode().is_enabled())
        self.sccp_overlay = kwargs.get("sccp_overlay", "auto")
        if self.sccp_overlay not in ("on", "off", "auto"):
            raise ValueError("sccp_overlay must be one of: on, off, auto")

    @typing.override
    def optimize(self, blk: ida_hexrays.mblock_t):
        if logger.debug_on:
            logger.debug(
                "[FCP] optimize() called at maturity=%s blk=%d",
                maturity_to_string(blk.mba.maturity) if blk.mba else "?",
                blk.serial,
            )
        if self.current_maturity not in self.maturities:
            if logger.debug_on:
                logger.debug(
                    "maturity is %s, expecting one of: %s",
                    maturity_to_string(self.current_maturity),
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

        func_ea = self._mba_function_ea(mba)
        if self._derived_xor_owned_mbas.get(mba) or (
            func_ea is not None and func_ea in self._derived_xor_owned_functions
        ):
            logger.info(
                "Skipping %s for previously recognized derived-XOR dispatcher-owned function",
                self.__class__.__name__,
            )
            self._seen[mba] = (
                self.current_maturity,
                self.current_generation,
            )
            return 0
        if recognize_derived_xor_dispatcher_models(mba=mba):
            self._derived_xor_owned_mbas[mba] = True
            if func_ea is not None:
                self._derived_xor_owned_functions.add(func_ea)
            logger.info(
                "Skipping %s for derived-XOR dispatcher-owned function",
                self.__class__.__name__,
            )
            self._seen[mba] = (
                self.current_maturity,
                self.current_generation,
            )
            return 0
        # Gate: skip FCP at MMAT_CALLS for UNKNOWN-dispatcher functions.
        # At this early maturity the dispatcher CFG is unresolved, so FCP
        # sees single-predecessor return blocks and folds dispatcher-state
        # constants (e.g. 0xffffffff) into the return register before
        # FakeJump/Hodur can reconstruct the real control flow.
        # TABLE/switch and CONDITION_CHAIN dispatchers are FCP-safe.
        if (
            self.flow_context is not None
            and self.current_maturity == ida_hexrays.MMAT_CALLS
        ):
            gate = self.flow_context.evaluate_early_fcp_gate()
            if gate.allowed:
                if logger.debug_on:
                    logger.debug(
                        "Skipping %s at MMAT_CALLS for unflatten-eligible function: %s",
                        self.__class__.__name__,
                        gate.reason,
                    )
                self._seen[mba] = (
                    self.current_maturity,
                    self.current_generation,
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
        self._seen[mba] = (
            self.current_maturity,
            self.current_generation,
        )  # remember we've run
        return nb_changes

    @staticmethod
    def _mba_function_ea(mba: ida_hexrays.mba_t) -> typing.Optional[int]:
        """Return a stable function identity for cross-maturity ownership gates."""
        for attr_name in ("entry_ea", "maturity_entry_ea"):
            try:
                value = int(getattr(mba, attr_name, 0) or 0)
            except Exception:
                continue
            if value not in (0, int(getattr(idaapi, "BADADDR", -1))):
                return value
        try:
            entry_blk = mba.get_mblock(0)
            if entry_blk is not None:
                value = int(getattr(entry_blk, "start", 0) or 0)
                if value not in (0, int(getattr(idaapi, "BADADDR", -1))):
                    return value
        except Exception:
            pass
        return None

    def _run_on_function(self, mba: ida_hexrays.mba_t) -> int:
        """
        Performs dataflow analysis and then rewrites the function.

        This function uses a fixed-point iteration strategy for rewriting. This is
        the standard, safe way to handle optimizers that can delete or replace
        the instruction being worked on (e.g., via `optimize_solo`), which
        invalidates simple instruction list iterators.

        If Cython is enabled and available, delegates to a highly optimized
        Cython implementation for better performance only when the explicit
        SCCP policy does not require the shared rewrite path.  A requested
        overlay must be merged by ``_slow_run_on_function``; the Cython full
        pass has no SCCP overlay seam and therefore cannot authorize that
        route.
        """
        # Demand is an invocation-local decision.  In particular, do not let
        # the shared path rescan the MBA after classic dataflow has run: the
        # legacy Cython pass and the overlay path must make the same routing
        # decision for this invocation.
        if self.sccp_overlay == "auto":
            sccp_demand = self._sccp_demand_present(mba)
        elif self.sccp_overlay == "on":
            sccp_demand = True
        elif self.sccp_overlay == "off":
            sccp_demand = False
        else:
            # ``configure`` rejects unknown values, but direct assignment must
            # remain fail-closed and use the shared overlay seam.
            sccp_demand = True

        if not self.cython_enabled:
            # Fallback to the slower, pure-Python implementation if Cython is disabled.
            return self._slow_run_on_function(mba, sccp_demand=sccp_demand)

        # The Cython full pass is deliberately limited to the paths that do
        # not request an SCCP overlay.  In particular, ``on`` and
        # ``auto``-with-demand must use the shared slow path even when the
        # extension is available.
        if self.sccp_overlay == "off" or (
            self.sccp_overlay == "auto" and not sccp_demand
        ):
            try:
                total_changes = self._run_cython_full_pass(mba)
            except (ImportError, AttributeError, TypeError):
                logger.warning(
                    "Cython module `_fast_dataflow` not found. Falling back to slow Python implementation."
                )
                self.cython_enabled = False
                return self._slow_run_on_function(mba, sccp_demand=sccp_demand)

            if total_changes > 0:
                safe_verify(mba, "rewriting", logger_func=logger.error)

            return total_changes

        # Unknown policy values are fail-closed here as well.  ``configure``
        # rejects them, but a direct attribute assignment must not silently
        # authorize the overlay-free Cython path.
        return self._slow_run_on_function(mba, sccp_demand=sccp_demand)

    def _run_cython_full_pass(self, mba: ida_hexrays.mba_t) -> int:
        """Run the overlay-free Cython dataflow/rewrite pass."""
        from d810.analyses.data_flow.constant_prop_dataflow import _fast_dataflow

        return _fast_dataflow.cy_run_full_pass(mba)

    def _run_dataflow(self, mba: ida_hexrays.mba_t):
        """Phase A - classic forward data-flow (GEN/KILL)."""
        logger.debug("Running dataflow analysis")
        if self.cython_enabled:
            try:
                from d810.analyses.data_flow.constant_prop_dataflow import (
                    _fast_dataflow,
                )

                return _fast_dataflow.run_dataflow_cython(mba)
            except (ImportError, AttributeError, TypeError):
                logger.warning(
                    "Cython module `_fast_dataflow` not found. Falling back to slow Python implementation."
                )
                self.cython_enabled = False
        return self._slow_dataflow(mba)

    def _slow_run_on_function(
        self,
        mba: ida_hexrays.mba_t,
        *,
        sccp_demand: bool | None = None,
    ) -> int:
        """The pure Python implementation of the analysis and rewrite pass.

        Phase A: Dataflow analysis to find where constants are known at the
        start of each block.

        Phase B: Iterate over each block and apply optimizations until the
        block is stable (reaches a fixed point).
        """
        if logger.debug_on:
            logger.debug(
                "[FCP] _slow_run_on_function: %d blocks, maturity=%s",
                mba.qty,
                maturity_to_string(mba.maturity),
            )
        IN, _ = self._slow_dataflow(mba)
        if not IN:
            return 0

        # Try SCCP for MBA-aware constants only after the classic fixpoint
        # completed successfully.  ``_get_sccp_overlay`` returns an empty
        # mapping for every unavailable or non-converged result, preserving
        # the proof boundary before any rewrite scan starts.
        sccp_overlay = self._requested_sccp_overlay(
            mba,
            IN,
            sccp_demand=sccp_demand,
        )

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

                # Merge SCCP-discovered constants into the local const map
                if sccp_overlay:
                    self._merge_sccp_into_constmap(consts, sccp_overlay, curr_blk)

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

        # NOTE: Do NOT call mba.optimize_local(0) here.
        # When running inside optblock_t callback, calling optimize_local re-enters
        # IDA's optimizer pipeline causing INTERR 50835 (shift operand size verification
        # failure on partially-transformed MBA).
        # IDA automatically re-runs optimization when optblock_t.func returns non-zero.
        # When running from _post_apply_instruction_sweep, the sweep handles
        # mark_chains_dirty() + optimize_local(0) between generations.
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
            from d810.analyses.data_flow.constant_prop_dataflow import (
                _fast_dataflow,
            )

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
            from d810.analyses.data_flow.constant_prop_dataflow import (
                _fast_dataflow,
            )

            # Side-effects handling - for *imprecise* side-effecting instructions
            # (e.g. calls) we must drop every tracked constant.
            if ins.is_unknown_call():
                for k in list(env):
                    env[k] = TOP
                return
            written_var = _fast_dataflow.cy_get_written_var_name(ins)
            is_const_assign = _fast_dataflow.cy_is_constant_stack_assignment(ins)
            # KILL when variable overwritten by non-constant value
            if written_var and not is_const_assign:
                env[written_var] = TOP
            # GEN - introduce new constant
            if is_const_assign:
                res = _fast_dataflow.cy_extract_assignment(ins)
                if res:
                    var, val_size = res
                    if var:
                        env[var] = Const(val_size[0], val_size[1])
        except (ImportError, AttributeError, TypeError):
            logger.warning(
                "Cython module `_fast_dataflow` not available. Falling back to slow transfer."
            )
            self.cython_enabled = False
            self._slow_transfer_single(mba, ins, env)

    def _slow_dataflow(self, mba: ida_hexrays.mba_t):
        entry_state = build_constant_entry_state(mba)

        def transfer(serial: int, in_state: ConstMap) -> ConstMap:
            blk = mba.get_mblock(serial)
            return self._transfer_block(blk, in_state)

        # Soundness gate: pass raise_on_nonconvergence=True so a partial
        # fixpoint surfaces as FixpointDidNotConverge rather than feeding
        # partial constants into the constant-propagation rewriter.  The
        # caller ``_slow_run_on_function`` already treats empty IN as "no
        # work to do" via ``if not IN: return 0``, so returning empty
        # dicts on non-convergence skips the optimization safely.
        try:
            result = run_forward_fixpoint_on_mba(
                mba,
                entry_state=entry_state,
                bottom={},
                meet=self._meet_strategy.meet,
                transfer=transfer,
                raise_on_nonconvergence=True,
            )
        except FixpointDidNotConverge as exc:
            logger.warning(
                "ForwardConstantPropagation: dataflow fixpoint did not "
                "converge in %d iterations (max=%d); skipping rewrite "
                "pass for this function",
                exc.iterations,
                exc.max_iterations,
            )
            return {}, {}
        return result.in_states, result.out_states

    def _get_sccp_overlay(self, mba: ida_hexrays.mba_t) -> typing.Optional[dict]:
        """Run SCCP and return flat lattice, or None if unavailable."""
        try:
            from d810.evaluator.hexrays_microcode.sccp import run_sccp

            result = run_sccp(mba)
            if result:
                n_consts = sum(1 for v in result.values() if v is not None)
                if logger.debug_on:
                    logger.debug(
                        "[FCP] SCCP overlay: %d constants discovered", n_consts
                    )
                return result if n_consts > 0 else None
            return None
        except Exception:
            return None

    def _requested_sccp_overlay(
        self,
        mba: ida_hexrays.mba_t,
        consts_by_block: dict,
        *,
        sccp_demand: bool | None = None,
    ) -> typing.Optional[dict]:
        """Return an SCCP overlay when the configured policy requests one.

        ``consts_by_block`` is intentionally accepted at this boundary even
        though demand discovery is conservative today.  The classic fixpoint
        has already succeeded when this method is called; retaining that
        explicit input keeps the ordering contract visible to future demand
        refinements without letting the overlay run before the soundness gate.
        """
        del consts_by_block
        if self.sccp_overlay == "off":
            return None
        if self.sccp_overlay == "auto":
            if sccp_demand is None:
                sccp_demand = self._sccp_demand_present(mba)
            if not sccp_demand:
                return None
        # Unknown values are fail-closed: configure() rejects them, while a
        # direct assignment still takes the shared path rather than silently
        # authorizing the overlay-free Cython pass.
        return self._get_sccp_overlay(mba)

    def _sccp_demand_present(self, mba: ida_hexrays.mba_t) -> bool:
        """Conservatively detect supported unresolved operands without SCCP.

        The scan is read-only.  Any malformed live object, missing field, or
        cyclic instruction chain demands the shared path, because a false
        negative would let the overlay-free Cython pass bypass SCCP.
        """

        def known_int_constants(prefix: str) -> frozenset[int]:
            try:
                return frozenset(
                    value
                    for name in dir(ida_hexrays)
                    if name.startswith(prefix)
                    and isinstance(value := getattr(ida_hexrays, name), int)
                )
            except Exception:
                # A broken IDA module surface must never authorize the
                # overlay-free Cython pass.
                return frozenset()

        known_mop_types = known_int_constants("mop_")
        known_opcodes = known_int_constants("m_")

        def scan_instruction(ins: object, seen_instructions: set[int]) -> bool:
            marker = id(ins)
            if marker in seen_instructions:
                return True
            seen_instructions.add(marker)
            try:
                opcode = int(ins.opcode)
            except Exception:
                return True
            if opcode not in known_opcodes:
                return True
            seen_operands: set[int] = set()
            for attr in ("l", "r"):
                try:
                    op = getattr(ins, attr)
                except Exception:
                    return True
                if scan_operand(op, seen_operands, seen_instructions):
                    return True
            return False

        def scan_operand(
            op: object,
            seen_operands: set[int],
            seen_instructions: set[int],
        ) -> bool:
            if op is None:
                return True
            marker = id(op)
            if marker in seen_operands:
                return True
            seen_operands.add(marker)
            try:
                op_type = op.t
            except Exception:
                return True
            if op_type in (ida_hexrays.mop_S, ida_hexrays.mop_r):
                return True
            if op_type == ida_hexrays.mop_d:
                try:
                    sub_ins = op.d
                except Exception:
                    return True
                if sub_ins is None:
                    return True
                return scan_instruction(sub_ins, seen_instructions)
            if op_type == ida_hexrays.mop_f:
                try:
                    callinfo = op.f
                    args = callinfo.args
                except Exception:
                    return True
                if args is None:
                    return True
                try:
                    return any(
                        scan_operand(arg, seen_operands, seen_instructions)
                        for arg in args
                    )
                except Exception:
                    return True
            if op_type not in known_mop_types:
                return True
            return False

        try:
            qty = int(mba.qty)
            if qty < 0:
                return True
            seen_blocks: set[int] = set()
            for block_index in range(qty):
                block = mba.get_mblock(block_index)
                if block is None:
                    return True
                block_marker = id(block)
                if block_marker in seen_blocks:
                    return True
                seen_blocks.add(block_marker)
                try:
                    ins = block.head
                except Exception:
                    return True
                seen_instructions: set[int] = set()
                while ins is not None:
                    if scan_instruction(ins, seen_instructions):
                        return True
                    try:
                        ins = ins.next
                    except Exception:
                        return True
        except Exception:
            return True
        return False

    def _merge_sccp_into_constmap(
        self,
        consts: ConstMap,
        sccp_overlay: dict,
        blk: ida_hexrays.mblock_t,
    ) -> None:
        """Merge SCCP-discovered constants into a block's const map.

        For each operand used in *blk* that SCCP resolved to a constant,
        add the constant to *consts* only when classic GEN/KILL has no fact.
        A classic ``TOP`` is positive evidence that predecessor paths disagree;
        replacing it with an SCCP value would erase that conflict and can make
        a live dispatcher arm appear unreachable.

        The merge scans the block's instructions to find ``mop_S`` / ``mop_r``
        operands, builds the ``mop_key`` for each, and checks the SCCP overlay.
        """
        if not sccp_overlay:
            return
        from d810.hexrays.expr.p_ast import get_mop_key

        ins = blk.head
        while ins:
            for attr in ("l", "r", "d"):
                op = getattr(ins, attr, None)
                if op is None:
                    continue
                if op.t in (ida_hexrays.mop_S, ida_hexrays.mop_r):
                    self._try_sccp_merge_op(consts, sccp_overlay, op, get_mop_key)
                # Also check sub-operands inside mop_d (sub-instruction) and
                # mop_f (call args) at one level of nesting.
                elif op.t == ida_hexrays.mop_d and op.d is not None:
                    for sub_attr in ("l", "r", "d"):
                        sub = getattr(op.d, sub_attr, None)
                        if sub is not None and sub.t in (
                            ida_hexrays.mop_S,
                            ida_hexrays.mop_r,
                        ):
                            self._try_sccp_merge_op(
                                consts, sccp_overlay, sub, get_mop_key
                            )
                elif op.t == ida_hexrays.mop_f and op.f is not None:
                    for a in op.f.args:
                        if a and a.t in (ida_hexrays.mop_S, ida_hexrays.mop_r):
                            self._try_sccp_merge_op(
                                consts, sccp_overlay, a, get_mop_key
                            )
            ins = ins.next

    @staticmethod
    def _try_sccp_merge_op(
        consts: ConstMap,
        sccp_overlay: dict,
        op: ida_hexrays.mop_t,
        get_mop_key: typing.Callable,
    ) -> None:
        """Merge a single SCCP-resolved operand into *consts* if beneficial."""
        key = get_mop_key(op)
        sccp_val = sccp_overlay.get(key)
        if sccp_val is None:
            return  # SCCP has TOP/BOTTOM for this var — nothing to add
        name = constant_propagation_var_name(op)
        if not name:
            return
        existing = consts.get(name, BOTTOM)
        if existing is not BOTTOM:
            # Preserve both a classic constant and a classic TOP conflict.
            # SCCP is an overlay, not an authority that may contradict the
            # path-complete GEN/KILL lattice.
            return
        consts[name] = Const(sccp_val, op.size)

    # meet delegates to the injected MeetStrategy
    def _meet(self, pred_outs: list[ConstMap]) -> ConstMap:
        """Delegate meet computation to the configured MeetStrategy.

        The default strategy (LatticeMeet) is sound at all CFG merge
        points via lattice join semantics.
        """
        result = self._meet_strategy.meet(pred_outs)
        if logger.debug_on:
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
        if (
            ins.opcode == ida_hexrays.m_call
            and ins.l is not None
            and ins.l.t == ida_hexrays.mop_h
        ):
            helper_name: str = ins.l.helper
            if helper_name.startswith(("__ROL", "__ROR")):
                return  # pure helper — preserve env
        if ins.has_side_effects() and ins.opcode != ida_hexrays.m_stx:
            for k in list(env):
                env[k] = TOP
            # Nothing more to learn from this instruction.
            return

        # 2. Memory resolution belongs to the preceding constant-memory stage.
        # Any ldx still present is unresolved here, so FCP must conservatively
        # KILL its destination rather than maintain a second constness policy.
        if ins.opcode == ida_hexrays.m_ldx:
            written_var = self._get_written_var_name(ins)
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
                if logger.debug_on:
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
        # right operand for binary ops.
        # For shift instructions (m_shl/m_shr/m_sar) the shift-amount operand
        # (ins.r) must have size == 1; IDA's verifier raises INTERR 50835 if it
        # does not.  Pass is_shift_amount=True so _slow_process_operand forces
        # the rewrite size to 1.
        if ins.r and self._slow_process_operand(
            ins.r,
            env,
            is_shift_amount=(ins.opcode in _SHIFT_OPCODES),
        ):
            changed = True
        # Do not fold the destination address of m_stx.  The d operand is a
        # memory address, not a scalar assignment target.  On unresolved
        # dispatcher CFGs, folding a pointer carrier here can turn a shared
        # terminal store into MEMORY[0].
        # m_call: args are in ins.d (mop_f); substitute constants into them
        if (
            ins.opcode == ida_hexrays.m_call
            and ins.d
            and self._slow_process_operand(ins.d, env)
        ):
            changed = True
        if not changed:
            return 0
        if logger.debug_on:
            logger.debug(
                "[FCP] rewrite: ea=0x%x opcode=%d (substitution applied)",
                ins.ea,
                ins.opcode,
            )
        # Ensure the instruction is internally consistent after we rewrote its operands.
        ins.optimize_solo()
        return 1

    def _slow_process_operand(
        self,
        op: ida_hexrays.mop_t,
        consts: ConstMap,
        is_shift_amount: bool = False,
    ) -> bool:
        changed = False
        if op.t == ida_hexrays.mop_S:
            name = constant_propagation_var_name(op)
            if name:
                lv = consts.get(name, BOTTOM)
                if not isinstance(lv, Const):
                    return False  # skip TOP and BOTTOM
                # Stack keys intentionally identify storage rather than a
                # particular mop width.  A narrower read is the low portion
                # of a known wider value; a wider read after a narrow write
                # would manufacture unknown high bytes and is unsound.
                if op.size > lv.size:
                    return False
                val = lv.value
                if op.size not in _VALID_MOP_SIZES:
                    logger.warning(
                        "Skipping constprop rewrite: invalid op.size %d for var %s",
                        op.size,
                        name,
                    )
                    return False
                # Shift instructions require r.size == 1 (INTERR 50835).
                # When folding a constant into the shift-amount operand, force
                # the rewrite size to 1 regardless of what the stack var says.
                rewrite_size = 1 if is_shift_amount else op.size
                safe_make_number(op, val, rewrite_size)
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
                    name = constant_propagation_var_name(addr)
                    if name:
                        lv_info = consts.get(name, BOTTOM)
                else:
                    base, off = extract_base_and_offset(addr)
                    if base:
                        base_name = constant_propagation_var_name(base)
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
                    safe_make_number(tmp, val, op.size)
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
            return constant_propagation_var_name(d)
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
        if (
            ins.opcode == ida_hexrays.m_stx
            and ins.d
            and ins.d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}
        ):
            return True
        return False

    # extract (var,(value,size)) for constant assignment
    def _extract_assignment(self, ins: ida_hexrays.minsn_t):
        if not self._is_constant_stack_assignment(ins):
            return None
        value, size = ins.l.nnn.value, ins.l.size
        var = None
        if ins.opcode == ida_hexrays.m_mov:
            var = constant_propagation_var_name(ins.d)
        elif ins.d.t in {ida_hexrays.mop_S, ida_hexrays.mop_r}:
            var = constant_propagation_var_name(ins.d)
        return (var, (value, size)) if var else None


# Backwards-compatibility alias so existing configs that reference the old name
# still load without error during any transition period.
StackVariableConstantPropagationRule = ForwardConstantPropagationRule
