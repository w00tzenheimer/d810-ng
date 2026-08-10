from __future__ import annotations

from d810.core import typing

"""fold_readonlydata.py

A peephole rule that replaces loads from a *provably read-only* table (typically
located in `.rdata` / `.rodata`) with an immediate load (`ldc`).
It handles two microcode patterns Hex-Rays emits:

1. Direct displacement load (array access)
   ldx  &($sym).8, #off        ***  ldc  #value

2. Direct global variable load (OLLVM opaque table reads)
   mov  $dword_XXXX.4, tmp.4   ***  ldc  #value

By eliminating the table look-up, we unlock many more constant-folding
opportunities in later optimisation stages.
"""

""" TODO:

Add support for indirect load through a temporary register
   mov  &($sym).8, rax.8
   xdu  [ds:(rax.8+#off)].1 ...   ***  ldc  #value
   
def _ea_from_indirect_load(
    self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
) -> Optional[int]:
    # Handle loads where base address is in a register that earlier got
    # its value from   mov &sym -> reg   inside the **same basic block**.
    # Expect operand of the form  [ reg + const ]  in DS segment.
    if ins.l.t != ida_hexrays.mop_b:
        return None
    mop_b = ins.l  # memory operand
    # if mop_b.fpc != ida_hexrays.segm_ds:
    #     return None  # only DS for now
    # Base must be a register (stored as mop_v) and displacement constant.
    if mop_b.b.t != ida_hexrays.mop_v:
        return None
    base_reg = mop_b.b
    if mop_b.i.t != ida_hexrays.mop_n:
        return None
    disp = mop_b.i.nnn.value

    # Look for defining instruction of *base_reg* in the current block.
    if blk is None:
        return None
    def_ins = ida_hexrays.find_defins(blk, ins, base_reg)
    if def_ins is None or def_ins.opcode != ida_hexrays.m_mov:
        return None
    # Must be  mov  &($sym).8, base_reg
    if def_ins.l.t != ida_hexrays.mop_S:
        return None
    base_ea = def_ins.l.s.start_ea
    return base_ea + disp

error:

.text:00000001800066D5 C38 48 8B 05 0E 36 06 00                  mov     rax, cs:_qword_1802D2C99+2                                  ; jumptable 0000000180004869 case 134
.text:00000001800066DC C38 48 89 84 24 00 06 00 00               mov     [rsp+0C38h+var_638], rax
.text:0000000180006B2B C38 48 8B 84 24 00 06 00 00               mov     rax, [rsp+0C38h+var_638]
.text:0000000180006B66 C38 48 89 84 24 A8 05 00 00               mov     [rsp+0C38h+var_690], rax
.text:0000000180006B7E C38 48 8B 84 24 A8 05 00 00               mov     rax, [rsp+0C38h+var_690]
.text:0000000180006B8E C38 48 89 84 24 A0 05 00 00               mov     [rsp+0C38h+var_698], rax
.text:0000000180006BA6 C38 48 8B 84 24 A0 05 00 00               mov     rax, [rsp+0C38h+var_698]
.text:0000000180006BAE C38 48 8B 80 20 03 00 00                  mov     rax, [rax+320h]
.text:0000000180006BB5 C38 48 89 84 24 98 05 00 00               mov     [rsp+0C38h+var_6A0], rax

this becomes: `(__ROL8__(MEMORY[0xB10000007FFE03FD]...)` which is obviously wrong.
"""


from d810.core.typing import Optional

import ida_hexrays
import idaapi
from d810.analyses.value_flow.global_constness import (
    GlobalConstDecision,
    GlobalConstPolicy,
    GlobalConstReason,
)
from d810.backends.hexrays.evidence.dereference_use import (
    value_reaches_dereference,
)
from d810.backends.hexrays.evidence.global_constness import (
    decide_hexrays_global_read,
)
from d810.backends.hexrays.global_const_annotation import (
    annotate_function_global_consts,
    annotate_global_table_access,
    discover_dynamic_global_table_access,
)
from d810.evaluator.evaluators import evaluate_concrete

# Opcodes where the right operand (shift amount) must have size == 1.
# Folding a constant into ins.r with a larger size triggers INTERR 50835.
# Mirrors the same set in forward_const_prop.py.
_SHIFT_OPCODES: frozenset[int] = frozenset(
    {
        ida_hexrays.m_shl,
        ida_hexrays.m_shr,
        ida_hexrays.m_sar,
    }
)

import d810.core.typing as typing
from d810.core import getLogger
from d810.errors import AstEvaluationException
from d810.hexrays.ir.mop_utils import mop_to_ast
from d810.hexrays.utils.hexrays_helpers import extract_literal_from_mop
from d810.optimizers.microcode.constant_materialization import (
    make_ldc_replacement,
    replace_operand_with_immediate,
)
from d810.optimizers.microcode.handler import ConfigParam
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)
from d810.hexrays.ir.number_operand import safe_make_number

peephole_logger = getLogger(__name__)


def _try_eval_pure_const_mop(mop: ida_hexrays.mop_t) -> Optional[int]:
    """Try to evaluate *mop* as a pure-constant expression tree.

    If *mop* is ``mop_n`` (an immediate constant), return its value directly.

    If *mop* is ``mop_d`` (the result of a sub-instruction), convert it to an
    AST via :func:`~d810.hexrays.expr.p_ast.mop_to_ast` and verify that every leaf in
    the tree is a constant.  When that holds, evaluate the tree with an empty
    variable dict (constants evaluate without any variable bindings) and return
    the resulting integer.

    Returns *None* if evaluation is not possible (non-constant leaves, AST
    build failure, or any other error).
    """
    if mop is None:
        return None

    # Fast path: already an immediate constant.
    if mop.t == ida_hexrays.mop_n:
        return mop.nnn.value

    # Only attempt AST evaluation for computed sub-expressions.
    if mop.t != ida_hexrays.mop_d:
        return None

    try:
        ast = mop_to_ast(mop)
        if ast is None:
            return None

        # Verify all leaves are constants — if any leaf is a non-constant
        # (e.g. a register or stack variable), we cannot evaluate statically.
        leaves = ast.get_leaf_list()
        if not leaves:
            return None
        if not all(leaf.is_constant() for leaf in leaves):
            return None

        result = evaluate_concrete(ast, {})
        if result is None:
            return None
        return int(result)
    except (AstEvaluationException, Exception):
        return None


# Operand types that may reference readonly global data.
_READONLY_CANDIDATE_TYPES: frozenset[int] = frozenset(
    {
        ida_hexrays.mop_v,  # Global variable
        ida_hexrays.mop_S,  # Stack/segment variable
        ida_hexrays.mop_d,  # Nested sub-instruction (may contain refs)
        ida_hexrays.mop_b,  # Micro basic block (may contain refs)
    }
)


def _has_potential_readonly_operand(ins) -> bool:
    """Fast check: could this instruction contain a readonly global reference?

    Returns True if any source operand has type mop_v, mop_S, mop_d, or mop_b.
    Pure register/constant/number instructions return False, avoiding the
    expensive clone-and-walk path in _fold_readonly_operands_in_expr().
    """
    for mop in (ins.l, ins.r):
        if mop and mop.t in _READONLY_CANDIDATE_TYPES:
            return True
    return False


class FoldReadonlyDataRule(PeepholeSimplificationRule):
    """Replace constant table look-ups by immediates."""

    CATEGORY = "Constant Folding"
    CONFIG_SCHEMA = PeepholeSimplificationRule.CONFIG_SCHEMA + (
        ConfigParam(
            "fold_writable_constants",
            bool,
            False,
            "Fold from writable segments with no write xrefs",
        ),
        ConfigParam(
            "rva_guard",
            bool,
            True,
            "Veto folds whose value is used as an address (def-use, not shape)",
        ),
        ConfigParam(
            "allow_executable_readonly",
            bool,
            False,
            "VERY DANGEROUS: treat executable read-only memory as constant data",
        ),
        ConfigParam(
            "persist_global_const_annotations",
            bool,
            False,
            "Bundle-owned: persist const types for proven global data items",
        ),
    )

    DESCRIPTION = (
        "Fold constant loads from .rodata array. "
        "Example: Replaces ldx from constant .rodata offset with ldc if value is readable."
    )

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        super().__init__(*args, **kwargs)
        # Run where the IR is stable enough to rewrite `ldx` forms safely.
        # MMAT_PREOPTIMIZED is included so that read-only data constants are
        # folded before MMAT_LOCOPT, enabling MBA pattern recognition to see
        # the simplified form at MMAT_LOCOPT (needed after Layer 1/2 maturity
        # gating was enforced in commits 986204a/c13dda9/500a05e).
        self.maturities = [
            ida_hexrays.MMAT_PREOPTIMIZED,
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
            getattr(ida_hexrays, "MMAT_GLBOPT1", ida_hexrays.MMAT_CALLS),
            getattr(ida_hexrays, "MMAT_GLBOPT3", ida_hexrays.MMAT_CALLS),
        ]
        # Expert escape hatch. Normal classification is architecture-neutral
        # and uses IDA's item metadata rather than platform/section names.
        self._allow_executable: bool = False
        # When True, also fold constants from writable segments that have no
        # write cross-references.  This is needed for hardened OLLVM where
        # opaque constant tables are placed in .data (writable) segments.
        self._fold_writable_constants: bool = False
        self._rva_guard: bool = True
        self._ctx_blk: ida_hexrays.mblock_t | None = None
        self._ctx_ins: ida_hexrays.minsn_t | None = None
        # This is enabled by the public constant-simplification bundle only.
        # Direct/legacy activation of this private rule remains non-persistent.
        self._persist_global_const_annotations: bool = False
        self._annotated_calls_mba_identity: int | None = None
        self._dynamic_annotation_mba_identity: int | None = None
        self._dynamic_annotation_maturity: int | None = None
        self._dynamic_annotation_keys: set[tuple[int, int, int, int]] = set()

    def configure(self, kwargs: dict) -> None:
        """Configure rule from project settings."""
        super().configure(kwargs)
        # Allow configuration via project config:
        # "allow_executable_readonly": true
        self._allow_executable = kwargs.get("allow_executable_readonly", False)
        if self._allow_executable:
            peephole_logger.warning(
                "VERY DANGEROUS constant-folding override enabled: "
                "executable read-only memory may be treated as data"
            )
        # "fold_writable_constants": true
        self._fold_writable_constants = kwargs.get("fold_writable_constants", False)
        # "rva_guard": how the pointer-like veto is answered. True keeps a veto
        # but prefers a def-use "is it dereferenced?" answer over the
        # value-shape guess; False drops the veto. See lpccp-suvl.
        self._rva_guard = bool(kwargs.get("rva_guard", True))
        self._persist_global_const_annotations = kwargs.get(
            "persist_global_const_annotations",
            False,
        )

    def _persist_proven_global_consts(
        self,
        blk: ida_hexrays.mblock_t | None,
        ins: ida_hexrays.minsn_t,
    ) -> None:
        """Persist safe const metadata without affecting rewrite eligibility."""

        if not self._persist_global_const_annotations:
            return
        try:
            mba = None if blk is None else blk.mba
            maturity = -1 if mba is None else int(mba.maturity)
            try:
                mba_identity = None if mba is None else int(mba.this)
            except (AttributeError, TypeError, ValueError):
                mba_identity = None if mba is None else id(mba)
            if maturity != int(ida_hexrays.MMAT_CALLS):
                # A new decompilation reaches earlier maturities before CALLS,
                # so this also makes immediate native-pointer reuse harmless.
                self._annotated_calls_mba_identity = None
            else:
                assert mba is not None
                assert mba_identity is not None
                if self._annotated_calls_mba_identity != mba_identity:
                    self._annotated_calls_mba_identity = mba_identity
                    report = annotate_function_global_consts(int(mba.entry_ea))
                else:
                    report = None
                if report is not None:
                    function_ea = int(mba.entry_ea)
                    for outcome in report.outcomes:
                        peephole_logger.debug(
                            "constant-simplification global annotation "
                            "function=0x%X item=0x%X..0x%X status=%s reason=%s",
                            function_ea,
                            outcome.item_head,
                            outcome.item_end,
                            outcome.status.value,
                            outcome.reason.value,
                        )
                if report is not None and report.changed_count:
                    peephole_logger.info(
                        "constant-simplification updated %d referenced global "
                        "const annotation(s) for function 0x%X",
                        report.changed_count,
                        function_ea,
                    )

            access = discover_dynamic_global_table_access(ins)
            if access is None:
                return
            starts_new_mba = self._dynamic_annotation_mba_identity != mba_identity
            restarts_preoptimized = maturity == int(
                ida_hexrays.MMAT_PREOPTIMIZED
            ) and self._dynamic_annotation_maturity != int(
                ida_hexrays.MMAT_PREOPTIMIZED
            )
            if starts_new_mba or restarts_preoptimized:
                self._dynamic_annotation_keys.clear()
                self._dynamic_annotation_mba_identity = mba_identity
            self._dynamic_annotation_maturity = maturity
            access_key = (
                access.item_head,
                access.item_end,
                access.element_size,
                access.element_count,
            )
            if access_key in self._dynamic_annotation_keys:
                return
            self._dynamic_annotation_keys.add(access_key)
            report = annotate_global_table_access(access)
            outcome = report.outcomes[0]
            peephole_logger.debug(
                "constant-simplification bounded table annotation "
                "instruction=0x%X item=0x%X..0x%X elements=%d width=%d "
                "status=%s reason=%s",
                access.instruction_ea,
                access.item_head,
                access.item_end,
                access.element_count,
                access.element_size,
                outcome.status.value,
                outcome.reason.value,
            )
            if report.changed_count:
                peephole_logger.info(
                    "constant-simplification persisted bounded const table "
                    "0x%X..0x%X (%d x %d-byte elements)",
                    access.item_head,
                    access.item_end,
                    access.element_count,
                    access.element_size,
                )
        except Exception:
            # Persistent metadata is an optional enrichment. A backend/type
            # failure must never abort or change the peephole rewrite itself.
            peephole_logger.debug(
                "constant-simplification could not persist global const metadata",
                exc_info=True,
            )

    # --------------------------------------------------------------------- #
    # Helper functions                                                      #
    # --------------------------------------------------------------------- #

    def _decision_for(
        self,
        addr: int,
        size: int,
        blk: ida_hexrays.mblock_t | None = None,
        ins: ida_hexrays.minsn_t | None = None,
        site: str = "unknown",
    ) -> GlobalConstDecision:
        """Ask the shared, architecture-neutral constness authority.

        ``blk``/``ins`` are optional context for the def-use dereference test.
        The trace needs a built graph, so it runs only when the cheap
        value-shape test would otherwise veto -- it refines that test rather
        than replacing it, keeping the common path free of graph work.
        """
        policy = (
            GlobalConstPolicy.AGGRESSIVE_NO_DIRECT_WRITES
            if self._fold_writable_constants
            else GlobalConstPolicy.STRICT
        )
        if blk is None:
            blk = getattr(self, "_ctx_blk", None)
        if ins is None:
            ins = getattr(self, "_ctx_ins", None)
        reaches: bool | None = None
        if self._rva_guard and (blk is None or ins is None) and peephole_logger.debug_on:
            peephole_logger.debug(
                "constant-simplification fold decision site=%s addr=0x%X: no "
                "instruction context, def-use test skipped",
                site,
                addr,
            )
        if self._rva_guard and blk is not None and ins is not None:
            probe = decide_hexrays_global_read(
                addr,
                size,
                policy=policy,
                allow_executable_readonly=self._allow_executable,
            )
            if probe.reason is GlobalConstReason.POINTER_LIKE_VALUE:
                # Seed with the GLOBAL's address: the test tracks where the
                # loaded value flows structurally, not what the value equals.
                reaches = value_reaches_dereference(blk, ins, address=addr)
        decision = decide_hexrays_global_read(
            addr,
            size,
            policy=policy,
            allow_executable_readonly=self._allow_executable,
            rva_guard=self._rva_guard,
            value_reaches_dereference=reaches,
        )
        # The fold verdict was previously invisible: only the ANNOTATION path
        # logged, and it answers a different question (persistent const), so a
        # dump could not say why a given global did or did not fold.
        if peephole_logger.debug_on:
            peephole_logger.debug(
                "constant-simplification fold decision site=%s addr=0x%X size=%d "
                "policy=%s rva_guard=%s reaches_deref=%s -> inline=%s reason=%s",
                site,
                addr,
                size,
                policy.value,
                self._rva_guard,
                reaches,
                decision.can_inline_read,
                decision.reason.value,
            )
        return decision

    def _is_foldable_address(self, addr: int) -> bool:
        """Compatibility predicate; concrete rewrites use the true read width."""
        return self._decision_for(addr, 1, site="predicate").can_inline_read

    # ------------------------------------------------------------------ #
    # Main peephole implementation                                      #
    # ------------------------------------------------------------------ #

    @typing.override
    def check_and_replace(
        self, blk: ida_hexrays.mblock_t | None, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        """Try to rewrite *ins*.  Return modified instruction or None."""

        self._persist_proven_global_consts(blk, ins)
        # The expression-fold path reaches _decision_for several frames down and
        # cannot thread (blk, ins) through every operand recursion; stash it for
        # the duration of this attempt so the def-use test is available there too.
        self._ctx_blk = blk
        self._ctx_ins = ins

        # Attempt the **direct displacement** form first ------------------ #
        ea = self._ea_from_direct_load(ins)
        if ea is None:
            # ------------------------------------------------------------ #
            # Handle direct global variable loads:                          #
            #   mov  $dword_XXXX.4, tmp.4                                  #
            # where l.t == mop_v (direct global reference).  These appear  #
            # in OLLVM opaque table reads.                                  #
            # ------------------------------------------------------------ #
            ea = self._ea_from_simple_mov_load(ins)

        # TODO(perf): emulator fallback disabled — too slow without caching.
        # Each call instantiates a new MicroCodeInterpreter. For AntiDebug
        # with 160+ byte_TABLE refs, this grinds at 100% CPU for 27+ minutes.
        # Needs per-pass interpreter reuse or expression-level caching.
        # if ea is None:
        #     ea = self._try_emulator_eval_address(ins, blk)

        if ea is None:
            # Quick pre-check: skip instructions that cannot possibly contain
            # a readonly global reference (pure register/constant operands).
            if not _has_potential_readonly_operand(ins):
                return None
            # Try folding readonly globals used as plain values inside
            # expression trees (e.g., nested under mop_d). Do NOT fold top-level
            # mov of addresses (e.g., function pointers / IAT entries) into
            # immediates - that breaks call-site rendering.
            expr_folded = self._fold_readonly_operands_in_expr(ins)
            return expr_folded

        # We have an effective address for a memory load.  Is it really read-only?
        if ea is None:
            return None
        # Compute the immediate value from memory contents at the EA.
        # Use the destination size when available, otherwise try source size.
        load_size = ins.d.size if (ins.d and ins.d.size) else ins.l.size
        if not load_size:
            return None
        decision = self._decision_for(ea, load_size, blk, ins, site="ldc-replace")
        if not decision.can_inline_read or decision.value is None:
            return None
        replacement = make_ldc_replacement(ins, decision.value, load_size)
        if peephole_logger.debug_on:
            peephole_logger.debug(
                "constant-simplification fold APPLIED site=ldc-replace addr=0x%X "
                "size=%d value=0x%X -> replacement=%s",
                ea,
                load_size,
                decision.value,
                "yes" if replacement is not None else "NONE",
            )
        return replacement

    # ------------------------------------------------------------------ #
    # EA reconstruction helpers                                           #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _ea_from_direct_load(ins: ida_hexrays.minsn_t) -> Optional[int]:
        """Reconstruct EA for the common direct-displacement variants Hex-Rays
        can emit for an `ldx` table look-up.
        Returns the effective address or *None* if the pattern is not matched.
        Supported forms::

            ldx  &sym , #off
            ldx  &sym , <pure-const-expr>
            ldx  $global_var , #off
            ldx  $global_var , <pure-const-expr>
            ldx  segment , $global_var
            ldx  ds ,  add(&sym , #off)
        """

        if ins.opcode != ida_hexrays.m_ldx:
            return None

        # Direct address operand emitted by early microcode. Treat the mop_v
        # as the address of the memory read so the caller replaces the whole
        # ldx. Replacing ins.r in place would turn the loaded value into a new
        # address and leave a bogus memory access behind.
        if ins.r.t == ida_hexrays.mop_v:
            return ins.r.g

        # ------------------------------------------------------------------
        #  Variant A:   ldx  &sym , #off
        #  Variant A':  ldx  &sym , <pure-const-expr>
        # ------------------------------------------------------------------
        if ins.l.t == ida_hexrays.mop_S:
            if ins.r.t == ida_hexrays.mop_n:
                base = ins.l.s.start_ea
                off = ins.r.nnn.value
                return base + off
            # Variant A': index is a computed expression — try evaluating it
            # as a pure-constant tree (all leaves are immediates).
            if ins.r.t == ida_hexrays.mop_d:
                off = _try_eval_pure_const_mop(ins.r)
                if off is not None:
                    base = ins.l.s.start_ea
                    return base + off

        # ------------------------------------------------------------------
        #  Variant A'': ldx  $global_var , #off
        #  Variant A''': ldx  $global_var , <pure-const-expr>
        #
        #  Handles table lookups like g_encDataRandomTable[constant_index]
        #  where the base address comes from a direct global variable (mop_v).
        #  The .g attribute of a mop_v operand holds the global EA directly.
        # ------------------------------------------------------------------
        if ins.l.t == ida_hexrays.mop_v:
            if ins.r.t == ida_hexrays.mop_n:
                base = ins.l.g
                off = ins.r.nnn.value
                return base + off
            # Variant A''': index is a computed expression — try evaluating it
            # as a pure-constant tree (all leaves are immediates).
            if ins.r.t == ida_hexrays.mop_d:
                off = _try_eval_pure_const_mop(ins.r)
                if off is not None:
                    base = ins.l.g
                    return base + off

        # ------------------------------------------------------------------
        #  Variant B:   ldx  ds , add(&sym , #off)
        # ------------------------------------------------------------------
        if ins.l.t == ida_hexrays.mop_r and ins.r.t == ida_hexrays.mop_d:
            add_ins = ins.r.d  # underlying micro-instruction of the mop_d
            if add_ins.opcode != ida_hexrays.m_add:
                return None
            # Expect one operand to be "&sym" (mop_a) and the other a constant.
            # Hex-Rays usually puts the address on the left, constant on right
            # but we handle both orders just in case.
            adr_op, cnst_op = add_ins.l, add_ins.r
            if adr_op.t != ida_hexrays.mop_a or cnst_op.t != ida_hexrays.mop_n:
                # swap and try again
                if (
                    add_ins.r.t == ida_hexrays.mop_a
                    and add_ins.l.t == ida_hexrays.mop_n
                ):
                    adr_op, cnst_op = add_ins.r, add_ins.l
                else:
                    return None
            # adr_op is mop_a  ->  resolve the inner symbol.
            inner = adr_op.a
            if inner.t == ida_hexrays.mop_v:
                base = inner.g
            elif inner.t == ida_hexrays.mop_S:
                base = inner.s.start_ea
            else:
                return None
            off = cnst_op.nnn.value
            return base + off

        return None

    @staticmethod
    def _ea_from_simple_mov_load(ins: ida_hexrays.minsn_t) -> Optional[int]:
        """Resolve EA for early `mov`-based memory loads.

        Pattern handled (typically seen at pre-optimized maturity)::

            mov  $_qword_xxx@?.8, rX.8

        Where the left operand is a direct reference to a global/readonly
        location (represented as `mop_v` or `mop_S`).
        """

        if ins.opcode != ida_hexrays.m_mov:
            return None

        # Source must be a direct global/addr operand; destination is ignored
        # here (the caller will validate size and build the `ldc`).
        src = ins.l
        if src is None:
            return None

        if src.t == ida_hexrays.mop_v:
            return src.g
        if src.t == ida_hexrays.mop_S:
            # Only accept true address-bearing symbols. In pre-optimized IR,
            # `mop_S` can also denote stack variables (`stkvar_ref_t`) which do
            # not have an EA and must be ignored.
            start_ea = getattr(src.s, "start_ea", None)
            if start_ea is not None:
                return start_ea
            return None

        return None

    # ------------------------------------------------------------------ #
    # Emulator-based address resolution fallback                        #
    # ------------------------------------------------------------------ #
    def _try_emulator_eval_address(
        self, ins: ida_hexrays.minsn_t, blk: ida_hexrays.mblock_t | None
    ) -> int | None:
        """Try to evaluate the address operand using the microcode emulator.

        This handles MBA-computed constant indices that pattern-based
        resolvers cannot match, e.g.,
        ``ldx ds, add(&byte_TABLE, xds(xdu(const & 0xF) + 0x60))``.

        The emulator's ``_resolve_segment_register`` handles ``ds.2``
        automatically, so no special setup is needed for segment registers.
        """
        if blk is None:
            return None

        # Only attempt for memory load/store opcodes where we have an
        # address operand to evaluate.
        if ins.opcode == ida_hexrays.m_ldx:
            addr_mop = ins.r
        elif ins.opcode == ida_hexrays.m_stx:
            addr_mop = ins.d
        else:
            return None

        if addr_mop is None or addr_mop.t not in (
            ida_hexrays.mop_d,
            ida_hexrays.mop_b,
        ):
            # Only try the emulator for computed expressions (mop_d) or
            # memory operands (mop_b) — simple constants / symbols are
            # already handled by the pattern-based resolvers.
            return None

        # Performance guard: only attempt emulator when the address expression
        # contains a mop_v (global reference like $byte_TABLE). Without a
        # global base address, the expression can't resolve to a foldable EA.
        if not self._contains_mop_v(addr_mop):
            return None

        try:
            from d810.evaluator.hexrays_microcode.emulator import (
                MicroCodeEnvironment,
                MicroCodeInterpreter,
            )

            env = MicroCodeEnvironment()
            env.set_cur_flow(blk, ins)
            interpreter = MicroCodeInterpreter(symbolic_mode=False)

            result = interpreter.eval(addr_mop, env)

            # Validate: result must be a plausible virtual address.
            if result is not None and result > 0x10000:
                return result
        except Exception:
            pass
        return None

    @staticmethod
    def _contains_mop_v(mop: ida_hexrays.mop_t, depth: int = 0) -> bool:
        """Check if an operand tree contains a mop_v (global address reference).

        Bounded depth-first walk to avoid deep recursion on complex trees.
        """
        if depth > 8:
            return False
        if mop.t == ida_hexrays.mop_v:
            return True
        if mop.t == ida_hexrays.mop_a and mop.a is not None:
            # mop_a wraps another operand (address-of)
            return FoldReadonlyDataRule._contains_mop_v(mop.a, depth + 1)
        if mop.t == ida_hexrays.mop_d and mop.d is not None:
            # mop_d is a sub-instruction — check l, r, d operands
            sub = mop.d
            for attr in ("l", "r", "d"):
                op = getattr(sub, attr, None)
                if op is not None and FoldReadonlyDataRule._contains_mop_v(
                    op, depth + 1
                ):
                    return True
        return False

    # ------------------------------------------------------------------ #
    # Expression tree folding                                            #
    # ------------------------------------------------------------------ #
    def _fold_readonly_operands_in_expr(
        self, ins: ida_hexrays.minsn_t
    ) -> ida_hexrays.minsn_t | None:
        """Return a copy of `ins` with any `mop_v`/`mop_S` operands that
        reside in a read-only segment replaced by numeric immediates.

        Only folds values used as r-values; addresses (`mop_a`) are not touched.
        """

        # Clone the instruction shallowly via operand assignment
        new_ins = ida_hexrays.minsn_t(ins.ea)
        new_ins.opcode = ins.opcode
        new_ins.l = ida_hexrays.mop_t()
        new_ins.l.assign(ins.l)
        new_ins.r = ida_hexrays.mop_t()
        new_ins.r.assign(ins.r)
        new_ins.d = ida_hexrays.mop_t()
        new_ins.d.assign(ins.d)

        changed = False
        changed |= self._fold_readonly_inplace(new_ins.l)
        # Avoid folding the call target of call-like instructions. Folding a
        # function pointer (e.g., IAT/vtable) into an immediate can confuse the
        # decompiler into emitting spurious MEMORY[ea](...) calls.
        m_icall = getattr(ida_hexrays, "m_icall", None)
        if new_ins.opcode in (ida_hexrays.m_call, m_icall):
            pass
        else:
            changed |= self._fold_readonly_inplace(new_ins.r)
        # do not touch destination

        if not changed:
            return None

        # Post-fixup: shift instructions (m_shl/m_shr/m_sar) require that
        # ins.r (the shift-amount operand) has size == 1.  If the recursive
        # fold just replaced ins.r with a mop_n of a larger size, IDA's
        # verifier will raise INTERR 50835.  Clamp the size here.
        if new_ins.opcode in _SHIFT_OPCODES:
            r = new_ins.r
            if r is not None and r.t == ida_hexrays.mop_n and r.size != 1:
                safe_make_number(r, r.nnn.value, 1)

        return new_ins

    def _fold_readonly_inplace(self, op: ida_hexrays.mop_t) -> bool:
        """Recursively fold `op` if it references a readonly global.

        Returns True if the operand (or any nested operand) was modified.
        """
        if not op:
            return False

        # Nested expression: recurse into its operands
        if op.t == ida_hexrays.mop_d:
            inner: ida_hexrays.minsn_t = op.d
            # Handle zero/sign-extend of a memory byte/word into an immediate when
            # the effective address can be resolved to &sym + const in a RO segment.
            if inner.opcode in (ida_hexrays.m_xdu, ida_hexrays.m_xds):
                src = inner.l
                ea = None
                mem_size = getattr(src, "size", 0) or 0

                # Case 1: mop_b (memory operand with base+index)
                if src and getattr(src, "t", None) == ida_hexrays.mop_b:
                    ea = self._ea_from_mop_b(src)

                # Case 2: mop_v (direct global variable reference like $unk_CAEB.1)
                # These represent direct reads from global addresses.
                elif src and getattr(src, "t", None) == ida_hexrays.mop_v:
                    ea = src.g

                if ea is not None:
                    out_size = getattr(op, "size", 0) or getattr(inner, "size", 0) or 0
                    if mem_size in (1, 2, 4, 8) and out_size in (1, 2, 4, 8):
                        decision = self._decision_for(ea, mem_size, site="expr-mem")
                        if decision.can_inline_read and decision.value is not None:
                            val = decision.value
                            # Apply sign/zero extension
                            if inner.opcode == ida_hexrays.m_xds:
                                sign_bit = 1 << (mem_size * 8 - 1)
                                if val & sign_bit:
                                    val = val - (1 << (mem_size * 8))
                            mask = (1 << (out_size * 8)) - 1
                            folded = val & mask
                            replace_operand_with_immediate(op, folded, out_size)
                            if peephole_logger.debug_on:
                                peephole_logger.debug(
                                    "constant-simplification fold APPLIED "
                                    "site=expr-mem addr=0x%X size=%d value=0x%X",
                                    ea,
                                    out_size,
                                    folded,
                                )
                            return True
            # Otherwise, recurse into sub-operands of the inner instruction
            res_l = self._fold_readonly_inplace(inner.l)
            res_r = self._fold_readonly_inplace(inner.r)
            return res_l or res_r

        # Address-of or pointer-like forms are not folded here
        if op.t in {ida_hexrays.mop_a, ida_hexrays.mop_b}:
            return False

        size = op.size if getattr(op, "size", 0) else 0

        # mop_v used as a source operand (r-value) IS a memory read from a
        # global address. If it's foldable, replace it with an immediate.
        if op.t == ida_hexrays.mop_v:
            ea = op.g
            if size in (1, 2, 4, 8):
                decision = self._decision_for(ea, size, site="expr-direct")
                if decision.can_inline_read and decision.value is not None:
                    replace_operand_with_immediate(op, decision.value, size)
                    if peephole_logger.debug_on:
                        peephole_logger.debug(
                            "constant-simplification fold APPLIED site=expr-direct "
                            "addr=0x%X size=%d value=0x%X",
                            ea,
                            size,
                            decision.value,
                        )
                    return True
            return False
        # Stack variables (mop_S) are NOT memory reads from global addresses.
        if op.t == ida_hexrays.mop_S:
            return False

        return False

    # ------------------------------------------------------------------ #
    # mop_b EA reconstruction                                            #
    # ------------------------------------------------------------------ #
    def _ea_from_mop_b(self, mop_b: ida_hexrays.mop_t) -> Optional[int]:
        """Try to reconstruct EA from a memory operand (mop_b).

        Handles patterns like [ds:( &sym + const )] or when the base is an add()
        expression that combines an address-of operand with a constant.
        """
        try:
            b = mop_b.b
            i = mop_b.i
        except Exception:
            return None

        def _addr_from_mop_a(mop_a: ida_hexrays.mop_t) -> Optional[int]:
            inner = mop_a.a
            if inner is None:
                return None
            if inner.t == ida_hexrays.mop_v:
                return inner.g
            if inner.t == ida_hexrays.mop_S:
                return getattr(inner.s, "start_ea", None)
            return None

        def _const_from_mop(m: ida_hexrays.mop_t) -> Optional[int]:
            if m is None:
                return 0
            if m.t == ida_hexrays.mop_n:
                return m.nnn.value
            lits = extract_literal_from_mop(m)
            if lits and len(lits) == 1:
                return lits[0][0]
            return None

        # Case 1: base is address-of symbol, optional constant in index
        if b and b.t == ida_hexrays.mop_a:
            base = _addr_from_mop_a(b)
            if base is None:
                return None
            off = _const_from_mop(i)
            if off is None:
                return None
            return base + off

        # Case 2: base is an add() expression combining &sym and const
        if b and b.t == ida_hexrays.mop_d and b.d and b.d.opcode == ida_hexrays.m_add:
            add_ins = b.d
            left, right = add_ins.l, add_ins.r
            # Try both orders to find (&sym, const)
            if left and left.t == ida_hexrays.mop_a:
                base = _addr_from_mop_a(left)
                if base is not None:
                    off = _const_from_mop(right)
                    if off is not None:
                        return base + off
            if right and right.t == ida_hexrays.mop_a:
                base = _addr_from_mop_a(right)
                if base is not None:
                    off = _const_from_mop(left)
                    if off is not None:
                        return base + off

        # Not a supported form
        return None
