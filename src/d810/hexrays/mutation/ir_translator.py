"""IDA-specific CFGBackend implementation.

Wraps existing IDA infrastructure:
- lift() -> flowgraph snapshot lift(mba)
- lower() -> materializes PatchPlan -> DeferredGraphModifier queue calls
- verify() -> calls safe_verify(mba)
"""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import TYPE_CHECKING, Callable

from d810.hexrays.contracts import CfgContractViolationError, IDACfgContract

from d810.cfg.graph_modification import (
    CloneConditionalAsGoto,
    CloneConditionalAsGotoFromBranchArm,
    GraphModification,
    RedirectGoto,
    RedirectBranch,
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    CreateConditionalRedirect,
    DuplicateBlock,
    DuplicateReplayAndRedirect,
    InsertBlock,
    RemoveEdge,
    NopInstructions,
)
from d810.cfg.flowgraph import (
    BranchPredicate,
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    OperandKind,
)
from d810.cfg.flowgraph import MopSnapshot as CfgMopSnapshot
from d810.ir.semantics import ControlTransferKind, PredicateKind
from d810.cfg.plan import (
    ExecutionPolicy,
    LegacyBlockOperation,
    PatchBypassDispatcherTrampoline,
    PatchCanonicalizeJumpTableCaseOverlap,
    PatchCloneConditionalAsGoto,
    PatchCloneConditionalAsGotoFromBranchArm,
    PatchConditionalRedirect,
    PatchConvertToGoto,
    PatchDuplicateBlock,
    PatchDuplicateReplayAndRedirect,
    PatchEdgeSplitCorridor,
    PatchEdgeSplitTrampoline,
    PatchInsertBlock,
    PatchLowerConditionalStateTransition,
    PatchNormalizeNWayDispatcherExit,
    PatchNopInstructions,
    PatchPhaseCycleLowering,
    PatchZeroStateWrite,
    PatchPromoteOperandToScalar,
    PatchPlan,
    PatchPrivateTerminalSuffix,
    PatchPrivateTerminalSuffixGroup,
    PatchDirectTerminalLoweringGroup,
    PatchReorderBlocks,
    PatchRedirectBranch,
    PatchRedirectGoto,
    PatchRemoveEdge,
    PatchScalarizeLocalAliasAccess,
    PatchStep,
)
from d810.hexrays.ir.block_helpers import get_pred_serials, get_succ_serials
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.hexrays.mutation.insn_snapshot_materializer import (
    insn_snapshots_from_captured_body,
    validate_captured_block_body,
    validate_insn_snapshots,
)

if TYPE_CHECKING:
    import ida_hexrays
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier as DeferredGraphModifierType
    from d810.hexrays.mutation.cfg_verify import safe_verify as safe_verify_type

logger = getLogger(__name__)

import os

import ida_hexrays
import idaapi

from d810.hexrays.utils.hexrays_formatters import maturity_to_string


def _block_kind_from_hexrays(block_type: int) -> BlockKind:
    block_type = int(block_type)
    if block_type == int(ida_hexrays.BLT_NONE):
        return BlockKind.NONE
    if block_type == int(ida_hexrays.BLT_STOP):
        return BlockKind.STOP
    if block_type == int(ida_hexrays.BLT_XTRN):
        return BlockKind.EXTERNAL
    if block_type == int(ida_hexrays.BLT_0WAY):
        return BlockKind.ZERO_WAY
    if block_type == int(ida_hexrays.BLT_1WAY):
        return BlockKind.ONE_WAY
    if block_type == int(ida_hexrays.BLT_2WAY):
        return BlockKind.TWO_WAY
    if block_type == int(ida_hexrays.BLT_NWAY):
        return BlockKind.N_WAY
    return BlockKind.UNKNOWN


def is_hexrays_opcode(opcode: int, name: str) -> bool:
    value = getattr(ida_hexrays, name, None)
    return value is not None and int(opcode) == int(value)


def _branch_predicate_from_hexrays(opcode: int) -> BranchPredicate | None:
    opcode = int(opcode)
    mapping = (
        ("m_jcnd", BranchPredicate.TRUTHY),
        ("m_jnz", BranchPredicate.NOT_EQUAL),
        ("m_jz", BranchPredicate.EQUAL),
        ("m_jae", BranchPredicate.UNSIGNED_GE),
        ("m_ja", BranchPredicate.UNSIGNED_GT),
        ("m_jbe", BranchPredicate.UNSIGNED_LE),
        ("m_jb", BranchPredicate.UNSIGNED_LT),
        ("m_jge", BranchPredicate.SIGNED_GE),
        ("m_jg", BranchPredicate.SIGNED_GT),
        ("m_jle", BranchPredicate.SIGNED_LE),
        ("m_jl", BranchPredicate.SIGNED_LT),
    )
    for name, predicate in mapping:
        if is_hexrays_opcode(opcode, name):
            return predicate
    return None


def _compare_width_from_operands(*operands: object) -> int | None:
    widths: list[int] = []
    for operand in operands:
        try:
            width = int(getattr(operand, "size", 0) or 0)
        except (TypeError, ValueError):
            width = 0
        if width > 0:
            widths.append(width)
    return max(widths) if widths else None


def _insn_kind_from_hexrays(opcode: int) -> InsnKind:
    opcode = int(opcode)
    if opcode == int(ida_hexrays.m_nop):
        return InsnKind.NOP
    if opcode == int(ida_hexrays.m_mov):
        return InsnKind.MOV
    if opcode == int(ida_hexrays.m_ldx):
        return InsnKind.LOAD
    if opcode == int(ida_hexrays.m_xdu):
        return InsnKind.XDU
    if opcode == int(ida_hexrays.m_add):
        return InsnKind.ADD
    if opcode == int(ida_hexrays.m_sub):
        return InsnKind.SUB
    if opcode == int(ida_hexrays.m_and):
        return InsnKind.AND
    if opcode == int(ida_hexrays.m_stx):
        return InsnKind.STORE
    if opcode == int(ida_hexrays.m_goto):
        return InsnKind.GOTO
    if is_hexrays_opcode(opcode, "m_call") or is_hexrays_opcode(opcode, "m_icall"):
        return InsnKind.CALL
    # E3-prep: ``m_jtbl`` is a multi-target jump-table tail.  Map
    # BEFORE the binary-conditional fallback so it lands in the
    # portable ``TABLE_JUMP`` kind rather than being swept into
    # ``COND_JUMP`` if the predicate helper grows to cover it.
    if is_hexrays_opcode(opcode, "m_jtbl"):
        return InsnKind.TABLE_JUMP
    if opcode in (int(ida_hexrays.m_jnz), int(ida_hexrays.m_jz)):
        return InsnKind.EQUALITY_JUMP
    if _branch_predicate_from_hexrays(opcode) is not None:
        return InsnKind.COND_JUMP
    return InsnKind.UNKNOWN


def _operand_kind_from_hexrays(operand_type: int) -> OperandKind:
    operand_type = int(operand_type)
    mapping = {
        int(ida_hexrays.mop_z): OperandKind.EMPTY,
        int(ida_hexrays.mop_r): OperandKind.REGISTER,
        int(ida_hexrays.mop_n): OperandKind.NUMBER,
        int(ida_hexrays.mop_str): OperandKind.STRING,
        int(ida_hexrays.mop_d): OperandKind.SUBINSN,
        int(ida_hexrays.mop_S): OperandKind.STACK,
        int(ida_hexrays.mop_v): OperandKind.GLOBAL,
        int(ida_hexrays.mop_b): OperandKind.BLOCK,
        int(ida_hexrays.mop_f): OperandKind.ARG_LIST,
        int(ida_hexrays.mop_l): OperandKind.LVAR,
        int(ida_hexrays.mop_a): OperandKind.ADDRESS,
        int(ida_hexrays.mop_h): OperandKind.HELPER,
        int(ida_hexrays.mop_c): OperandKind.CASE_LIST,
        int(ida_hexrays.mop_fn): OperandKind.FP_CONST,
        int(ida_hexrays.mop_p): OperandKind.PAIR,
        int(ida_hexrays.mop_sc): OperandKind.SCATTERED,
    }
    return mapping.get(operand_type, OperandKind.UNKNOWN)


def is_control_flow_opcode(opcode: int) -> bool:
    """Return True if ``opcode`` is any Hex-Rays control-flow microcode op.

    Covers gotos, conditional jumps (signed / unsigned / equality), indirect
    jumps (``m_ijmp``), jump tables (``m_jtbl``), and direct / indirect calls
    (``m_call`` / ``m_icall``).  Use this to ask "is this instruction control
    flow?" without enumerating ``InsnKind`` cases at every call site.
    """
    if _branch_predicate_from_hexrays(opcode) is not None:
        return True
    for name in ("m_goto", "m_ijmp", "m_jtbl", "m_call", "m_icall"):
        if is_hexrays_opcode(opcode, name):
            return True
    return False


def classify_live_insn_kind(insn: object) -> InsnKind | None:
    """Return backend-neutral instruction semantics for a live Hex-Rays insn."""
    try:
        return _insn_kind_from_hexrays(int(getattr(insn, "opcode")))
    except (AttributeError, TypeError, ValueError):
        return None


def classify_live_operand_kind(mop: object) -> OperandKind | None:
    """Return backend-neutral operand semantics for a live Hex-Rays operand."""
    try:
        return _operand_kind_from_hexrays(int(getattr(mop, "t")))
    except (AttributeError, TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Portable semantic-IR adapter (Hex-Rays mcode_t -> d810.ir.semantics enums)
# ---------------------------------------------------------------------------
#
# These functions are the Hex-Rays side of the backend-neutral semantic
# vocabulary defined in `d810.ir.semantics`.  They take a live Hex-Rays
# instruction and return a portable kind enum -- so consumers in
# `d810.recon` and elsewhere can branch on `PredicateKind.ULT` /
# `ControlTransferKind.GOTO` without learning `m_jb` / `m_goto` / the
# numeric mcode_t opcode values.  The mapping below is the ONLY place
# the project ties Hex-Rays opcode names to portable semantics.
#
# Implementation scope: minimum-viable for current axis-C consumers.
# Add new family enums + adapter functions in lockstep with the
# consumers that need them; do NOT preload all of mcode_t.
#
# All lookups go through `is_hexrays_opcode(opcode, "m_X")` so the
# vendor names live as STRING LITERALS (the
# `no-vendor-identifier-in-portable-core` ast-grep rule targets
# attribute access on aliased ida_hexrays / idaapi modules, not
# string contents).


def _branch_predicate_only_from_hexrays(opcode: int) -> PredicateKind | None:
    """Branch-only predicate mapping: ``m_jX`` opcodes ONLY.

    Excludes ``m_set*`` byte materializations -- those carry a
    predicate but are NOT control transfers.  Use this when the
    caller is specifically deciding "is this a conditional branch?".
    ``classify_predicate`` (below) is the broader entry-point that
    also recognises ``m_set*``.

    Returns ``None`` for non-branch opcodes.
    """
    opcode = int(opcode)
    mapping = (
        ("m_jz", PredicateKind.EQ),
        ("m_jnz", PredicateKind.NE),
        ("m_jae", PredicateKind.UGE),
        ("m_ja", PredicateKind.UGT),
        ("m_jbe", PredicateKind.ULE),
        ("m_jb", PredicateKind.ULT),
        ("m_jge", PredicateKind.SGE),
        ("m_jg", PredicateKind.SGT),
        ("m_jle", PredicateKind.SLE),
        ("m_jl", PredicateKind.SLT),
        ("m_jcnd", PredicateKind.TRUTHY),
    )
    for name, kind in mapping:
        if is_hexrays_opcode(opcode, name):
            return kind
    return None


def _set_predicate_only_from_hexrays(opcode: int) -> PredicateKind | None:
    """Set-only predicate mapping: ``m_setX`` byte materializations.

    Conceptually mirrors ``_branch_predicate_only_from_hexrays`` but
    on the materialization side: each ``m_set*`` opcode produces a
    byte carrying the predicate result rather than transferring
    control.  Kept separate so the ``ControlTransferKind`` dispatch
    in ``_control_transfer_from_hexrays`` cannot misclassify a
    materialization as a conditional branch.

    Returns ``None`` for non-set opcodes.
    """
    opcode = int(opcode)
    mapping = (
        ("m_setz", PredicateKind.EQ),
        ("m_setnz", PredicateKind.NE),
        ("m_setae", PredicateKind.UGE),
        ("m_seta", PredicateKind.UGT),
        ("m_setbe", PredicateKind.ULE),
        ("m_setb", PredicateKind.ULT),
        ("m_setge", PredicateKind.SGE),
        ("m_setg", PredicateKind.SGT),
        ("m_setle", PredicateKind.SLE),
        ("m_setl", PredicateKind.SLT),
    )
    for name, kind in mapping:
        if is_hexrays_opcode(opcode, name):
            return kind
    return None


def _predicate_kind_from_hexrays(opcode: int) -> PredicateKind | None:
    """Map any predicate-carrying opcode (branch OR set) to its
    portable ``PredicateKind``.

    Composes the two narrow mappers so callers that want "what
    comparison is this instruction asking?" don't need to know
    whether the result is consumed as branch direction or as a
    materialized byte.
    """
    kind = _branch_predicate_only_from_hexrays(opcode)
    if kind is not None:
        return kind
    return _set_predicate_only_from_hexrays(opcode)


def _control_transfer_from_hexrays(opcode: int) -> ControlTransferKind | None:
    """Map a Hex-Rays control-flow opcode int to its transfer kind.

    Covers gotos, conditional branches, jump tables, indirect jumps,
    and returns.  Calls (``m_call`` / ``m_icall``) are explicitly NOT
    included -- they'll get their own ``CallKind`` family when a
    consumer needs them.  ``m_set*`` byte materializations are
    explicitly NOT control transfers -- the dispatch uses
    ``_branch_predicate_only_from_hexrays`` (NOT the broader
    ``_predicate_kind_from_hexrays``) so a materialization can never
    be misclassified as ``CONDITIONAL_BRANCH``.

    Returns ``None`` for non-transfer opcodes.
    """
    opcode = int(opcode)
    if is_hexrays_opcode(opcode, "m_goto"):
        return ControlTransferKind.GOTO
    if is_hexrays_opcode(opcode, "m_jtbl"):
        return ControlTransferKind.TABLE_BRANCH
    if is_hexrays_opcode(opcode, "m_ijmp"):
        return ControlTransferKind.INDIRECT_BRANCH
    if is_hexrays_opcode(opcode, "m_ret"):
        return ControlTransferKind.RETURN
    if _branch_predicate_only_from_hexrays(opcode) is not None:
        return ControlTransferKind.CONDITIONAL_BRANCH
    return None


def classify_branch_predicate(insn: object) -> PredicateKind | None:
    """Return the portable predicate carried by a live conditional
    branch / set instruction, or ``None`` for non-predicate opcodes.

    Note that this covers BOTH conditional branches (``m_jX``) and
    byte-materialized predicates (``m_setX``); they share the
    predicate semantic and the call site decides whether the
    result is consumed as branch direction (pair with
    ``classify_control_transfer``) or as a materialized byte (no
    associated transfer kind).

    Use this at the recon-side seam where a file previously did
    ``if insn.opcode == ida_hexrays.m_jbe`` -- now ask
    ``if classify_branch_predicate(insn) is PredicateKind.ULE``.
    """
    try:
        return _predicate_kind_from_hexrays(int(getattr(insn, "opcode")))
    except (AttributeError, TypeError, ValueError):
        return None


def classify_control_transfer(insn: object) -> ControlTransferKind | None:
    """Return the portable transfer kind for a live control-flow
    instruction, or ``None`` for non-transfer opcodes.

    ``m_set*`` byte materializations return ``None`` -- they carry
    a predicate but no transfer; ``classify_branch_predicate``
    is the function that recognises them.

    Pair with ``classify_branch_predicate(insn)`` when the consumer
    needs both "is this a conditional branch?" and "what predicate
    does it test?".
    """
    try:
        return _control_transfer_from_hexrays(int(getattr(insn, "opcode")))
    except (AttributeError, TypeError, ValueError):
        return None


def capture_mop_snapshot(mop: "ida_hexrays.mop_t") -> CfgMopSnapshot | None:
    """Capture a lightweight ``CfgMopSnapshot`` from a live ``mop_t``.

    Returns ``None`` for empty (``mop_z``) operands.
    """
    if mop is None or mop.t == ida_hexrays.mop_z:
        return None
    t = mop.t
    size = mop.size
    kind = _operand_kind_from_hexrays(t)
    if t == ida_hexrays.mop_n:
        nnn = mop.nnn
        return CfgMopSnapshot(t=t, size=size, value=int(nnn.value) if nnn is not None else 0, kind=kind)
    if t == ida_hexrays.mop_S:
        s = mop.s
        return CfgMopSnapshot(t=t, size=size, stkoff=s.off if s is not None else None, kind=kind)
    if t == ida_hexrays.mop_r:
        return CfgMopSnapshot(t=t, size=size, reg=mop.r, kind=kind)
    if t == ida_hexrays.mop_b:
        return CfgMopSnapshot(t=t, size=size, block_ref=mop.b, kind=kind)
    if t == ida_hexrays.mop_v:
        # E2a: carry the global address across the snapshot boundary so
        # portable dispatcher-state analyses can key by ``gaddr`` instead
        # of reaching back into the live ``mop_t``.
        return CfgMopSnapshot(t=t, size=size, gaddr=int(mop.g), kind=kind)
    if t == ida_hexrays.mop_l:
        # E2a: carry the lvar offset across the snapshot boundary so
        # portable dispatcher-state analyses can key by ``lvar_off``
        # instead of reaching back into the live ``mop_t``.
        lref = mop.l
        return CfgMopSnapshot(
            t=t,
            size=size,
            lvar_off=int(lref.off) if lref is not None else None,
            kind=kind,
        )
    return CfgMopSnapshot(t=t, size=size, kind=kind)


def capture_insn_snapshot(insn: "ida_hexrays.minsn_t") -> InsnSnapshot:
    """Capture a rich ``InsnSnapshot`` from a live ``minsn_t``.

    Populates both the legacy ``operands``/``operand_slots`` fields and the
    new typed ``l``/``r``/``d`` fields.
    """
    opcode = insn.opcode
    ea = insn.ea
    try:
        display_text = str(insn.dstr())
    except Exception:
        display_text = ""

    operand_slots = tuple(
        (slot_name, MopSnapshot.from_mop(mop))
        for slot_name, mop in (
            ("l", insn.l),
            ("r", insn.r),
            ("d", insn.d),
        )
        if mop.t != ida_hexrays.mop_z  # type: ignore[attr-defined]
    )
    operands = tuple(operand for _, operand in operand_slots)
    branch_predicate = _branch_predicate_from_hexrays(opcode)
    insn_kind = _insn_kind_from_hexrays(opcode)
    left = capture_mop_snapshot(insn.l)
    right = capture_mop_snapshot(insn.r)
    dest = capture_mop_snapshot(insn.d)

    return InsnSnapshot(
        opcode=opcode,
        ea=ea,
        operands=operands,
        operand_slots=operand_slots,
        display_text=display_text,
        l=left,
        r=right,
        d=dest,
        kind=insn_kind,
        raw_opcode=int(opcode),
        branch_predicate=branch_predicate,
        compare_width=_compare_width_from_operands(left, right),
        is_conditional_jump=branch_predicate is not None,
        is_unconditional_jump=insn_kind is InsnKind.GOTO,
        is_call=insn_kind is InsnKind.CALL,
    )


def lift_block(blk: "ida_hexrays.mblock_t") -> BlockSnapshot:
    serial = blk.serial
    block_type = blk.type
    flags = blk.flags
    start_ea = blk.start

    succs = get_succ_serials(blk)
    preds = get_pred_serials(blk)

    insn_snapshots: list[InsnSnapshot] = []
    insn = blk.head
    while insn:
        insn_snapshots.append(capture_insn_snapshot(insn))
        insn = insn.next

    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=flags,
        start_ea=start_ea,
        insn_snapshots=tuple(insn_snapshots),
        kind=_block_kind_from_hexrays(block_type),
        raw_block_type=int(block_type),
    )


def lift(mba: "ida_hexrays.mba_t") -> FlowGraph:
    blocks = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        blocks[blk.serial] = lift_block(blk)

    # E2b: pin a small, portable metadata contract on every lifted
    # ``FlowGraph`` so recon consumers never have to reach back into
    # the live ``mba_t`` for these values:
    #
    # * ``maturity``        -- int, raw ``mba.maturity`` (already present)
    # * ``maturity_name``   -- str, ``MMAT_*`` name (or ``Unknown maturity: N``)
    # * ``cpu_arch_name``   -- str, IDA processor module name
    #                          (``metapc``, ``ARM``, ``PPC``, ...)
    #
    # ``cpu_arch_name`` lookup is wrapped because ``inf_get_procname``
    # can return bytes on some IDA builds and we want a clean ``str``.
    # A lookup failure here MUST NOT gate decompilation -- fall back
    # to ``"unknown"`` (deterministic non-empty sentinel so consumers
    # can do string compares without special-casing ``""``).
    try:
        raw_proc = idaapi.inf_get_procname()
    except Exception:
        raw_proc = None
    if isinstance(raw_proc, bytes):
        try:
            cpu_arch_name = raw_proc.decode("ascii", "replace") or "unknown"
        except Exception:
            cpu_arch_name = "unknown"
    else:
        cpu_arch_name = str(raw_proc) if raw_proc else "unknown"

    return FlowGraph(
        blocks=blocks,
        entry_serial=0,
        func_ea=mba.entry_ea,
        metadata={
            "maturity": int(mba.maturity),
            "maturity_name": maturity_to_string(int(mba.maturity)),
            "cpu_arch_name": cpu_arch_name,
        },
    )


def _unsupported_insert_block_reason(step: PatchInsertBlock) -> str | None:
    if step.captured_body is not None:
        if step.captured_body.summary.contains_call:
            return (
                f"PatchInsertBlock({step.pred_serial}->{step.succ_serial}) "
                "cannot replay call-containing captured body"
            )
        reason = validate_captured_block_body(step.captured_body)
    else:
        reason = validate_insn_snapshots(step.instructions)
    if reason is not None:
        return (
            f"PatchInsertBlock({step.pred_serial}->{step.succ_serial}) "
            f"cannot rebuild instructions: {reason}"
        )
    return None


def _unsupported_duplicate_block_reason(step: PatchDuplicateBlock) -> str | None:
    if step.pred_serial is None:
        return f"PatchDuplicateBlock(source={step.source_serial}) missing predecessor"
    if step.pred_redirect_kind not in {"one_way", "conditional"}:
        return (
            f"PatchDuplicateBlock(source={step.source_serial}, pred={step.pred_serial}) "
            f"unsupported predecessor edge kind: {step.pred_redirect_kind}"
        )
    if len(step.source_successors) > 2:
        return (
            f"PatchDuplicateBlock(source={step.source_serial}) "
            f"unsupported successor count: {len(step.source_successors)}"
        )
    if len(step.source_successors) == 2:
        if step.fallthrough_serial is None:
            return (
                f"PatchDuplicateBlock(source={step.source_serial}) "
                "missing duplicated fallthrough serial"
            )
        if step.fallthrough_target is None:
            return (
                f"PatchDuplicateBlock(source={step.source_serial}) "
                "missing duplicated fallthrough target"
            )
        if step.target_serial is None and step.conditional_target is None:
            return (
                f"PatchDuplicateBlock(source={step.source_serial}) "
                "missing duplicated conditional target"
            )
    return None


def _unsupported_duplicate_replay_reason(
    step: PatchDuplicateReplayAndRedirect,
) -> str | None:
    if len(step.per_pred_replays) < 2:
        return (
            f"PatchDuplicateReplayAndRedirect(source={step.source_serial}) "
            "requires at least two predecessor replay rows"
        )
    seen_preds: set[int] = set()
    for entry in step.per_pred_replays:
        if entry.pred_serial in seen_preds:
            return (
                f"PatchDuplicateReplayAndRedirect(source={step.source_serial}) "
                f"duplicates predecessor {entry.pred_serial}"
            )
        seen_preds.add(entry.pred_serial)
        if entry.captured_body.summary.contains_call:
            return (
                "PatchDuplicateReplayAndRedirect("
                f"source={step.source_serial}, pred={entry.pred_serial}) "
                "cannot replay call-containing captured body"
            )
        reason = validate_captured_block_body(entry.captured_body)
        if reason is not None:
            return (
                "PatchDuplicateReplayAndRedirect("
                f"source={step.source_serial}, pred={entry.pred_serial}) "
                f"cannot rebuild replay body: {reason}"
            )
    return None



class IDAIRTranslator:
    """CFGBackend implementation for IDA Pro's Hex-Rays microcode.

    Translates between the FlowGraph representation and IDA's
    mblock_t/mba_t structures using DeferredGraphModifier.

    Example:
        >>> backend = IDAIRTranslator()
        >>> cfg = backend.lift(mba)
        >>> modifications = [ConvertToGoto(block_serial=3, goto_target=5)]
        >>> count = backend.lower(modifications, mba)
        >>> backend.verify(mba)
        True
    """

    def __init__(
        self,
        *,
        allow_legacy_block_creation: bool = True,
        contract: IDACfgContract | None = None,
    ) -> None:
        self.allow_legacy_block_creation = allow_legacy_block_creation
        self._contract = contract
        self._last_lowering_phase: str | None = None
        self._last_lowering_subphase: str | None = None

    @property
    def contract(self) -> IDACfgContract | None:
        return self._contract

    @contract.setter
    def contract(self, value: IDACfgContract | None) -> None:
        self._contract = value

    @property
    def last_lowering_phase(self) -> str | None:
        """Phase of last failure from lower(), or None if lower() succeeded."""
        return self._last_lowering_phase

    @property
    def last_lowering_subphase(self) -> str | None:
        """Most specific subphase reported by the backend, when available."""
        return self._last_lowering_subphase

    @property
    def name(self) -> str:
        """Unique identifier for the backend."""
        return "ida"

    def lift(self, mba: "ida_hexrays.mba_t") -> FlowGraph:
        """Convert IDA's mba_t to FlowGraph snapshot.

        Args:
            mba: IDA microcode block array to snapshot.

        Returns:
            FlowGraph snapshot capturing current topology.
        """
        return lift(mba)

    def lower(
        self,
        patch_plan: PatchPlan,
        mba: "ida_hexrays.mba_t",
        *,
        post_apply_hook=None,
    ) -> int:
        """Apply a PatchPlan to mba via DeferredGraphModifier.

        ``PatchPlan`` concrete operations are lowered directly. Supported
        block-creating steps are materialized through backend queue/apply
        operations. Unsupported block creation remains explicit legacy fallback
        and can be rejected before any live mutation when
        ``allow_legacy_block_creation`` is disabled.

        Args:
            patch_plan: Finalized backend execution plan.
            mba: IDA microcode block array to modify.

        Returns:
            Count of successfully applied modifications.

        Example:
            >>> patch_plan = PatchPlan(
            ...     steps=(PatchRedirectGoto(from_serial=10, old_target=20, new_target=30),)
            ... )
            >>> count = backend.lower(patch_plan, mba)
            >>> count
            1
        """
        # Import here to make it patchable in tests
        from d810.hexrays.mutation import deferred_modifier

        self._last_lowering_phase = None
        self._last_lowering_subphase = None

        if not isinstance(patch_plan, PatchPlan):
            raise TypeError(
                "IDAIRTranslator.lower() now requires PatchPlan; "
                "compile GraphModification lists before lowering"
            )
        if patch_plan.legacy_block_operations and not self.allow_legacy_block_creation:
            logger.warning(
                "PatchPlan contains %d legacy block-creating steps but legacy block creation is disabled",
                len(patch_plan.legacy_block_operations),
            )
            self._last_lowering_phase = "lowering"
            return 0
        unsupported_reasons = self._unsupported_patch_plan_reasons(patch_plan)
        if unsupported_reasons:
            logger.warning(
                "PatchPlan contains unsupported lowering step(s): %s",
                ", ".join(unsupported_reasons),
            )
            self._last_lowering_phase = "lowering"
            return 0

        # Derive execution policy from the plan itself (not a translator flag).
        relaxed = patch_plan.execution_policy in (
            ExecutionPolicy.NOP_CLEANUP_RELAXED,
            ExecutionPolicy.NOP_MERGE_BLOCKS_RELAXED,
        )
        merge_blocks_cleanup = (
            patch_plan.execution_policy == ExecutionPolicy.NOP_MERGE_BLOCKS_RELAXED
        )

        # Safety gate: relaxed NOP policies only permit instruction-local
        # NOP cleanup.  Reject any plan containing block-creating, edge-changing,
        # or redirect steps so relaxed mode cannot silently bypass the verifier
        # for structural mutations.
        if relaxed:
            _NOP_ONLY_ALLOWED = (PatchNopInstructions, PatchZeroStateWrite)
            disallowed = [
                type(s).__name__
                for s in patch_plan.steps
                if not isinstance(s, _NOP_ONLY_ALLOWED)
            ]
            if disallowed:
                logger.error(
                    "relaxed NOP plan contains non-NOP steps "
                    "(%s); rejecting to prevent verifier bypass on structural edits",
                    ", ".join(disallowed),
                )
                self._last_lowering_phase = "lowering"
                return 0

        modifier = deferred_modifier.DeferredGraphModifier(mba)

        # Build effective post-apply hook: caller hook + contract check
        effective_hook: Callable[[], None] | None = None
        # NOP cleanup intentionally creates a transient CFG/successor mismatch
        # that Hex-Rays resolves in the apply tail via optimize_local().
        # Running the live post-contract before that cleanup would abort the
        # maintenance step, leaving the MBA in the transient state.
        if post_apply_hook is not None or (self.contract is not None and not relaxed):

            def _combined_post_apply_hook() -> None:
                if post_apply_hook is not None:
                    post_apply_hook()
                if self.contract is not None and not relaxed:
                    self.contract.verify(mba, plan=patch_plan, phase="post")

            effective_hook = _combined_post_apply_hook

        if patch_plan.contains_block_creation:
            logger.info(
                "Lowering PatchPlan with %d concrete ops and %d legacy block-creating steps",
                len(patch_plan.concrete_operations),
                len(patch_plan.legacy_block_operations),
            )

        verify_each_mod = not patch_plan.contains_block_creation

        for step in patch_plan.steps:
            self._queue_patch_step(modifier, step)

        # Apply all queued modifications with snapshot rollback enabled.
        # Under relaxed NOP cleanup, disable rollback so the NOPs survive
        # even if IDA's GLBOPT1 verifier complains (INTERR 50846).
        enable_rollback = not relaxed
        # Opt-in transactional mode: gates the batch with pre-apply conflict
        # detection and rolls back on any mid-batch abort. Off by default to
        # preserve existing behavior; enable for probes that want all-or-nothing.
        use_transactional = os.getenv(
            "D810_DEFERRED_TRANSACTIONAL", ""
        ).strip() == "1" and enable_rollback
        # Opt-in staged atomic mode: destructive mods lowered to copy-and-swap
        # via mba.copy_block so intermediate state is invisible to IDA-level
        # observers. Composable with transactional.
        use_staged_atomic = os.getenv(
            "D810_DEFERRED_STAGED_ATOMIC", ""
        ).strip() == "1"
        try:
            result_count = modifier.apply(
                run_optimize_local=not merge_blocks_cleanup,
                run_deep_cleaning=merge_blocks_cleanup,
                verify_each_mod=verify_each_mod and enable_rollback,
                rollback_on_verify_failure=verify_each_mod and enable_rollback,
                continue_on_verify_failure=verify_each_mod,
                enable_snapshot_rollback=enable_rollback,
                post_apply_hook=effective_hook,
                transactional=use_transactional,
                staged_atomic=use_staged_atomic,
            )
        except Exception:
            self._last_lowering_phase = modifier.last_apply_phase or "backend_apply"
            self._last_lowering_subphase = modifier.last_apply_subphase
            raise

        # If verify failed (even after rollback attempt), signal the pipeline
        # to stop by returning 0. A positive result with verify_failed=True
        # means rollback also failed - the MBA may be corrupted.
        if modifier.verify_failed:
            self._last_lowering_phase = modifier.last_apply_phase or "native_verify"
            self._last_lowering_subphase = modifier.last_apply_subphase
            if relaxed and result_count > 0:
                logger.info(
                    "DeferredGraphModifier.verify_failed is set after apply "
                    "but execution_policy=%s; "
                    "returning %d applied modifications",
                    patch_plan.execution_policy.value,
                    result_count,
                )
            else:
                logger.warning(
                    "DeferredGraphModifier.verify_failed is set after apply; "
                    "returning 0 to prevent pipeline from treating changes as successful"
                )
                return 0

        if result_count == 0 and self._last_lowering_phase is None:
            self._last_lowering_phase = modifier.last_apply_phase
            self._last_lowering_subphase = modifier.last_apply_subphase

        return result_count

    def _unsupported_patch_plan_reasons(self, patch_plan: PatchPlan) -> list[str]:
        reasons: list[str] = []
        for step in patch_plan.steps:
            match step:
                case PatchRedirectGoto() | PatchRedirectBranch() | PatchConvertToGoto():
                    continue
                case PatchNopInstructions() | PatchZeroStateWrite() | PatchEdgeSplitTrampoline() | PatchEdgeSplitCorridor() | PatchConditionalRedirect() | PatchCloneConditionalAsGoto() | PatchCloneConditionalAsGotoFromBranchArm():
                    continue
                case PatchPromoteOperandToScalar():
                    continue
                case (
                    PatchLowerConditionalStateTransition()
                    | PatchNormalizeNWayDispatcherExit()
                    | PatchBypassDispatcherTrampoline()
                    | PatchCanonicalizeJumpTableCaseOverlap()
                    | PatchScalarizeLocalAliasAccess()
                    | PatchPhaseCycleLowering()
                ):
                    continue
                case PatchPrivateTerminalSuffix():
                    continue
                case PatchPrivateTerminalSuffixGroup():
                    continue
                case PatchDirectTerminalLoweringGroup():
                    continue
                case PatchReorderBlocks():
                    continue
                case PatchInsertBlock() as insert_step:
                    reason = _unsupported_insert_block_reason(insert_step)
                    if reason is not None:
                        reasons.append(reason)
                case PatchDuplicateBlock() as duplicate_step:
                    reason = _unsupported_duplicate_block_reason(duplicate_step)
                    if reason is not None:
                        reasons.append(reason)
                case PatchDuplicateReplayAndRedirect() as replay_step:
                    reason = _unsupported_duplicate_replay_reason(replay_step)
                    if reason is not None:
                        reasons.append(reason)
                case PatchRemoveEdge():
                    continue
                case LegacyBlockOperation(modification=CreateConditionalRedirect()):
                    continue
                case LegacyBlockOperation(modification=EdgeRedirectViaPredSplit()):
                    continue
                case LegacyBlockOperation(
                    modification=InsertBlock(pred_serial=pred, succ_serial=succ)
                ):
                    reasons.append(f"InsertBlock({pred}->{succ})")
                case LegacyBlockOperation(
                    modification=DuplicateBlock(
                        source_block=src,
                        target_block=target,
                        pred_serial=pred,
                    )
                ):
                    reasons.append(
                        f"DuplicateBlock(source={src}, target={target}, pred={pred})"
                    )
                case LegacyBlockOperation(modification=mod):
                    reasons.append(type(mod).__name__)
                case _:
                    reasons.append(type(step).__name__)
        return reasons


    def _queue_patch_step(
        self,
        modifier: "DeferredGraphModifierType",
        step: PatchStep,
    ) -> None:
        match step:
            case PatchRedirectGoto(from_serial=src, old_target=old, new_target=new):
                modifier.queue_goto_change(
                    src,
                    new,
                    description=f"redirect goto {src}: {old}->{new}",
                )

            case PatchRedirectBranch(from_serial=src, old_target=old, new_target=new):
                modifier.queue_conditional_target_change(
                    src,
                    new,
                    old_target=old,
                    description=f"redirect branch {src}: {old}->{new}",
                )

            case PatchConvertToGoto(block_serial=serial, goto_target=target):
                modifier.queue_convert_to_goto(
                    serial,
                    target,
                    description=f"convert {serial} to goto {target}",
                )

            case PatchRemoveEdge(from_serial=src, to_serial=dst):
                modifier.queue_remove_edge(
                    src,
                    dst,
                    description=f"remove edge {src}->{dst}",
                )

            case PatchNopInstructions(block_serial=serial, insn_eas=eas):
                for ea in eas:
                    modifier.queue_insn_nop(
                        serial,
                        ea,
                        description=f"nop {hex(ea)} in block {serial}",
                    )

            case PatchZeroStateWrite(block_serial=serial, insn_ea=ea):
                modifier.queue_zero_state_write(
                    serial,
                    ea,
                    description=f"zero state write {hex(ea)} in block {serial}",
                )

            case PatchPromoteOperandToScalar(
                block_serial=serial,
                host_ea=host_ea,
                host_opcode=opcode,
                operand_side=side,
            ):
                modifier.queue_promote_operand_to_scalar(
                    serial,
                    host_ea,
                    opcode,
                    side,
                    description=(
                        f"promote operand {side} of insn at {hex(host_ea)} "
                        f"in block {serial}"
                    ),
                )

            case PatchLowerConditionalStateTransition(
                source_serial=src,
                old_dispatcher_serial=dispatcher,
                rewrite_from_ea=ea,
                condition_operand=condition,
                false_target_serial=false_target,
                true_target_serial=true_target,
                proof_id=proof_id,
            ):
                modifier.queue_lower_conditional_state_transition(
                    source_serial=src,
                    old_dispatcher_serial=dispatcher,
                    rewrite_from_ea=ea,
                    condition_operand=condition,
                    false_target_serial=false_target,
                    true_target_serial=true_target,
                    proof_id=proof_id,
                    description=(
                        f"lower conditional state transition {src}: "
                        f"{dispatcher}->{false_target}/{true_target}"
                    ),
                )

            case PatchNormalizeNWayDispatcherExit(
                block_serial=serial,
                dispatcher_entry_serial=dispatcher,
                keep_target_serial=keep,
            ):
                modifier.queue_normalize_nway_dispatcher_exit(
                    serial,
                    dispatcher,
                    keep_target_serial=keep,
                    description=(
                        f"normalize NWAY dispatcher exit {serial}: "
                        f"drop dispatcher {dispatcher}"
                    ),
                )

            case PatchBypassDispatcherTrampoline(
                source_serial=src,
                trampoline_serial=trampoline,
                target_serial=target,
            ):
                modifier.queue_bypass_dispatcher_trampoline(
                    src,
                    trampoline,
                    target,
                    description=(
                        f"bypass dispatcher trampoline {src}: "
                        f"{trampoline}->{target}"
                    ),
                )

            case PatchCanonicalizeJumpTableCaseOverlap(
                jtbl_serial=serial,
                retarget_map=retarget_map,
                deduplicate=deduplicate,
            ):
                modifier.queue_canonicalize_jtbl_case_overlap(
                    serial,
                    retarget_map,
                    deduplicate=deduplicate,
                    description=(
                        f"canonicalize jump-table overlap {serial}: "
                        f"{len(retarget_map)} retargets"
                    ),
                )

            case PatchScalarizeLocalAliasAccess(
                block_serial=serial,
                host_ea=host_ea,
                host_opcode=opcode,
                alias_token=alias,
                base_token=base,
                host_text_sha1=host_text_sha1,
                value_size=value_size,
            ):
                modifier.queue_scalarize_local_alias_access(
                    serial,
                    host_ea,
                    opcode,
                    alias,
                    base,
                    host_text_sha1=host_text_sha1,
                    value_size=value_size,
                    description=(
                        f"scalarize local alias {alias}->{base} at "
                        f"{hex(host_ea)} in block {serial}"
                    ),
                )

            case PatchPhaseCycleLowering(
                header_entries=header_entries,
                header_target=header_target,
                body_entries=body_entries,
                body_target=body_target,
                next_phase_entries=next_phase_entries,
                next_phase_target=next_phase_target,
                terminal_entries=terminal_entries,
                terminal_target=terminal_target,
            ):
                modifier.queue_phase_cycle_lowering(
                    header_entries=header_entries,
                    header_target=header_target,
                    body_entries=body_entries,
                    body_target=body_target,
                    next_phase_entries=next_phase_entries,
                    next_phase_target=next_phase_target,
                    terminal_entries=terminal_entries,
                    terminal_target=terminal_target,
                    description="lower dispatcher phase cycle",
                )

            case PatchEdgeSplitTrampoline(
                source_serial=src,
                via_pred=pred,
                apply_old_target=old,
                new_target=new,
                assigned_serial=assigned,
            ):
                modifier.queue_edge_split_trampoline(
                    source_block=src,
                    via_pred=pred,
                    old_target=old,
                    new_target=new,
                    expected_serial=assigned,
                    description=(
                        f"edge-split trampoline pred={pred} src={src} "
                        f"{old}->{new} via {assigned}"
                    ),
                )

            case PatchEdgeSplitCorridor(
                source_serial=src,
                via_pred=pred,
                old_target=old,
                new_target=new,
                clone_until=clone_until,
                source_new_target=source_new_target,
                rule_priority=priority,
            ):
                modifier.queue_edge_redirect(
                    src_block=src,
                    old_target=old,
                    new_target=new,
                    via_pred=pred,
                    clone_until=clone_until,
                    source_new_target=source_new_target,
                    rule_priority=priority,
                    description=(
                        f"edge-split corridor pred={pred} src={src} "
                        f"{old}->{new} until {clone_until}"
                    ),
                )

            case PatchConditionalRedirect(
                source_serial=src,
                ref_block=ref,
                conditional_target=conditional_target,
                fallthrough_target=fallthrough_target,
                old_target_serial=old_target,
                assigned_serial=assigned,
                fallthrough_serial=fallthrough_serial,
                instructions=instructions,
            ):
                modifier.queue_create_conditional_redirect(
                    source_blk_serial=src,
                    ref_blk_serial=ref,
                    conditional_target_serial=conditional_target,
                    fallthrough_target_serial=fallthrough_target,
                    old_target_serial=old_target,
                    instructions_to_copy=instructions,
                    expected_conditional_serial=assigned,
                    expected_fallthrough_serial=fallthrough_serial,
                    description=(
                        f"conditional redirect src={src} ref={ref} "
                        f"cond={conditional_target} ft={fallthrough_target} "
                        f"via {assigned}/{fallthrough_serial}"
                    ),
                )

            case PatchInsertBlock(
                pred_serial=pred,
                succ_serial=succ,
                assigned_serial=assigned,
                instructions=instructions,
                old_target_serial=old_target,
                captured_body=captured_body,
            ):
                if captured_body is not None:
                    instructions = insn_snapshots_from_captured_body(captured_body)
                modifier.queue_create_and_redirect(
                    source_block_serial=pred,
                    final_target_serial=succ,
                    instructions_to_copy=list(instructions),
                    is_0_way=False,
                    expected_serial=assigned,
                    old_target_serial=old_target,
                    description=(
                        f"insert block {pred}->{assigned}->{succ} "
                        f"with {len(instructions)} instructions "
                        f"(old_target={old_target})"
                    ),
                )

            case PatchDuplicateBlock(
                source_serial=src,
                pred_serial=pred,
                target_serial=target,
                conditional_target=conditional_target,
                fallthrough_target=fallthrough_target,
                assigned_serial=assigned,
                fallthrough_serial=fallthrough_serial,
            ):
                modifier.queue_duplicate_block(
                    source_block_serial=src,
                    pred_serial=pred,
                    target_serial=target,
                    conditional_target=conditional_target,
                    fallthrough_target=fallthrough_target,
                    expected_serial=assigned,
                    expected_secondary_serial=fallthrough_serial,
                    description=(
                        f"duplicate block src={src} pred={pred} "
                        f"target={target} cond={conditional_target} "
                        f"ft={fallthrough_target} via {assigned}"
                    ),
                )

            case PatchDuplicateReplayAndRedirect(
                source_serial=src,
                dispatcher_entry=dispatcher,
                per_pred_replays=per_pred_replays,
            ):
                replay_entries = []
                for entry in per_pred_replays:
                    replay_entries.append(
                        (
                            entry.pred_serial,
                            entry.target_serial,
                            entry.replay_serial,
                            entry.clone_serial,
                            tuple(insn_snapshots_from_captured_body(entry.captured_body)),
                        )
                    )
                modifier.queue_duplicate_replay_and_redirect(
                    source_block_serial=src,
                    dispatcher_entry_serial=dispatcher,
                    per_pred_replays=tuple(replay_entries),
                    description=(
                        f"duplicate replay source={src} dispatcher={dispatcher} "
                        f"rows={len(replay_entries)}"
                    ),
                )

            case PatchCloneConditionalAsGoto(
                source_serial=src,
                pred_serial=pred,
                goto_target=target,
                assigned_serial=assigned,
                reason=reason,
            ):
                modifier.queue_clone_conditional_as_goto(
                    source_block_serial=src,
                    pred_serial=pred,
                    goto_target_serial=target,
                    expected_serial=assigned,
                    description=(
                        f"clone conditional as goto pred={pred} src={src} "
                        f"target={target} via {assigned}: {reason}"
                    ),
                )

            case PatchCloneConditionalAsGotoFromBranchArm(
                source_serial=src,
                pred_serial=pred,
                pred_arm=arm,
                goto_target=target,
                assigned_serial=assigned,
                reason=reason,
            ):
                modifier.queue_clone_conditional_as_goto_from_branch_arm(
                    source_block_serial=src,
                    pred_serial=pred,
                    pred_arm=arm,
                    goto_target_serial=target,
                    expected_serial=assigned,
                    description=(
                        f"clone conditional as goto from arm pred={pred} arm={arm} "
                        f"src={src} target={target} via {assigned}: {reason}"
                    ),
                )

            case PatchPrivateTerminalSuffix(
                anchor_serial=anchor,
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix,
                clone_assigned_serials=clone_serials,
            ):
                modifier.queue_private_terminal_suffix(
                    anchor_serial=anchor,
                    shared_entry_serial=shared_entry,
                    return_block_serial=return_block,
                    suffix_serials=suffix,
                    clone_expected_serials=clone_serials,
                    description=(
                        f"private terminal suffix anchor={anchor} "
                        f"shared_entry={shared_entry} return={return_block} "
                        f"suffix={suffix} clones={clone_serials}"
                    ),
                )

            case PatchPrivateTerminalSuffixGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix_serials,
                anchors=anchors,
                per_anchor_clone_assigned_serials=per_anchor_serials,
            ):
                modifier.queue_private_terminal_suffix_group(
                    anchors=anchors,
                    shared_entry_serial=shared_entry,
                    return_block_serial=return_block,
                    suffix_serials=suffix_serials,
                    per_anchor_clone_expected_serials=per_anchor_serials,
                )

            case PatchDirectTerminalLoweringGroup(
                shared_entry_serial=shared_entry,
                return_block_serial=return_block,
                suffix_serials=suffix_serials,
                sites=sites,
            ):
                modifier.queue_direct_terminal_lowering_group(
                    shared_entry_serial=shared_entry,
                    return_block_serial=return_block,
                    suffix_serials=suffix_serials,
                    sites=sites,
                )

            case PatchReorderBlocks(
                dfs_block_order=order,
                old_to_new=old_to_new_pairs,
                two_way_old_to_trampoline=two_way_tramp_pairs,
            ):
                modifier.queue_reorder_blocks(
                    dfs_block_order=order,
                    old_to_new=dict(old_to_new_pairs) if old_to_new_pairs else None,
                    old_to_trampoline=dict(two_way_tramp_pairs) if two_way_tramp_pairs else None,
                    description=f"reorder {len(order)} blocks in DFS order",
                )

            case LegacyBlockOperation(modification=mod):
                self._queue_legacy_block_operation(modifier, mod)

            case _:
                logger.warning("Unknown PatchPlan step type: %s", type(step).__name__)

    def _queue_legacy_block_operation(
        self,
        modifier: "DeferredGraphModifierType",
        modification: GraphModification,
    ) -> None:
        match modification:
            case EdgeRedirectViaPredSplit(
                src_block=src,
                old_target=old,
                new_target=new,
                via_pred=pred,
                clone_until=clone_until,
                rule_priority=priority,
            ):
                modifier.queue_edge_redirect(
                    src_block=src,
                    old_target=old,
                    new_target=new,
                    via_pred=pred,
                    clone_until=clone_until,
                    rule_priority=priority,
                    description=f"edge redirect via pred split: pred={pred} src={src} {old}->{new}",
                )

            case CreateConditionalRedirect(
                source_block=src,
                ref_block=ref,
                conditional_target=cond_target,
                fallthrough_target=fallthrough_target,
                old_target_serial=old_target,
                instructions=instructions,
            ):
                modifier.queue_create_conditional_redirect(
                    source_blk_serial=src,
                    ref_blk_serial=ref,
                    conditional_target_serial=cond_target,
                    fallthrough_target_serial=fallthrough_target,
                    old_target_serial=old_target,
                    instructions_to_copy=instructions,
                    description=(
                        f"create conditional redirect src={src} ref={ref} "
                        f"cond={cond_target} fallthrough={fallthrough_target}"
                    ),
                )

            case DuplicateBlock(
                source_block=src,
                target_block=target,
                pred_serial=pred,
                conditional_target=conditional_target,
                fallthrough_target=fallthrough_target,
            ):
                modifier.queue_duplicate_block(
                    source_block_serial=src,
                    pred_serial=pred,
                    target_serial=target,
                    conditional_target=conditional_target,
                    fallthrough_target=fallthrough_target,
                    description=(
                        f"duplicate block src={src} pred={pred} target={target} "
                        f"cond={conditional_target} ft={fallthrough_target}"
                    ),
                )

            case CloneConditionalAsGoto(
                source_block=src,
                pred_serial=pred,
                goto_target=target,
                reason=reason,
            ):
                modifier.queue_clone_conditional_as_goto(
                    source_block_serial=src,
                    pred_serial=pred,
                    goto_target_serial=target,
                    description=(
                        f"clone conditional as goto pred={pred} src={src} "
                        f"target={target}: {reason}"
                    ),
                )

            case CloneConditionalAsGotoFromBranchArm(
                source_block=src,
                pred_serial=pred,
                pred_arm=arm,
                goto_target=target,
                reason=reason,
            ):
                modifier.queue_clone_conditional_as_goto_from_branch_arm(
                    source_block_serial=src,
                    pred_serial=pred,
                    pred_arm=arm,
                    goto_target_serial=target,
                    description=(
                        f"clone conditional as goto from arm pred={pred} "
                        f"arm={arm} src={src} target={target}: {reason}"
                    ),
                )

            case InsertBlock(pred_serial=pred, succ_serial=succ, instructions=insns):
                logger.warning(
                    "InsertBlock(%d->%d) requires InsnSnapshot->minsn_t conversion (not yet implemented), skipping",
                    pred,
                    succ,
                )

            case _:
                logger.warning("Unsupported legacy block operation: %s", type(modification).__name__)

    def verify(self, mba: "ida_hexrays.mba_t") -> bool:
        """Verify mba consistency after modifications.

        Args:
            mba: IDA microcode block array to verify.

        Returns:
            True if verification passed, False if corruption detected.

        Raises:
            RuntimeError: If verification fails (propagated from safe_verify).
        """
        # Import here to make it patchable in tests
        from d810.hexrays.mutation import cfg_verify

        try:
            cfg_verify.safe_verify(mba, "IDAIRTranslator.verify()")
            return True
        except RuntimeError:
            return False


__all__ = [
    "IDAIRTranslator",
    "classify_branch_predicate",
    "classify_control_transfer",
    "classify_live_insn_kind",
    "classify_live_operand_kind",
    "is_control_flow_opcode",
    "is_hexrays_opcode",
    "capture_insn_snapshot",
    "capture_mop_snapshot",
    "lift",
    "lift_block",
]
