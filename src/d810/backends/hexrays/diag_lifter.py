"""Hex-Rays diag-replay source lifter (llr-rv7p E opt-4).

Lifts an OFFLINE diagnostic-snapshot source -- a graph of
:class:`d810.core.diag.snapshot.BlockSnapshot` blocks whose ``instructions`` are
``InstructionSnapshot`` rows captured by the live Hex-Rays serializer -- into a
canonical :class:`d810.ir.flowgraph.FlowGraph` that portable fact collectors
iterate through the SAME :meth:`InstructionProjection.from_block` path as a live
source.  (Pre-opt-4 the collectors had an inline diag branch that projected each
row with ``project_instruction`` singular; routing diag through the lifter makes
offline replay use ``project_instruction_sequence`` -- i.e. faithfully match the
live path -- per the 4a decision.)

This module owns the Hex-Rays opcode vocabulary (``_OPCODE_NAME_TO_INSN_KIND``)
and the diag-row -> ``InsnSnapshot`` reconstruction.  It lives under
``d810.backends`` -- NOT portable-core ``d810.ir`` -- because the ``m_*``
mnemonic spellings are vendor-specific and ``d810.ir`` / ``d810.analyses`` must
stay backend-agnostic (epic llr-rv7p, category E).  It imports no ``ida_*``
module, so offline replay (the diagnostics CLI and the system/runtime collector
tests) can register and use it without a live IDA.

Registration funnels through the idempotent ``ensure_diag_lifter_registered()``;
``backends/`` is the single lawful ``register_live_lifter()`` call site (the
``register-live-lifter-only-in-backends`` ast-grep rule ignores ``backends/**``).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from types import MappingProxyType

from d810.capabilities.source_lifter import register_live_lifter
from d810.core.typing import Any
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.instructions import Instruction
from d810.ir.insn_projection import _SUBINSN_VALUE_OPS, project_instruction

__all__ = [
    "DiagSourceLifter",
    "diag_row_has_operand_tree",
    "ensure_diag_lifter_registered",
    "parse_diag_meta_operand",
    "project_diag_instruction",
]


# opcode_name (diag string) -> portable InsnKind.  Accepts both the Hex-Rays
# ``m_*`` spelling captured by the serializer and the portable enum spellings,
# so a diag row resolves to the same semantic operation the live path infers.
# Vendor-coupled by design -> lives under ``backends``, never portable-core.
_OPCODE_NAME_TO_INSN_KIND: Mapping[str, InsnKind] = MappingProxyType(
    {
        "m_mov": InsnKind.MOV,
        "mov": InsnKind.MOV,
        "m_ldx": InsnKind.LOAD,
        "load": InsnKind.LOAD,
        "m_stx": InsnKind.STORE,
        "store": InsnKind.STORE,
        "m_add": InsnKind.ADD,
        "add": InsnKind.ADD,
        "m_sub": InsnKind.SUB,
        "sub": InsnKind.SUB,
        "m_and": InsnKind.AND,
        "and": InsnKind.AND,
        "m_mul": InsnKind.MUL,
        "mul": InsnKind.MUL,
        "m_xdu": InsnKind.XDU,
        "xdu": InsnKind.XDU,
        "m_xds": InsnKind.XDS,
        "xds": InsnKind.XDS,
        "m_goto": InsnKind.GOTO,
        "goto": InsnKind.GOTO,
        "m_ret": InsnKind.RET,
        "ret": InsnKind.RET,
    }
)

# mop ``t`` type-num -> portable OperandKind (relocated from ir; diag-only).
_TYPE_NUM_TO_OPERAND_KIND: Mapping[int, OperandKind] = MappingProxyType(
    {
        0: OperandKind.EMPTY,  # mop_z
        1: OperandKind.REGISTER,  # mop_r
        2: OperandKind.NUMBER,  # mop_n
        3: OperandKind.STRING,  # mop_str
        4: OperandKind.SUBINSN,  # mop_d
        5: OperandKind.STACK,  # mop_S
        6: OperandKind.GLOBAL,  # mop_v
        7: OperandKind.BLOCK,  # mop_b
        8: OperandKind.ARG_LIST,  # mop_f
        9: OperandKind.LVAR,  # mop_l
        10: OperandKind.ADDRESS,  # mop_a
        11: OperandKind.HELPER,  # mop_h
        12: OperandKind.CASE_LIST,  # mop_c
        13: OperandKind.FP_CONST,  # mop_fn
        14: OperandKind.PAIR,  # mop_p
        15: OperandKind.SCATTERED,  # mop_sc
    }
)


def _coerce_global_ea(value: object) -> int | None:
    """Coerce a serializer ``global_ea`` field (``"0x%x"`` string) to int."""
    if value is None:
        return None
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def parse_diag_meta_operand(meta_node: Mapping | None) -> MopSnapshot | None:
    """Project one diag ``meta`` operand node onto a portable ``MopSnapshot``.

    ``meta_node`` is one ``l`` / ``r`` / ``d`` (or nested ``sub_instruction`` /
    ``sub_operand`` / ``args``) dict produced by the serializer's
    ``_mop_to_meta``.  Recurses through ``sub_instruction`` (mop_d) and
    ``sub_operand`` (mop_a); ``args`` (mop_f) lists become nested portable
    operands.  Returns ``None`` for an empty / absent node.
    """
    if not isinstance(meta_node, Mapping):
        return None
    type_num = meta_node.get("type_num")
    if type_num is None:
        return None
    type_num = int(type_num)
    kind = _TYPE_NUM_TO_OPERAND_KIND.get(type_num, OperandKind.UNKNOWN)
    if kind is OperandKind.EMPTY:
        return None
    size = int(meta_node.get("size") or 0)

    value = meta_node.get("value")
    register = meta_node.get("register")
    stkoff = meta_node.get("stkoff")
    block_num = meta_node.get("block_num")
    lvar_idx = meta_node.get("lvar_idx")
    gaddr = _coerce_global_ea(meta_node.get("global_ea"))

    sub_l: MopSnapshot | None = None
    sub_r: MopSnapshot | None = None
    sub_kind: InsnKind | None = None
    sub_value_op_kind: ValueOpKind | None = None
    if kind is OperandKind.SUBINSN:
        sub_insn = meta_node.get("sub_instruction")
        if isinstance(sub_insn, Mapping):
            sub_kind = _OPCODE_NAME_TO_INSN_KIND.get(
                str(sub_insn.get("opcode_name") or "")
            )
            if sub_kind is not None:
                sub_value_op_kind = _SUBINSN_VALUE_OPS.get(sub_kind)
            sub_l = parse_diag_meta_operand(sub_insn.get("l"))
            sub_r = parse_diag_meta_operand(sub_insn.get("r"))
    elif kind is OperandKind.ADDRESS:
        # mop_a wraps a single inner operand under ``sub_operand``.
        sub_l = parse_diag_meta_operand(meta_node.get("sub_operand"))

    args: tuple[MopSnapshot, ...] = ()
    if kind is OperandKind.ARG_LIST:
        raw_args = meta_node.get("args")
        if isinstance(raw_args, (list, tuple)):
            args = tuple(
                arg
                for arg in (parse_diag_meta_operand(node) for node in raw_args)
                if arg is not None
            )

    stack_refs = _collect_stack_refs(kind, stkoff, sub_l, sub_r, args)

    return MopSnapshot(
        t=type_num,
        size=size,
        value=int(value) if value is not None else None,
        stkoff=int(stkoff) if stkoff is not None else None,
        reg=int(register) if register is not None else None,
        block_ref=int(block_num) if block_num is not None else None,
        gaddr=gaddr,
        lvar_off=int(lvar_idx) if lvar_idx is not None else None,
        stack_refs=stack_refs,
        kind=kind,
        sub_kind=sub_kind,
        sub_value_op_kind=sub_value_op_kind,
        sub_l=sub_l,
        sub_r=sub_r,
        args=args,
    )


def _collect_stack_refs(
    kind: OperandKind,
    stkoff: object,
    sub_l: MopSnapshot | None,
    sub_r: MopSnapshot | None,
    args: tuple[MopSnapshot, ...],
) -> tuple[int, ...]:
    """Flatten stack offsets reachable from a (possibly nested) operand."""
    refs: list[int] = []
    if kind is OperandKind.STACK and stkoff is not None:
        refs.append(int(stkoff))
    for child in (sub_l, sub_r, *args):
        if child is not None:
            refs.extend(child.stack_refs)
            if child.kind is OperandKind.STACK and child.stkoff is not None:
                refs.append(int(child.stkoff))
    return tuple(dict.fromkeys(refs))


def _row_field(row: object, name: str) -> object:
    """Read ``name`` from a diag row (dataclass attr or mapping key)."""
    if isinstance(row, Mapping):
        return row.get(name)
    return getattr(row, name, None)


def _row_int(row: object, name: str) -> int | None:
    value = _row_field(row, name)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _diag_meta_payload(row: object) -> Mapping[str, object]:
    raw = _row_field(row, "meta")
    if isinstance(raw, Mapping):
        return raw
    if isinstance(raw, str) and raw:
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError):
            return {}
        return payload if isinstance(payload, Mapping) else {}
    return {}


def diag_row_has_operand_tree(row: object) -> bool:
    """Return whether ``row`` carries a parseable diag ``meta`` operand tree.

    A production DB-replay / ``observability_models.InstructionSnapshot`` row may
    carry a recursive ``_instruction_operands_meta``-shaped ``meta`` JSON whose
    ``l`` / ``r`` / ``d`` nodes project to portable operands.  Such *meta-rich*
    rows can be lifted faithfully via :func:`project_diag_instruction`.

    A *meta-less* row -- one whose ``meta`` is absent / empty / carries only
    attrs (e.g. ``{"byte_index": 1}``) with no operand tree -- returns ``False``
    so callers keep reading the flat ``src_l_*`` / ``dest_*`` fields (the
    canonical projection only reads the operand tree, never the flat fields, so
    routing a meta-less row through it would drop those facts).
    """
    meta = _diag_meta_payload(row)
    if not meta:
        return False
    return any(
        parse_diag_meta_operand(meta.get(slot)) is not None for slot in ("l", "r", "d")
    )


def _diag_row_to_insn_snapshot(row: object) -> InsnSnapshot:
    """Rebuild a portable ``InsnSnapshot`` from a diag instruction row.

    ``row`` is a ``d810.core.observability_models.InstructionSnapshot`` (or the
    equivalent SQLite ``instructions`` row -- dataclass *or* mapping).  Flat
    fields plus the recursive ``meta`` ``l`` / ``r`` / ``d`` operand tree are
    rebuilt into the snapshot; the caller (or ``from_block``) then projects it.
    """
    meta = _diag_meta_payload(row)
    l = parse_diag_meta_operand(meta.get("l"))
    r = parse_diag_meta_operand(meta.get("r"))
    d = parse_diag_meta_operand(meta.get("d"))

    opcode_name = str(_row_field(row, "opcode_name") or "")
    kind = _OPCODE_NAME_TO_INSN_KIND.get(opcode_name, InsnKind.UNKNOWN)
    opcode = _row_int(row, "opcode")
    if opcode is None:
        opcode = -1
    ea = _row_int(row, "ea")
    if ea is None:
        ea = 0
    dstr = str(_row_field(row, "dstr") or "")

    opcode_attrs = {"raw_opcode_name": opcode_name} if opcode_name else {}

    return InsnSnapshot(
        opcode=opcode,
        ea=ea,
        operands=(),
        display_text=dstr,
        l=l,
        r=r,
        d=d,
        kind=kind,
        opcode_attrs=opcode_attrs,
    )


def project_diag_instruction(row: object) -> Instruction:
    """Project a production diag instruction row onto the canonical
    ``Instruction`` (single-record view, via :func:`project_instruction`).

    Retained for callers that lift one row in isolation (the
    ``project_diag_instruction`` unit pins).  Block/collector replay goes through
    :class:`DiagSourceLifter` -> ``from_block`` instead, which emits the same
    flat sequence the live path produces.
    """
    return project_instruction(_diag_row_to_insn_snapshot(row))


class DiagSourceLifter:
    """Lift an offline diag-snapshot source into a canonical ``FlowGraph``."""

    def matches(self, source: Any) -> bool:
        'True iff ``source`` is a diag-snapshot graph.\n\n        A diag block carries raw instruction rows (``instructions``) and no\n        canonical ``insn_snapshots`` -- the exact discriminator the removed\n        inline collector branch used (``getattr(blk, "insn_snapshots", None) is\n        not None``).  Duck-typed so it covers both\n        :class:`d810.core.diag.snapshot.BlockSnapshot` and the loose\n        ``SimpleNamespace`` doubles some collector tests build.  Canonical\n        ``FlowGraph`` snapshots (``d810.ir`` blocks carry ``insn_snapshots``) and\n        live ``mba`` sources (no ``blocks``) do not match, so the preanalysis default\n        iteration / the live lifter handle them.'
        blocks_attr = getattr(source, "blocks", None)
        if blocks_attr is None:
            return False
        blocks = (
            blocks_attr.values() if isinstance(blocks_attr, Mapping) else blocks_attr
        )
        for blk in blocks:
            return getattr(blk, "insn_snapshots", None) is None and hasattr(
                blk, "instructions"
            )
        return False

    def lift(self, source: Any) -> FlowGraph:
        """Rebuild a canonical ``FlowGraph`` whose blocks carry reconstructed
        ``insn_snapshots`` -- so the collectors' ``from_block`` path projects diag
        rows identically to the live source."""
        blocks_attr = getattr(source, "blocks", source)
        diag_blocks = (
            list(blocks_attr.values())
            if isinstance(blocks_attr, Mapping)
            else list(blocks_attr)
        )
        canonical: dict[int, BlockSnapshot] = {}
        for diag_blk in diag_blocks:
            serial = int(diag_blk.serial)
            canonical[serial] = BlockSnapshot(
                serial=serial,
                block_type=int(getattr(diag_blk, "block_type", 0) or 0),
                succs=tuple(int(s) for s in (getattr(diag_blk, "succs", ()) or ())),
                preds=tuple(int(p) for p in (getattr(diag_blk, "preds", ()) or ())),
                flags=0,
                start_ea=int(getattr(diag_blk, "start_ea", 0) or 0),
                insn_snapshots=tuple(
                    _diag_row_to_insn_snapshot(row)
                    for row in (getattr(diag_blk, "instructions", ()) or ())
                ),
            )
        entry = getattr(source, "entry_serial", None)
        if entry is None or int(entry) not in canonical:
            entry = min(canonical) if canonical else 0
        func_ea = int(getattr(source, "func_ea", 0) or 0)
        return FlowGraph(blocks=canonical, entry_serial=int(entry), func_ea=func_ea)


# Module-level singleton so repeated registration (e.g. after a registry reset
# in a test/reload path) re-registers the SAME instance; register_live_lifter's
# identity dedupe then never appends a duplicate.
_LIFTER = DiagSourceLifter()


def ensure_diag_lifter_registered() -> None:
    """Register the diag-replay lifter; idempotent and reset-safe.

    Offline-replay entry points (the diagnostics CLI and the system/runtime
    collector tests) call this -- or import this module -- so a diag source
    reaching a fact collector is lifted to a canonical ``FlowGraph`` instead of
    falling through to the (removed) inline diag branch.
    """
    register_live_lifter(_LIFTER)


# Import-time registration (the single lawful register_live_lifter() call site).
ensure_diag_lifter_registered()
