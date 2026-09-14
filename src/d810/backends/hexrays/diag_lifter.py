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

This module uses the shared Hex-Rays opcode vocabulary
(``instruction_vocabulary``)
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

from d810.capabilities.source_lifter import register_live_lifter
from d810.core.typing import Any
from d810.core.observability_models import DIAG_PROVENANCE_VERSION
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
from d810.ir.insn_projection import project_instruction
from d810.ir.semantics import CallKind
from d810.hexrays.instruction_vocabulary import (
    call_kind_for_opcode_name,
    canonical_opcode_name,
    control_transfer_kind_for_opcode_name,
    insn_kind_for_opcode_name,
    operand_kind_for_name,
    predicate_for_opcode_name,
    branch_predicate_for_opcode_name,
    normalize_conditional_operands,
    validate_operand_shape,
    value_op_kind_for_opcode_name,
)

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
    type_name = meta_node.get("type")
    if not isinstance(type_name, str):
        raise ValueError("diag operand lacks canonical type name")
    kind = operand_kind_for_name(type_name)
    if kind is None:
        raise ValueError("diag operand type name is outside the closed vocabulary")
    raw_type_num = meta_node.get("type_num")
    if type(raw_type_num) is int:
        type_num = int(raw_type_num)
    else:
        raise ValueError("diag operand type number is not an exact integer")
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
    sub_predicate_kind = None
    sub_raw_opcode: int | None = None
    if kind is OperandKind.SUBINSN:
        sub_insn = meta_node.get("sub_instruction")
        if not isinstance(sub_insn, Mapping):
            raise ValueError("diag subinstruction lacks a closed opcode record")
        sub_name = str(sub_insn.get("opcode_name") or "")
        if type(sub_insn.get("opcode")) is not int:
            raise ValueError("diag subinstruction opcode is not an exact integer")
        sub_raw_opcode = int(sub_insn["opcode"])
        if sub_name != canonical_opcode_name(sub_name):
            raise ValueError("diag subinstruction opcode name is not canonical")
        sub_kind = insn_kind_for_opcode_name(sub_name)
        if sub_kind is None:
            raise ValueError(
                f"diag subinstruction opcode {sub_name!r} is outside the closed vocabulary"
            )
        sub_l = parse_diag_meta_operand(sub_insn.get("l"))
        sub_r = parse_diag_meta_operand(sub_insn.get("r"))
        sub_d = parse_diag_meta_operand(sub_insn.get("d"))
        validate_operand_shape(sub_name, l=sub_l, r=sub_r, d=sub_d)
        sub_value_op_kind = value_op_kind_for_opcode_name(sub_name)
        sub_predicate_kind = predicate_for_opcode_name(sub_name)
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
        sub_raw_opcode=sub_raw_opcode if kind is OperandKind.SUBINSN else None,
        sub_predicate_kind=sub_predicate_kind,
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


def _row_exact_int(row: object, name: str) -> int | None:
    value = _row_field(row, name)
    if value is None:
        return None
    if type(value) is not int:
        raise ValueError(f"diag {name} is not an exact integer")
    return value


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
    left = parse_diag_meta_operand(meta.get("l"))
    r = parse_diag_meta_operand(meta.get("r"))
    d = parse_diag_meta_operand(meta.get("d"))

    opcode_name = str(_row_field(row, "opcode_name") or "")
    canonical_name = canonical_opcode_name(opcode_name)
    if opcode_name != canonical_name:
        raise ValueError("diag instruction opcode name is not canonical")
    kind = insn_kind_for_opcode_name(canonical_name)
    if kind is None:
        raise ValueError("diag instruction opcode is outside the closed vocabulary")
    # SET materializations carry a PredicateKind but are not control-flow
    # branches. Keep the exact predicate on the snapshot while deriving
    # branch-only normalization/target facts from the branch namespace.
    predicate = predicate_for_opcode_name(canonical_name)
    branch_predicate = branch_predicate_for_opcode_name(canonical_name)
    call_kind = call_kind_for_opcode_name(canonical_name)
    opcode = _row_exact_int(row, "opcode")
    if opcode is None:
        raise ValueError("diag instruction lacks recorded nominal opcode")
    version = _row_exact_int(row, "provenance_version")
    if version is None:
        version = _row_exact_int(meta, "provenance_version")
    if version != DIAG_PROVENANCE_VERSION:
        raise ValueError("diag instruction provenance schema is not eligible")
    raw_marker_present = (
        isinstance(row, Mapping) and "raw_opcode" in row
    ) or hasattr(row, "raw_opcode") or "raw_opcode" in meta
    raw_value = _row_field(row, "raw_opcode")
    if raw_value is None and "raw_opcode" in meta:
        raw_value = meta["raw_opcode"]
    if not raw_marker_present:
        raise ValueError("diag instruction lacks recorded raw opcode provenance")
    if raw_value is not None and type(raw_value) is not int:
        raise ValueError("diag instruction raw opcode is not an exact integer")
    raw_opcode = raw_value
    if opcode >= 0 and raw_opcode is None:
        raise ValueError("diag instruction lacks recorded raw opcode provenance")
    if opcode < 0:
        if (
            opcode != -1
            or raw_opcode is not None
            or opcode_name != "m_goto"
            or kind is not InsnKind.GOTO
            or left is None
            or left.kind is not OperandKind.BLOCK
            or left.block_ref is None
            or r is not None
            or d is not None
            or left.size != 0
        ):
            raise ValueError("synthetic diag instruction is not a complete normalized GOTO")
    ea = _row_int(row, "ea")
    if ea is None:
        ea = 0
    dstr = str(_row_field(row, "dstr") or "")

    validate_operand_shape(canonical_name, l=left, r=r, d=d)
    compare_width = None
    if branch_predicate is not None:
        normalized = normalize_conditional_operands(
            canonical_name, l=left, r=r, d=d,
        )
        if normalized is not None:
            left, r, compare_width = normalized
    opcode_attrs = {"raw_opcode_name": opcode_name} if opcode_name else {}
    if branch_predicate is not None and compare_width is None:
        compare_width = left.size if left is not None and left.size > 0 else None
    if branch_predicate is not None and compare_width is None:
        raise ValueError("conditional diag instruction lacks complete expression evidence")
    if branch_predicate is not None and meta.get("l") is not None:
        opcode_attrs["raw_conditional_l"] = meta["l"]
    is_assert = _row_field(row, "is_assert")
    if type(is_assert) not in (bool, int, type(None)) or is_assert not in (
        None,
        0,
        1,
    ):
        raise ValueError("diag instruction assertion identity is not boolean")

    return InsnSnapshot(
        opcode=opcode,
        ea=ea,
        operands=(),
        display_text=dstr,
        l=left,
        r=r,
        d=d,
        kind=kind,
        value_op_kind=value_op_kind_for_opcode_name(canonical_name),
        raw_opcode=raw_opcode,
        predicate_kind=predicate,
        branch_predicate=branch_predicate,
        call_kind=call_kind,
        control_transfer_kind=control_transfer_kind_for_opcode_name(canonical_name),
        is_conditional_jump=branch_predicate is not None,
        is_call=call_kind is not None,
        is_assert=bool(is_assert),
        compare_width=compare_width,
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
            block_meta = _diag_meta_payload(diag_blk)
            block_version = _row_exact_int(diag_blk, "provenance_version")
            if block_version is None:
                block_version = _row_exact_int(block_meta, "provenance_version")
            if block_version != DIAG_PROVENANCE_VERSION:
                raise ValueError("diag block provenance schema is not eligible")
            instructions = tuple(
                _diag_row_to_insn_snapshot(row)
                for row in (getattr(diag_blk, "instructions", ()) or ())
            )
            for instruction in instructions:
                if instruction.is_conditional_jump:
                    if instruction.d is None or instruction.d.block_ref not in {
                        int(serial) for serial in (getattr(diag_blk, "succs", ()) or ())
                    }:
                        raise ValueError("conditional diag instruction target is foreign")
            if instructions:
                tail_opcode = _row_exact_int(diag_blk, "tail_opcode")
                if tail_opcode is None and "tail_opcode" in block_meta:
                    tail_opcode = _row_exact_int(block_meta, "tail_opcode")
                raw_tail_opcode = _row_exact_int(diag_blk, "raw_tail_opcode")
                if raw_tail_opcode is None and "raw_tail_opcode" in block_meta:
                    raw_tail_opcode = _row_exact_int(block_meta, "raw_tail_opcode")
                tail_kind = _row_field(diag_blk, "tail_kind")
                if tail_kind is None:
                    tail_kind = block_meta.get("tail_kind")
                if tail_opcode is None or tail_kind is None:
                    raise ValueError("diag block lacks recorded tail provenance")
                if tail_opcode >= 0 and raw_tail_opcode is None:
                    raise ValueError("diag block lacks recorded tail provenance")
                if tail_opcode < 0 and raw_tail_opcode is not None:
                    raise ValueError("synthetic diag block carries raw tail provenance")
                if not isinstance(tail_kind, InsnKind):
                    try:
                        tail_kind = InsnKind(str(tail_kind))
                    except (TypeError, ValueError) as exc:
                        raise ValueError("diag block tail kind is not closed") from exc
                if tail_opcode == -1:
                    synthetic_tail = instructions[-1]
                    if (
                        len(getattr(diag_blk, "succs", ()) or ()) != 1
                        or synthetic_tail.l is None
                        or synthetic_tail.l.kind is not OperandKind.BLOCK
                        or synthetic_tail.l.block_ref != int(diag_blk.succs[0])
                    ):
                        raise ValueError("synthetic diag GOTO target is not the sole successor")
            else:
                tail_opcode = raw_tail_opcode = tail_kind = None
            canonical[serial] = BlockSnapshot(
                serial=serial,
                block_type=int(getattr(diag_blk, "block_type", 0) or 0),
                succs=tuple(int(s) for s in (getattr(diag_blk, "succs", ()) or ())),
                preds=tuple(int(p) for p in (getattr(diag_blk, "preds", ()) or ())),
                flags=0,
                start_ea=int(getattr(diag_blk, "start_ea", 0) or 0),
                insn_snapshots=instructions,
                tail_opcode=tail_opcode,
                raw_tail_opcode=raw_tail_opcode,
                tail_kind=tail_kind,
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
