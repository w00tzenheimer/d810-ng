"State-write anchor fact collector.\n\nThis collector observes ``mov #const, %var_<stkoff>`` style state-variable\nwrites BEFORE IDA's MMAT_LOCOPT constant-propagation collapses transit-state\nconstants into eventual successor blocks.\n\nBackground\n----------\nOn ``sub_7FFD3338C040`` we observed 34 state-write constants getting\nrewritten in-place between ``MMAT_LOCOPT pre_d810`` and ``MMAT_LOCOPT\npost_d810`` (e.g. ``blk[100] 0x5A21D9DB -> 0x63D54755``).  D810 is NOT the\nmutator: by elimination, IDA's own MMAT_LOCOPT constant-propagation pass\ncollapses transit-state writes into the eventually-reaching successor's\nstate.  Once the rewrite happens, the preanalysis DAG built at GLBOPT1 reflects\nthe post-CP microcode and disagrees with the linearized reference.\n\nThis fact captures the ORIGINAL state-write constant at LOCOPT-pre so later\nconsumers can compare against the GLBOPT1 preanalysis view and detect IDA-driven\nrewrites.\n\nLifecycle integration\n---------------------\nThe :class:`PreanalysisFactRuntime` already invokes collectors at\n``MMAT_LOCOPT`` with ``phase=\"pre_d810\"``.  No runtime changes are required\nto capture LOCOPT-pre observations.  Cross-maturity rewrite detection lives\nin\n:meth:`PreanalysisFactRuntime._derive_state_write_anchor_lifecycle`, which\nemits :data:`FactStatus.STATE_CONST_REWRITTEN` mappings when the same\n``(block_serial, instruction_ea, state_var_stkoff)`` produces a different\n``state_const`` at a later maturity.\n\nllr-3b41 S8 -- per-collector port onto the canonical IR, following the proven\nS3 (:mod:`d810.analyses.value_flow.zero_blob`) / S4\n(:mod:`d810.analyses.value_flow.call_anchor`) / S5\n(:mod:`d810.analyses.control_flow.state_transition_anchor`) dual-currency\npattern.  A collector-local source iterator routes:\n\n* **meta-rich** sources -- a portable :class:`~d810.ir.flowgraph.FlowGraph`\n  block, or a diag row carrying a parseable ``meta`` operand tree -- through\n  the SAME canonical :func:`~d810.ir.insn_projection.project_diag_instruction`\n  / ``InstructionProjection.from_block`` projection.  ``dest_stkoff`` /\n  ``dest_size`` are then read off the canonical ``Instruction.result`` and\n  ``src_l_value`` off the first canonical input, so a state-write is anchored\n  on recovered stack/const semantics rather than opcode-table flat fields.\nThere is no meta-less fallback -- every production fact target is a canonical\n``FlowGraph``.\n\n``_block_succs`` / ``_block_start_ea_lookup`` / ``_DEST_VAR_RE`` are exported\nunchanged for reuse by the state_transition_anchor collector (S5).\n"

from __future__ import annotations

from collections.abc import Mapping
import re
from dataclasses import dataclass

from d810.capabilities.source_lifter import select_lifter
from d810.core.typing import Any, Iterable
from d810.ir.expressions import ValueOpKind
from d810.ir.instructions import Instruction
from d810.ir.insn_projection import (
    InstructionProjection,
)
from d810.ir.maturity import EARLY_FACT_COLLECTION_IR_MATURITIES
from d810.analyses.fact_collection_context import (
    FactCollectionContext,
    coerce_fact_collection_context,
    fact_provider_label,
)
from d810.analyses.value_flow.induction_carrier import (
    _canonical_opcode_name,
    _canonical_operands,
    _const_value_from_varnode,
    _reg_from_varnode,
    _size_from_varnode,
    _stkoff_from_varnode,
    _value_op_from_instruction,
)
from d810.analyses.value_flow.model import FactObservation
from d810.analyses.value_flow.contract_evidence import (
    ContractEvidenceToken,
    contract_evidence_payload,
)


_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES

# Capture ``%var_<HEX>.<SIZE>`` (with optional SSA brace suffix) so we can
# preserve the destination signature reported by IDA's ``dstr`` in fact
# evidence/payload.  The first capture is the offset hex; the second is the
# size suffix.
_DEST_VAR_RE = re.compile(
    r"%var_([0-9A-Fa-f]+)\.(\d+)(?:\{[^}]*\})?",
)
# A short opcode-only fingerprint of the block's instructions, used for
# correlation across maturities.
_OPCODE_FINGERPRINT_LIMIT = 8


@dataclass(frozen=True)
class _StateWriteInsn:
    """Uniform semantic view consumed by state_write_anchor.

    Built solely from a canonical :class:`~d810.ir.instructions.Instruction`
    (llr-3b41 S11 deleted the legacy meta-less flat path).  Exposes ONLY the fields this collector reads -- ``dest_stkoff`` /
    ``dest_size`` / ``src_l_value`` (the state-write operands) plus
    identity/evidence fields (``block_serial`` / ``insn_index`` / ``ea`` /
    ``opcode_name`` / ``dstr``).

    For the canonical path ``dest_stkoff`` / ``dest_size`` are read off
    ``Instruction.result`` (a ``Varnode`` in ``Space.STACK``; an unknown-offset
    stack dest collapses to ``Varnode(UNKNOWN)`` / ``WeakStackSlot`` and yields
    ``None`` for ``dest_stkoff``, matching legacy) and ``src_l_value`` is the
    const of the first canonical input (a ``Varnode`` in ``Space.CONST``; else
    ``None``).
    """

    block_serial: int
    insn_index: int
    ea: int | None
    opcode_name: str
    dstr: str
    dest_stkoff: int | None
    dest_reg: int | None
    dest_size: int | None
    src_l_value: int | None
    operation: ValueOpKind | None

    @classmethod
    def from_canonical(
        cls,
        *,
        block_serial: int,
        index: int,
        instruction: Instruction,
    ) -> "_StateWriteInsn":
        dest, left, _right = _canonical_operands(instruction)
        attrs = instruction.attrs
        ea_raw = attrs.get("ea")
        return cls(
            block_serial=int(block_serial),
            insn_index=int(index),
            ea=int(ea_raw) if ea_raw is not None else None,
            opcode_name=_canonical_opcode_name(instruction),
            dstr=str(attrs.get("display_text") or ""),
            dest_stkoff=_stkoff_from_varnode(dest),
            dest_reg=_reg_from_varnode(dest),
            dest_size=_size_from_varnode(dest),
            src_l_value=_const_value_from_varnode(left),
            operation=_value_op_from_instruction(instruction),
        )


@dataclass(frozen=True)
class _BlockStateWriteContext:
    """Per-block context captured once and reused across instructions."""

    serial: int
    succs: tuple[int, ...]
    opcode_fingerprint: str


def _block_succs(target: Any, block_serial: int) -> tuple[int, ...]:
    """Return successor serials for a block from a portable FlowGraph
    (``blocks`` mapping of ``BlockSnapshot`` with ``.succs``)."""
    blocks = getattr(target, "blocks", target)
    block_iter = blocks.values() if isinstance(blocks, Mapping) else blocks
    for blk in block_iter:
        try:
            if int(getattr(blk, "serial")) == int(block_serial):
                raw = getattr(blk, "succs", ()) or ()
                return tuple(int(succ) for succ in raw)
        except (TypeError, ValueError):
            continue
    return ()


def _iter_state_write_insns(target: Any) -> Iterable[_StateWriteInsn]:
    """Yield this collector's semantic record for every instruction in ``target``.

    Canonical-only (llr-3b41 S11): a meta-rich FlowGraph block is projected via
    ``InstructionProjection.from_block``; an offline diag row carrying a ``meta``
    operand tree is lifted via ``project_diag_instruction``.  The meta-less flat
    fallback was removed -- it was unreachable by any real source once every
    production fact target became a canonical ``FlowGraph``.  A registered live
    :class:`~d810.capabilities.source_lifter.SourceLifter` lifts a backend
    source to a portable flow graph first.
    """
    lifter = select_lifter(target)
    if lifter is not None:
        target = lifter.lift(target)

    blocks = getattr(target, "blocks", target)
    if isinstance(blocks, Mapping):
        block_iter = blocks.values()
    else:
        block_iter = blocks

    for blk in block_iter:
        block_serial = int(getattr(blk, "serial"))
        for index, instruction in enumerate(InstructionProjection.from_block(blk)):
            yield _StateWriteInsn.from_canonical(
                block_serial=block_serial,
                index=index,
                instruction=instruction,
            )


def _opcode_fingerprint(
    instructions: tuple[_StateWriteInsn, ...],
    block_serial: int,
) -> str:
    """Return a short opcode-only fingerprint for the block's first
    ``_OPCODE_FINGERPRINT_LIMIT`` instructions.

    Used as a correlation aid in the diag DB so SQL queries can match
    blocks across maturities even if serials shift slightly.
    """
    block_insns = [
        insn for insn in instructions if int(insn.block_serial) == int(block_serial)
    ]
    block_insns.sort(key=lambda insn: int(insn.insn_index))
    head = [
        str(insn.opcode_name or "") for insn in block_insns[:_OPCODE_FINGERPRINT_LIMIT]
    ]
    return "|".join(head)


def _dest_var_signature(insn: _StateWriteInsn) -> str | None:
    """Return the ``%var_<offset>.<size>`` signature parsed from the
    instruction's ``dstr`` representation, if present.

    The destination's stkoff already lives in
    :pyattr:`_StateWriteInsn.dest_stkoff`; this signature preserves the
    human-readable form (e.g. ``%var_7BC.4``) that downstream tools like
    the diag CLI display directly.
    """
    text = str(insn.dstr or "")
    match = _DEST_VAR_RE.search(text)
    if match is None:
        return None
    return f"%var_{match.group(1).upper()}.{match.group(2)}"


def _instruction_anchor_ea(
    insn: _StateWriteInsn,
    block_start_ea_by_serial: dict[int, int | None],
) -> int | None:
    """Return a stable EA for an instruction.

    Falls back to ``block_start_ea + insn_index`` when ``insn.ea`` is
    zero/missing so the lifecycle has SOMETHING to correlate on.  Synthetic
    EAs are still useful: they remain stable across maturities for the
    same ``(block_serial, insn_index)`` pair, which is the common case for
    state writers that ride along their original block.
    """
    if insn.ea is not None and int(insn.ea) != 0:
        return int(insn.ea)
    block_start = block_start_ea_by_serial.get(int(insn.block_serial))
    if block_start is None:
        return None
    return int(block_start) + int(insn.insn_index)


def _block_start_ea_lookup(target: Any) -> dict[int, int | None]:
    """Return a ``{block_serial: start_ea | None}`` map built from the
    snapshot/live target without re-iterating instructions."""
    lookup: dict[int, int | None] = {}
    blocks = getattr(target, "blocks", target)
    block_iter = blocks.values() if isinstance(blocks, Mapping) else blocks
    for blk in block_iter:
        try:
            serial = int(getattr(blk, "serial"))
        except (TypeError, ValueError):
            continue
        ea = getattr(blk, "start_ea", None)
        if ea is None:
            ea = getattr(blk, "start", None)
        try:
            lookup[serial] = int(ea) if ea is not None else None
        except (TypeError, ValueError):
            lookup[serial] = None
    return lookup


def _is_state_const_write(insn: _StateWriteInsn) -> bool:
    """Return ``True`` if ``insn`` writes a constant into state storage."""
    if insn.operation is not ValueOpKind.MOVE:
        return False
    if insn.dest_stkoff is None and insn.dest_reg is None:
        return False
    return insn.src_l_value is not None


def _iter_state_const_writes(
    instructions: tuple[_StateWriteInsn, ...],
) -> Iterable[_StateWriteInsn]:
    for insn in instructions:
        if _is_state_const_write(insn):
            yield insn


class StateWriteAnchorFactCollector:
    """Observe ``mov #const, %var_<stkoff>`` state-variable writes.

    The collector intentionally registers at every maturity in
    :data:`_TARGET_MATURITIES` (PREOPT, LOCOPT, CALLS, GLBOPT1).  The
    LOCOPT-pre observation captures the ORIGINAL constant; observations
    at later maturities allow the lifecycle runtime to detect rewrites
    via :class:`FactStatus.STATE_CONST_REWRITTEN` mappings.

    The collector is observability-only: it never modifies microcode and
    has no influence on planning or CFG mutation.
    """

    name = "StateWriteAnchorFactCollector"
    fact_kinds = frozenset({"StateWriteAnchorFact"})
    maturities = _TARGET_MATURITIES

    def collect(
        self,
        target: Any,
        *,
        context: FactCollectionContext | None = None,
        func_ea: int | None = None,
        phase: str = "pre_d810",
        **legacy_fields: Any,
    ) -> tuple[FactObservation, ...]:
        context = coerce_fact_collection_context(
            context,
            func_ea=func_ea,
            phase=phase,
            legacy_fields=legacy_fields,
        )
        phase = context.phase
        maturity_text = fact_provider_label(context)
        instructions = tuple(_iter_state_write_insns(target))
        if not instructions:
            return ()

        block_start_ea = _block_start_ea_lookup(target)

        # Cache per-block context so we don't recompute fingerprints for
        # blocks with multiple state writes.
        block_contexts: dict[int, _BlockStateWriteContext] = {}

        observations: list[FactObservation] = []
        # Dedupe using ``(block_serial, insn_index, anchor_ea, storage)``.
        seen: set[tuple[int, int, int, str, int]] = set()

        for insn in _iter_state_const_writes(instructions):
            block_serial = int(insn.block_serial)
            if insn.dest_stkoff is not None:
                storage_kind, storage_offset = "stk", int(insn.dest_stkoff)
            elif insn.dest_reg is not None:
                storage_kind, storage_offset = "reg", int(insn.dest_reg)
            else:
                continue
            anchor_ea = _instruction_anchor_ea(insn, block_start_ea)
            if anchor_ea is None:
                # Without a stable EA we can't anchor the lifecycle row.
                continue
            dedupe = (
                block_serial,
                int(insn.insn_index),
                int(anchor_ea),
                storage_kind,
                storage_offset,
            )
            if dedupe in seen:
                continue
            seen.add(dedupe)

            ctx = block_contexts.get(block_serial)
            if ctx is None:
                ctx = _BlockStateWriteContext(
                    serial=block_serial,
                    succs=_block_succs(target, block_serial),
                    opcode_fingerprint=_opcode_fingerprint(instructions, block_serial),
                )
                block_contexts[block_serial] = ctx

            const_value = int(insn.src_l_value or 0)
            const_value_u64 = const_value & 0xFFFFFFFFFFFFFFFF
            dest_var_signature = _dest_var_signature(insn)
            dest_size = int(insn.dest_size or 0)

            # Semantic key intentionally excludes ``state_const`` so the
            # fact_id remains stable across maturities for the SAME write
            # site, while the payload preserves the per-maturity constant
            # for the lifecycle to compare on.
            storage_key = (
                f"stkoff=0x{storage_offset:x}"
                if storage_kind == "stk"
                else f"reg={storage_offset}"
            )
            semantic_key = (
                f"state_write_anchor:blk={block_serial}:"
                f"insn={int(insn.insn_index)}:"
                f"ea=0x{int(anchor_ea):x}:"
                f"{storage_key}"
            )
            fact_id = semantic_key
            payload: dict[str, Any] = {
                "state_const_hex": f"0x{const_value_u64:016x}",
                "state_const_u64": const_value_u64,
                "state_const": const_value_u64,
                "block_serial": block_serial,
                "instruction_index": int(insn.insn_index),
                "instruction_ea_hex": f"0x{int(anchor_ea) & 0xFFFFFFFFFFFFFFFF:016x}",
                "instruction_ea": int(anchor_ea),
                "state_var_stkoff": (storage_offset if storage_kind == "stk" else None),
                "state_var_stkoff_hex": (
                    f"0x{storage_offset:x}" if storage_kind == "stk" else None
                ),
                "dest_var_signature": dest_var_signature,
                "dest_size": dest_size,
                "block_dstr": ctx.opcode_fingerprint,
                "successor_blocks": list(ctx.succs),
                "opcode": insn.opcode_name,
                **contract_evidence_payload(
                    ContractEvidenceToken.STATE_VARIABLE_WRITES
                ),
            }
            if storage_kind == "reg":
                payload["state_var_reg"] = storage_offset

            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="StateWriteAnchorFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.9,
                    source_block=block_serial,
                    source_ea=int(anchor_ea),
                    block_fingerprint=(
                        f"blk[{block_serial}].{int(insn.insn_index)}:{insn.opcode_name}"
                    ),
                    mop_signature=(
                        f"state_write:mop_S:0x{storage_offset:x}:{dest_size}"
                        if storage_kind == "stk"
                        else f"state_write:mop_r:{storage_offset}:{dest_size}"
                    ),
                    payload=payload,
                    evidence=(insn.dstr,),
                )
            )
        return tuple(observations)


__all__ = ["StateWriteAnchorFactCollector"]
