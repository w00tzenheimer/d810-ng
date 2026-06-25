"""Return-carrier fact collector.

This collector observes writes into the microcode return-slot carrier before
later optimizer passes can inline, fold, or sever the carrier identity.  It is
diagnostic only: it records facts for the maturity lifecycle and does not make
planner or CFG decisions.

When the return-slot write's source is a stkvar ``K`` (a one-step
``stack_identity_carrier``), the collector also performs a single-step backward
trace to locate the upstream instruction that defines ``K`` and records that
instruction's EA, block, opcode, full dstr, and source storage identities. Later
passes consult this payload at GLBOPT1+ to know that a target block / stkvar set
corresponds to a return-carrier MBA materialization site even after IDA's CALLS
phase has folded the canonical ``add ... -> %var_K; mov %var_K -> %var_8``
chain into a sub-instruction operand tree.

llr-3b41 (missed 9th collector) -- this collector now consumes the canonical
:class:`~d810.ir.instructions.Instruction` IR through a collector-local
dual-currency iterator (:func:`_iter_return_carrier_insns`), following the proven
S3 (:mod:`d810.analyses.value_flow.zero_blob`) .. S9
(:mod:`d810.analyses.value_flow.induction_carrier`) pattern.  return_carrier reads
the full operand surface (return-register reads, stack-identity carrier movs,
constant/computed return writers, and a positional upstream-writer walk), so the
canonical :class:`_InstructionView` is the right currency -- a narrower
per-collector adapter would only re-expose the same fields.  Like S9, this reuses
induction_carrier's SHARED :func:`_instruction_view_from_canonical` /
:func:`_legacy_view_from_diag_row` directly: a portable
:class:`~d810.ir.flowgraph.FlowGraph` block or a diag row carrying a parseable
``meta`` operand tree is projected to a canonical ``Instruction`` and adapted to
the canonical :class:`_InstructionView`; meta-less rows stay on the byte-identical
legacy flat path (gated by ``diag_row_has_operand_tree``).  This routes the
collector through the canonical projection WITHOUT touching the shared
:func:`_iter_instruction_views` the not-yet-ported ``ollvm_carrier_profile``
(S10) still depends on.
"""
from __future__ import annotations

from collections.abc import Mapping

from d810.capabilities.source_lifter import select_lifter
from d810.core.typing import Any, Iterable
from d810.ir.expressions import ValueOpKind
from d810.ir.insn_projection import (
    InstructionProjection,
    diag_row_has_operand_tree,
    project_diag_instruction,
)
from d810.ir.maturity import EARLY_FACT_COLLECTION_IR_MATURITIES
from d810.analyses.fact_collection_context import (
    FactCollectionContext,
    coerce_fact_collection_context,
    fact_provider_label,
)
from d810.analyses.value_flow.induction_carrier import (
    _InstructionView,
    _instruction_view_from_canonical,
    _legacy_view_from_diag_row,
    _operation_of_view,
)
from d810.analyses.value_flow import (
    RETURN_VALUE_FACT_TYPE,
    project_value_flow_facts,
)
from d810.analyses.value_flow.model import FactObservation


_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES

# Current live evidence is x86-64 Hex-Rays microcode, where IDA uses register
# id 0 for the integer return register (rax/eax). Keep this as a structural
# register identity instead of parsing the rendered "rax" spelling.
_INTEGER_RETURN_REGISTER_IDS = frozenset({0})


def _iter_return_carrier_insns(target: Any) -> Iterable[_InstructionView]:
    """Yield return_carrier's dual-currency instruction views.

    llr-3b41 (missed 9th collector) -- the per-collector port of
    return_carrier onto the canonical IR, following the proven S3
    (:mod:`d810.analyses.value_flow.zero_blob`) .. S9
    (:mod:`d810.analyses.value_flow.induction_carrier`) dual-currency pattern.

    Because return_carrier reads the full operand surface (return-register
    reads, stack-identity carrier movs, constant/computed return writers, and a
    positional upstream-writer walk), the canonical :class:`_InstructionView` is
    the right currency, so this iterator reuses induction_carrier's SHARED
    :func:`_instruction_view_from_canonical` / :func:`_legacy_view_from_diag_row`
    helpers directly rather than duplicating a narrower adapter: meta-rich
    sources -- a portable :class:`~d810.ir.flowgraph.FlowGraph` block (via
    ``InstructionProjection.from_block``) or a diag row carrying a parseable
    ``meta`` operand tree (via
    :func:`~d810.ir.insn_projection.project_diag_instruction`) -- are projected
    to a canonical :class:`~d810.ir.instructions.Instruction` and adapted to the
    canonical :class:`_InstructionView` the return-carrier classifiers consume;
    meta-less rows stay on the byte-identical legacy flat path
    (:func:`_legacy_view_from_diag_row`, gated by ``diag_row_has_operand_tree``).

    A registered live :class:`~d810.capabilities.source_lifter.SourceLifter`
    lifts a backend source to a portable flow graph first (behaviour-identical
    to no-lifter when none is registered) -- preserving the pre-port behaviour of
    the shared :func:`_iter_instruction_views` this replaces.  This routes the
    collector through the canonical projection WITHOUT touching that shared
    iterator the not-yet-ported ``ollvm_carrier_profile`` (S10) still depends on.
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
        if getattr(blk, "insn_snapshots", None) is not None:
            for index, instruction in enumerate(InstructionProjection.from_block(blk)):
                yield _instruction_view_from_canonical(
                    block_serial=block_serial,
                    index=index,
                    instruction=instruction,
                )
            continue
        for index, insn in enumerate(getattr(blk, "instructions", ())):
            if diag_row_has_operand_tree(insn):
                yield _instruction_view_from_canonical(
                    block_serial=block_serial,
                    index=int(getattr(insn, "index", index)),
                    instruction=project_diag_instruction(insn),
                )
                continue
            yield _legacy_view_from_diag_row(block_serial, index, insn)


def _is_return_register_read(insn: _InstructionView) -> bool:
    if _operation_of_view(insn) is not ValueOpKind.MOVE:
        return False
    if insn.src_l_stkoff is None:
        return False
    if insn.dest_reg not in _INTEGER_RETURN_REGISTER_IDS:
        return False
    return True


def _return_slot_offsets(instructions: tuple[_InstructionView, ...]) -> frozenset[int]:
    return frozenset(
        int(insn.src_l_stkoff)
        for insn in instructions
        if _is_return_register_read(insn)
    )


def _source_signature(insn: _InstructionView) -> str:
    if insn.src_l_stkoff is not None:
        return f"{insn.src_l_type or 'src_l'}:0x{int(insn.src_l_stkoff):x}"
    if insn.src_l_value is not None:
        return f"const:0x{int(insn.src_l_value):x}"
    if insn.src_r_stkoff is not None:
        return f"{insn.src_r_type or 'src_r'}:0x{int(insn.src_r_stkoff):x}"
    if insn.src_r_value is not None:
        return f"const:0x{int(insn.src_r_value):x}"
    return "computed"


def _find_upstream_writer(
    instructions: tuple[_InstructionView, ...],
    target_stkoff: int,
    *,
    exclude: _InstructionView | None = None,
) -> _InstructionView | None:
    """Return the LAST instruction PRECEDING ``exclude`` in iteration
    order that writes ``target_stkoff`` with ``mop_S`` dest, or
    ``None`` if no such writer exists or ``exclude`` is missing.

    Iteration order from :func:`_iter_return_carrier_insns` walks blocks
    in serial-ascending order and instructions in ``insn_index`` order.
    For a carrier-mov at position P, only writers strictly preceding P
    are considered.  This avoids picking a function-wide LAST writer
    that has no def/use relationship with the carrier-mov: previously
    the function picked the last writer regardless of its position, so
    on functions with many writers to the same return-carrier slot the
    fact ended up pointing at an arbitrary later block instead of the
    actual canonical producer.

    Concrete observation: on ``sub_7FFD3338C040`` the canonical
    return-carrier MBA at block 140 EA ``0x180014333`` precedes the
    trampoline ``mov %var_7C8, %var_8`` at block 141 EA
    ``0x1800143c5``; the older "function-wide LAST" heuristic skipped
    block 140 because block 254 EA ``0x180015e84`` also writes
    ``%var_7C8`` (a different MBA with shorter ``var_refs``) later in
    iteration order.  Scoping by iteration position is sufficient to
    recover the canonical producer in both cases: when a carrier-mov
    ``mov %var_K, %var_8`` is reached, every reaching def of
    ``%var_K`` lies earlier in the function-wide iteration (because
    ``_iter_return_carrier_insns`` walks blocks in topological order for
    the captured snapshot).  Multi-step chains and CFG-aware
    reaching-def analysis remain follow-up work.
    """
    if exclude is None:
        return None
    anchor_block = int(exclude.block_serial)
    anchor_index = int(exclude.insn_index)
    last: _InstructionView | None = None
    for insn in instructions:
        ins_block = int(insn.block_serial)
        ins_idx = int(insn.insn_index)
        # Stop at or past the carrier-mov: writers at the same block
        # AFTER the carrier-mov cannot be its reaching def, and writers
        # in higher-numbered blocks come after the carrier-mov in the
        # function-wide iteration order.
        if ins_block > anchor_block:
            break
        if ins_block == anchor_block and ins_idx >= anchor_index:
            break
        if insn.dest_stkoff is None:
            continue
        if int(insn.dest_stkoff) != int(target_stkoff):
            continue
        last = insn
    return last


def _stack_storage_key(offset: int) -> str:
    return f"S{int(offset)}"


def _stack_storage_record(offset: int) -> dict[str, int | str]:
    return {
        "kind": "stack",
        "prefix": "S",
        "offset": int(offset),
        "key": _stack_storage_key(offset),
    }


def _source_storage_offsets(insn: _InstructionView) -> tuple[int, ...]:
    seen: set[int] = set()
    offsets: list[int] = []
    for offset in (
        *insn.source_stkoffs,
        insn.src_l_stkoff,
        insn.src_r_stkoff,
    ):
        if offset is None:
            continue
        value = int(offset)
        if value in seen:
            continue
        seen.add(value)
        offsets.append(value)
    return tuple(offsets)


def _carrier_class(insn: _InstructionView) -> str:
    operation = _operation_of_view(insn)
    if operation is ValueOpKind.ZEXT:
        return "protected_non_carrier_return_writer_candidate"
    if operation is ValueOpKind.MOVE and insn.src_l_stkoff is not None:
        return "stack_identity_carrier"
    if insn.src_l_value is not None or insn.src_r_value is not None:
        return "constant_or_offset_return"
    return "computed_return"


class ReturnSlotFactCollector:
    """Observe return-slot writes across maturities.

    Canonical class name (value-flow rename Phase 4). Tracks the storage
    slot used to communicate a function's return value at the ABI
    boundary (e.g. ``%var_8.8`` for stack-returned aggregates). The peer
    class :class:`ReturnValueFactCollector` projects those observations
    into canonical return-value value-flow facts when a caller wants the
    normalized family directly.

    Raw observations still serialize as ``ReturnCarrierFact`` because that is
    the source ontology produced by this collector. Projected value-flow facts
    serialize as ``MaterializationPointFact``,
    ``MemoryUseFact``, and ``ReturnValueFact``.
    """

    name = "ReturnSlotFactCollector"
    fact_kinds = frozenset({"ReturnCarrierFact"})
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
        instructions = tuple(_iter_return_carrier_insns(target))
        return_slots = _return_slot_offsets(instructions)
        if not return_slots:
            return ()

        observations: list[FactObservation] = []
        seen: set[tuple[int, int, int]] = set()
        for insn in instructions:
            if insn.dest_stkoff is None or int(insn.dest_stkoff) not in return_slots:
                continue
            dest_size = int(insn.dest_size or 0)
            dedupe = (insn.block_serial, insn.insn_index, int(insn.dest_stkoff))
            if dedupe in seen:
                continue
            seen.add(dedupe)

            slot = int(insn.dest_stkoff)
            source = _source_signature(insn)
            carrier_class = _carrier_class(insn)
            semantic_key = (
                f"return_carrier:slot=0x{slot:x}:class={carrier_class}:"
                f"source={source}"
            )
            fact_id = (
                f"{semantic_key}:blk={insn.block_serial}:"
                f"insn={insn.insn_index}:ea=0x{int(insn.ea or 0):x}"
            )
            payload: dict[str, Any] = {
                "return_slot_stkoff": slot,
                "return_slot_storage_key": _stack_storage_key(slot),
                "return_slot_storage_identity": _stack_storage_record(slot),
                "dest_size": dest_size,
                "opcode": insn.opcode_name,
                "carrier_class": carrier_class,
                "source_signature": source,
                "source_l_type": insn.src_l_type,
                "source_l_stkoff": insn.src_l_stkoff,
                "source_l_value": insn.src_l_value,
                "source_r_type": insn.src_r_type,
                "source_r_stkoff": insn.src_r_stkoff,
                "source_r_value": insn.src_r_value,
                "block_serial": insn.block_serial,
                "insn_index": insn.insn_index,
            }

            # When the carrier is a stack identity (the canonical
            # OLLVM ``mov %var_K -> %var_8`` trampoline), record the
            # upstream instruction that defines ``%var_K``.  This
            # captures the return-carrier MBA's identity *before* IDA's
            # CALLS phase folds the chain into a sub-instruction
            # operand tree, so later GLBOPT1 consumers can recognise
            # the materialization site even when its canonical form
            # has been erased.
            evidence: tuple[str, ...] = (insn.dstr,)
            if (
                carrier_class == "stack_identity_carrier"
                and insn.src_l_stkoff is not None
            ):
                upstream = _find_upstream_writer(
                    instructions,
                    int(insn.src_l_stkoff),
                    exclude=insn,
                )
                if upstream is not None:
                    upstream_source_offsets = _source_storage_offsets(upstream)
                    upstream_source_keys = tuple(
                        _stack_storage_key(offset)
                        for offset in upstream_source_offsets
                    )
                    payload.update({
                        "carrier_dst_stkoff": int(insn.src_l_stkoff),
                        "carrier_dst_storage_key": _stack_storage_key(
                            int(insn.src_l_stkoff)
                        ),
                        "carrier_dst_storage_identity": _stack_storage_record(
                            int(insn.src_l_stkoff)
                        ),
                        "upstream_writer_block_serial": upstream.block_serial,
                        "upstream_writer_insn_index": upstream.insn_index,
                        "upstream_writer_ea": upstream.ea,
                        "upstream_writer_opcode": upstream.opcode_name,
                        "upstream_writer_dest_stkoff": upstream.dest_stkoff,
                        "upstream_writer_dest_storage_key": (
                            _stack_storage_key(upstream.dest_stkoff)
                            if upstream.dest_stkoff is not None
                            else None
                        ),
                        "upstream_writer_dest_storage_identity": (
                            _stack_storage_record(upstream.dest_stkoff)
                            if upstream.dest_stkoff is not None
                            else None
                        ),
                        "upstream_writer_dstr": upstream.dstr,
                        "upstream_writer_source_storage_keys": list(
                            upstream_source_keys
                        ),
                        "upstream_writer_source_storage_identities": [
                            _stack_storage_record(offset)
                            for offset in upstream_source_offsets
                        ],
                    })
                    evidence = (insn.dstr, upstream.dstr)

            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="ReturnCarrierFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.86,
                    source_block=insn.block_serial,
                    source_ea=insn.ea,
                    block_fingerprint=(
                        f"blk[{insn.block_serial}].{insn.insn_index}:"
                        f"{insn.opcode_name}"
                    ),
                    mop_signature=f"return_slot:mop_S:0x{slot:x}:{dest_size}",
                    payload=payload,
                    evidence=evidence,
                )
            )
        return tuple(observations)


__all__ = [
    "ReturnSlotFactCollector",
    "ReturnValueFactCollector",
]


class ReturnValueFactCollector:
    """Collect canonical facts about the recovered return value.

    Distinct from :class:`ReturnSlotFactCollector`, which records facts
    about the storage slot. This collector reuses the same Hodur
    return-slot evidence and returns only the normalized ``ReturnValueFact``
    projection.
    """

    name = "ReturnValueFactCollector"
    fact_kinds: frozenset[str] = frozenset({RETURN_VALUE_FACT_TYPE})
    maturities = _TARGET_MATURITIES

    def __init__(self) -> None:
        self._slot_collector = ReturnSlotFactCollector()

    def collect(
        self,
        target: object,
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
        projected = project_value_flow_facts(self._slot_collector.collect(
            target,
            context=context,
        ))
        return tuple(fact for fact in projected if fact.kind == RETURN_VALUE_FACT_TYPE)
