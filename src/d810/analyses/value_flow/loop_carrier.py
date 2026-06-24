"""Loop-carrier fact collector.

This collector observes conditional loop predicates whose input stack
variables are derived from a common carrier stack variable, then classifies
whether that carrier has a writer inside the predicate's loop SCC.

The motivating ``sub_7FFD3338C040`` case is the terminal byte loop rendered
by Hex-Rays as ``for (i = ...; i + v11 == v12; ...)``.  The predicate inputs
(``i``, ``v11``, ``v12``) are recomputed from carrier ``v22`` / ``%var_3A8``,
but the post-HCC loop back-edges reach the predicate without traversing a
``%var_3A8`` writer.  This fact records that as
``LOOP_CARRIER_WRITER_OUTSIDE_SCC`` without changing CFG or planning.
"""
from __future__ import annotations

from collections.abc import Mapping
from collections import Counter
from dataclasses import dataclass

from d810.core.typing import Any
from d810.ir.directed_graph import tarjan_scc as _canonical_tarjan_scc
from d810.ir.maturity import EARLY_FACT_COLLECTION_IR_MATURITIES
from d810.ir.semantics import ControlTransferKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.analyses.fact_collection_context import (
    FactCollectionContext,
    coerce_fact_collection_context,
    fact_provider_label,
)
from d810.analyses.value_flow.induction_carrier import (
    _InstructionView,
    _iter_instruction_views,
)
from d810.analyses.value_flow.state_write_anchor import (
    _block_start_ea_lookup,
    _block_succs,
    _instruction_anchor_ea,
)
from d810.analyses.value_flow.model import FactObservation


_TARGET_MATURITIES = EARLY_FACT_COLLECTION_IR_MATURITIES

@dataclass(frozen=True)
class _CarrierCandidate:
    identity: StorageIdentity
    source_readers: tuple[_InstructionView, ...]
    writers: tuple[_InstructionView, ...]


def _stack_identity(stkoff: int | None) -> StorageIdentity | None:
    if stkoff is None:
        return None
    return StorageIdentity(kind=StorageIdentityKind.STACK, offset=int(stkoff))


def _identity_keys(identities: tuple[StorageIdentity, ...]) -> tuple[str, ...]:
    return tuple(identity.key for identity in identities)


def _dest_identity(insn: _InstructionView) -> StorageIdentity | None:
    """Return the canonical storage identity written by ``insn``, if any."""
    return _stack_identity(insn.dest_stkoff)


def _merge_stkoffs(*groups: tuple[int, ...]) -> tuple[int, ...]:
    seen: set[int] = set()
    merged: list[int] = []
    for group in groups:
        for offset in group:
            value = int(offset)
            if value in seen:
                continue
            seen.add(value)
            merged.append(value)
    return tuple(merged)


def _expanded_source_stkoffs(
    insn: _InstructionView,
    temp_source_stkoffs: dict[tuple[int, int], tuple[int, ...]],
) -> tuple[int, ...]:
    temp_sources = tuple(
        offset
        for temp in insn.src_temps
        for offset in temp_source_stkoffs.get((int(insn.block_serial), int(temp)), ())
    )
    return _merge_stkoffs(tuple(int(offset) for offset in insn.source_stkoffs), temp_sources)


def _source_identities(
    insn: _InstructionView,
    temp_source_stkoffs: dict[tuple[int, int], tuple[int, ...]],
) -> tuple[StorageIdentity, ...]:
    return tuple(
        identity
        for offset in _expanded_source_stkoffs(insn, temp_source_stkoffs)
        if (identity := _stack_identity(offset)) is not None
    )


def _temp_source_stkoff_lookup(
    instructions: tuple[_InstructionView, ...],
) -> dict[tuple[int, int], tuple[int, ...]]:
    """Return source-stack identities for temp-producing canonical records."""
    lookup: dict[tuple[int, int], tuple[int, ...]] = {}
    ordered = sorted(instructions, key=lambda insn: (int(insn.block_serial), int(insn.insn_index)))
    for insn in ordered:
        if insn.dest_temp is None:
            continue
        lookup[(int(insn.block_serial), int(insn.dest_temp))] = _expanded_source_stkoffs(
            insn,
            lookup,
        )
    return lookup


def _is_conditional_jump(insn: _InstructionView) -> bool:
    return insn.control_transfer is ControlTransferKind.CONDITIONAL_BRANCH


def _all_block_serials(target: Any) -> tuple[int, ...]:
    if hasattr(target, "qty") and hasattr(target, "get_mblock"):
        try:
            return tuple(range(int(getattr(target, "qty", 0) or 0)))
        except (TypeError, ValueError):
            return ()

    blocks = getattr(target, "blocks", target)
    block_iter = blocks.values() if isinstance(blocks, Mapping) else blocks
    serials: list[int] = []
    for blk in block_iter:
        try:
            serials.append(int(getattr(blk, "serial")))
        except (TypeError, ValueError):
            continue
    return tuple(sorted(set(serials)))


def _succs_by_block(target: Any) -> dict[int, tuple[int, ...]]:
    return {serial: _block_succs(target, serial) for serial in _all_block_serials(target)}


def _strongly_connected_components(
    succs_by_block: dict[int, tuple[int, ...]],
) -> tuple[tuple[int, ...], ...]:
    """Tarjan SCC over the block graph (keys-only nodes), as a tuple of
    sorted-tuple components.

    Delegates to the canonical ``d810.ir.directed_graph.tarjan_scc``;
    successors not present as keys are not treated as nodes, and each component
    is a sorted tuple (historical semantics preserved).
    """
    keys = set(succs_by_block)
    adj = {
        node: tuple(s for s in succs if s in keys)
        for node, succs in succs_by_block.items()
    }
    return tuple(tuple(sorted(component)) for component in _canonical_tarjan_scc(adj))


def _loop_scc_by_block(
    succs_by_block: dict[int, tuple[int, ...]],
) -> dict[int, tuple[int, ...]]:
    result: dict[int, tuple[int, ...]] = {}
    for component in _strongly_connected_components(succs_by_block):
        is_loop = len(component) > 1 or any(
            block in succs_by_block.get(block, ()) for block in component
        )
        if not is_loop:
            continue
        for block in component:
            result[int(block)] = component
    return result


def _candidate_carriers_for_predicate(
    predicate_vars: tuple[StorageIdentity, ...],
    writers_by_dest_identity: dict[StorageIdentity, list[_InstructionView]],
    temp_source_stkoffs: dict[tuple[int, int], tuple[int, ...]],
) -> tuple[_CarrierCandidate, ...]:
    readers_by_source_identity: dict[StorageIdentity, list[_InstructionView]] = {}
    for predicate_var in predicate_vars:
        for writer in writers_by_dest_identity.get(predicate_var, ()):
            for source_identity in _source_identities(writer, temp_source_stkoffs):
                if source_identity == predicate_var:
                    continue
                readers_by_source_identity.setdefault(source_identity, []).append(writer)

    candidates: list[_CarrierCandidate] = []
    for identity, readers in sorted(
        readers_by_source_identity.items(),
        key=lambda item: item[0].key,
    ):
        # The sub_7FFD carrier is shared across multiple predicate-input
        # writers.  Requiring two readers keeps the collector away from
        # incidental one-off stack temporaries.
        unique_reader_dests = {
            _dest_identity(reader)
            for reader in readers
            if _dest_identity(reader) is not None
        }
        if len(unique_reader_dests) < 2:
            continue
        carrier_writers = tuple(writers_by_dest_identity.get(identity, ()))
        if not carrier_writers:
            continue
        candidates.append(
            _CarrierCandidate(
                identity=identity,
                source_readers=tuple(readers),
                writers=carrier_writers,
            )
        )
    return tuple(candidates)


def _carrier_stkoff(writers: tuple[_InstructionView, ...]) -> int | None:
    counts: Counter[int] = Counter()
    for writer in writers:
        if writer.dest_stkoff is not None:
            counts[int(writer.dest_stkoff)] += 1
    if not counts:
        return None
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


class LoopPredicateValueFactCollector:
    """Observe loop predicates whose carrier writer is outside the loop SCC.

    Canonical collector class name for loop-predicate source evidence.
    Raw observations still serialize as ``LoopCarrierFact`` because that is the
    source ontology produced by this collector; projected value-flow facts
    serialize as ``LoopPredicateValueFact``.
    """

    name = "LoopPredicateValueFactCollector"
    fact_kinds = frozenset({"LoopCarrierFact"})
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
        instructions = tuple(_iter_instruction_views(target))
        if not instructions:
            return ()

        succs = _succs_by_block(target)
        loop_scc = _loop_scc_by_block(succs)
        if not loop_scc:
            return ()

        temp_source_stkoffs = _temp_source_stkoff_lookup(instructions)
        writers_by_dest_identity: dict[StorageIdentity, list[_InstructionView]] = {}
        for insn in instructions:
            identity = _dest_identity(insn)
            if identity is None:
                continue
            if insn.dest_type != "mop_S" and insn.dest_stkoff is None:
                continue
            writers_by_dest_identity.setdefault(identity, []).append(insn)
        for writers in writers_by_dest_identity.values():
            writers.sort(key=lambda item: (int(item.block_serial), int(item.insn_index)))

        block_start_ea = _block_start_ea_lookup(target)
        observations: list[FactObservation] = []
        seen: set[tuple[int, int, str]] = set()

        for insn in instructions:
            if not _is_conditional_jump(insn):
                continue
            predicate_block = int(insn.block_serial)
            component = loop_scc.get(predicate_block)
            if component is None:
                continue

            predicate_vars = _source_identities(insn, temp_source_stkoffs)
            if len(predicate_vars) < 2:
                continue

            for candidate in _candidate_carriers_for_predicate(
                predicate_vars,
                writers_by_dest_identity,
                temp_source_stkoffs,
            ):
                dedupe = (predicate_block, int(insn.insn_index), candidate.identity.key)
                if dedupe in seen:
                    continue
                seen.add(dedupe)

                writer_blocks = tuple(
                    sorted({int(writer.block_serial) for writer in candidate.writers})
                )
                in_loop_blocks = tuple(block for block in writer_blocks if block in component)
                outside_loop_blocks = tuple(
                    block for block in writer_blocks if block not in component
                )
                if in_loop_blocks:
                    classification = "LOOP_CARRIER_WRITER_IN_SCC"
                elif outside_loop_blocks:
                    classification = "LOOP_CARRIER_WRITER_OUTSIDE_SCC"
                else:
                    classification = "LOOP_CARRIER_WRITER_UNKNOWN"

                predicate_ea = _instruction_anchor_ea(insn, block_start_ea)
                reader_blocks = tuple(
                    sorted({int(reader.block_serial) for reader in candidate.source_readers})
                )
                carrier_stkoff = _carrier_stkoff(candidate.writers)
                semantic_key = (
                    f"loop_carrier:predicate_blk={predicate_block}:"
                    f"insn={int(insn.insn_index)}:"
                    f"carrier={candidate.identity.key}:maturity={maturity_text}:phase={phase}"
                )
                predicate_storage_keys = _identity_keys(predicate_vars)

                payload: dict[str, Any] = {
                    "classification": classification,
                    "predicate_block_serial": predicate_block,
                    "predicate_instruction_index": int(insn.insn_index),
                    "predicate_instruction_ea": predicate_ea,
                    "predicate_instruction_ea_hex": (
                        f"0x{int(predicate_ea) & 0xFFFFFFFFFFFFFFFF:016x}"
                        if predicate_ea is not None
                        else None
                    ),
                    "predicate_dstr": insn.dstr,
                    "predicate_var_tokens": list(predicate_storage_keys),
                    "predicate_storage_keys": list(predicate_storage_keys),
                    "carrier_var_token": candidate.identity.key,
                    "carrier_storage_identity": candidate.identity.to_record(),
                    "carrier_stkoff": carrier_stkoff,
                    "carrier_stkoff_hex": (
                        f"0x{carrier_stkoff:x}" if carrier_stkoff is not None else None
                    ),
                    "carrier_writer_blocks": list(writer_blocks),
                    "carrier_writer_blocks_in_loop": list(in_loop_blocks),
                    "carrier_writer_blocks_outside_loop": list(outside_loop_blocks),
                    "carrier_writer_eas": [
                        _instruction_anchor_ea(writer, block_start_ea)
                        for writer in candidate.writers
                    ],
                    "carrier_writer_dstrs": [
                        writer.dstr for writer in candidate.writers
                    ],
                    "carrier_reader_blocks": list(reader_blocks),
                    "carrier_reader_dstrs": [
                        reader.dstr for reader in candidate.source_readers
                    ],
                    "loop_scc_blocks": list(component),
                }

                evidence = (
                    insn.dstr,
                    *(reader.dstr for reader in candidate.source_readers[:4]),
                    *(writer.dstr for writer in candidate.writers[:4]),
                )
                observations.append(
                    FactObservation(
                        fact_id=semantic_key,
                        kind="LoopCarrierFact",
                        semantic_key=semantic_key,
                        maturity=maturity_text,
                        phase=phase,
                        confidence=0.80,
                        source_block=predicate_block,
                        source_ea=predicate_ea,
                        block_fingerprint=(
                            f"blk[{predicate_block}].{int(insn.insn_index)}:"
                            f"{insn.opcode_name}"
                        ),
                        mop_signature=(
                            f"loop_carrier:{candidate.identity.key}:"
                            f"{classification}:predicate_blk={predicate_block}"
                        ),
                        payload=payload,
                        evidence=evidence,
                    )
                )

        return tuple(observations)


__all__ = ["LoopPredicateValueFactCollector"]
