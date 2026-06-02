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
import re

from d810.core.typing import Any
from d810.ir.directed_graph import tarjan_scc as _canonical_tarjan_scc
from d810.analyses.value_flow.induction_carrier import (
    _MATURITY_VALUES,
    _InstructionView,
    _iter_instruction_views,
    _maturity_name,
)
from d810.analyses.value_flow.state_write_anchor import (
    _block_start_ea_lookup,
    _block_succs,
    _instruction_anchor_ea,
)
from d810.analyses.value_flow.model import FactObservation


_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
})

_CONDITIONAL_OPCODES = frozenset({"m_jnz", "m_jz", "equality_jump", "cond_jump"})
_VAR_TOKEN_RE = re.compile(r"%var_([0-9A-Fa-f]+)\.\d+(?:\{[^}]*\})?")


@dataclass(frozen=True)
class _CarrierCandidate:
    token: str
    source_readers: tuple[_InstructionView, ...]
    writers: tuple[_InstructionView, ...]


def _var_tokens(text: str) -> tuple[str, ...]:
    """Return normalized ``%var_<HEX>`` tokens from an instruction string."""
    return tuple(f"%var_{match.group(1).upper()}" for match in _VAR_TOKEN_RE.finditer(text))


def _dest_token(insn: _InstructionView) -> str | None:
    """Return the destination stack-var token from ``insn.dstr``.

    Hex-Rays microcode ``dstr`` renders operands in source...,dest order for
    the stack writes relevant here.  The last stack-var token is therefore the
    human-readable destination token (for example ``%var_3A8``).
    """
    tokens = _var_tokens(insn.dstr)
    if not tokens:
        return None
    return tokens[-1]


def _source_tokens(insn: _InstructionView) -> tuple[str, ...]:
    tokens = _var_tokens(insn.dstr)
    if len(tokens) <= 1:
        return ()
    return tokens[:-1]


def _is_conditional_jump(insn: _InstructionView) -> bool:
    if insn.opcode_name in _CONDITIONAL_OPCODES:
        return True
    text = str(insn.dstr or "").lstrip().lower()
    return text.startswith("jnz ") or text.startswith("jz ")


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
    predicate_vars: tuple[str, ...],
    writers_by_dest_token: dict[str, list[_InstructionView]],
) -> tuple[_CarrierCandidate, ...]:
    readers_by_source_token: dict[str, list[_InstructionView]] = {}
    for predicate_var in predicate_vars:
        for writer in writers_by_dest_token.get(predicate_var, ()):
            for source_token in _source_tokens(writer):
                if source_token == predicate_var:
                    continue
                readers_by_source_token.setdefault(source_token, []).append(writer)

    candidates: list[_CarrierCandidate] = []
    for token, readers in sorted(readers_by_source_token.items()):
        # The sub_7FFD carrier is shared across multiple predicate-input
        # writers.  Requiring two readers keeps the collector away from
        # incidental one-off stack temporaries.
        unique_reader_dests = {
            _dest_token(reader)
            for reader in readers
            if _dest_token(reader) is not None
        }
        if len(unique_reader_dests) < 2:
            continue
        carrier_writers = tuple(writers_by_dest_token.get(token, ()))
        if not carrier_writers:
            continue
        candidates.append(
            _CarrierCandidate(
                token=token,
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
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> tuple[FactObservation, ...]:
        maturity_text = _maturity_name(maturity)
        instructions = tuple(_iter_instruction_views(target))
        if not instructions:
            return ()

        succs = _succs_by_block(target)
        loop_scc = _loop_scc_by_block(succs)
        if not loop_scc:
            return ()

        writers_by_dest_token: dict[str, list[_InstructionView]] = {}
        for insn in instructions:
            token = _dest_token(insn)
            if token is None:
                continue
            if insn.dest_type != "mop_S" and insn.dest_stkoff is None:
                continue
            writers_by_dest_token.setdefault(token, []).append(insn)
        for writers in writers_by_dest_token.values():
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

            predicate_vars = _var_tokens(insn.dstr)
            if len(predicate_vars) < 2:
                continue

            for candidate in _candidate_carriers_for_predicate(
                predicate_vars,
                writers_by_dest_token,
            ):
                dedupe = (predicate_block, int(insn.insn_index), candidate.token)
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
                    f"carrier={candidate.token}:maturity={maturity_text}:phase={phase}"
                )

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
                    "predicate_var_tokens": list(predicate_vars),
                    "carrier_var_token": candidate.token,
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
                            f"loop_carrier:{candidate.token}:"
                            f"{classification}:predicate_blk={predicate_block}"
                        ),
                        payload=payload,
                        evidence=evidence,
                    )
                )

        return tuple(observations)


__all__ = ["LoopPredicateValueFactCollector"]
