"""Terminal byte-emitter fact collector.

This collector is observability-only.  It records byte-emitter shaped memory
stores and their local guard/edge context so the diag DB can answer where each
terminal byte step survives, remaps, or disappears across microcode maturities.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from d810.core.typing import Any, Iterable
from d810.recon.facts.collectors.induction_carrier import (
    _MATURITY_VALUES,
    _InstructionView,
    _iter_instruction_views,
    _maturity_name,
)
from d810.recon.facts.model import FactObservation

_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
})

_STX_OPCODES = frozenset({"m_stx", "op_1"})
_STORE_TEXT_RE = re.compile(r"^\s*stx\s+(.+?),\s*ds\.\d+,\s*(.+)$", re.IGNORECASE)
_DS_ADDRESS_RE = re.compile(r"\[ds\.[^\]]+\]")
_VAR_TOKEN_RE = re.compile(r"%var_([0-9a-fA-F]+)\.\d+(?:\{[^}]*\})?")
_BYTE_INDEX_RE = re.compile(
    r"(?:v52\s*\[\s*(?P<v52>[0-6])\s*\]|"
    r"byte(?:_index)?\s*[=:]\s*(?P<label>[0-6])|"
    r"\bbyte(?P<compact>[0-6])\b)",
    re.IGNORECASE,
)
_SOURCE_OFFSET_INDEX_RE = re.compile(
    r"xdu\.\d+\(\[ds\.[^\]]*#(?P<offset>[0-6])\.\d+[^\]]*\]",
    re.IGNORECASE,
)
_SMALL_GUARD_RE = re.compile(
    r"(?P<lhs>(?:tail_count|tail|v53|%var_[0-9a-zA-Z_]+\.\d+(?:\{[^}]*\})?))"
    r"[^,\n;]*(?P<op>==|!=)\s*#?(?P<value>0x[0-6]|[0-6])(?:\.\d+)?",
    re.IGNORECASE,
)
_JUMP_SMALL_CONST_RE = re.compile(
    r"\b(?P<op>jz|jnz|jcnd)\b.*?(?P<lhs>%var_[0-9a-zA-Z_]+\.\d+(?:\{[^}]*\})?).*?"
    r"#(?P<value>0x[0-6]|[0-6])(?:\.\d+)?",
    re.IGNORECASE,
)
_SSA_SUFFIX_RE = re.compile(r"\{[^}]*\}")


@dataclass(frozen=True)
class _BlockView:
    serial: int
    start_ea: int | None
    succs: tuple[int, ...]
    preds: tuple[int, ...]
    instructions: tuple[_InstructionView, ...]


@dataclass(frozen=True)
class _GuardView:
    byte_index: int
    condition: str
    counter_signature: str
    insn: _InstructionView


@dataclass(frozen=True)
class _EmitterCandidate:
    block: _BlockView
    insn: _InstructionView
    byte_index: int
    destination: str
    source: str
    counter: str
    guard: _GuardView | None
    guard_condition: str
    emitter_role: str
    confidence: float
    evidence: tuple[str, ...]


def _normal_text(value: str) -> str:
    without_ssa = _SSA_SUFFIX_RE.sub("", str(value))
    return " ".join(without_ssa.strip().split())


def _parse_small_int(value: str) -> int | None:
    try:
        parsed = int(str(value), 0)
    except ValueError:
        return None
    return parsed if 0 <= parsed <= 6 else None


def _byte_index_from_text(text: str) -> int | None:
    match = _BYTE_INDEX_RE.search(text)
    if match is not None:
        value = match.group("v52") or match.group("label") or match.group("compact")
        return _parse_small_int(value)
    offset_match = _SOURCE_OFFSET_INDEX_RE.search(text)
    if offset_match is not None:
        return _parse_small_int(offset_match.group("offset"))
    return None


def _guard_from_instruction(insn: _InstructionView) -> _GuardView | None:
    text = _normal_text(insn.dstr)
    for regex in (_SMALL_GUARD_RE, _JUMP_SMALL_CONST_RE):
        match = regex.search(text)
        if match is None:
            continue
        byte_index = _parse_small_int(match.group("value"))
        if byte_index is None:
            continue
        lhs = match.group("lhs")
        return _GuardView(
            byte_index=byte_index,
            condition=text,
            counter_signature=lhs,
            insn=insn,
        )
    return None


def _is_byte_emit_store(insn: _InstructionView) -> bool:
    text = insn.dstr.lower()
    if insn.opcode_name in _STX_OPCODES:
        return True
    if text.lstrip().startswith("stx "):
        return True
    return False


def _memory_destination_signature(insn: _InstructionView) -> str:
    text = _normal_text(insn.dstr)
    address = _DS_ADDRESS_RE.search(text)
    if address is not None:
        return address.group(0)
    store = _STORE_TEXT_RE.search(text)
    if store is not None:
        return _normal_text(store.group(2))
    if insn.dest_stkoff is not None:
        return f"{insn.dest_type or 'dest'}:0x{int(insn.dest_stkoff):x}"
    return "unknown-destination"


def _source_byte_signature(insn: _InstructionView, block: _BlockView) -> str:
    text = _normal_text(insn.dstr)
    source_index = _BYTE_INDEX_RE.search(text)
    if source_index is not None:
        return source_index.group(0)
    store = _STORE_TEXT_RE.search(text)
    if store is not None:
        return _normal_text(store.group(1))
    for prior in reversed(block.instructions[: insn.insn_index]):
        prior_text = _normal_text(prior.dstr)
        if _BYTE_INDEX_RE.search(prior_text) is not None:
            return prior_text
    if insn.src_l_stkoff is not None:
        return f"{insn.src_l_type or 'src_l'}:0x{int(insn.src_l_stkoff):x}"
    if insn.src_r_stkoff is not None:
        return f"{insn.src_r_type or 'src_r'}:0x{int(insn.src_r_stkoff):x}"
    return "unknown-source"


def _guard_for_block(block: _BlockView) -> _GuardView | None:
    for insn in block.instructions:
        guard = _guard_from_instruction(insn)
        if guard is not None:
            return guard
    return None


def _block_metadata(target: Any) -> dict[int, tuple[int | None, tuple[int, ...], tuple[int, ...]]]:
    metadata: dict[int, tuple[int | None, tuple[int, ...], tuple[int, ...]]] = {}
    if hasattr(target, "qty") and hasattr(target, "get_mblock"):
        qty = int(getattr(target, "qty", 0) or 0)
        for block_index in range(qty):
            blk = target.get_mblock(block_index)
            if blk is None:
                continue
            serial = int(getattr(blk, "serial", block_index))
            start_ea = getattr(blk, "start", None)
            if start_ea is None:
                start_ea = getattr(blk, "start_ea", None)
            try:
                succs = tuple(int(blk.succ(i)) for i in range(int(blk.nsucc())))
            except Exception:
                succs = ()
            try:
                preds = tuple(int(blk.pred(i)) for i in range(int(blk.npred())))
            except Exception:
                preds = ()
            metadata[serial] = (
                int(start_ea) if start_ea is not None else None,
                succs,
                preds,
            )
        return metadata

    blocks = getattr(target, "blocks", target)
    block_iter = blocks.values() if isinstance(blocks, dict) else blocks
    for blk in block_iter:
        serial = int(getattr(blk, "serial"))
        start_ea = getattr(blk, "start_ea", None)
        if start_ea is None:
            start_ea = getattr(blk, "start", None)
        succs = tuple(int(succ) for succ in getattr(blk, "succs", ()) or ())
        preds = tuple(int(pred) for pred in getattr(blk, "preds", ()) or ())
        metadata[serial] = (
            int(start_ea) if start_ea is not None else None,
            succs,
            preds,
        )
    return metadata


def _iter_block_views(target: Any) -> Iterable[_BlockView]:
    by_block: dict[int, list[_InstructionView]] = {}
    for insn in _iter_instruction_views(target):
        by_block.setdefault(insn.block_serial, []).append(insn)

    metadata = _block_metadata(target)
    for serial, instructions in sorted(by_block.items()):
        ordered = tuple(sorted(instructions, key=lambda insn: insn.insn_index))
        start_ea, succs, preds = metadata.get(serial, (None, (), ()))
        yield _BlockView(
            serial=serial,
            start_ea=start_ea,
            succs=succs,
            preds=preds,
            instructions=ordered,
        )


def _continuation_edge(block: _BlockView) -> int | None:
    return block.succs[0] if block.succs else None


def _return_edge(block: _BlockView, guard: _GuardView | None) -> int | None:
    if not block.succs:
        return block.serial
    if guard is None:
        return None
    target = _jump_target(guard.insn)
    if target is not None and target in block.succs:
        if guard.byte_index == 0 and _jump_opcode(guard.insn) == "jnz":
            for succ in block.succs:
                if succ != target:
                    return succ
        return target
    return None


_JUMP_TARGET_RE = re.compile(r"@(?P<target>\d+)\b")
_JUMP_OPCODE_RE = re.compile(r"^\s*(?P<opcode>jz|jnz|jcnd)\b", re.IGNORECASE)


def _jump_target(insn: _InstructionView) -> int | None:
    match = _JUMP_TARGET_RE.search(insn.dstr)
    if match is None:
        return None
    try:
        return int(match.group("target"), 10)
    except ValueError:
        return None


def _jump_opcode(insn: _InstructionView) -> str | None:
    match = _JUMP_OPCODE_RE.search(_normal_text(insn.dstr))
    if match is None:
        return None
    return match.group("opcode").lower()


def _continuation_edge_for_return(block: _BlockView, return_edge: int | None) -> int | None:
    if not block.succs:
        return None
    if return_edge is None:
        return block.succs[0] if len(block.succs) == 1 else None
    for succ in block.succs:
        if succ != return_edge:
            return succ
    return None


def _terminal_family_id(
    candidate: _EmitterCandidate,
    terminal_counters: frozenset[str],
    terminal_blocks: frozenset[int],
    terminal_destinations: frozenset[str],
) -> str:
    if candidate.counter in terminal_counters:
        return "terminal_tail"
    if candidate.byte_index == 1 and candidate.destination in terminal_destinations:
        return "terminal_tail"
    if (
        candidate.byte_index == 6
        and candidate.counter == "unknown-counter"
        and (
            bool(set(candidate.block.preds) & terminal_blocks)
            or "%var_188" in candidate.destination
        )
    ):
        return "terminal_tail"
    return "non_terminal_byte_emitter"


class TerminalByteEmitterFactCollector:
    """Observe terminal byte-emitter memory stores across maturities."""

    name = "TerminalByteEmitterFactCollector"
    fact_kinds = frozenset({"TerminalByteEmitterFact"})
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
        candidates: list[_EmitterCandidate] = []
        seen: set[tuple[int, int, str]] = set()
        store_counters: set[str] = set()
        zero_guard_candidates: list[tuple[_BlockView, _GuardView]] = []

        for block in _iter_block_views(target):
            guard = _guard_for_block(block)
            emitted_in_block = False
            for insn in block.instructions:
                if not _is_byte_emit_store(insn):
                    continue
                explicit_index = _byte_index_from_text(insn.dstr)
                byte_index = explicit_index
                if byte_index is None and guard is not None:
                    byte_index = guard.byte_index
                if byte_index is None:
                    continue

                destination = _memory_destination_signature(insn)
                source = _source_byte_signature(insn, block)
                counter = guard.counter_signature if guard is not None else "unknown-counter"
                guard_condition = guard.condition if guard is not None else "unknown-guard"
                if byte_index != 0 and counter != "unknown-counter":
                    store_counters.add(counter)
                dedupe = (
                    block.serial,
                    insn.insn_index,
                    f"{byte_index}:{destination}:{counter}",
                )
                if dedupe in seen:
                    continue
                seen.add(dedupe)
                emitted_in_block = True
                candidates.append(
                    _EmitterCandidate(
                        block=block,
                        insn=insn,
                        byte_index=byte_index,
                        destination=destination,
                        source=source,
                        counter=counter,
                        guard=guard,
                        guard_condition=guard_condition,
                        emitter_role="memory_store",
                        confidence=0.72 if guard is not None else 0.62,
                        evidence=tuple(
                            view.dstr
                            for view in block.instructions
                            if view is insn or _guard_from_instruction(view) is not None
                        ),
                    )
                )
            if emitted_in_block or guard is None or guard.byte_index != 0:
                continue
            zero_guard_candidates.append((block, guard))

        for block, guard in zero_guard_candidates:
            counter = guard.counter_signature
            if counter not in store_counters:
                continue
            semantic_key = (
                "terminal_byte_emitter:byte_index=0:"
                f"dest=guard-only:counter={counter}"
            )
            mop_signature = (
                "terminal_byte_emit:byte=0:"
                f"dest=guard-only:counter={counter}"
            )
            dedupe = (block.serial, guard.insn.insn_index, semantic_key)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            candidates.append(
                _EmitterCandidate(
                    block=block,
                    insn=guard.insn,
                    byte_index=0,
                    destination="guard-only",
                    source="guard-only",
                    counter=counter,
                    guard=guard,
                    guard_condition=guard.condition,
                    emitter_role="guard_only",
                    confidence=0.54,
                    evidence=(guard.insn.dstr,),
                )
            )

        terminal_counters = frozenset(
            candidate.counter
            for candidate in candidates
            if candidate.emitter_role == "guard_only" and candidate.byte_index == 0
        )
        terminal_blocks = frozenset(
            candidate.block.serial
            for candidate in candidates
            if candidate.counter in terminal_counters
        )
        terminal_destinations = frozenset(
            candidate.destination
            for candidate in candidates
            if (
                candidate.counter in terminal_counters
                and candidate.emitter_role == "memory_store"
                and candidate.destination != "guard-only"
            )
        )

        observations: list[FactObservation] = []
        for candidate in candidates:
            family_id = _terminal_family_id(
                candidate,
                terminal_counters,
                terminal_blocks,
                terminal_destinations,
            )
            block = candidate.block
            insn = candidate.insn
            semantic_key = (
                f"terminal_byte_emitter:family={family_id}:"
                f"byte_index={candidate.byte_index}:"
                f"dest={candidate.destination}:counter={candidate.counter}"
            )
            mop_signature = (
                f"terminal_byte_emit:family={family_id}:"
                f"byte={candidate.byte_index}:"
                f"dest={candidate.destination}:counter={candidate.counter}"
            )
            fact_id = (
                f"{semantic_key}:blk={block.serial}:"
                f"insn={insn.insn_index}:ea=0x{int(insn.ea or 0):x}"
            )
            return_edge = _return_edge(block, candidate.guard)
            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="TerminalByteEmitterFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=candidate.confidence,
                    source_block=block.serial,
                    source_ea=insn.ea,
                    block_fingerprint=(
                        f"blk[{block.serial}].{insn.insn_index}:"
                        f"{insn.opcode_name}"
                    ),
                    mop_signature=mop_signature,
                    payload={
                        "family_id": family_id,
                        "corridor_role": family_id,
                        "byte_index": candidate.byte_index,
                        "source_byte_expression": candidate.source,
                        "source_block": block.serial,
                        "destination_buffer_expression": candidate.destination,
                        "destination_block": block.serial,
                        "counter_carrier": candidate.counter,
                        "guard_condition": candidate.guard_condition,
                        "guard_block": (
                            candidate.guard.insn.block_serial
                            if candidate.guard is not None
                            else None
                        ),
                        "guard_insn_index": (
                            candidate.guard.insn.insn_index
                            if candidate.guard is not None
                            else None
                        ),
                        "return_edge": return_edge,
                        "continuation_edge": _continuation_edge_for_return(
                            block,
                            return_edge,
                        ),
                        "successor_blocks": list(block.succs),
                        "predecessor_blocks": list(block.preds),
                        "block_serial": block.serial,
                        "block_ea": block.start_ea,
                        "insn_index": insn.insn_index,
                        "opcode": insn.opcode_name,
                        "emitter_role": candidate.emitter_role,
                    },
                    evidence=candidate.evidence,
                )
            )
        return tuple(observations)


__all__ = ["TerminalByteEmitterFactCollector"]
