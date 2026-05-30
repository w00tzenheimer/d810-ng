"""Hex-Rays live-analysis evidence adapters."""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.backedge_classifier import parse_var_tokens


@dataclass(frozen=True, slots=True)
class BlockTopologyEvidence:
    """Normalized live block topology evidence."""

    serial: int
    block_type: str
    succs: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PredicateReadWriteEvidence:
    """Normalized per-block write and predicate-read evidence."""

    block_serial: int
    writes: frozenset[str]
    predicate_reads: frozenset[str]


# Map mblock_t.type integer to symbolic name. Kept in the Hex-Rays evidence
# adapter so Hodur strategy policy sees only normalized block-type names.
_MBLOCK_TYPE_NAMES = {
    0: "BLT_NONE",
    1: "BLT_STOP",
    2: "BLT_0WAY",
    3: "BLT_1WAY",
    4: "BLT_2WAY",
    5: "BLT_NWAY",
    6: "BLT_XTRN",
}

_CONDITIONAL_JUMP_LEADING_WORDS = frozenset({
    "jcnd", "jnz", "jz", "jae", "jb", "ja", "jbe",
    "jg", "jge", "jl", "jle", "jtbl",
})

_UNCONDITIONAL_JUMP_LEADING_WORDS = frozenset({"goto", "ijmp", "ret"})

_JUMP_LEADING_WORDS = (
    _CONDITIONAL_JUMP_LEADING_WORDS | _UNCONDITIONAL_JUMP_LEADING_WORDS
)


class HexRaysLiveAnalysisBackend:
    """Collect normalized live evidence from Hex-Rays-like MBA objects."""

    def collect_block_topology(
        self,
        mba: object,
    ) -> tuple[BlockTopologyEvidence, ...]:
        evidence: list[BlockTopologyEvidence] = []
        qty = int(getattr(mba, "qty", 0))
        for serial in range(qty):
            blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
            if blk is None:
                continue
            nsucc = int(blk.nsucc())  # type: ignore[attr-defined]
            block_type = _MBLOCK_TYPE_NAMES.get(
                int(getattr(blk, "type")),
                f"type_{int(getattr(blk, 'type'))}",
            )
            evidence.append(
                BlockTopologyEvidence(
                    serial=int(serial),
                    block_type=block_type,
                    succs=tuple(int(blk.succ(i)) for i in range(nsucc)),  # type: ignore[attr-defined]
                )
            )
        return tuple(evidence)

    def collect_predicate_read_write_evidence(
        self,
        mba: object,
    ) -> tuple[PredicateReadWriteEvidence, ...]:
        evidence: list[PredicateReadWriteEvidence] = []
        qty = int(getattr(mba, "qty", 0))
        for serial in range(qty):
            blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
            if blk is None:
                continue
            evidence.append(_collect_block_predicate_read_write(serial, blk))
        return tuple(evidence)


def _collect_block_predicate_read_write(
    block_serial: int,
    blk: object,
) -> PredicateReadWriteEvidence:
    block_writes: set[str] = set()
    tail_text: str | None = None
    insn = getattr(blk, "head", None)
    while insn is not None:
        try:
            text = insn._print()
        except Exception:
            text = ""
        opcode = _leading_opcode(text)
        tail_text = text
        if opcode in _JUMP_LEADING_WORDS:
            insn = getattr(insn, "next", None)
            continue
        tokens = parse_var_tokens(text)
        if tokens:
            # Hex-Rays dstr convention renders destination as the last %var.
            dest = max(tokens, key=lambda token: text.rfind(token))
            block_writes.add(dest)
        insn = getattr(insn, "next", None)

    tail_reads = frozenset()
    if tail_text is not None and _leading_opcode(tail_text) in _CONDITIONAL_JUMP_LEADING_WORDS:
        tail_reads = parse_var_tokens(tail_text)
    return PredicateReadWriteEvidence(
        block_serial=int(block_serial),
        writes=frozenset(block_writes),
        predicate_reads=tail_reads,
    )


def _leading_opcode(text: str) -> str:
    stripped = (text or "").lstrip()
    if not stripped:
        return ""
    end = 0
    while end < len(stripped) and not stripped[end].isspace():
        end += 1
    return stripped[:end].lower()


__all__ = [
    "BlockTopologyEvidence",
    "HexRaysLiveAnalysisBackend",
    "PredicateReadWriteEvidence",
]
