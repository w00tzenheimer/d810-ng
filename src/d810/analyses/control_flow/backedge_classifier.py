"""Classify CFG back-edges as real-loop iteration vs spurious round-trip.

Companion to ``d810.analyses.control_flow.scc``: SCCs identify cycles, this module
classifies the cycle-closing edges.

Definitions
-----------
A back-edge ``(src, tgt)`` in a strongly-connected component is
**real-loop** when ``src`` mutates a variable that ``tgt`` reads in its
tail predicate. The mutation is the iteration update; the read is the
loop test. This is what compilers emit for ``while``/``for``/``do-while``.

A back-edge is **spurious** when no overlap exists. The cycle is closing
but no iteration is happening — typical of OLLVM dispatcher state-machine
residue that survived recon-DAG-level unflattening: a "redo with new
state" jump where ``src`` does not actually change anything ``tgt`` tests.

The classifier is **strictly local** — it compares ``src``'s writes to
``tgt``'s predicate read-set without walking the full SCC. This keeps the
algorithm O(1) per edge and pure-Python. Multi-step write chains
(e.g. ``A`` writes carrier, ``A → B → tgt`` and ``B`` is the back-edge
source) are intentionally classified as ``UNKNOWN`` and left to a
downstream pass that does full reaching-def analysis.

Token convention
----------------
Variables are represented as ``%var_HEX`` strings, matching the
``dstr`` rendering used by ``loop_carrier.py``. The
``parse_var_tokens(text)`` helper extracts them from a ``dstr``-like
string. Consumers that have access to typed operands can populate the
write/read maps directly without going through the regex helper.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from d810.core.logging import getLogger
from d810.core.typing import Iterable, Mapping

logger = getLogger(__name__)


class BackedgeClass(str, Enum):
    """Classification of a back-edge inside an SCC."""

    REAL_LOOP = "REAL_LOOP"
    SPURIOUS = "SPURIOUS"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class BackedgeClassification:
    """One classified back-edge with full evidence trail.

    Parameters
    ----------
    src_serial : int
        Source block of the back-edge.
    tgt_serial : int
        Target block (the predicate / loop head).
    classification : BackedgeClass
        REAL_LOOP / SPURIOUS / UNKNOWN.
    src_writes : frozenset[str]
        Variable tokens written by ``src`` (locally — same block).
    tgt_predicate_reads : frozenset[str]
        Variable tokens read by ``tgt``'s tail predicate.
    overlap : frozenset[str]
        Intersection ``src_writes & tgt_predicate_reads``. Empty when
        classification is SPURIOUS or UNKNOWN.
    reason : str
        Human-readable explanation suitable for diagnostic logs.
    """

    src_serial: int
    tgt_serial: int
    classification: BackedgeClass
    src_writes: frozenset[str]
    tgt_predicate_reads: frozenset[str]
    overlap: frozenset[str]
    reason: str

    @property
    def is_real_loop(self) -> bool:
        return self.classification is BackedgeClass.REAL_LOOP

    @property
    def is_spurious(self) -> bool:
        return self.classification is BackedgeClass.SPURIOUS


_VAR_TOKEN_RE = re.compile(r"%var_[0-9A-Fa-f]+")


def parse_var_tokens(text: str) -> frozenset[str]:
    """Return ``%var_HEX`` tokens in ``text``.

    Mirrors the convention used by ``loop_carrier.py`` so the two layers
    agree on how a microcode operand prints.

    >>> sorted(parse_var_tokens("add    %var_178.8, #1.8, %var_170.8"))
    ['%var_170', '%var_178']
    >>> parse_var_tokens("")
    frozenset()
    >>> parse_var_tokens(None)  # tolerant of None
    frozenset()
    """
    if not text:
        return frozenset()
    return frozenset(_VAR_TOKEN_RE.findall(text))


def classify_backedge(
    *,
    src_serial: int,
    tgt_serial: int,
    src_writes: frozenset[str],
    tgt_predicate_reads: frozenset[str],
) -> BackedgeClassification:
    """Classify one back-edge from the local write/read sets.

    See module docstring for the definition of REAL_LOOP / SPURIOUS /
    UNKNOWN. The decision is purely set-theoretic: overlap → real loop;
    no overlap with non-empty predicate reads → spurious; empty
    predicate reads → unknown.
    """
    if not tgt_predicate_reads:
        return BackedgeClassification(
            src_serial=int(src_serial),
            tgt_serial=int(tgt_serial),
            classification=BackedgeClass.UNKNOWN,
            src_writes=frozenset(src_writes),
            tgt_predicate_reads=frozenset(tgt_predicate_reads),
            overlap=frozenset(),
            reason=f"blk[{tgt_serial}] has no readable tail predicate",
        )
    overlap = frozenset(src_writes) & frozenset(tgt_predicate_reads)
    if overlap:
        return BackedgeClassification(
            src_serial=int(src_serial),
            tgt_serial=int(tgt_serial),
            classification=BackedgeClass.REAL_LOOP,
            src_writes=frozenset(src_writes),
            tgt_predicate_reads=frozenset(tgt_predicate_reads),
            overlap=overlap,
            reason=(
                f"blk[{src_serial}] writes {sorted(overlap)} which "
                f"blk[{tgt_serial}]'s predicate reads"
            ),
        )
    return BackedgeClassification(
        src_serial=int(src_serial),
        tgt_serial=int(tgt_serial),
        classification=BackedgeClass.SPURIOUS,
        src_writes=frozenset(src_writes),
        tgt_predicate_reads=frozenset(tgt_predicate_reads),
        overlap=frozenset(),
        reason=(
            f"blk[{src_serial}] does not write any var read by "
            f"blk[{tgt_serial}]'s predicate"
        ),
    )


def classify_backedges(
    edges: Iterable[tuple[int, int]],
    *,
    block_writes: Mapping[int, frozenset[str]],
    block_predicate_reads: Mapping[int, frozenset[str]],
) -> tuple[BackedgeClassification, ...]:
    """Classify many back-edges at once.

    ``block_writes`` and ``block_predicate_reads`` are looked up per
    edge; missing keys are treated as empty sets. The returned tuple
    preserves input edge order.
    """
    out: list[BackedgeClassification] = []
    empty: frozenset[str] = frozenset()
    for src, tgt in edges:
        out.append(
            classify_backedge(
                src_serial=int(src),
                tgt_serial=int(tgt),
                src_writes=block_writes.get(int(src), empty),
                tgt_predicate_reads=block_predicate_reads.get(int(tgt), empty),
            )
        )
    return tuple(out)


def log_classifications(
    classifications: tuple[BackedgeClassification, ...],
) -> None:
    """One INFO line per non-UNKNOWN classification.

    Spurious back-edges are the actionable signal — they're the
    redirect candidates. Real-loop edges are logged at DEBUG so they
    don't drown out the actionable list.
    """
    real = [c for c in classifications if c.is_real_loop]
    spurious = [c for c in classifications if c.is_spurious]
    unknown = [
        c for c in classifications
        if c.classification is BackedgeClass.UNKNOWN
    ]
    logger.info(
        "back-edge classification: real=%d spurious=%d unknown=%d",
        len(real),
        len(spurious),
        len(unknown),
    )
    for c in spurious:
        logger.info(
            "back-edge SPURIOUS: %d->%d (%s)",
            c.src_serial,
            c.tgt_serial,
            c.reason,
        )
    if logger.debug_on:
        for c in real:
            logger.debug(
                "back-edge REAL_LOOP: %d->%d carrier=%s",
                c.src_serial,
                c.tgt_serial,
                sorted(c.overlap),
            )


__all__ = [
    "BackedgeClass",
    "BackedgeClassification",
    "classify_backedge",
    "classify_backedges",
    "log_classifications",
    "parse_var_tokens",
]
