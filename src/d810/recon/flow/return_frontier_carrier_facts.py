"""Return-frontier carrier-fact detector (FlowGraph-snapshot, pre-mutation).

For each block whose tail is ``m_ret`` (or whose ``block_type`` is
``BLT_STOP``), walk *backwards* over the immutable :class:`FlowGraph`
snapshot to find the FIRST block that writes the return slot
(rax-typed register or the return-slot stkvar) and record the carrier
identity of that writer's source operand.

Unlike :mod:`d810.recon.flow.return_frontier_carrier_audit` (which
runs against the live ``mba_t`` *post*-pipeline), this detector runs
at FlowGraph-build time against the pre-mutation snapshot.  The
intent is to provide HCC's plan-emission stage with a stable,
immutable record of the carrier's def-chain blocks BEFORE any
``RedirectGoto`` / ``DuplicateAndRedirect`` / ``InsertBlock`` mod can
collapse the def chain into a copy-prop-vulnerable shape.

Outputs are pure data (``ReturnFrontierCarrierFact`` records). The
HCC carrier-shred guard consumes the ``writer_path_blocks`` set to
reject any topology mod that would inject a foreign predecessor into
a block on the carrier-def path or rewrite an edge inside it.

This module follows the same idioms as
:func:`d810.recon.flow.linearized_state_dag.detect_side_effect_corridors`:
- It runs against the FlowGraph snapshot (no live mba access).
- It introspects ``InsnSnapshot.opcode`` and the rich ``l``/``r``/``d``
  ``MopSnapshot`` fields (``t``, ``stkoff``, ``reg``).
- It is conservative: when the carrier cannot be cleanly captured (no
  ``mop_l`` / ``mop_S`` source on the writer), no fact is emitted.

Default bounds:
- BFS depth: 8 blocks back from the return tail (matches the audit's
  ``_DEFAULT_MAX_DEPTH``).
- BFS visited cap: 64 blocks (matches the audit).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot
from d810.core import logging

logger = logging.getLogger(
    "D810.recon.flow.return_frontier_carrier_facts", logging.INFO
)

__all__ = [
    "ReturnFrontierCarrierFact",
    "detect_return_frontier_carrier_facts",
]


# ---------------------------------------------------------------------------
# Mop type constants from ida_hexrays (replicated as integers).
#
# We hardcode these because (a) the detector runs at FlowGraph-build time and
# IDA may already have been imported, but (b) we don't want a hard import
# dependency in the recon layer.  These values are stable across IDA SDK
# versions: see ida_hexrays.hpp ``mop_t::t`` enum.
# ---------------------------------------------------------------------------
_MOP_R = 1   # mop_r: register
_MOP_N = 2   # mop_n: numeric constant
_MOP_S = 3   # mop_S/mop_str: stkvar reference
_MOP_L = 7   # mop_l: lvar reference

# Opcodes (subset).  We rely on ida_hexrays at runtime for the canonical
# values; this dict is the fallback used when the import fails (offline
# unit tests).
_FALLBACK_OPCODES = {
    "m_ret": 0x59,
    "m_mov": 0x0F,
    "m_stx": 0x0D,
    "m_add": 0x10,
    "m_xdu": 0x1B,
    "m_xds": 0x1C,
    "m_low": 0x1D,
    "m_high": 0x1E,
}

# BLT_STOP from mblock_t::type enum.
_BLT_STOP = 1

_DEFAULT_MAX_DEPTH = 8
_DEFAULT_MAX_VISITED = 64


def _resolve_opcodes() -> dict[str, int]:
    """Try to import ida_hexrays for canonical opcode values; fall back
    to the constants at the top if unavailable (offline tests)."""
    try:
        import ida_hexrays  # type: ignore[import-not-found]
    except ImportError:
        return dict(_FALLBACK_OPCODES)
    out: dict[str, int] = {}
    for name in _FALLBACK_OPCODES:
        out[name] = int(getattr(ida_hexrays, name, _FALLBACK_OPCODES[name]))
    return out


@dataclass(frozen=True, slots=True)
class ReturnFrontierCarrierFact:
    """Immutable record of a return-frontier writer's carrier identity.

    Attributes:
        ret_block: Serial of the block containing m_ret/BLT_STOP.
        writer_block: Serial of the block writing the return slot.
        walk_path: Block serials from writer_block ... ret_block (inclusive
            on both ends).  Length >= 1 (at minimum the writer is also the
            ret block).
        carrier_lvar_idx: lvar_idx of the writer's source ``mop_l``, or
            ``None`` if the source is not an lvar.
        carrier_stkoff: Stack offset of the writer's source ``mop_S``, or
            ``None`` if the source is not a stkvar.
        writer_path_blocks: Frozenset of block serials whose preservation
            is required for the carrier identity to survive end-to-end
            (writer + immediate predecessors that reference the carrier
            via mop_l/mop_S).  HCC uses this set to reject mods that
            would inject foreign predecessors or rewrite edges inside.
    """

    ret_block: int
    writer_block: int
    walk_path: tuple[int, ...]
    carrier_lvar_idx: int | None
    carrier_stkoff: int | None
    writer_path_blocks: frozenset[int]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_return_block(blk: BlockSnapshot, m_ret: int) -> bool:
    """True iff this block is BLT_STOP or its tail is m_ret."""
    if int(blk.block_type) == _BLT_STOP:
        return True
    if blk.tail_opcode is not None and int(blk.tail_opcode) == m_ret:
        return True
    tail = blk.tail
    if tail is not None and int(tail.opcode) == m_ret:
        return True
    return False


def _dest_is_return_slot(
    insn: InsnSnapshot, *, return_stkoff: int
) -> bool:
    """Heuristic: writer's destination is rax (any mop_r) OR the
    return-slot stkvar at ``return_stkoff``.

    We accept any mop_r as a candidate because rax is the standard return
    register on x64 and OLLVM's pre-finalize lowering uses an lvar/stkvar
    intermediate.  This matches the audit's ``_dest_is_return_slot``.
    """
    dst = insn.d
    if dst is None:
        return False
    t = int(dst.t)
    if t == _MOP_R:
        return True
    if t == _MOP_S:
        if dst.stkoff is None:
            return True  # accept-on-unknown
        return int(dst.stkoff) == int(return_stkoff)
    if t == _MOP_L:
        # Snapshot doesn't expose lvar idx; accept any mop_l dst as a
        # candidate (filtered downstream by carrier capture).
        return True
    return False


def _is_trivial_copy(
    insn: InsnSnapshot,
    *,
    m_mov: int,
    return_stkoff: int,
) -> bool:
    """True iff the insn is a pure trampoline copy (stkvar->reg or
    reg->stkvar of the return slot).  Walker treats these as transparent
    so it can find the upstream computation."""
    if int(insn.opcode) != m_mov:
        return False
    src = insn.l
    dst = insn.d
    if src is None or dst is None:
        return False
    st = int(src.t)
    dt = int(dst.t)
    if st == _MOP_S and dt == _MOP_R:
        if src.stkoff is None or int(src.stkoff) == int(return_stkoff):
            return True
    if st == _MOP_R and dt == _MOP_S:
        if dst.stkoff is None or int(dst.stkoff) == int(return_stkoff):
            return True
    return False


def _find_writer_in_block(
    blk: BlockSnapshot,
    *,
    m_mov: int,
    m_stx: int,
    m_add: int,
    return_stkoff: int,
    skip_trivial_copy: bool = True,
) -> InsnSnapshot | None:
    """Return the LAST instruction in ``blk`` that writes the return
    slot, ignoring trivial trampoline copies.  None if none found."""
    last: InsnSnapshot | None = None
    for insn in blk.insn_snapshots:
        op = int(insn.opcode)
        if op not in (m_mov, m_stx, m_add):
            continue
        if not _dest_is_return_slot(insn, return_stkoff=return_stkoff):
            continue
        if skip_trivial_copy and _is_trivial_copy(
            insn, m_mov=m_mov, return_stkoff=return_stkoff
        ):
            continue
        last = insn
    return last


def _writer_carrier_identity(
    writer: InsnSnapshot,
) -> tuple[int | None, int | None]:
    """Return ``(carrier_lvar_idx, carrier_stkoff)`` from the writer's
    source operand (``writer.l``).  Both None means the carrier cannot
    be captured (writer was a const / sub-instruction / arithmetic).

    The MopSnapshot in d810.cfg.flowgraph does NOT carry lvar_idx
    directly (it's the lightweight pure-Python value type).  When the
    snapshot was captured by the richer
    ``d810.hexrays.ir.mop_snapshot.MopSnapshot``, lvar info is exposed
    via private attribute conventions; we use ``getattr`` with a
    fall-through.  When unavailable, we record only stkoff.
    """
    src = writer.l
    if src is None:
        return None, None
    t = int(src.t)
    carrier_lvar_idx: int | None = None
    carrier_stkoff: int | None = None
    if t == _MOP_L:
        # Try several conventional attribute names for the lvar index.
        for attr in ("lvar_idx", "l_idx", "idx", "value"):
            cand = getattr(src, attr, None)
            if cand is not None:
                try:
                    carrier_lvar_idx = int(cand)
                    break
                except (TypeError, ValueError):
                    continue
    elif t == _MOP_S:
        if src.stkoff is not None:
            try:
                carrier_stkoff = int(src.stkoff)
            except (TypeError, ValueError):
                carrier_stkoff = None
    return carrier_lvar_idx, carrier_stkoff


def _insn_references_carrier(
    insn: InsnSnapshot,
    *,
    carrier_lvar_idx: int | None,
    carrier_stkoff: int | None,
) -> bool:
    """True iff any operand of ``insn`` references the carrier via
    mop_l (idx match) or mop_S (stkoff match)."""
    for mop in (insn.l, insn.r, insn.d):
        if mop is None:
            continue
        try:
            t = int(mop.t)
        except (AttributeError, TypeError):
            continue
        if carrier_lvar_idx is not None and t == _MOP_L:
            for attr in ("lvar_idx", "l_idx", "idx", "value"):
                cand = getattr(mop, attr, None)
                if cand is not None:
                    try:
                        if int(cand) == int(carrier_lvar_idx):
                            return True
                    except (TypeError, ValueError):
                        continue
        if carrier_stkoff is not None and t == _MOP_S:
            if mop.stkoff is not None:
                try:
                    if int(mop.stkoff) == int(carrier_stkoff):
                        return True
                except (TypeError, ValueError):
                    continue
    return False


def _block_references_carrier(
    blk: BlockSnapshot,
    *,
    carrier_lvar_idx: int | None,
    carrier_stkoff: int | None,
) -> bool:
    if carrier_lvar_idx is None and carrier_stkoff is None:
        return False
    for insn in blk.insn_snapshots:
        if _insn_references_carrier(
            insn,
            carrier_lvar_idx=carrier_lvar_idx,
            carrier_stkoff=carrier_stkoff,
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


def detect_return_frontier_carrier_facts(
    flow_graph: FlowGraph | None,
    *,
    return_stkoff_hint: int = 0x7F0,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_visited: int = _DEFAULT_MAX_VISITED,
) -> tuple[ReturnFrontierCarrierFact, ...]:
    """Detect carrier-def facts at every return-frontier block.

    For each block whose tail is m_ret (or BLT_STOP-typed), perform a
    bounded backward BFS along the FlowGraph predecessor edges to find
    the first block writing the return slot.  Capture the source
    operand's carrier identity (mop_l idx or mop_S stkoff).  Compute
    ``writer_path_blocks`` = the set of blocks on the writer's def
    chain that reference the same carrier, plus the writer itself.

    Returns a tuple of facts ordered by ``ret_block`` ascending for
    determinism.  Skips ret blocks where the carrier cannot be cleanly
    captured (e.g., writer source is a constant or sub-instruction).
    """
    if flow_graph is None:
        return ()
    opcodes = _resolve_opcodes()
    m_ret = opcodes["m_ret"]
    m_mov = opcodes["m_mov"]
    m_stx = opcodes["m_stx"]
    m_add = opcodes["m_add"]

    facts: list[ReturnFrontierCarrierFact] = []

    for ret_serial in sorted(flow_graph.blocks.keys()):
        ret_blk = flow_graph.blocks[ret_serial]
        if not _is_return_block(ret_blk, m_ret):
            continue

        # Determine the return slot.  Try to auto-detect the trampoline
        # ``mov %var_X.8, rax.8`` in the ret block; fall back to hint.
        return_stkoff = int(return_stkoff_hint)
        for ins in ret_blk.insn_snapshots:
            if int(ins.opcode) != m_mov:
                continue
            s, d = ins.l, ins.d
            if s is None or d is None:
                continue
            try:
                if int(s.t) == _MOP_S and int(d.t) == _MOP_R:
                    if s.stkoff is not None:
                        return_stkoff = int(s.stkoff)
                        break
            except (AttributeError, TypeError):
                continue

        # Bounded BFS backward to find the writer.
        writer: InsnSnapshot | None = None
        writer_serial: int | None = None
        walk_path: tuple[int, ...] = ()

        local_writer = _find_writer_in_block(
            ret_blk,
            m_mov=m_mov,
            m_stx=m_stx,
            m_add=m_add,
            return_stkoff=return_stkoff,
        )
        if local_writer is not None:
            writer = local_writer
            writer_serial = ret_serial
            walk_path = (ret_serial,)
        else:
            visited: set[int] = {ret_serial}
            frontier: list[tuple[int, int, tuple[int, ...]]] = [
                (ret_serial, 0, (ret_serial,))
            ]
            hit_cap = False
            while frontier:
                if len(visited) > max_visited:
                    hit_cap = True
                    break
                serial, depth, path = frontier.pop(0)
                if depth >= max_depth:
                    continue
                cur_blk = flow_graph.blocks.get(serial)
                if cur_blk is None:
                    continue
                for pserial in cur_blk.preds:
                    if pserial in visited:
                        continue
                    visited.add(pserial)
                    pblk = flow_graph.blocks.get(pserial)
                    if pblk is None:
                        continue
                    pwriter = _find_writer_in_block(
                        pblk,
                        m_mov=m_mov,
                        m_stx=m_stx,
                        m_add=m_add,
                        return_stkoff=return_stkoff,
                    )
                    new_path = path + (pserial,)
                    if pwriter is not None:
                        writer = pwriter
                        writer_serial = pserial
                        walk_path = new_path
                        frontier = []  # break outer
                        break
                    frontier.append((pserial, depth + 1, new_path))
            if writer is None:
                logger.debug(
                    "RETURN_FRONTIER_CARRIER_FACT: ret=blk[%d] "
                    "writer=<none> (cap=%s)",
                    ret_serial,
                    "1" if hit_cap else "0",
                )
                continue

        assert writer is not None and writer_serial is not None

        # Capture the carrier identity from the writer's source.
        carrier_lvar_idx, carrier_stkoff = _writer_carrier_identity(writer)
        if carrier_lvar_idx is None and carrier_stkoff is None:
            # Writer's source is a constant / sub-instruction / something
            # we cannot key on.  Carrier already lost; emit no fact.
            logger.debug(
                "RETURN_FRONTIER_CARRIER_FACT: ret=blk[%d] writer=blk[%d] "
                "carrier=<unrecognized> skip",
                ret_serial,
                writer_serial,
            )
            continue

        # Compute writer_path_blocks: writer + any immediate predecessor
        # of writer that references the same carrier.  The HCC guard
        # uses this as the protected set.
        protected: set[int] = {int(writer_serial)}
        # Reverse the walk_path so the writer end is the seed; include
        # the path itself (handler exit -> writer fall-through is part
        # of the def chain).
        for s in walk_path:
            protected.add(int(s))

        writer_blk = flow_graph.blocks.get(writer_serial)
        if writer_blk is not None:
            for pserial in writer_blk.preds:
                pblk = flow_graph.blocks.get(pserial)
                if pblk is None:
                    continue
                if _block_references_carrier(
                    pblk,
                    carrier_lvar_idx=carrier_lvar_idx,
                    carrier_stkoff=carrier_stkoff,
                ):
                    protected.add(int(pserial))

        fact = ReturnFrontierCarrierFact(
            ret_block=int(ret_serial),
            writer_block=int(writer_serial),
            walk_path=tuple(int(s) for s in walk_path),
            carrier_lvar_idx=carrier_lvar_idx,
            carrier_stkoff=carrier_stkoff,
            writer_path_blocks=frozenset(protected),
        )
        facts.append(fact)
        logger.info(
            "RETURN_FRONTIER_CARRIER_FACT: ret=blk[%d] writer=blk[%d] "
            "path=%s carrier_lvar=%s|stkoff=%s path_blocks=%s",
            fact.ret_block,
            fact.writer_block,
            list(fact.walk_path),
            (
                str(fact.carrier_lvar_idx)
                if fact.carrier_lvar_idx is not None
                else "None"
            ),
            (
                f"0x{fact.carrier_stkoff:x}"
                if fact.carrier_stkoff is not None
                else "None"
            ),
            sorted(fact.writer_path_blocks),
        )

    return tuple(facts)
