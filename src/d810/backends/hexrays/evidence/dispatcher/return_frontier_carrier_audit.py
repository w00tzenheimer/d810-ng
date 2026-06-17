"""Return-frontier carrier-identity audit (observability-only).

For each block whose tail is m_ret (or whose type is BLT_STOP), capture
the returned mop_t and walk its reaching definition chain.  Compare
against protected side-effect corridor membership to classify whether
the return value's carrier identity has been severed by D810's
upstream simplifications.

This module performs a bounded backward DFS through the live mba CFG
(via blk.npred / blk.preds) starting from each m_ret/BLT_STOP block,
to find the actual return-slot writer.  In sub_7FFD3338C040, the
BLT_STOP block contains only the m_ret epilogue while the actual
return-slot write lives in an upstream predecessor (e.g. blk[41] for
the 0xC5FB... constant case, blk[51] for the a5+0xD0 pointer case).

Read-only.  Does NOT modify CFG state.  Emits structured log lines per
return block.

Env gate: D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT=1 (off by default;
when on, audit fires once at post_pipeline boundary and emits one
log line per return-frontier block).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

# Use the d810 logger pattern -- NOT stdlib logging.  See
# .claude/rules/CORE_INSTRUCTIONS.md.
from d810.core.logging import getLogger
from d810.analyses.control_flow.return_frontier_artifacts import (
    ReturnFrontierArtifactPriors,
    ReturnFrontierCarrierClassification,
)

logger = getLogger(__name__)

_AUDIT_ENV = "D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT"


@dataclass(frozen=True, slots=True)
class ReturnFrontierCarrierEntry:
    block_serial: int                # the BLT_STOP/m_ret block
    writer_block: int | None         # block that actually writes the return slot
    walk_path: tuple[int, ...]       # path from ret_blk to writer_blk
    returned_mop_repr: str           # human-readable mop description
    reaching_def_block: int | None
    reaching_def_opcode: int | None
    carrier_lvar_idx: int | None     # if mop_l carrier
    carrier_stkoff: int | None       # if mop_S carrier
    in_protected_corridor: bool
    classification: str              # one of CLASSIFICATIONS
    diagnostic: str                  # human-readable explanation


CLASSIFICATIONS = (
    "RETURN_CARRIER_LOST",
    ReturnFrontierCarrierClassification.PROTECTED_NON_CARRIER_RETURN_WRITER.value,
    "POINTER_IDENTITY_PROPAGATED",
    "UNKNOWN_FAN_IN_DIVERGENCE",
    "UNKNOWN",
)


def is_audit_enabled() -> bool:
    """Return True iff the env gate is set to '1'."""
    return os.environ.get(_AUDIT_ENV, "").strip() == "1"


# Default bounds for the backward walker.
_DEFAULT_MAX_DEPTH = 8
_DEFAULT_MAX_VISITED = 64


def _safe_int(val, default: int = -1) -> int:
    try:
        return int(val)
    except (TypeError, ValueError, AttributeError):
        return default


def _iter_block_insns(blk):
    """Yield instructions head→tail of an mblock_t."""
    insn = getattr(blk, "head", None)
    while insn is not None:
        yield insn
        insn = getattr(insn, "next", None)


def _writer_carrier_signature(insn, *, mop_n, mop_l, mop_S):
    """Build a hashable carrier signature for a writer instruction.

    Used at fan-in to verify all predecessors converge on the same
    carrier identity.  Returns a tuple of ``(kind, key)`` or ``None``
    if the source operand cannot be characterized.
    """
    if insn is None:
        return None
    src = getattr(insn, "l", None)
    if src is None:
        return None
    try:
        t = int(src.t)
    except (AttributeError, TypeError):
        return None
    if t == mop_n:
        try:
            v = int(src.nnn.value) & 0xFFFFFFFFFFFFFFFF if src.nnn is not None else 0
            return ("const", v)
        except (AttributeError, TypeError):
            return ("const", None)
    if t == mop_l:
        try:
            return ("lvar", int(src.l.idx))
        except (AttributeError, TypeError):
            return ("lvar", None)
    if t == mop_S:
        try:
            return ("stkoff", int(src.s.off))
        except (AttributeError, TypeError):
            return ("stkoff", None)
    # Other mop kinds (mop_d, mop_r, mop_a, ...): use opcode + dstr as
    # a coarse signature.  Good enough for divergence detection.
    try:
        return ("other", _safe_int(insn.opcode, -1), src.dstr())
    except Exception:
        return ("other", _safe_int(insn.opcode, -1), None)


def _dest_is_return_slot(insn, *, mop_r, mop_S, mop_l, return_stkoff: int | None):
    """Heuristic: True iff the destination of ``insn`` is the return
    register (rax) or the function's return-slot stkvar.

    Without architecture-specific knowledge we treat *any* m_mov whose
    dest is a register as a candidate return-slot writer (the return
    register is rax in x64, but the audit runs on the live mba where
    the return slot may be a stkvar like %var_8.8).
    """
    dst = getattr(insn, "d", None)
    if dst is None:
        return False
    try:
        t = int(dst.t)
    except (AttributeError, TypeError):
        return False
    if t == mop_r:
        return True
    if t == mop_S:
        if return_stkoff is None:
            return True  # without a known slot, accept any stkvar dst
        try:
            return int(dst.s.off) == int(return_stkoff)
        except (AttributeError, TypeError):
            return False
    if t == mop_l:
        # Some pipelines lower the return slot to an lvar reference.
        return True
    return False


def _is_trivial_return_slot_copy(
    insn,
    *,
    m_mov: int,
    mop_r: int,
    mop_S: int,
    return_stkoff: int | None,
) -> bool:
    """True iff ``insn`` is a pure stack->reg or reg->stack copy of
    the return slot (e.g. ``mov %var_8.8, rax.8`` or ``mov rax.8,
    %var_8.8``).  These trampoline copies are not the real
    return-slot writers; the audit must walk past them to find the
    upstream computation."""
    op = _safe_int(getattr(insn, "opcode", None), -1)
    if op != m_mov:
        return False
    src = getattr(insn, "l", None)
    dst = getattr(insn, "d", None)
    if src is None or dst is None:
        return False
    try:
        st = int(src.t)
        dt = int(dst.t)
    except (AttributeError, TypeError):
        return False
    # Case 1: src is the return-slot stkvar, dst is a register.
    if st == mop_S and dt == mop_r:
        if return_stkoff is None:
            return True
        try:
            return int(src.s.off) == int(return_stkoff)
        except (AttributeError, TypeError):
            return False
    # Case 2: src is a register, dst is the return-slot stkvar.
    if st == mop_r and dt == mop_S:
        if return_stkoff is None:
            return True
        try:
            return int(dst.s.off) == int(return_stkoff)
        except (AttributeError, TypeError):
            return False
    return False


def _find_return_slot_writer_in_block(
    blk,
    *,
    m_mov: int,
    m_stx: int,
    m_add: int,
    mop_r: int,
    mop_S: int,
    mop_l: int,
    return_stkoff: int | None,
    skip_trivial_copy: bool = True,
):
    """Return the LAST instruction in ``blk`` that writes the return
    slot (m_mov / m_stx / m_add whose destination is rax or the
    return-slot stkoff), or None if no such write exists in this
    block.

    When ``skip_trivial_copy`` is True (default), pure trampoline
    copies (``mov %var_8.8, rax.8`` and the symmetric reg->stkvar) are
    ignored -- the walker should treat them as transparent and
    continue searching predecessors.
    """
    last_writer = None
    for insn in _iter_block_insns(blk):
        op = _safe_int(getattr(insn, "opcode", None), -1)
        if op not in (m_mov, m_stx, m_add):
            continue
        if not _dest_is_return_slot(
            insn,
            mop_r=mop_r,
            mop_S=mop_S,
            mop_l=mop_l,
            return_stkoff=return_stkoff,
        ):
            continue
        if skip_trivial_copy and _is_trivial_return_slot_copy(
            insn, m_mov=m_mov, mop_r=mop_r, mop_S=mop_S,
            return_stkoff=return_stkoff,
        ):
            continue
        last_writer = insn
    return last_writer


def _block_predecessors(blk):
    """Return the list of predecessor block serials for ``blk`` using
    the IDA mblock_t API.

    On real IDA mblock_t objects ``npred`` and ``pred`` are *methods*
    (npred() -> int, pred(i) -> int).  On some shimmed/snapshot
    surfaces they may be plain attributes / sequences.  Handle both.
    """
    preds: list[int] = []

    # Resolve npred whether it's a method or an attribute.
    npred_attr = getattr(blk, "npred", None)
    npred_val = 0
    if callable(npred_attr):
        try:
            npred_val = int(npred_attr())
        except (TypeError, ValueError):
            npred_val = 0
    else:
        npred_val = _safe_int(npred_attr, 0)

    pred_attr = getattr(blk, "pred", None)
    if callable(pred_attr) and npred_val > 0:
        for k in range(npred_val):
            try:
                preds.append(int(pred_attr(k)))
            except (TypeError, ValueError):
                continue
        if preds:
            return preds

    # Fallback: predset attribute (intvec_t-like sequence).
    predset = getattr(blk, "predset", None)
    if predset is not None:
        try:
            for v in predset:
                preds.append(int(v))
        except TypeError:
            pass
    return preds


def _walk_to_return_writer(
    mba,
    ret_blk,
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_visited: int = _DEFAULT_MAX_VISITED,
    m_mov: int,
    m_stx: int,
    m_add: int,
    mop_r: int,
    mop_n: int,
    mop_l: int,
    mop_S: int,
    return_stkoff: int | None,
):
    """Bounded BFS backward from a BLT_STOP/m_ret block, looking for
    the nearest predecessor (or the block itself) that contains a
    return-slot write.

    Returns ``(writers, divergence_note)`` where ``writers`` is a
    list of ``(writer_insn, path_serials)`` tuples.  When all
    predecessors converge on the same carrier identity the list has
    a single entry; on fan-in divergence the list contains one entry
    per divergent predecessor so each can be classified separately.
    """
    ret_serial = _safe_int(getattr(ret_blk, "serial", -1), -1)

    # Local scan first.
    local = _find_return_slot_writer_in_block(
        ret_blk,
        m_mov=m_mov,
        m_stx=m_stx,
        m_add=m_add,
        mop_r=mop_r,
        mop_S=mop_S,
        mop_l=mop_l,
        return_stkoff=return_stkoff,
    )
    if local is not None:
        return [(local, (ret_serial,))], "ok-local"

    visited: set[int] = {ret_serial}
    # Each frontier entry: (serial, depth, path_so_far)
    frontier: list[tuple[int, int, tuple[int, ...]]] = [
        (ret_serial, 0, (ret_serial,))
    ]
    found: list[tuple[object, tuple[int, ...]]] = []
    hit_max_depth = False
    hit_max_visited = False

    while frontier:
        if len(visited) > max_visited:
            hit_max_visited = True
            break
        serial, depth, path = frontier.pop(0)
        if depth >= max_depth:
            hit_max_depth = True
            continue
        try:
            blk = mba.get_mblock(serial)
        except Exception:
            continue
        if blk is None:
            continue
        preds = _block_predecessors(blk)

        for ps in preds:
            if ps in visited:
                continue
            visited.add(ps)
            try:
                pblk = mba.get_mblock(ps)
            except Exception:
                continue
            if pblk is None:
                continue
            w = _find_return_slot_writer_in_block(
                pblk,
                m_mov=m_mov,
                m_stx=m_stx,
                m_add=m_add,
                mop_r=mop_r,
                mop_S=mop_S,
                mop_l=mop_l,
                return_stkoff=return_stkoff,
            )
            new_path = path + (ps,)
            if w is not None:
                found.append((w, new_path))
            else:
                frontier.append((ps, depth + 1, new_path))

    if found:
        # Determine whether the writers diverge in carrier identity.
        sigs = {
            _writer_carrier_signature(
                w, mop_n=mop_n, mop_l=mop_l, mop_S=mop_S
            )
            for w, _ in found
        }
        if len(sigs) > 1:
            # Sort: shortest path first, deterministic for identical
            # paths via the writer's source repr.
            def _stable_key(item):
                w, p = item
                try:
                    src = getattr(w, "l", None)
                    repr_ = src.dstr() if src is not None else ""
                except Exception:
                    repr_ = ""
                return (len(p), p, repr_)
            found.sort(key=_stable_key)
            return found, "fan-in-divergence"
        # All converge on the same carrier identity: pick shortest.
        found.sort(key=lambda t: len(t[1]))
        return [found[0]], "ok"

    if hit_max_depth:
        return [], "max-depth"
    if hit_max_visited:
        return [], "max-visited"
    return [], "no-writer"


def _detect_dead_def_state_guard(
    mba,
    writer,
    *,
    m_mov: int,
    m_stx: int,
    m_add: int,
    mop_r: int,
    mop_S: int,
    mop_l: int,
):
    """Detect protected non-carrier return-frontier writers.

    If the writer's source mop is an m_add (or similar arithmetic op)
    whose .l references a stkoff/lvar that has *no* live def anywhere
    else in the function (i.e. no m_mov/m_stx writes to that stkoff
    exist), the writer is encoding a use-of-dead-def. Recon treats that
    writer as topology evidence to preserve, not as a carrier to lower.

    Returns (matched, reason_str).
    """
    if writer is None:
        return False, ""
    op = _safe_int(getattr(writer, "opcode", None), -1)
    if op != m_add:
        return False, ""
    src_mop = getattr(writer, "l", None)
    if src_mop is None:
        return False, ""
    try:
        t = int(src_mop.t)
    except (AttributeError, TypeError):
        return False, ""
    target_stkoff: int | None = None
    target_lvar: int | None = None
    if t == mop_S:
        try:
            target_stkoff = int(src_mop.s.off)
        except (AttributeError, TypeError):
            pass
    elif t == mop_l:
        try:
            target_lvar = int(src_mop.l.idx)
        except (AttributeError, TypeError):
            pass
    else:
        return False, ""

    if target_stkoff is None and target_lvar is None:
        return False, ""

    # Walk every block, every instruction, looking for a writer to
    # this stkoff/lvar.  If none found, the def is dead.
    qty = _safe_int(getattr(mba, "qty", 0), 0)
    for i in range(qty):
        try:
            blk = mba.get_mblock(i)
        except Exception:
            continue
        if blk is None:
            continue
        for insn in _iter_block_insns(blk):
            iop = _safe_int(getattr(insn, "opcode", None), -1)
            if iop not in (m_mov, m_stx, m_add):
                continue
            dst = getattr(insn, "d", None)
            if dst is None:
                continue
            try:
                dt = int(dst.t)
            except (AttributeError, TypeError):
                continue
            if target_stkoff is not None and dt == mop_S:
                try:
                    if int(dst.s.off) == target_stkoff:
                        return False, ""
                except (AttributeError, TypeError):
                    pass
            if target_lvar is not None and dt == mop_l:
                try:
                    if int(dst.l.idx) == target_lvar:
                        return False, ""
                except (AttributeError, TypeError):
                    pass
    if target_stkoff is not None:
        return True, f"add-source stkoff=0x{target_stkoff:x} has no live def"
    return True, f"add-source lvar={target_lvar} has no live def"


def _detect_arg_propagation(
    writer,
    writer_block,
    mba,
    *,
    m_add: int,
    m_stx: int,
    mop_l: int,
    mop_r: int,
    mop_S: int,
):
    """Secondary detection for POINTER_IDENTITY_PROPAGATED.

    If the writer is m_add (or another arithmetic op) whose source
    operand references an arg register/stkoff directly, AND the same
    block contains a sibling m_stx instruction whose lvar source
    references the same SSA value, classify as propagated.

    Returns (matched, reason_str).
    """
    if writer is None or writer_block is None:
        return False, ""
    op = _safe_int(getattr(writer, "opcode", None), -1)
    if op != m_add:
        return False, ""
    src_mop = getattr(writer, "l", None)
    if src_mop is None:
        return False, ""
    try:
        t = int(src_mop.t)
    except (AttributeError, TypeError):
        return False, ""

    # Capture the source identity (register name or stkoff) we want to
    # match against m_stx siblings in the same block.
    src_kind: str | None = None
    src_key: int | None = None
    src_repr = ""
    if t == mop_r:
        src_kind = "reg"
        try:
            src_key = int(src_mop.r)
        except (AttributeError, TypeError):
            return False, ""
        try:
            src_repr = src_mop.dstr()
        except Exception:
            src_repr = "<reg>"
    elif t == mop_S:
        src_kind = "stkoff"
        try:
            src_key = int(src_mop.s.off)
        except (AttributeError, TypeError):
            return False, ""
        try:
            src_repr = src_mop.dstr()
        except Exception:
            src_repr = "<stkoff>"
    elif t == mop_l:
        src_kind = "lvar"
        try:
            src_key = int(src_mop.l.idx)
        except (AttributeError, TypeError):
            return False, ""
        try:
            src_repr = src_mop.dstr()
        except Exception:
            src_repr = "<lvar>"
    else:
        return False, ""

    # Heuristic: arg-like sources typically have repr starting with
    # "%arg_" or are positional registers (rcx/rdx/r8/r9 for x64
    # Windows).  We don't enforce strict naming -- the presence of a
    # sibling stx using the same key is sufficient evidence.
    looks_arg = src_repr.startswith("%arg_") or src_kind == "reg"

    # Search the same block for an m_stx whose source matches.
    sibling_match = False
    for insn in _iter_block_insns(writer_block):
        if insn is writer:
            continue
        iop = _safe_int(getattr(insn, "opcode", None), -1)
        if iop != m_stx:
            continue
        s = getattr(insn, "l", None)
        if s is None:
            continue
        try:
            st = int(s.t)
        except (AttributeError, TypeError):
            continue
        try:
            if src_kind == "reg" and st == mop_r and int(s.r) == src_key:
                sibling_match = True
                break
            if src_kind == "stkoff" and st == mop_S and int(s.s.off) == src_key:
                sibling_match = True
                break
            if src_kind == "lvar" and st == mop_l and int(s.l.idx) == src_key:
                sibling_match = True
                break
        except (AttributeError, TypeError):
            continue

    if sibling_match and looks_arg:
        return True, (
            f"writer m_add source {src_repr} matches sibling m_stx; "
            f"arg-pointer copy-prop pattern"
        )
    if looks_arg:
        # No sibling stx, but the source IS an arg -- still indicative
        # of a propagated arg pointer.
        return True, (
            f"writer m_add source {src_repr} is arg-like; "
            f"propagated without sibling stx"
        )
    return False, ""


def audit_return_frontier_carriers(
    mba,                              # ida_hexrays.mba_t (live)
    side_effect_corridors: tuple[tuple[int, ...], ...] = (),
    *,
    label: str = "post_pipeline",
    return_stkoff: int | None = None,
    artifact_priors: ReturnFrontierArtifactPriors | None = None,
) -> tuple[ReturnFrontierCarrierEntry, ...]:
    """Audit every return-tail block; return one entry per return block.

    Read-only.  When the audit env gate is unset, this function is a
    complete no-op (returns empty tuple, emits no log lines).

    For each block whose tail is m_ret (or block_type == BLT_STOP):
      1. Walk backward through predecessors (bounded DFS) to find the
         nearest block that writes the return slot.
      2. Extract the source mop_t SRC and a human-readable repr from
         that writer instruction.
      3. Determine carrier identity (mop_l / mop_S / mop_n / mop_d).
      4. Apply primary classification rules + two secondary detectors
         (dead-def state guard and arg propagation).
      5. Emit one structured log line per entry, including
         writer_blk[M] and path=[...].
    """
    if not is_audit_enabled():
        return ()

    if mba is None:
        return ()
    effective_artifact_priors = artifact_priors or ReturnFrontierArtifactPriors()

    try:
        import ida_hexrays
    except ImportError:
        logger.warning("audit: ida_hexrays unavailable")
        return ()

    m_ret = getattr(ida_hexrays, "m_ret", -1)
    m_mov = getattr(ida_hexrays, "m_mov", -1)
    m_stx = getattr(ida_hexrays, "m_stx", -1)
    m_add = getattr(ida_hexrays, "m_add", -1)
    BLT_STOP = getattr(ida_hexrays, "BLT_STOP", 1)
    mop_n = getattr(ida_hexrays, "mop_n", -1)
    mop_l = getattr(ida_hexrays, "mop_l", -1)
    mop_S = getattr(ida_hexrays, "mop_S", -1)
    mop_d = getattr(ida_hexrays, "mop_d", -1)
    mop_r = getattr(ida_hexrays, "mop_r", -1)

    # Build the corridor block set for fast membership tests.
    exit_path_blocks: set[int] = set()
    for chain in side_effect_corridors:
        for b in chain:
            try:
                exit_path_blocks.add(int(b))
            except (TypeError, ValueError):
                pass

    entries: list[ReturnFrontierCarrierEntry] = []

    qty = _safe_int(getattr(mba, "qty", 0), 0)
    if qty <= 0:
        return ()

    for i in range(qty):
        try:
            blk = mba.get_mblock(i)
        except Exception:
            continue
        if blk is None:
            continue

        # Decide if this is a return-frontier block.
        is_return = False
        try:
            if int(getattr(blk, "type", -1)) == BLT_STOP:
                is_return = True
        except (TypeError, ValueError):
            pass
        tail = getattr(blk, "tail", None)
        if not is_return and tail is not None:
            try:
                if int(tail.opcode) == m_ret:
                    is_return = True
            except AttributeError:
                pass
        if not is_return:
            continue

        block_serial_int = _safe_int(getattr(blk, "serial", -1), -1)
        in_corridor = block_serial_int in exit_path_blocks

        # Auto-detect the return slot stkoff from the BLT_STOP block's
        # trampoline copy (``mov %var_X.8, rax.8``) if not explicitly
        # provided.  Without this, every stkvar write looks like a
        # candidate and the audit picks trampoline copies.
        local_stkoff = return_stkoff
        if local_stkoff is None:
            for ins in _iter_block_insns(blk):
                if _safe_int(getattr(ins, "opcode", None), -1) != m_mov:
                    continue
                s = getattr(ins, "l", None)
                d = getattr(ins, "d", None)
                if s is None or d is None:
                    continue
                try:
                    if int(s.t) == mop_S and int(d.t) == mop_r:
                        local_stkoff = int(s.s.off)
                        break
                except (AttributeError, TypeError):
                    continue

        # Walk backward to find the actual return-slot writer(s).
        writers, walk_note = _walk_to_return_writer(
            mba,
            blk,
            m_mov=m_mov,
            m_stx=m_stx,
            m_add=m_add,
            mop_r=mop_r,
            mop_n=mop_n,
            mop_l=mop_l,
            mop_S=mop_S,
            return_stkoff=local_stkoff,
        )
        if walk_note in ("max-depth", "max-visited"):
            logger.warning(
                "RETURN_FRONTIER_CARRIER_AUDIT[%s]: blk[%d] walk hit %s "
                "bound (max_depth=%d max_visited=%d)",
                label, block_serial_int, walk_note,
                _DEFAULT_MAX_DEPTH, _DEFAULT_MAX_VISITED,
            )

        if not writers:
            entries.append(ReturnFrontierCarrierEntry(
                block_serial=block_serial_int,
                writer_block=None,
                walk_path=tuple(),
                returned_mop_repr="<no-write-found>",
                reaching_def_block=None,
                reaching_def_opcode=None,
                carrier_lvar_idx=None,
                carrier_stkoff=None,
                in_protected_corridor=in_corridor,
                classification="UNKNOWN",
                diagnostic=f"no return-slot write found ({walk_note})",
            ))
            logger.info(
                "RETURN_FRONTIER_CARRIER_AUDIT[%s]: ret_blk[%d] "
                "writer_blk=<none> path=[] returned=<no-write-found> "
                "classification=UNKNOWN reason=no-write-found(%s)",
                label, block_serial_int, walk_note,
            )
            continue

        # Emit one entry per writer.  When walk_note is
        # 'fan-in-divergence' there will be 2+ writers (one per
        # divergent predecessor); otherwise a single writer.
        is_divergent = walk_note == "fan-in-divergence"
        for return_write_insn, walk_path in writers:
            writer_serial = walk_path[-1] if walk_path else block_serial_int
            try:
                writer_blk = mba.get_mblock(writer_serial)
            except Exception:
                writer_blk = None

            src_mop = getattr(return_write_insn, "l", None)
            try:
                returned_repr = src_mop.dstr() if src_mop is not None else "<null>"
            except Exception:
                returned_repr = "<dstr-failed>"

            try:
                full_dstr = return_write_insn.dstr()
            except Exception:
                full_dstr = "<dstr-failed>"

            carrier_lvar_idx: int | None = None
            carrier_stkoff: int | None = None
            try:
                if src_mop is not None and int(src_mop.t) == mop_l:
                    if src_mop.l is not None:
                        carrier_lvar_idx = int(src_mop.l.idx)
                if src_mop is not None and int(src_mop.t) == mop_S:
                    if src_mop.s is not None:
                        carrier_stkoff = int(src_mop.s.off)
            except (AttributeError, TypeError):
                pass

            # Primary classification.
            classification = "UNKNOWN"
            diagnostic = "default"
            try:
                if src_mop is not None and int(src_mop.t) == mop_n:
                    val = 0
                    try:
                        val = (
                            int(src_mop.nnn.value)
                            if src_mop.nnn is not None else 0
                        )
                    except (AttributeError, TypeError):
                        val = 0
                    masked = val & 0xFFFFFFFFFFFFFFFF
                    if (
                        effective_artifact_priors
                        .is_known_impossible_return_constant(masked)
                    ):
                        classification = (
                            ReturnFrontierCarrierClassification
                            .PROTECTED_NON_CARRIER_RETURN_WRITER.value
                        )
                        diagnostic = (
                            f"returned constant 0x{masked:016x} matches "
                            f"configured protected return-artifact prior; "
                            f"original carrier likely state-var widening"
                        )
                    else:
                        classification = "RETURN_CARRIER_LOST"
                        diagnostic = (
                            f"returned constant 0x{masked:016x}; carrier missing"
                        )
                elif src_mop is not None and int(src_mop.t) == mop_d:
                    classification = "POINTER_IDENTITY_PROPAGATED"
                    diagnostic = (
                        "returned mop is sub-instruction (mop_d); "
                        "copy-prop likely inlined def into return-slot write"
                    )
                elif carrier_lvar_idx is not None or carrier_stkoff is not None:
                    classification = "UNKNOWN"
                    diagnostic = (
                        f"carrier present (lvar_idx={carrier_lvar_idx}, "
                        f"stkoff={carrier_stkoff}); requires deeper trace to verify"
                    )
                else:
                    classification = "RETURN_CARRIER_LOST"
                    diagnostic = "no recognizable carrier"
            except (AttributeError, TypeError) as exc:
                diagnostic = f"classification failed: {exc!r}"

            # Secondary detector: arg-pointer propagation (catches the
            # snap14→snap16 a5+0xD0 pattern).  Run BEFORE the dead-def
            # detector because IDA represents arg registers as
            # mop_S at the caller-supplied arg slot (e.g. 0x820 for
            # %arg_20) -- which the dead-def detector would otherwise
            # misclassify as a state-guard artifact since the caller
            # writes that slot, not us.
            if classification not in (
                ReturnFrontierCarrierClassification
                .PROTECTED_NON_CARRIER_RETURN_WRITER.value,
                "POINTER_IDENTITY_PROPAGATED",
            ):
                ap_match, ap_reason = _detect_arg_propagation(
                    return_write_insn, writer_blk, mba,
                    m_add=m_add, m_stx=m_stx,
                    mop_l=mop_l, mop_r=mop_r, mop_S=mop_S,
                )
                if ap_match:
                    classification = "POINTER_IDENTITY_PROPAGATED"
                    diagnostic = f"arg propagation: {ap_reason}"

            # Secondary detector: dead-def state guard (catches the
            # 0xC5FB... pattern where the writer is m_add of a stkoff
            # that has no live def anywhere in the function).
            if classification not in (
                ReturnFrontierCarrierClassification
                .PROTECTED_NON_CARRIER_RETURN_WRITER.value,
                "POINTER_IDENTITY_PROPAGATED",
            ):
                sg_match, sg_reason = _detect_dead_def_state_guard(
                    mba, return_write_insn,
                    m_mov=m_mov, m_stx=m_stx, m_add=m_add,
                    mop_r=mop_r, mop_S=mop_S, mop_l=mop_l,
                )
                if sg_match:
                    classification = (
                        ReturnFrontierCarrierClassification
                        .PROTECTED_NON_CARRIER_RETURN_WRITER.value
                    )
                    diagnostic = f"dead-def state-guard: {sg_reason}"

            reaching_def_opcode: int | None = None
            try:
                reaching_def_opcode = int(return_write_insn.opcode)
            except (AttributeError, TypeError):
                pass

            entry = ReturnFrontierCarrierEntry(
                block_serial=block_serial_int,
                writer_block=writer_serial,
                walk_path=tuple(walk_path),
                returned_mop_repr=returned_repr,
                reaching_def_block=writer_serial,
                reaching_def_opcode=reaching_def_opcode,
                carrier_lvar_idx=carrier_lvar_idx,
                carrier_stkoff=carrier_stkoff,
                in_protected_corridor=in_corridor,
                classification=classification,
                diagnostic=diagnostic,
            )
            entries.append(entry)
            path_str = ",".join(str(s) for s in walk_path)
            divergence_tag = "[divergent] " if is_divergent else ""
            logger.info(
                "RETURN_FRONTIER_CARRIER_AUDIT[%s]: %sret_blk[%d] "
                "writer_blk[%s] path=[%s] returned=%s "
                "carrier=lvar=%s|stkoff=%s reaching_def=%s op=0x%s "
                "corridor=%s classification=%s reason=%s",
                label,
                divergence_tag,
                entry.block_serial,
                writer_serial if writer_serial is not None else "?",
                path_str,
                full_dstr,
                entry.carrier_lvar_idx,
                (
                    f"0x{entry.carrier_stkoff:x}"
                    if entry.carrier_stkoff is not None
                    else "None"
                ),
                (
                    f"blk[{entry.reaching_def_block}]"
                    if entry.reaching_def_block is not None
                    else "<none>"
                ),
                (
                    f"{entry.reaching_def_opcode:x}"
                    if entry.reaching_def_opcode is not None
                    else "?"
                ),
                "Y" if entry.in_protected_corridor else "N",
                entry.classification,
                entry.diagnostic,
            )

    return tuple(entries)
