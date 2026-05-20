"""Hex-Rays return-path cleanup evidence collection."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays


@dataclass(frozen=True, slots=True)
class ReturnCleanupSite:
    """A neutral cleanup site discovered from live return-path microcode."""

    block_serial: int
    insn_ea: int
    reason: str
    observed_state: int | None = None
    mux_block_serial: int | None = None


@dataclass(frozen=True, slots=True)
class ReturnCleanupEvidence:
    """Batch result for return-path cleanup evidence."""

    stop_serial: int | None
    stop_pred_count: int
    sites: tuple[ReturnCleanupSite, ...]


class HexRaysReturnCleanupEvidenceBackend:
    """Collect leaked state-constant return cleanup sites from live MBA blocks."""

    def collect_return_cleanup_evidence(
        self,
        mba: object,
        *,
        known_state_constants: set[int] | frozenset[int],
        state_var_stkoff: int | None = None,
    ) -> ReturnCleanupEvidence:
        known_consts = {int(value) for value in known_state_constants}
        stop_serial = _find_stop_block(mba)
        if stop_serial is None:
            return ReturnCleanupEvidence(
                stop_serial=None,
                stop_pred_count=0,
                sites=(),
            )

        stop_blk = mba.get_mblock(stop_serial)  # type: ignore[attr-defined]
        if stop_blk is None:
            return ReturnCleanupEvidence(
                stop_serial=int(stop_serial),
                stop_pred_count=0,
                sites=(),
            )

        sites: list[ReturnCleanupSite] = []
        npred = int(stop_blk.npred())  # type: ignore[attr-defined]

        # First inspect shared return-mux feeders. A leaked constant can be
        # staged one block before BLT_STOP, then moved into rax by a mux.
        for i in range(npred):
            mux_serial = int(stop_blk.pred(i))  # type: ignore[attr-defined]
            mux_blk = mba.get_mblock(mux_serial)  # type: ignore[attr-defined]
            if mux_blk is None:
                continue
            return_slot_stkoff = _find_return_slot_stkoff(mux_blk)
            if return_slot_stkoff is None:
                continue

            mux_npred = int(mux_blk.npred())  # type: ignore[attr-defined]
            for j in range(mux_npred):
                feeder_serial = int(mux_blk.pred(j))  # type: ignore[attr-defined]
                feeder_blk = mba.get_mblock(feeder_serial)  # type: ignore[attr-defined]
                if feeder_blk is None:
                    continue
                if int(feeder_blk.nsucc()) != 1:  # type: ignore[attr-defined]
                    continue
                if int(feeder_blk.succ(0)) != mux_serial:  # type: ignore[attr-defined]
                    continue

                insn = getattr(feeder_blk, "tail", None)
                walk_limit = 6
                walked = 0
                while insn is not None and walked < walk_limit:
                    if _is_synthetic_return_feeder_insn(
                        insn,
                        return_slot_stkoff=return_slot_stkoff,
                        state_var_stkoff=state_var_stkoff,
                    ):
                        sites.append(
                            ReturnCleanupSite(
                                block_serial=feeder_serial,
                                insn_ea=int(insn.ea),
                                reason="synthetic_return_feeder",
                                mux_block_serial=mux_serial,
                            )
                        )
                        break
                    insn = getattr(insn, "prev", None)
                    walked += 1

        # Preserve the original narrow scan of direct BLT_STOP predecessors.
        for i in range(npred):
            pred_serial = int(stop_blk.pred(i))  # type: ignore[attr-defined]
            pred_blk = mba.get_mblock(pred_serial)  # type: ignore[attr-defined]
            if pred_blk is None:
                continue

            insn = getattr(pred_blk, "tail", None)
            walk_limit = 8
            walked = 0
            while insn is not None and walked < walk_limit:
                if _is_state_const_mov(insn, known_consts):
                    sites.append(
                        ReturnCleanupSite(
                            block_serial=pred_serial,
                            insn_ea=int(insn.ea),
                            reason="state_const_mov",
                            observed_state=_state_const_mov_value(insn),
                        )
                    )
                    break
                insn = getattr(insn, "prev", None)
                walked += 1

        return ReturnCleanupEvidence(
            stop_serial=int(stop_serial),
            stop_pred_count=npred,
            sites=tuple(sites),
        )


def _find_stop_block(mba: object) -> int | None:
    qty = int(getattr(mba, "qty", 0))
    for serial in range(qty - 1, -1, -1):
        blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
        if blk is not None and int(getattr(blk, "type")) == 1:
            return int(serial)
    return None


def _is_state_const_mov(
    insn: object,
    known_consts: set[int],
) -> bool:
    if getattr(insn, "opcode", None) != ida_hexrays.m_mov:
        return False

    src = getattr(insn, "l", None)
    if src is None or getattr(src, "t", None) != ida_hexrays.mop_n:
        return False

    val = _state_const_mov_value(insn)
    if val not in known_consts:
        return False

    dst = getattr(insn, "d", None)
    if dst is None:
        return False
    if getattr(dst, "t", None) not in (ida_hexrays.mop_r, ida_hexrays.mop_S):
        return False

    return True


def _state_const_mov_value(insn: object) -> int | None:
    src = getattr(insn, "l", None)
    try:
        return int(src.nnn.value)
    except (AttributeError, TypeError, ValueError):
        return None


def _find_return_slot_stkoff(mux_blk: object) -> int | None:
    insn = getattr(mux_blk, "head", None)
    walk_limit = 4
    walked = 0
    while insn is not None and walked < walk_limit:
        if (
            getattr(insn, "opcode", None) == ida_hexrays.m_mov
            and getattr(insn, "l", None) is not None
            and insn.l.t == ida_hexrays.mop_S
            and getattr(insn, "d", None) is not None
            and insn.d.t == ida_hexrays.mop_r
        ):
            try:
                return int(insn.l.s.off)
            except Exception:
                return None
        insn = getattr(insn, "next", None)
        walked += 1
    return None


def _is_synthetic_return_feeder_insn(
    insn: object,
    *,
    return_slot_stkoff: int,
    state_var_stkoff: int | None,
) -> bool:
    dst = getattr(insn, "d", None)
    if (
        dst is None
        or getattr(dst, "t", None) != ida_hexrays.mop_S
        or getattr(dst, "s", None) is None
        or int(dst.s.off) != int(return_slot_stkoff)
    ):
        return False

    src = getattr(insn, "l", None)
    if getattr(insn, "opcode", None) == ida_hexrays.m_mov and src is not None and src.t == ida_hexrays.mop_n:
        return True

    if getattr(insn, "opcode", None) not in (
        ida_hexrays.m_mov,
        ida_hexrays.m_xdu,
        ida_hexrays.m_xds,
    ):
        return False

    if (
        state_var_stkoff is not None
        and src is not None
        and getattr(src, "t", None) == ida_hexrays.mop_S
        and getattr(src, "s", None) is not None
        and int(src.s.off) == int(state_var_stkoff)
    ):
        return True

    return False


__all__ = [
    "HexRaysReturnCleanupEvidenceBackend",
    "ReturnCleanupEvidence",
    "ReturnCleanupSite",
]
