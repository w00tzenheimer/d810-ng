"""Hex-Rays instruction capture adapter for backend-owned block bodies."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.cfg.flowgraph import InsnSnapshot
from d810.cfg.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.cfg.semantic_region_materialization import (
    InstructionCaptureFacts,
    decide_instruction_capture,
)
from d810.core.logging import getLogger
from d810.evaluator.hexrays_microcode.chains import find_reaching_defs_for_stkvar
from d810.hexrays.mutation.insn_snapshot_materializer import (
    HEXRAYS_INSN_SNAPSHOT_BODY_BACKEND_ID,
    insn_snapshots_from_captured_body,
    validate_captured_block_body,
)
from d810.hexrays.mutation.ir_translator import capture_insn_snapshot

logger = getLogger(__name__)


_CLOSING_FORBIDDEN: frozenset[int] = frozenset(
    {
        ida_hexrays.m_ret,
        ida_hexrays.m_jtbl,
        ida_hexrays.m_ijmp,
        ida_hexrays.m_ext,
    }
)

_CALL_FORBIDDEN: frozenset[int] = frozenset(
    {
        ida_hexrays.m_call,
        ida_hexrays.m_icall,
    }
)


@dataclass(frozen=True, slots=True)
class HexRaysBlockCaptureResult:
    """Classification result for a Hex-Rays block-body capture."""

    kind: str
    body: CapturedBlockBody | None = None
    abort_reason: str | None = None
    call_ea: int | None = None
    is_indirect: bool | None = None
    pre_call_count: int | None = None
    post_call_count: int | None = None


class HexRaysInstructionCaptureBackend:
    """Capture Hex-Rays instruction bodies behind an opaque cfg payload."""

    backend_id = HEXRAYS_INSN_SNAPSHOT_BODY_BACKEND_ID

    def body_from_snapshots(
        self,
        snapshots: tuple[InsnSnapshot, ...],
        *,
        source_blocks: tuple[int, ...],
        capture_id: str,
        contains_call: bool = False,
    ) -> CapturedBlockBody:
        source_eas = frozenset(
            int(snapshot.ea)
            for snapshot in snapshots
            if int(getattr(snapshot, "ea", 0) or 0) > 0
        )
        return CapturedBlockBody(
            backend_id=self.backend_id,
            capture_id=capture_id,
            summary=CapturedBlockBodySummary(
                source_blocks=tuple(int(block) for block in source_blocks),
                instruction_count=len(snapshots),
                source_eas=source_eas,
                contains_call=contains_call,
            ),
            payload=tuple(snapshots),
        )

    def snapshots_from_body(self, body: CapturedBlockBody) -> tuple[InsnSnapshot, ...]:
        return insn_snapshots_from_captured_body(body)

    def validate_body(self, body: CapturedBlockBody) -> str | None:
        return validate_captured_block_body(body)

    def combine_bodies(
        self,
        bodies: tuple[CapturedBlockBody, ...],
        *,
        capture_id: str,
    ) -> CapturedBlockBody:
        snapshots: list[InsnSnapshot] = []
        source_blocks: list[int] = []
        contains_call = False
        for body in bodies:
            snapshots.extend(self.snapshots_from_body(body))
            for block in body.summary.source_blocks:
                if int(block) not in source_blocks:
                    source_blocks.append(int(block))
            contains_call = contains_call or bool(body.summary.contains_call)
        return self.body_from_snapshots(
            tuple(snapshots),
            source_blocks=tuple(source_blocks),
            capture_id=capture_id,
            contains_call=contains_call,
        )

    def capture_block_composable_instructions_v2(
        self,
        blk: object,
        *,
        state_var_stkoff: int | None = None,
        byte_evidence_eas: frozenset[int] = frozenset(),
    ) -> HexRaysBlockCaptureResult:
        """Capture a composable block body or classify why capture stops."""
        source_block = _block_serial(blk)
        block_has_byte_evidence = False
        if byte_evidence_eas:
            probe = getattr(blk, "head", None)
            while probe is not None:
                try:
                    probe_ea = int(getattr(probe, "ea", 0) or 0)
                except Exception:
                    probe_ea = 0
                if probe_ea and probe_ea in byte_evidence_eas:
                    block_has_byte_evidence = True
                    break
                probe = getattr(probe, "next", None)
        try:
            insn = blk.head  # type: ignore[attr-defined]
        except Exception:
            return HexRaysBlockCaptureResult(
                kind="closing_abort",
                abort_reason="blk_head_unreadable",
            )
        snapshots: list[InsnSnapshot] = []
        call_eas: list[tuple[int, bool]] = []
        pre_call_count = 0
        post_call_count = 0
        seen_call = False
        while insn is not None:
            try:
                opcode = int(insn.opcode)
            except Exception:
                return HexRaysBlockCaptureResult(
                    kind="closing_abort",
                    abort_reason="opcode_unreadable",
                )
            try:
                is_jcond = bool(ida_hexrays.is_mcode_jcond(opcode))
            except Exception:
                return HexRaysBlockCaptureResult(
                    kind="closing_abort",
                    abort_reason="jcond_check_raised",
                )
            decision = decide_instruction_capture(
                InstructionCaptureFacts(
                    is_goto=(opcode == ida_hexrays.m_goto),
                    is_nop=(opcode == ida_hexrays.m_nop),
                    is_closing_forbidden=(opcode in _CLOSING_FORBIDDEN),
                    is_conditional_jump=is_jcond,
                    is_call=(opcode in _CALL_FORBIDDEN),
                    is_state_write=_is_state_write(insn, state_var_stkoff),
                    is_tail=(getattr(insn, "next", None) is None),
                    block_has_required_payload_evidence=block_has_byte_evidence,
                ),
                opcode=opcode,
            )
            if decision.action == "skip":
                insn = insn.next
                continue
            if decision.action == "abort":
                return HexRaysBlockCaptureResult(
                    kind="closing_abort",
                    abort_reason=decision.abort_reason,
                )
            if decision.action == "drop_control_tail":
                break
            if decision.action == "record_call":
                try:
                    call_ea = int(getattr(insn, "ea", 0))
                except Exception:
                    call_ea = 0
                call_eas.append((call_ea, opcode == ida_hexrays.m_icall))
                seen_call = True
                insn = insn.next
                continue
            try:
                snap = capture_insn_snapshot(insn)
            except Exception as exc:
                logger.warning(
                    "HexRaysInstructionCaptureBackend: capture_insn_snapshot"
                    " failed at ea=0x%x opcode=%d: %s",
                    int(getattr(insn, "ea", 0)),
                    opcode,
                    exc,
                )
                return HexRaysBlockCaptureResult(
                    kind="closing_abort",
                    abort_reason="capture_snapshot_failed",
                )
            snapshots.append(snap)
            if seen_call:
                post_call_count += 1
            else:
                pre_call_count += 1
            insn = insn.next
        if not call_eas:
            return HexRaysBlockCaptureResult(
                kind="composable",
                body=self.body_from_snapshots(
                    tuple(snapshots),
                    source_blocks=(source_block,),
                    capture_id=f"block:{source_block}",
                ),
            )
        if len(call_eas) > 1:
            return HexRaysBlockCaptureResult(
                kind="closing_abort",
                abort_reason=f"multi_call_anchor_count={len(call_eas)}",
            )
        call_ea, is_indirect = call_eas[0]
        return HexRaysBlockCaptureResult(
            kind="opaque_call_anchor",
            call_ea=call_ea,
            is_indirect=is_indirect,
            pre_call_count=pre_call_count,
            post_call_count=post_call_count,
        )

    def capture_transitive_def_chain(
        self,
        mba: object,
        region_anchor: int,
        initial_reads: set[tuple[int, int]],
        *,
        max_depth: int = 8,
        max_total: int = 64,
    ) -> CapturedBlockBody | None:
        """Capture reaching def-chain instructions as an opaque body."""
        captured: dict[int, InsnSnapshot] = {}
        capture_order: list[int] = []
        captured_source_blocks: set[int] = set()
        visited: set[tuple[int, int]] = set()
        in_progress: set[tuple[int, int]] = set()

        def _resolve(stkoff: int, size: int, depth: int) -> bool:
            key = (int(stkoff), int(size))
            if key in visited:
                return True
            if key in in_progress:
                return True
            if depth > max_depth:
                logger.info(
                    "HCC_DEF_PROBE depth-exceeded anchor=%d stkoff=0x%x size=%d depth=%d",
                    int(region_anchor), int(stkoff), int(size), depth,
                )
                return False
            if len(capture_order) > max_total:
                logger.info(
                    "HCC_DEF_PROBE max-total-exceeded anchor=%d stkoff=0x%x size=%d captured=%d",
                    int(region_anchor), int(stkoff), int(size), len(capture_order),
                )
                return False
            in_progress.add(key)
            try:
                probe_defs = find_reaching_defs_for_stkvar(
                    mba, int(region_anchor), int(stkoff), int(size),
                )
            except Exception as exc:
                probe_defs = None
                logger.info(
                    "HCC_DEF_PROBE chain-raised anchor=%d stkoff=0x%x size=%d exc=%s",
                    int(region_anchor), int(stkoff), int(size), exc,
                )
            if not probe_defs:
                logger.info(
                    "HCC_DEF_PROBE no-defs-external anchor=%d stkoff=0x%x size=%d"
                    " (treated as external input, no capture needed)",
                    int(region_anchor), int(stkoff), int(size),
                )
                visited.add(key)
                in_progress.discard(key)
                return True
            logger.info(
                "HCC_DEF_PROBE found anchor=%d stkoff=0x%x size=%d n_defs=%d sites=%s",
                int(region_anchor), int(stkoff), int(size), len(probe_defs),
                [(int(d.block_serial), hex(int(d.ins_ea))) for d in probe_defs[:5]],
            )
            for def_site in probe_defs:
                try:
                    captured_source_blocks.add(int(def_site.block_serial))
                except Exception:
                    continue
            insn = _find_live_def_insn(mba, region_anchor, stkoff, size)
            if insn is None:
                in_progress.discard(key)
                return False
            try:
                def_ea = int(getattr(insn, "ea", 0) or 0)
                opcode = int(insn.opcode)
            except Exception:
                in_progress.discard(key)
                return False
            sub_reads: set[tuple[int, int]] = set()
            _collect_stkvar_reads_from_mop(getattr(insn, "l", None), sub_reads)
            _collect_stkvar_reads_from_mop(getattr(insn, "r", None), sub_reads)
            d_op = getattr(insn, "d", None)
            if d_op is not None:
                try:
                    d_type = int(d_op.t)
                except Exception:
                    d_type = -1
                if opcode == ida_hexrays.m_stx or d_type == ida_hexrays.mop_d:
                    _collect_stkvar_reads_from_mop(d_op, sub_reads)
            sub_reads.discard(key)
            for sub_off, sub_sz in sorted(sub_reads):
                if not _resolve(sub_off, sub_sz, depth + 1):
                    in_progress.discard(key)
                    return False
            if def_ea not in captured:
                try:
                    snap = capture_insn_snapshot(insn)
                except Exception:
                    in_progress.discard(key)
                    return False
                captured[def_ea] = snap
                capture_order.append(def_ea)
            visited.add(key)
            in_progress.discard(key)
            return True

        for stkoff, size in sorted(initial_reads):
            if not _resolve(int(stkoff), int(size), 0):
                return None

        snapshots = tuple(captured[ea] for ea in capture_order)
        return self.body_from_snapshots(
            snapshots,
            source_blocks=tuple(sorted(captured_source_blocks)),
            capture_id=f"def-chain:{int(region_anchor)}",
        )

    def collect_stkvar_reads_in_block(
        self,
        blk: object,
        *,
        skip_jcond_tail: bool = True,
    ) -> set[tuple[int, int]]:
        return _collect_stkvar_reads_in_block(blk, skip_jcond_tail=skip_jcond_tail)


def _block_serial(blk: object) -> int:
    try:
        return int(getattr(blk, "serial", -1))
    except Exception:
        return -1


def _find_live_def_insn(
    mba: object,
    region_anchor: int,
    stkoff: int,
    size: int,
) -> object | None:
    try:
        defs = find_reaching_defs_for_stkvar(
            mba, int(region_anchor), int(stkoff), int(size),
        )
    except Exception:
        return None
    if not defs:
        return None
    for def_site in defs:
        try:
            def_blk_serial = int(def_site.block_serial)
            def_ea = int(def_site.ins_ea)
        except Exception:
            continue
        try:
            def_blk = mba.get_mblock(def_blk_serial)  # type: ignore[attr-defined]
        except Exception:
            continue
        if def_blk is None:
            continue
        cur = getattr(def_blk, "head", None)
        while cur is not None:
            try:
                cur_ea = int(getattr(cur, "ea", 0) or 0)
            except Exception:
                cur_ea = 0
            if cur_ea == def_ea:
                return cur
            cur = getattr(cur, "next", None)
    return None


def _collect_stkvar_reads_from_mop(
    mop: object,
    reads: set[tuple[int, int]],
) -> None:
    if mop is None:
        return
    try:
        t = int(mop.t)
    except Exception:
        return
    if t == ida_hexrays.mop_S:
        s = getattr(mop, "s", None)
        if s is None:
            return
        try:
            reads.add((int(s.off), int(mop.size)))
        except Exception:
            return
        return
    if t == ida_hexrays.mop_d:
        sub = getattr(mop, "d", None)
        if sub is None:
            return
        _collect_stkvar_reads_from_mop(getattr(sub, "l", None), reads)
        _collect_stkvar_reads_from_mop(getattr(sub, "r", None), reads)
        _collect_stkvar_reads_from_mop(getattr(sub, "d", None), reads)


def _collect_stkvar_reads_in_block(
    blk: object,
    *,
    skip_jcond_tail: bool = True,
) -> set[tuple[int, int]]:
    reads: set[tuple[int, int]] = set()
    cur = getattr(blk, "head", None)
    while cur is not None:
        try:
            opcode = int(cur.opcode)
        except Exception:
            opcode = -1
        if skip_jcond_tail:
            try:
                if ida_hexrays.is_mcode_jcond(opcode):
                    break
            except Exception:
                pass
        _collect_stkvar_reads_from_mop(getattr(cur, "l", None), reads)
        _collect_stkvar_reads_from_mop(getattr(cur, "r", None), reads)
        d = getattr(cur, "d", None)
        if d is not None:
            try:
                d_type = int(d.t)
            except Exception:
                d_type = -1
            if opcode == ida_hexrays.m_stx or d_type == ida_hexrays.mop_d:
                _collect_stkvar_reads_from_mop(d, reads)
        cur = getattr(cur, "next", None)
    return reads


def _is_state_write(insn: object, state_var_stkoff: int | None) -> bool:
    if state_var_stkoff is None:
        return False
    try:
        opcode = int(insn.opcode)
    except Exception:
        return False
    if opcode != ida_hexrays.m_mov:
        return False
    dst = getattr(insn, "d", None)
    if dst is None:
        return False
    try:
        if dst.t != ida_hexrays.mop_S:
            return False
        return int(dst.s.off) == int(state_var_stkoff)
    except Exception:
        return False


__all__ = [
    "HexRaysBlockCaptureResult",
    "HexRaysInstructionCaptureBackend",
]
