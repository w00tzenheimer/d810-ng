"""Hex-Rays instruction capture adapter for backend-owned block bodies."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.cfg.flowgraph import InsnSnapshot
from d810.transforms.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.transforms.semantic_region_materialization import (
    InstructionCaptureFacts,
    decide_instruction_capture,
)
from d810.transforms.state_write_cleanup import (
    StateWriteCleanupAction,
    StateWriteCleanupRequest,
)
from d810.analyses.control_flow.state_write_evidence import StateConstantWriteEvidence
from d810.core.logging import getLogger
from d810.core.typing import Protocol
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


class StateWriteCleanupEvidenceBackend(Protocol):
    """Backend boundary for state-write cleanup classification."""

    def classify_trivial_tail_state_write_cleanup(
        self,
        block: object,
        *,
        state_variable: object,
        expected_state: int,
    ) -> StateWriteCleanupRequest | None:
        """Classify ``state = CONST; goto`` tail cleanup from a block snapshot."""

    def classify_matching_state_write_cleanup(
        self,
        block: object,
        *,
        state_variable: object,
        expected_state: int,
    ) -> StateWriteCleanupRequest | None:
        """Classify a single matching constant state write in a block snapshot."""


class InsertBlockCallAuditBackend(Protocol):
    """Backend boundary for call checks on materialized InsertBlock bodies."""

    def captured_body_contains_call(self, captured_body: object) -> bool:
        """Return whether a backend-owned captured body contains a call."""

    def instruction_snapshot_is_call(self, instruction_snapshot: object) -> bool:
        """Return whether a legacy instruction snapshot represents a call."""


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

    def captured_body_contains_call(self, captured_body: object) -> bool:
        return bool(
            getattr(
                getattr(captured_body, "summary", None),
                "contains_call",
                False,
            )
        )

    def instruction_snapshot_is_call(self, instruction_snapshot: object) -> bool:
        try:
            opcode = int(getattr(instruction_snapshot, "opcode", -1))
        except Exception:
            return False
        return opcode in _CALL_FORBIDDEN

    def classify_trivial_tail_state_write_cleanup(
        self,
        block: object,
        *,
        state_variable: object,
        expected_state: int,
    ) -> StateWriteCleanupRequest | None:
        """Classify ``state = CONST; goto`` tail cleanup from a block snapshot."""
        state_var_stkoff = _state_variable_stkoff(state_variable)
        if state_var_stkoff is None:
            return None
        block_serial = _block_serial(block)
        insns = tuple(getattr(block, "insn_snapshots", ()) or ())
        if len(insns) != 2:
            return None
        write_insn, tail_insn = insns
        if int(getattr(write_insn, "opcode", -1)) != ida_hexrays.m_mov:
            return None
        if int(getattr(tail_insn, "opcode", -1)) != ida_hexrays.m_goto:
            return None

        if not _is_state_var_dest(
            getattr(write_insn, "d", None),
            state_var_stkoff,
        ):
            return None
        value = _const_mop_value(getattr(write_insn, "l", None))
        if value is None:
            return None
        expected = int(expected_state) & 0xFFFFFFFF
        observed = int(value) & 0xFFFFFFFF
        if observed != expected:
            return None
        insn_ea = int(getattr(write_insn, "ea", 0) or 0)
        if insn_ea == 0:
            return None
        return StateWriteCleanupRequest(
            action=StateWriteCleanupAction.NOP_INSTRUCTION,
            block_serial=block_serial,
            insn_ea=insn_ea,
            expected_state=expected,
            observed_state=observed,
            reason="trivial_tail_state_write",
        )

    def classify_matching_state_write_cleanup(
        self,
        block: object,
        *,
        state_variable: object,
        expected_state: int,
    ) -> StateWriteCleanupRequest | None:
        """Classify a single matching constant state write in a block snapshot."""
        state_var_stkoff = _state_variable_stkoff(state_variable)
        if state_var_stkoff is None:
            return None
        block_serial = _block_serial(block)
        matched_insn_ea: int | None = None
        observed_state: int | None = None
        state_write_count = 0
        expected = int(expected_state) & 0xFFFFFFFF
        for insn in tuple(getattr(block, "insn_snapshots", ()) or ()):
            if int(getattr(insn, "opcode", -1)) != ida_hexrays.m_mov:
                continue
            if not _is_state_var_dest(getattr(insn, "d", None), state_var_stkoff):
                continue
            state_write_count += 1
            value = _const_mop_value(getattr(insn, "l", None))
            if value is None:
                return None
            observed = int(value) & 0xFFFFFFFF
            if observed != expected:
                return None
            matched_insn_ea = int(getattr(insn, "ea", 0) or 0)
            observed_state = observed

        if state_write_count != 1 or matched_insn_ea in (None, 0):
            return None
        return StateWriteCleanupRequest(
            action=StateWriteCleanupAction.ZERO_SOURCE,
            block_serial=block_serial,
            insn_ea=int(matched_insn_ea),
            expected_state=expected,
            observed_state=observed_state,
            reason="matching_constant_state_write",
        )

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

    def collect_unresolved_stkvar_reads(
        self,
        snapshots: tuple[InsnSnapshot, ...],
        *,
        state_variable: object | None,
    ) -> set[int]:
        """Return top-level stack reads not defined earlier in ``snapshots``."""
        state_var_stkoff = _state_variable_stkoff(state_variable)
        written: set[int] = set()
        needed: set[int] = set()
        for snap in tuple(snapshots):
            for slot in (getattr(snap, "l", None), getattr(snap, "r", None)):
                if slot is None:
                    continue
                try:
                    slot_t = int(getattr(slot, "t", -1))
                except Exception:
                    slot_t = -1
                if slot_t != ida_hexrays.mop_S:
                    continue
                stkoff = _mop_stkoff(slot)
                if stkoff is not None and int(stkoff) not in written:
                    needed.add(int(stkoff))

            d = getattr(snap, "d", None)
            if d is None:
                continue
            try:
                d_t = int(getattr(d, "t", -1))
            except Exception:
                d_t = -1
            if d_t == ida_hexrays.mop_S:
                d_off = _mop_stkoff(d)
                if d_off is not None:
                    written.add(int(d_off))

        if state_var_stkoff is not None:
            needed.discard(int(state_var_stkoff))
        return needed - written

    def find_unique_const_writer_for_stkoff(
        self,
        mba: object,
        target_stkoff: int,
        *,
        state_variable: object | None,
    ) -> int | None:
        """Return the unique block that writes a constant to ``target_stkoff``."""
        state_var_stkoff = _state_variable_stkoff(state_variable)
        if (
            state_var_stkoff is not None
            and int(target_stkoff) == int(state_var_stkoff)
        ):
            return None
        try:
            qty = int(getattr(mba, "qty", 0))
        except Exception:
            return None

        writers: list[int] = []
        for serial in range(qty):
            try:
                blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
            except Exception:
                continue
            if blk is None:
                continue
            cur = getattr(blk, "head", None)
            while cur is not None:
                try:
                    opcode = int(cur.opcode)
                except Exception:
                    opcode = -1
                if opcode == ida_hexrays.m_mov and _is_state_var_dest(
                    getattr(cur, "d", None),
                    int(target_stkoff),
                ):
                    if _const_mop_value(getattr(cur, "l", None)) is not None:
                        writers.append(int(serial))
                        if len(writers) > 1:
                            return None
                        break
                cur = getattr(cur, "next", None)

        if len(writers) == 1:
            return writers[0]
        return None

    def collect_state_constant_writes(
        self,
        mba: object,
        *,
        state_variable: object | None,
    ) -> tuple[StateConstantWriteEvidence, ...]:
        """Collect constant writes to the dispatcher state variable."""
        state_var_stkoff = _state_variable_stkoff(state_variable)
        if state_var_stkoff is None:
            return ()
        try:
            qty = int(getattr(mba, "qty", 0))
        except Exception:
            return ()

        writes: list[StateConstantWriteEvidence] = []
        for serial in range(qty):
            try:
                blk = mba.get_mblock(serial)  # type: ignore[attr-defined]
            except Exception:
                continue
            if blk is None:
                continue
            cur = getattr(blk, "head", None)
            while cur is not None:
                try:
                    opcode = int(cur.opcode)
                except Exception:
                    opcode = -1
                if opcode == ida_hexrays.m_mov and _is_state_var_dest(
                    getattr(cur, "d", None),
                    state_var_stkoff,
                ):
                    value = _const_mop_value(getattr(cur, "l", None))
                    if value is not None:
                        try:
                            insn_ea = int(getattr(cur, "ea", 0) or 0)
                        except Exception:
                            insn_ea = 0
                        writes.append(
                            StateConstantWriteEvidence(
                                block_serial=int(serial),
                                insn_ea=insn_ea,
                                state_value=int(value),
                            )
                        )
                cur = getattr(cur, "next", None)
        return tuple(writes)

    def block_contains_call(self, mba: object, block_serial: int) -> bool:
        """Return whether the live block contains a call-like instruction."""
        try:
            blk = mba.get_mblock(int(block_serial))  # type: ignore[attr-defined]
        except Exception:
            return False
        if blk is None:
            return False
        cur = getattr(blk, "head", None)
        while cur is not None:
            try:
                if self.instruction_snapshot_is_call(cur):
                    return True
            except Exception:
                return False
            cur = getattr(cur, "next", None)
        return False

    def block_has_non_state_payload(
        self,
        mba: object,
        block_serial: int,
        *,
        state_variable: object | None,
    ) -> bool:
        """Return whether a block has payload beyond state write/goto glue."""
        state_var_stkoff = _state_variable_stkoff(state_variable)
        try:
            blk = mba.get_mblock(int(block_serial))
        except Exception:
            return False
        if blk is None:
            return False
        insn = getattr(blk, "head", None)
        while insn is not None:
            try:
                opcode = int(insn.opcode)
            except Exception:
                return True
            if opcode in {ida_hexrays.m_nop, ida_hexrays.m_goto}:
                insn = getattr(insn, "next", None)
                continue
            if _is_state_write(insn, state_var_stkoff):
                insn = getattr(insn, "next", None)
                continue
            return True
        return False


def _block_serial(blk: object) -> int:
    try:
        return int(getattr(blk, "serial", -1))
    except Exception:
        return -1


def _mop_stkoff(mop: object) -> int | None:
    if mop is None:
        return None
    stkoff = getattr(mop, "stkoff", None)
    if stkoff is not None:
        try:
            return int(stkoff)
        except Exception:
            pass
    s = getattr(mop, "s", None)
    if s is None:
        return None
    try:
        return int(s.off)
    except Exception:
        return None


def _state_variable_stkoff(state_variable: object) -> int | None:
    try:
        return int(state_variable)
    except Exception:
        return _mop_stkoff(state_variable)


def _is_state_var_dest(mop: object, state_var_stkoff: int | None) -> bool:
    if mop is None or state_var_stkoff is None:
        return False
    try:
        if int(getattr(mop, "t", -1)) != ida_hexrays.mop_S:
            return False
    except Exception:
        return False
    stkoff = _mop_stkoff(mop)
    return stkoff is not None and int(stkoff) == int(state_var_stkoff)


def _const_mop_value(mop: object) -> int | None:
    if mop is None:
        return None
    try:
        if int(getattr(mop, "t", -1)) != ida_hexrays.mop_n:
            return None
    except Exception:
        return None
    candidates = [getattr(mop, "value", None)]
    nnn = getattr(mop, "nnn", None)
    candidates.append(getattr(nnn, "value", None))
    for value in candidates:
        if value is None:
            continue
        try:
            return int(value)
        except Exception:
            continue
    return None


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
        stkoff = _mop_stkoff(mop)
        if stkoff is not None:
            try:
                reads.add((int(stkoff), int(mop.size)))
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
    return _is_state_var_dest(getattr(insn, "d", None), state_var_stkoff)


__all__ = [
    "HexRaysBlockCaptureResult",
    "HexRaysInstructionCaptureBackend",
    "StateWriteCleanupEvidenceBackend",
]
