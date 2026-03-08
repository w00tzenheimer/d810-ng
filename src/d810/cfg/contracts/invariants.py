"""CFG invariants derived from Hex-Rays verifier expectations."""

from __future__ import annotations

from types import MappingProxyType
from d810.core.typing import Any, Iterable
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph

try:
    import ida_hexrays
except ImportError:  # pragma: no cover - exercised in unit tests without IDA.
    class _FallbackHexRays:
        BLT_NONE = 0
        BLT_STOP = 1
        BLT_0WAY = 2
        BLT_1WAY = 3
        BLT_2WAY = 4
        BLT_NWAY = 5
        BLT_XTRN = 6

        m_nop = 0
        m_jtbl = 1
        m_goto = 2
        m_jcnd = 3
        m_jnz = 4
        m_jz = 5
        m_jae = 6
        m_jb = 7
        m_ja = 8
        m_jbe = 9
        m_jg = 10
        m_jge = 11
        m_jl = 12
        m_jle = 13
        m_ijmp = 14
        m_ret = 15
        m_ext = 16
        m_push = 17
        m_pop = 18

        mop_b = 100
        mop_c = 101
        NORET_FORBID_ANALYSIS = 0

        # Maturity levels
        MMAT_GENERATED = 0
        MMAT_PREOPTIMIZED = 1
        MMAT_LOCOPT = 2
        MMAT_CALLS = 3
        MMAT_GLBOPT1 = 4
        MMAT_GLBOPT2 = 5
        MMAT_GLBOPT3 = 6
        MMAT_LVARS = 7

        # Block flags
        MBL_FAKE = 0x10

        # Known MBL_* flag bits mask (best-effort from IDA SDK)
        _KNOWN_MBL_MASK = 0xFFFF  # conservative: treat low 16 bits as known

        @staticmethod
        def is_mcode_jcond(opcode: int) -> bool:
            return int(opcode) in {
                _FallbackHexRays.m_jcnd,
                _FallbackHexRays.m_jnz,
                _FallbackHexRays.m_jz,
                _FallbackHexRays.m_jae,
                _FallbackHexRays.m_jb,
                _FallbackHexRays.m_ja,
                _FallbackHexRays.m_jbe,
                _FallbackHexRays.m_jg,
                _FallbackHexRays.m_jge,
                _FallbackHexRays.m_jl,
                _FallbackHexRays.m_jle,
            }

    ida_hexrays = _FallbackHexRays()  # type: ignore[assignment]

from d810.cfg.contracts.report import InvariantViolation


_COND_OPCODE_NAMES = (
    "m_jcnd",
    "m_jnz",
    "m_jz",
    "m_jae",
    "m_jb",
    "m_ja",
    "m_jbe",
    "m_jg",
    "m_jge",
    "m_jl",
    "m_jle",
)


def _vector_values(vec: Any | None) -> list[int]:
    if vec is None:
        return []
    if hasattr(vec, "size") and hasattr(vec, "__getitem__"):
        return [int(vec[i]) for i in range(int(vec.size()))]
    return [int(v) for v in vec]


def _succ_list(blk) -> list[int]:
    snapshot_succs = getattr(blk, "succs", None)
    if snapshot_succs is not None and not callable(snapshot_succs):
        return [int(v) for v in snapshot_succs]
    return _vector_values(getattr(blk, "succset", None))


def _pred_list(blk) -> list[int]:
    snapshot_preds = getattr(blk, "preds", None)
    if snapshot_preds is not None and not callable(snapshot_preds):
        return [int(v) for v in snapshot_preds]
    return _vector_values(getattr(blk, "predset", None))


def _serial_in_predset(blk, serial: int) -> bool:
    return int(serial) in _pred_list(blk)


def _serial_in_succset(blk, serial: int) -> bool:
    return int(serial) in _succ_list(blk)


def _block_serial(blk) -> int | None:
    if blk is None:
        return None
    if not hasattr(blk, "serial"):
        return None
    try:
        return int(blk.serial)
    except Exception:
        return None


def _same_block_ref(left, right) -> bool:
    if left is right:
        return True
    left_serial = _block_serial(left)
    right_serial = _block_serial(right)
    if left_serial is not None and right_serial is not None:
        return left_serial == right_serial
    return False


def _serials_for_scope(mba, focus_serials: Iterable[int] | None) -> list[int]:
    if focus_serials is not None:
        return [int(s) for s in focus_serials]
    if isinstance(mba, FlowGraph):
        return sorted(int(s) for s in mba.blocks)
    return list(range(int(mba.qty)))


def _safe_get_block(mba, serial: int):
    if isinstance(mba, FlowGraph):
        return mba.get_block(serial)
    if serial < 0 or serial >= int(mba.qty):
        return None
    try:
        return mba.get_mblock(serial)
    except Exception:
        return None


def _insn_ea(tail) -> int | None:
    if tail is None or not hasattr(tail, "ea"):
        return None
    try:
        return int(tail.ea)
    except Exception:
        return None


def _qty(mba) -> int:
    if isinstance(mba, FlowGraph):
        return int(mba.num_blocks)
    return int(mba.qty)


def _blk_type(blk) -> int:
    return int(getattr(blk, "type", getattr(blk, "block_type", 0)))


def _nsucc(blk) -> int:
    probe = getattr(blk, "nsucc", None)
    if callable(probe):
        return int(probe())
    if probe is not None:
        return int(probe)
    return len(_succ_list(blk))


def _tail_opcode(blk) -> int:
    # Check explicit tail_opcode field first — may be updated by projection
    # without updating instruction snapshots.
    tail_opcode = getattr(blk, "tail_opcode", None)
    if tail_opcode is not None:
        return int(tail_opcode)
    # Fall back to .tail.opcode (live blocks or snapshots without tail_opcode).
    tail = getattr(blk, "tail", None)
    if tail is not None and hasattr(tail, "opcode"):
        try:
            return int(tail.opcode)
        except Exception:
            pass
    insn_snapshots = getattr(blk, "insn_snapshots", ())
    if insn_snapshots:
        return int(insn_snapshots[-1].opcode)
    return int(getattr(ida_hexrays, "m_nop", 0))


def _is_snapshot_block(blk) -> bool:
    return isinstance(blk, BlockSnapshot)


def _violation(
    *,
    code: str,
    phase: str,
    message: str,
    block_serial: int | None,
    insn_ea: int | None = None,
    verify_code: int | None = None,
    details: dict[str, Any] | None = None,
) -> InvariantViolation:
    payload = dict(details or {})
    if verify_code is not None:
        payload["verify_code"] = int(verify_code)
    return InvariantViolation(
        code=code,
        phase=phase,
        message=message,
        block_serial=block_serial,
        insn_ea=insn_ea,
        details=MappingProxyType(payload) if payload else None,
    )


def _mop_is_mblock(op) -> bool:
    if op is None:
        return False
    checker = getattr(op, "is_mblock", None)
    if callable(checker):
        try:
            return bool(checker())
        except Exception:
            return False
    return int(getattr(op, "t", -1)) == int(getattr(ida_hexrays, "mop_b"))


def _is_conditional_jump_opcode(opcode: int) -> bool:
    predicate = getattr(ida_hexrays, "is_mcode_jcond", None)
    if callable(predicate):
        try:
            if bool(predicate(int(opcode))):
                return True
        except Exception:
            pass
    return int(opcode) in {
        int(getattr(ida_hexrays, name, -1)) for name in _COND_OPCODE_NAMES
    }


def _jtbl_targets(tail) -> tuple[list[int] | None, str | None]:
    if tail is None:
        return None, "jtbl tail missing"
    right = getattr(tail, "r", None)
    if right is None or int(getattr(right, "t", -1)) != int(getattr(ida_hexrays, "mop_c")):
        return None, "jtbl without case-list operand"
    cases = getattr(right, "c", None)
    if cases is None:
        return None, "jtbl case-list operand missing case table"
    targets = getattr(cases, "targets", None)
    if targets is None:
        return None, "jtbl case-list is missing targets"
    try:
        return _vector_values(targets), None
    except Exception:
        return None, "jtbl case-list targets are unreadable"


def _block_type_name(blk_type: int) -> str:
    for name in (
        "BLT_NONE",
        "BLT_STOP",
        "BLT_XTRN",
        "BLT_0WAY",
        "BLT_1WAY",
        "BLT_2WAY",
        "BLT_NWAY",
    ):
        if int(getattr(ida_hexrays, name, -1)) == int(blk_type):
            return name
    return f"UNKNOWN({blk_type})"


def _expected_successor_count(blk_type: int, nsucc: int) -> int | None:
    if int(blk_type) == int(getattr(ida_hexrays, "BLT_STOP", -2)):
        return 0
    if int(blk_type) == int(getattr(ida_hexrays, "BLT_XTRN", -2)):
        return 0
    if int(blk_type) == int(getattr(ida_hexrays, "BLT_0WAY", -2)):
        return 0
    if int(blk_type) == int(getattr(ida_hexrays, "BLT_1WAY", -2)):
        return 1
    if int(blk_type) == int(getattr(ida_hexrays, "BLT_2WAY", -2)):
        return 2
    if int(blk_type) == int(getattr(ida_hexrays, "BLT_NWAY", -2)):
        return int(nsucc)
    return None


def _is_call_block(blk) -> bool:
    probe = getattr(blk, "is_call_block", None)
    if callable(probe):
        try:
            return bool(probe())
        except Exception:
            return False
    return False


def _tail_is_noret_call(tail) -> bool:
    if tail is None:
        return False
    probe = getattr(tail, "is_noret_call", None)
    if not callable(probe):
        return False

    no_analysis = int(getattr(ida_hexrays, "NORET_FORBID_ANALYSIS", 0))
    signatures = (
        (),
        (no_analysis,),
        (None, no_analysis),
    )
    for args in signatures:
        try:
            return bool(probe(*args))
        except TypeError:
            continue
        except Exception:
            return False
    return False


def block_list_consistency(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check next/prev links and list boundaries (verify.cpp 50840..50843)."""
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)
    qty = int(mba.qty)

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue

        nextb = getattr(blk, "nextb", None)
        prevb = getattr(blk, "prevb", None)

        if nextb is not None and not _same_block_ref(getattr(nextb, "prevb", None), blk):
            violations.append(
                _violation(
                    code="CFG_50840_BLOCK_LIST_NEXT_PREV",
                    phase=phase,
                    message=f"Block {serial} nextb->prevb does not point back to block",
                    block_serial=int(serial),
                    verify_code=50840,
                )
            )
        if prevb is not None and not _same_block_ref(getattr(prevb, "nextb", None), blk):
            violations.append(
                _violation(
                    code="CFG_50841_BLOCK_LIST_PREV_NEXT",
                    phase=phase,
                    message=f"Block {serial} prevb->nextb does not point back to block",
                    block_serial=int(serial),
                    verify_code=50841,
                )
            )

        expected_is_last = int(serial) == qty - 1
        expected_is_first = int(serial) == 0
        if (nextb is None) != expected_is_last:
            violations.append(
                _violation(
                    code="CFG_50842_BLOCK_LIST_END_BOUNDARY",
                    phase=phase,
                    message=(
                        f"Block {serial} nextb boundary mismatch: "
                        f"nextb_is_none={nextb is None}, expected_last={expected_is_last}"
                    ),
                    block_serial=int(serial),
                    verify_code=50842,
                )
            )
        if (prevb is None) != expected_is_first:
            violations.append(
                _violation(
                    code="CFG_50843_BLOCK_LIST_BEGIN_BOUNDARY",
                    phase=phase,
                    message=(
                        f"Block {serial} prevb boundary mismatch: "
                        f"prevb_is_none={prevb is None}, expected_first={expected_is_first}"
                    ),
                    block_serial=int(serial),
                    verify_code=50843,
                )
            )

    return violations


def pred_succ_symmetry(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check bidirectional edge consistency between succset/predset."""
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)
    qty = _qty(mba)

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue

        for succ in _succ_list(blk):
            succ_blk = _safe_get_block(mba, int(succ))
            if succ_blk is None:
                violations.append(
                    _violation(
                        code="CFG_50857_SUCC_OUT_OF_RANGE",
                        phase=phase,
                        message=f"Block {serial} successor {succ} is out of range [0, {qty})",
                        block_serial=int(serial),
                        verify_code=50857,
                    )
                )
                continue
            if not _serial_in_predset(succ_blk, int(serial)):
                violations.append(
                    _violation(
                        code="CFG_50858_SUCC_PRED_MISMATCH",
                        phase=phase,
                        message=(
                            f"Block {serial} -> {succ} exists in succset but "
                            "successor predset is missing this block"
                        ),
                        block_serial=int(serial),
                        verify_code=50858,
                    )
                )

        for pred in _pred_list(blk):
            pred_blk = _safe_get_block(mba, int(pred))
            if pred_blk is None:
                violations.append(
                    _violation(
                        code="CFG_EDGE_PRED_MISSING_BLOCK",
                        phase=phase,
                        message=f"Block {serial} predecessor {pred} is out of range [0, {qty})",
                        block_serial=int(serial),
                    )
                )
                continue
            if not _serial_in_succset(pred_blk, int(serial)):
                violations.append(
                    _violation(
                        code="CFG_50861_PRED_SUCC_MISMATCH",
                        phase=phase,
                        message=(
                            f"Block {pred} -> {serial} missing in predecessor succset"
                        ),
                        block_serial=int(serial),
                        verify_code=50861,
                    )
                )

    return violations


def predecessor_uniqueness(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check predset uniqueness (verify.cpp 50862)."""
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue
        seen: set[int] = set()
        for pred in _pred_list(blk):
            if pred in seen:
                violations.append(
                    _violation(
                        code="CFG_50862_DUPLICATE_PRED",
                        phase=phase,
                        message=f"Block {serial} has duplicate predecessor {pred}",
                        block_serial=int(serial),
                        verify_code=50862,
                    )
                )
                break
            seen.add(pred)
    return violations


def block_type_vs_tail(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check block type coherence with tail opcode and successor vector size."""
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)
    qty = _qty(mba)

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue

        blk_type = _blk_type(blk)
        if blk_type == int(getattr(ida_hexrays, "BLT_NONE", -1)):
            continue

        nsucc = _nsucc(blk)
        tail = getattr(blk, "tail", None)
        tail_opcode = _tail_opcode(blk)
        succs = _succ_list(blk)

        expected_nsucc = _expected_successor_count(blk_type, nsucc)
        if expected_nsucc is None:
            violations.append(
                _violation(
                    code="CFG_51815_WRONG_BLOCK_TYPE",
                    phase=phase,
                    message=f"Block {serial} has unsupported type {_block_type_name(blk_type)}",
                    block_serial=int(serial),
                    verify_code=51815,
                )
            )
            continue

        is_nway = blk_type == int(getattr(ida_hexrays, "BLT_NWAY", -1))
        is_jtbl = tail is not None and tail_opcode == int(getattr(ida_hexrays, "m_jtbl", -1))
        if is_nway != is_jtbl:
            violations.append(
                _violation(
                    code="CFG_50855_NWAY_JTBL_MISMATCH",
                    phase=phase,
                    message=(
                        f"Block {serial} type={_block_type_name(blk_type)} "
                        f"tail_opcode={tail_opcode} violates NWAY<->jtbl equivalence"
                    ),
                    block_serial=int(serial),
                    insn_ea=_insn_ea(tail),
                    verify_code=50855,
                )
            )

        if nsucc != expected_nsucc:
            violations.append(
                _violation(
                    code="CFG_50856_BAD_NSUCC",
                    phase=phase,
                    message=(
                        f"Block {serial} type={_block_type_name(blk_type)} "
                        f"expects nsucc={expected_nsucc}, got {nsucc}"
                    ),
                    block_serial=int(serial),
                    verify_code=50856,
                )
            )

        if blk_type == int(getattr(ida_hexrays, "BLT_2WAY", -1)) and not _is_conditional_jump_opcode(tail_opcode):
            violations.append(
                _violation(
                    code="CFG_BLT2WAY_NON_JCC_TAIL",
                    phase=phase,
                    message=(
                        f"Block {serial} type=BLT_2WAY but tail opcode={tail_opcode} "
                        "is not a conditional jump"
                    ),
                    block_serial=int(serial),
                    insn_ea=_insn_ea(tail),
                )
            )

        if (
            not _is_snapshot_block(blk)
            and blk_type == int(getattr(ida_hexrays, "BLT_1WAY", -1))
            and _is_call_block(blk)
        ):
            if _tail_is_noret_call(tail):
                violations.append(
                    _violation(
                        code="CFG_51774_NORET_CALL_BLOCK_NOT_0WAY",
                        phase=phase,
                        message=f"Block {serial} call-tail is noreturn but type is BLT_1WAY",
                        block_serial=int(serial),
                        insn_ea=_insn_ea(tail),
                        verify_code=51774,
                    )
                )
            # Guarded by `not _is_snapshot_block(blk)` above — snapshot blocks
            # may have non-contiguous serials, so serial+1 is only valid for
            # live IDA blocks.
            expected_next = int(serial) + 1
            if nsucc == 0 or succs[0] != expected_next:
                violations.append(
                    _violation(
                        code="CFG_50854_CALL_BLOCK_FLOW_MISMATCH",
                        phase=phase,
                        message=(
                            f"Block {serial} call block must flow to serial+1={expected_next}, "
                            f"got succs={succs}"
                        ),
                        block_serial=int(serial),
                        verify_code=50854,
                        details={"expected_next": expected_next, "qty": qty},
                    )
                )

    return violations


def successor_set_matches_tail_semantics(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check exact successor derivation parity with verifier.cpp outs logic."""
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue

        blk_type = _blk_type(blk)
        if blk_type == int(getattr(ida_hexrays, "BLT_NONE", -1)):
            continue

        tail = getattr(blk, "tail", None)
        tail_opcode = _tail_opcode(blk)
        succs = _succ_list(blk)
        nsucc = _nsucc(blk)
        expected_nsucc = _expected_successor_count(blk_type, nsucc)
        if expected_nsucc is None:
            continue

        outs: list[int] = []
        if tail_opcode == int(getattr(ida_hexrays, "m_jtbl", -1)):
            if _is_snapshot_block(blk):
                outs = list(succs)
            else:
                targets, err = _jtbl_targets(tail)
                if err is not None:
                    violations.append(
                        _violation(
                            code="CFG_50859_JTBL_CASELIST_INVALID",
                            phase=phase,
                            message=f"Block {serial}: {err}",
                            block_serial=int(serial),
                            insn_ea=_insn_ea(tail),
                            verify_code=50859,
                        )
                    )
                else:
                    outs = list(targets or [])
        elif tail_opcode == int(getattr(ida_hexrays, "m_goto", -1)):
            if _is_snapshot_block(blk):
                if succs:
                    outs.append(int(succs[0]))
            else:
                left = getattr(tail, "l", None)
                if _mop_is_mblock(left):
                    outs.append(int(getattr(left, "b")))
        elif _is_conditional_jump_opcode(tail_opcode):
            if _is_snapshot_block(blk):
                # Projected snapshot: trust simulated successor list
                outs = list(succs)
            else:
                outs.append(int(serial) + 1)  # fallthrough
                dest = getattr(tail, "d", None)
                if dest is not None and hasattr(dest, "b"):
                    try:
                        target = int(dest.b)
                    except Exception:
                        target = None
                    else:
                        if target is not None and target not in outs:
                            outs.append(target)
        elif tail_opcode in {
            int(getattr(ida_hexrays, "m_ijmp", -1)),
            int(getattr(ida_hexrays, "m_ret", -1)),
        }:
            outs = []
        elif tail_opcode == int(getattr(ida_hexrays, "m_ext", -1)):
            outs = list(succs)
        elif expected_nsucc != 0:
            if _is_snapshot_block(blk):
                outs = list(succs)
            else:
                outs.append(int(serial) + 1)

        if outs != succs:
            violations.append(
                _violation(
                    code="CFG_50860_SUCC_MISMATCH",
                    phase=phase,
                    message=(
                        f"Block {serial} derived outs {outs} do not match succset {succs}"
                    ),
                    block_serial=int(serial),
                    insn_ea=_insn_ea(tail),
                    verify_code=50860,
                    details={
                        "tail_opcode": int(tail_opcode),
                        "derived_outs": tuple(int(v) for v in outs),
                        "succset": tuple(int(v) for v in succs),
                    },
                )
            )

    return violations


# ---------------------------------------------------------------------------
# Closing-opcode constants used by several checks below.
# ---------------------------------------------------------------------------
def _closing_opcodes() -> frozenset[int]:
    """Return the set of opcodes that must only appear at tail position."""
    return frozenset(
        int(getattr(ida_hexrays, name, -1))
        for name in ("m_goto", "m_jcnd", "m_jtbl", "m_ijmp", "m_ret")
        if int(getattr(ida_hexrays, name, -1)) >= 0
    )


def _iter_insns(blk):
    """Yield instructions from a block.

    For :class:`BlockSnapshot` objects, iterates over ``insn_snapshots``
    directly (``InsnSnapshot`` has no ``.next`` pointer, so the head→next
    walk would silently yield only the first instruction).  For live IDA
    blocks, walks the ``head → .next`` chain as before.
    """
    if _is_snapshot_block(blk):
        yield from blk.insn_snapshots
        return
    insn = getattr(blk, "head", None)
    while insn is not None:
        yield insn
        insn = getattr(insn, "next", None)


def _block_has_flag(blk, flag_name: str) -> bool:
    flags = int(getattr(blk, "flags", 0))
    flag_val = int(getattr(ida_hexrays, flag_name, 0))
    return bool(flags & flag_val)


def _known_mbl_mask() -> int:
    """Return the mask of all known MBL_* flag bits (best-effort)."""
    # Prefer runtime discovery to stay aligned with SDK changes across IDA
    # versions and avoid false positives on valid block maintenance flags.
    mask = 0
    for name in dir(ida_hexrays):
        if not name.startswith("MBL_"):
            continue
        val = getattr(ida_hexrays, name, None)
        if val is not None:
            try:
                mask |= int(val)
            except Exception:
                pass
    if mask:
        return int(mask)

    # Fallback for non-IDA test environments and stripped wrappers.
    fallback_names = (
        "MBL_PRIV",
        "MBL_NONFAKE",
        "MBL_FAKE",
        "MBL_GOTO",
        "MBL_TCAL",
        "MBL_PUSH",
        "MBL_DMT64",
        "MBL_COMB",
        "MBL_PROP",
        "MBL_DEAD",
        "MBL_LIST",
        "MBL_INCONST",
        "MBL_CALL",
        "MBL_BACKPROP",
        "MBL_NORET",
        "MBL_DSLOT",
        "MBL_VALRANGES",
        "MBL_KEEP",
        "MBL_INLINED",
        "MBL_EXTFRAME",
    )
    for name in fallback_names:
        val = getattr(ida_hexrays, name, None)
        if val is not None:
            try:
                mask |= int(val)
            except Exception:
                pass
    return int(mask) if mask else 0xFFFF


def block_serial_range(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check block.serial < mba.qty for every block (verify.cpp 50851)."""
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)
    qty = _qty(mba)

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue
        blk_serial = int(getattr(blk, "serial", serial))
        if blk_serial >= qty:
            violations.append(
                _violation(
                    code="CFG_50851_SERIAL_OUT_OF_RANGE",
                    phase=phase,
                    message=(
                        f"Block at index {serial} has serial={blk_serial} "
                        f">= mba.qty={qty}"
                    ),
                    block_serial=serial,
                    verify_code=50851,
                )
            )
    return violations


def block_closing_opcode_at_tail(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check closing opcodes appear only at tail position (verify.cpp 50864).

    Also checks that push/pop do not exist after MMAT_CALLS (verify.cpp 50865),
    and that entry/exit/extern blocks are empty (verify.cpp 51814).
    """
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)
    qty = int(mba.qty)
    closing = _closing_opcodes()
    maturity = int(getattr(mba, "maturity", 0))
    mmat_calls = int(getattr(ida_hexrays, "MMAT_CALLS", 3))
    after_calls = maturity >= mmat_calls

    m_push = int(getattr(ida_hexrays, "m_push", -1))
    m_pop = int(getattr(ida_hexrays, "m_pop", -1))
    blt_xtrn = int(getattr(ida_hexrays, "BLT_XTRN", 6))

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue

        blk_type = int(getattr(blk, "type", 0))
        is_special = (
            serial == 0
            or serial == qty - 1
            or blk_type == blt_xtrn
        )
        tail = getattr(blk, "tail", None)

        # Check 51814: special blocks must be empty
        if is_special and tail is not None:
            violations.append(
                _violation(
                    code="CFG_51814_SPECIAL_BLOCK_NOT_EMPTY",
                    phase=phase,
                    message=(
                        f"Block {serial} is a special block (entry/exit/extern) "
                        "but has instructions"
                    ),
                    block_serial=serial,
                    verify_code=51814,
                )
            )

        # Walk all instructions for per-insn checks
        all_insns = list(_iter_insns(blk))
        for idx, insn in enumerate(all_insns):
            opcode = int(getattr(insn, "opcode", 0))
            is_tail_position = idx == len(all_insns) - 1

            # Check 50864: closing opcodes must be at tail
            if opcode in closing and not is_tail_position:
                violations.append(
                    _violation(
                        code="CFG_50864_CLOSING_OPCODE_NOT_AT_TAIL",
                        phase=phase,
                        message=(
                            f"Block {serial}: closing opcode {opcode} found at "
                            f"instruction index {idx}, not at tail"
                        ),
                        block_serial=serial,
                        insn_ea=_insn_ea(insn),
                        verify_code=50864,
                    )
                )

            # Check 50865: push/pop after MMAT_CALLS
            if after_calls and opcode in (m_push, m_pop):
                violations.append(
                    _violation(
                        code="CFG_50865_PUSH_POP_AFTER_CONVERSION",
                        phase=phase,
                        message=(
                            f"Block {serial}: found {'m_push' if opcode == m_push else 'm_pop'} "
                            f"after MMAT_CALLS (maturity={maturity})"
                        ),
                        block_serial=serial,
                        insn_ea=_insn_ea(insn),
                        verify_code=50865,
                    )
                )

    return violations


def block_address_range(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check start/end address invariants for non-fake blocks (verify.cpp 50869, 50870)."""
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)
    mbl_fake = int(getattr(ida_hexrays, "MBL_FAKE", 0x10))
    entry_ea = int(getattr(mba, "entry_ea", 0))

    # Determine function end address if available
    func_end: int | None = None
    try:
        last_blk = mba.get_mblock(int(mba.qty) - 1)
        if last_blk is not None and hasattr(last_blk, "end"):
            func_end = int(last_blk.end)
    except Exception:
        func_end = None

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue

        flags = int(getattr(blk, "flags", 0))
        if flags & mbl_fake:
            continue  # fake blocks exempt from address checks

        start = int(getattr(blk, "start", 0))
        end = int(getattr(blk, "end", 0))

        # Check 50869: start >= end for non-fake block
        if start >= end:
            violations.append(
                _violation(
                    code="CFG_50869_START_GE_END",
                    phase=phase,
                    message=(
                        f"Block {serial}: start=0x{start:x} >= end=0x{end:x}"
                    ),
                    block_serial=serial,
                    verify_code=50869,
                )
            )

        # Check 50870: block outside function boundaries
        if func_end is not None:
            if start < entry_ea or end > func_end:
                violations.append(
                    _violation(
                        code="CFG_50870_BLOCK_OUTSIDE_FUNC",
                        phase=phase,
                        message=(
                            f"Block {serial}: range [0x{start:x}, 0x{end:x}) falls outside "
                            f"function [0x{entry_ea:x}, 0x{func_end:x})"
                        ),
                        block_serial=serial,
                        verify_code=50870,
                    )
                )

    return violations


def block_unknown_flags(
    mba,
    *,
    phase: str,
    focus_serials: Iterable[int] | None = None,
) -> list[InvariantViolation]:
    """Check for unknown bits in block.flags (verify.cpp 50844, best-effort)."""
    violations: list[InvariantViolation] = []
    serials = _serials_for_scope(mba, focus_serials)
    known_mask = _known_mbl_mask()

    for serial in serials:
        blk = _safe_get_block(mba, int(serial))
        if blk is None:
            continue
        flags = int(getattr(blk, "flags", 0))
        unknown_bits = flags & ~known_mask
        if unknown_bits:
            violations.append(
                _violation(
                    code="CFG_50844_UNKNOWN_BLOCK_FLAGS",
                    phase=phase,
                    message=(
                        f"Block {serial}: flags=0x{flags:x} contains unknown bits "
                        f"0x{unknown_bits:x} (known_mask=0x{known_mask:x})"
                    ),
                    block_serial=serial,
                    verify_code=50844,
                )
            )
    return violations
