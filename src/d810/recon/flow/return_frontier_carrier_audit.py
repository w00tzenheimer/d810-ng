"""Return-frontier carrier-identity audit (observability-only).

For each block whose tail is m_ret (or whose type is BLT_STOP), capture
the returned mop_t and walk its reaching definition chain.  Compare
against protected side-effect corridor membership to classify whether
the return value's carrier identity has been severed by D810's
upstream simplifications.

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

logger = getLogger(__name__)

_AUDIT_ENV = "D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT"


@dataclass(frozen=True, slots=True)
class ReturnFrontierCarrierEntry:
    block_serial: int
    returned_mop_repr: str           # human-readable mop description (mop_t.dstr() if available)
    reaching_def_block: int | None
    reaching_def_opcode: int | None
    carrier_lvar_idx: int | None     # if mop_l carrier
    carrier_stkoff: int | None       # if mop_S carrier
    in_protected_corridor: bool
    classification: str              # one of CLASSIFICATIONS
    diagnostic: str                  # human-readable explanation


CLASSIFICATIONS = (
    "RETURN_CARRIER_LOST",
    "STATE_GUARD_ARTIFACT",
    "POINTER_IDENTITY_PROPAGATED",
    "UNKNOWN",
)


def is_audit_enabled() -> bool:
    """Return True iff the env gate is set to '1'."""
    return os.environ.get(_AUDIT_ENV, "").strip() == "1"


# Known pre-existing function-pool qwords for sub_7FFD3338C040.
# Documented in MEMORY.md as a real pool artifact, NOT a D810
# fabrication -- its presence as a returned constant indicates the
# return-slot has no live def and IDA pulled it from the pool.
_KNOWN_POOL_ARTIFACT_VALUES = frozenset({
    0xC5FB34A1D9A6E315,
})


def audit_return_frontier_carriers(
    mba,                              # ida_hexrays.mba_t (live)
    side_effect_corridors: tuple[tuple[int, ...], ...] = (),
    *,
    label: str = "post_pipeline",
) -> tuple[ReturnFrontierCarrierEntry, ...]:
    """Audit every return-tail block; return one entry per return block.

    Read-only.  When the audit env gate is unset, this function is a
    complete no-op (returns empty tuple, emits no log lines).

    For each block whose tail is m_ret (or block_type == BLT_STOP):
      1. Find the instruction that writes the return value (commonly
         a `mov SRC, rax` or `stx SRC, [return-slot]`).
      2. Extract the source mop_t SRC and a human-readable repr.
      3. Determine carrier identity:
         * mop_l (lvar)  -> record lvar_idx
         * mop_S (stkvar) -> record stkoff
         * mop_n (constant) -> carrier likely missing entirely
         * mop_d (sub-instruction) -> POINTER_IDENTITY_PROPAGATED
           is the prime suspect (copy-prop substituted def into use)
      4. Check if `block_serial` is in any protected corridor tuple.
      5. Classify per the rules in CLASSIFICATIONS.
      6. Emit one structured log line per entry.
    """
    if not is_audit_enabled():
        return ()

    if mba is None:
        return ()

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

    # Build the corridor block set for fast membership tests.
    corridor_blocks: set[int] = set()
    for chain in side_effect_corridors:
        for b in chain:
            try:
                corridor_blocks.add(int(b))
            except (TypeError, ValueError):
                pass

    entries: list[ReturnFrontierCarrierEntry] = []

    qty = 0
    try:
        qty = int(getattr(mba, "qty", 0))
    except (TypeError, ValueError):
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

        # Find the write that defines the return value.  Two common
        # shapes:
        #   * `mov SRC.8, rax.8` immediately before m_ret
        #   * `stx SRC.8 -> [stack_return_slot]` then mov stack -> rax
        # We capture the LAST such write before m_ret and capture
        # its source operand description.
        return_write_insn = None
        insn = getattr(blk, "head", None)
        while insn is not None:
            try:
                op = int(insn.opcode)
            except AttributeError:
                insn = getattr(insn, "next", None)
                continue
            if op == m_mov or op == m_stx or op == m_add:
                return_write_insn = insn
            insn = getattr(insn, "next", None)

        block_serial_int = -1
        try:
            block_serial_int = int(blk.serial)
        except (AttributeError, TypeError):
            pass

        in_corridor = block_serial_int in corridor_blocks

        if return_write_insn is None:
            entries.append(ReturnFrontierCarrierEntry(
                block_serial=block_serial_int,
                returned_mop_repr="<no-write-found>",
                reaching_def_block=None,
                reaching_def_opcode=None,
                carrier_lvar_idx=None,
                carrier_stkoff=None,
                in_protected_corridor=in_corridor,
                classification="UNKNOWN",
                diagnostic="no return-slot write found before m_ret",
            ))
            logger.info(
                "RETURN_FRONTIER_CARRIER_AUDIT[%s]: blk[%d] "
                "returned=<no-write-found> classification=UNKNOWN "
                "reason=no-write-found",
                label, block_serial_int,
            )
            continue

        src_mop = getattr(return_write_insn, "l", None)
        try:
            returned_repr = src_mop.dstr() if src_mop is not None else "<null>"
        except Exception:
            returned_repr = "<dstr-failed>"

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

        # Classification.
        classification = "UNKNOWN"
        diagnostic = "default"
        try:
            if src_mop is not None and int(src_mop.t) == mop_n:
                val = 0
                try:
                    val = int(src_mop.nnn.value) if src_mop.nnn is not None else 0
                except (AttributeError, TypeError):
                    val = 0
                masked = val & 0xFFFFFFFFFFFFFFFF
                if masked in _KNOWN_POOL_ARTIFACT_VALUES:
                    classification = "STATE_GUARD_ARTIFACT"
                    diagnostic = (
                        f"returned constant 0x{masked:016x} matches known pool "
                        f"artifact; original carrier likely state-var widening"
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

        reaching_def_opcode: int | None = None
        try:
            reaching_def_opcode = int(return_write_insn.opcode)
        except (AttributeError, TypeError):
            pass

        entry = ReturnFrontierCarrierEntry(
            block_serial=block_serial_int,
            returned_mop_repr=returned_repr,
            reaching_def_block=block_serial_int,
            reaching_def_opcode=reaching_def_opcode,
            carrier_lvar_idx=carrier_lvar_idx,
            carrier_stkoff=carrier_stkoff,
            in_protected_corridor=in_corridor,
            classification=classification,
            diagnostic=diagnostic,
        )
        entries.append(entry)
        logger.info(
            "RETURN_FRONTIER_CARRIER_AUDIT[%s]: blk[%d] returned=%s "
            "carrier=lvar=%s|stkoff=%s reaching_def=blk[%s] op=0x%s "
            "corridor=%s classification=%s reason=%s",
            label,
            entry.block_serial,
            entry.returned_mop_repr,
            entry.carrier_lvar_idx,
            entry.carrier_stkoff,
            entry.reaching_def_block,
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
