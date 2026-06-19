"""State-write anchor fact collector.

This collector observes ``mov #const, %var_<stkoff>`` style state-variable
writes BEFORE IDA's MMAT_LOCOPT constant-propagation collapses transit-state
constants into eventual successor blocks.

Background
----------
On ``sub_7FFD3338C040`` we observed 34 state-write constants getting
rewritten in-place between ``MMAT_LOCOPT pre_d810`` and ``MMAT_LOCOPT
post_d810`` (e.g. ``blk[100] 0x5A21D9DB -> 0x63D54755``).  D810 is NOT the
mutator: by elimination, IDA's own MMAT_LOCOPT constant-propagation pass
collapses transit-state writes into the eventually-reaching successor's
state.  Once the rewrite happens, the recon DAG built at GLBOPT1 reflects
the post-CP microcode and disagrees with the linearized reference.

This fact captures the ORIGINAL state-write constant at LOCOPT-pre so later
consumers can compare against the GLBOPT1 recon view and detect IDA-driven
rewrites.

Lifecycle integration
---------------------
The :class:`FactLifecycleRuntime` already invokes collectors at
``MMAT_LOCOPT`` with ``phase="pre_d810"``.  No runtime changes are required
to capture LOCOPT-pre observations.  Cross-maturity rewrite detection lives
in
:meth:`FactLifecycleRuntime._derive_state_write_anchor_lifecycle`, which
emits :data:`FactStatus.STATE_CONST_REWRITTEN` mappings when the same
``(block_serial, instruction_ea, state_var_stkoff)`` produces a different
``state_const`` at a later maturity.
"""
from __future__ import annotations

from collections.abc import Mapping
import re
from dataclasses import dataclass

from d810.core.typing import Any, Iterable
from d810.analyses.value_flow.induction_carrier import (
    _MATURITY_VALUES,
    _InstructionView,
    _iter_instruction_views,
    _maturity_name,
)
from d810.analyses.value_flow.model import FactObservation
from d810.analyses.value_flow.contract_evidence import (
    ContractEvidenceToken,
    contract_evidence_payload,
)


# State-write opcodes: plain ``m_mov`` (``op_4``) is the canonical OLLVM
# state writer (``mov #0xXXXX, %var_3C.4``).  ``m_xdu`` / ``m_xds`` show up
# when the dispatch state is widened/narrowed between maturity passes.
_MOV_OPCODES = frozenset({"m_mov", "op_4", "mov"})

_TARGET_MATURITIES = frozenset({
    _MATURITY_VALUES["MMAT_PREOPTIMIZED"],
    _MATURITY_VALUES["MMAT_LOCOPT"],
    _MATURITY_VALUES["MMAT_CALLS"],
    _MATURITY_VALUES["MMAT_GLBOPT1"],
})

# Capture ``%var_<HEX>.<SIZE>`` (with optional SSA brace suffix) so we can
# preserve the destination signature reported by IDA's ``dstr`` in fact
# evidence/payload.  The first capture is the offset hex; the second is the
# size suffix.
_DEST_VAR_RE = re.compile(
    r"%var_([0-9A-Fa-f]+)\.(\d+)(?:\{[^}]*\})?",
)
# A short opcode-only fingerprint of the block's instructions, used for
# correlation across maturities.
_OPCODE_FINGERPRINT_LIMIT = 8


@dataclass(frozen=True)
class _BlockStateWriteContext:
    """Per-block context captured once and reused across instructions."""

    serial: int
    succs: tuple[int, ...]
    opcode_fingerprint: str


def _block_succs(target: Any, block_serial: int) -> tuple[int, ...]:
    """Return successor serials for a block from a portable FlowGraph
    (``blocks`` mapping of ``BlockSnapshot`` with ``.succs``)."""
    blocks = getattr(target, "blocks", target)
    block_iter = blocks.values() if isinstance(blocks, Mapping) else blocks
    for blk in block_iter:
        try:
            if int(getattr(blk, "serial")) == int(block_serial):
                raw = getattr(blk, "succs", ()) or ()
                return tuple(int(succ) for succ in raw)
        except (TypeError, ValueError):
            continue
    return ()


def _opcode_fingerprint(
    instructions: tuple[_InstructionView, ...],
    block_serial: int,
) -> str:
    """Return a short opcode-only fingerprint for the block's first
    ``_OPCODE_FINGERPRINT_LIMIT`` instructions.

    Used as a correlation aid in the diag DB so SQL queries can match
    blocks across maturities even if serials shift slightly.
    """
    block_insns = [
        insn for insn in instructions if int(insn.block_serial) == int(block_serial)
    ]
    block_insns.sort(key=lambda insn: int(insn.insn_index))
    head = [str(insn.opcode_name or "") for insn in block_insns[:_OPCODE_FINGERPRINT_LIMIT]]
    return "|".join(head)


def _dest_var_signature(insn: _InstructionView) -> str | None:
    """Return the ``%var_<offset>.<size>`` signature parsed from the
    instruction's ``dstr`` representation, if present.

    The destination's stkoff already lives in
    :pyattr:`_InstructionView.dest_stkoff`; this signature preserves the
    human-readable form (e.g. ``%var_7BC.4``) that downstream tools like
    the diag CLI display directly.
    """
    text = str(insn.dstr or "")
    match = _DEST_VAR_RE.search(text)
    if match is None:
        return None
    return f"%var_{match.group(1).upper()}.{match.group(2)}"


def _instruction_anchor_ea(
    insn: _InstructionView,
    block_start_ea_by_serial: dict[int, int | None],
) -> int | None:
    """Return a stable EA for an instruction.

    Falls back to ``block_start_ea + insn_index`` when ``insn.ea`` is
    zero/missing so the lifecycle has SOMETHING to correlate on.  Synthetic
    EAs are still useful: they remain stable across maturities for the
    same ``(block_serial, insn_index)`` pair, which is the common case for
    state writers that ride along their original block.
    """
    if insn.ea is not None and int(insn.ea) != 0:
        return int(insn.ea)
    block_start = block_start_ea_by_serial.get(int(insn.block_serial))
    if block_start is None:
        return None
    return int(block_start) + int(insn.insn_index)


def _block_start_ea_lookup(target: Any) -> dict[int, int | None]:
    """Return a ``{block_serial: start_ea | None}`` map built from the
    snapshot/live target without re-iterating instructions."""
    lookup: dict[int, int | None] = {}
    blocks = getattr(target, "blocks", target)
    block_iter = blocks.values() if isinstance(blocks, Mapping) else blocks
    for blk in block_iter:
        try:
            serial = int(getattr(blk, "serial"))
        except (TypeError, ValueError):
            continue
        ea = getattr(blk, "start_ea", None)
        if ea is None:
            ea = getattr(blk, "start", None)
        try:
            lookup[serial] = int(ea) if ea is not None else None
        except (TypeError, ValueError):
            lookup[serial] = None
    return lookup


def _is_state_const_write(insn: _InstructionView) -> bool:
    """Return ``True`` if ``insn`` writes a constant into a stack slot."""
    if insn.opcode_name not in _MOV_OPCODES:
        return False
    if insn.dest_type != "mop_S" or insn.dest_stkoff is None:
        return False
    return insn.src_l_value is not None


def _iter_state_const_writes(
    instructions: tuple[_InstructionView, ...],
) -> Iterable[_InstructionView]:
    for insn in instructions:
        if _is_state_const_write(insn):
            yield insn


class StateWriteAnchorFactCollector:
    """Observe ``mov #const, %var_<stkoff>`` state-variable writes.

    The collector intentionally registers at every maturity in
    :data:`_TARGET_MATURITIES` (PREOPT, LOCOPT, CALLS, GLBOPT1).  The
    LOCOPT-pre observation captures the ORIGINAL constant; observations
    at later maturities allow the lifecycle runtime to detect rewrites
    via :class:`FactStatus.STATE_CONST_REWRITTEN` mappings.

    The collector is observability-only: it never modifies microcode and
    has no influence on planning or CFG mutation.
    """

    name = "StateWriteAnchorFactCollector"
    fact_kinds = frozenset({"StateWriteAnchorFact"})
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
        instructions = tuple(_iter_instruction_views(target))
        if not instructions:
            return ()

        block_start_ea = _block_start_ea_lookup(target)

        # Cache per-block context so we don't recompute fingerprints for
        # blocks with multiple state writes.
        block_contexts: dict[int, _BlockStateWriteContext] = {}

        observations: list[FactObservation] = []
        # Dedupe using ``(block_serial, insn_index, anchor_ea, stkoff)``.
        seen: set[tuple[int, int, int, int]] = set()

        for insn in _iter_state_const_writes(instructions):
            block_serial = int(insn.block_serial)
            stkoff = int(insn.dest_stkoff or 0)
            anchor_ea = _instruction_anchor_ea(insn, block_start_ea)
            if anchor_ea is None:
                # Without a stable EA we can't anchor the lifecycle row.
                continue
            dedupe = (
                block_serial,
                int(insn.insn_index),
                int(anchor_ea),
                stkoff,
            )
            if dedupe in seen:
                continue
            seen.add(dedupe)

            ctx = block_contexts.get(block_serial)
            if ctx is None:
                ctx = _BlockStateWriteContext(
                    serial=block_serial,
                    succs=_block_succs(target, block_serial),
                    opcode_fingerprint=_opcode_fingerprint(instructions, block_serial),
                )
                block_contexts[block_serial] = ctx

            const_value = int(insn.src_l_value or 0)
            const_value_u64 = const_value & 0xFFFFFFFFFFFFFFFF
            dest_var_signature = _dest_var_signature(insn)
            dest_size = int(insn.dest_size or 0)

            # Semantic key intentionally excludes ``state_const`` so the
            # fact_id remains stable across maturities for the SAME write
            # site, while the payload preserves the per-maturity constant
            # for the lifecycle to compare on.
            semantic_key = (
                f"state_write_anchor:blk={block_serial}:"
                f"insn={int(insn.insn_index)}:"
                f"ea=0x{int(anchor_ea):x}:"
                f"stkoff=0x{stkoff:x}"
            )
            fact_id = semantic_key
            payload: dict[str, Any] = {
                "state_const_hex": f"0x{const_value_u64:016x}",
                "state_const_u64": const_value_u64,
                "state_const": const_value_u64,
                "block_serial": block_serial,
                "instruction_index": int(insn.insn_index),
                "instruction_ea_hex": f"0x{int(anchor_ea) & 0xFFFFFFFFFFFFFFFF:016x}",
                "instruction_ea": int(anchor_ea),
                "state_var_stkoff": stkoff,
                "state_var_stkoff_hex": f"0x{stkoff:x}",
                "dest_var_signature": dest_var_signature,
                "dest_size": dest_size,
                "block_dstr": ctx.opcode_fingerprint,
                "successor_blocks": list(ctx.succs),
                "opcode": insn.opcode_name,
                **contract_evidence_payload(
                    ContractEvidenceToken.STATE_VARIABLE_WRITES
                ),
            }

            observations.append(
                FactObservation(
                    fact_id=fact_id,
                    kind="StateWriteAnchorFact",
                    semantic_key=semantic_key,
                    maturity=maturity_text,
                    phase=phase,
                    confidence=0.9,
                    source_block=block_serial,
                    source_ea=int(anchor_ea),
                    block_fingerprint=(
                        f"blk[{block_serial}].{int(insn.insn_index)}:"
                        f"{insn.opcode_name}"
                    ),
                    mop_signature=(
                        f"state_write:mop_S:0x{stkoff:x}:{dest_size}"
                    ),
                    payload=payload,
                    evidence=(insn.dstr,),
                )
            )
        return tuple(observations)


__all__ = ["StateWriteAnchorFactCollector"]
