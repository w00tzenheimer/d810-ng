"""Canonical-FlowGraph FactObservation pins (llr-pkuq).

These tests pin two FactObservations on the CANONICAL ``FlowGraph`` path that
lost their flat, meta-less ``_InstructionView`` cases when that view was deleted
(llr-3b41 S11, commit ``4159e22ea``).  The underlying behaviour is verified
functional on production targets; this is dedicated COVERAGE on a synthetic
canonical ``FlowGraph`` (pure Python, no IDA imports), matching the construction
idiom of the existing canonical collector suites
(``test_induction_carrier_collector.py`` / ``test_terminal_byte_emitter_collector.py``).

1. ``InductionVariableFactCollector`` writeback-tail FactObservation -- the
   writeback-tail signal reads ``instruction.attrs["address_stack_refs"]``, which
   ``d810.ir.insn_projection._instruction_attrs`` populates by recursively walking
   the operand tree for ``OperandKind.ADDRESS`` stack references.  A stack->stack
   ``MOV`` followed by a later instruction that uses the MOV's *source* stkoff
   inside a memory ADDRESS operand must yield a ``writeback_tail`` carrier fact.

2. ``TerminalByteEmitterFactCollector`` byte-emit corridor ``byte_index``
   FactObservation -- a memory STORE carrying an explicit ``byte_index`` provenance
   attr (``InsnSnapshot.opcode_attrs``, which flows into ``Instruction.attrs`` and
   is read by ``_byte_index_from_instruction``) must yield a byte-emit fact whose
   ``semantic_key`` / payload pin that byte index.
"""

from __future__ import annotations

from d810.ir.flowgraph import (
    BlockSnapshot as CfgBlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.value_flow.induction_carrier import (
    InductionVariableFactCollector,
    _MATURITY_VALUES,
)
from d810.analyses.value_flow.terminal_byte_emitter import (
    TerminalByteEmitterFactCollector,
)


def _cfg_stack(stkoff: int, *, size: int = 8) -> MopSnapshot:
    return MopSnapshot(kind=OperandKind.STACK, stkoff=stkoff, size=size)


def _cfg_address(*stkoffs: int, size: int = 8) -> MopSnapshot:
    """An ``OperandKind.ADDRESS`` operand referencing stack identities.

    ``_instruction_attrs`` walks this into ``attrs["address_stack_refs"]``, the
    structural signal the writeback-tail collector consumes.
    """
    return MopSnapshot(
        kind=OperandKind.ADDRESS,
        stack_refs=tuple(int(off) for off in stkoffs),
        size=size,
    )


def _cfg_insn(
    *,
    index: int,
    kind: InsnKind,
    l: MopSnapshot | None = None,
    r: MopSnapshot | None = None,
    d: MopSnapshot | None = None,
    display_text: str = "",
    opcode_attrs: dict | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=index,
        ea=0x180020000 + index,
        operands=(),
        kind=kind,
        l=l,
        r=r,
        d=d,
        display_text=display_text,
        opcode_attrs=opcode_attrs or {},
    )


def _cfg_target(
    *instructions: InsnSnapshot,
    serial: int = 10,
    succs: tuple[int, ...] = (),
    preds: tuple[int, ...] = (),
) -> FlowGraph:
    return FlowGraph(
        blocks={
            serial: CfgBlockSnapshot(
                serial=serial,
                block_type=1 if len(succs) <= 1 else 2,
                succs=succs,
                preds=preds,
                flags=0,
                start_ea=0x180020000,
                insn_snapshots=tuple(instructions),
            )
        },
        entry_serial=serial,
        func_ea=0x401000,
    )


def test_induction_writeback_tail_fact_from_canonical_flowgraph() -> None:
    """A stack->stack MOV whose source is later used inside a memory ADDRESS
    operand yields a ``writeback_tail`` induction FactObservation.

    The pairing is driven purely by ``instruction.attrs["address_stack_refs"]``
    (populated by ``_instruction_attrs`` from the canonical ADDRESS operand), so
    a passing assertion PROVES the structural address ref -- not rendered text --
    drove the recovery on the canonical path.
    """
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_insn(
                index=0,
                kind=InsnKind.MOV,
                d=_cfg_stack(0x700),
                l=_cfg_stack(0x680),
                display_text="mov %var_178.8, %var_158.8",
            ),
            _cfg_insn(
                index=1,
                kind=InsnKind.STORE,
                d=_cfg_stack(0x688),
                l=_cfg_address(0x680),
                display_text="stx %var_170.8, ds.2, [ds.2:%var_178.8]",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    writeback = [f for f in facts if f.payload.get("carrier_kind") == "writeback_tail"]
    assert len(writeback) == 1
    fact = writeback[0]
    assert fact.kind == "InductionCarrierFact"
    assert fact.semantic_key == (
        "induction:writeback_tail:dest=0x700:source=0x680:size=8"
    )
    assert fact.payload["dest_stkoff"] == 0x700
    assert fact.payload["source_stkoff"] == 0x680
    assert fact.payload["dest_token"] == "S1792"
    assert fact.payload["source_token"] == "S1664"
    assert fact.payload["move_insn_index"] == 0
    assert fact.payload["address_use_insn_index"] == 1


def test_induction_writeback_tail_requires_address_ref_not_dstr() -> None:
    """Without a structural ADDRESS operand (so no ``address_stack_refs`` attr)
    the same rendered text yields NO writeback-tail fact: the signal is the
    operand-tree address ref, not the ``display_text``."""
    collector = InductionVariableFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_insn(
                index=0,
                kind=InsnKind.MOV,
                d=_cfg_stack(0x700),
                l=_cfg_stack(0x680),
                display_text="mov %var_178.8, %var_158.8",
            ),
            _cfg_insn(
                index=1,
                kind=InsnKind.STORE,
                # source stkoff present only as a plain stack operand, never
                # inside an ADDRESS operand -> no address_stack_refs.
                d=_cfg_stack(0x688),
                l=_cfg_stack(0x680),
                display_text="stx %var_170.8, ds.2, [ds.2:%var_178.8]",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="pre_d810",
    )

    assert [f for f in facts if f.payload.get("carrier_kind") == "writeback_tail"] == []


def test_terminal_byte_emit_byte_index_fact_from_canonical_flowgraph() -> None:
    """A memory STORE carrying an explicit ``byte_index`` provenance attr on the
    canonical ``FlowGraph`` yields a byte-emit FactObservation pinning that byte
    index.

    ``byte_index`` arrives via ``InsnSnapshot.opcode_attrs`` -> ``Instruction.attrs``
    -> ``_byte_index_from_instruction``; this is the flat meta-less corridor case
    that lost its ``_InstructionView`` path and is now reached through canonical
    instruction attrs.
    """
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_insn(
                index=0,
                kind=InsnKind.STORE,
                d=_cfg_stack(0x700),
                l=_cfg_stack(0x520),
                display_text="stx byte3, ds.1, %var_dst.8",
                opcode_attrs={"byte_index": 3},
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == "TerminalByteEmitterFact"
    assert "byte_index=3" in fact.semantic_key
    assert "dest=S1792" in fact.semantic_key
    assert fact.payload["byte_index"] == 3
    assert fact.payload["destination_buffer_expression"] == "S1792"
    assert fact.payload["emitter_role"] == "memory_store"
    assert fact.payload["source_byte_expression"] == "byte[3]"


def test_terminal_byte_emit_store_without_byte_index_yields_no_fact() -> None:
    """The same canonical STORE without an explicit ``byte_index`` attr and with
    no guard yields no byte-emit fact -- pinning that the byte index is what
    authorizes the corridor observation, not the STORE alone."""
    collector = TerminalByteEmitterFactCollector()

    facts = collector.collect(
        _cfg_target(
            _cfg_insn(
                index=0,
                kind=InsnKind.STORE,
                d=_cfg_stack(0x700),
                l=_cfg_stack(0x520),
                display_text="stx %var_tmp.1, ds.1, %var_dst.8",
            ),
        ),
        func_ea=0x401000,
        maturity=_MATURITY_VALUES["MMAT_GLBOPT1"],
        phase="pre_d810",
    )

    assert facts == ()
