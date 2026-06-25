"""S10 (ticket llr-3b41): post-D810 fact capture is canonical, not flat.

``d810.hexrays.fact_target.mba_to_fact_target`` was the LONE production fact
source that handed collectors a flat, meta-less ``SimpleNamespace`` target
(``serial`` + flat ``instructions`` only, NO ``insn_snapshots``).  Every
collector therefore routed the post-D810 path through its meta-less legacy
``_InstructionView`` fallback.  S10 made ``mba_to_fact_target`` return the same
canonical :class:`~d810.ir.flowgraph.FlowGraph` the pre-D810 ``FLOWGRAPH_READY``
path produces (via ``ir_translator.lift``), so post-D810 capture now flows
through the canonical ``InstructionProjection.from_block`` branch.

``mba_to_fact_target`` itself is IDA-bound (it imports ``ir_translator`` which
imports ``idaapi``), so this file cannot import it under the
``unit-tests-no-hexrays`` contract.  Instead it pins the CONSUMER-side contract
that S10 relies on: feeding the SAME state write through the retired flat shape
vs the canonical ``FlowGraph`` shape.

Documented S10 fact change (EMBRACE, strictly-better recovery):

* The retired flat shape labelled a state-write ``mov`` with the raw opcode
  string ``"m_mov"`` (the old ``fact_target._opcode_name`` mapping).  But
  ``StateWriteAnchorFactCollector`` only recognizes a MOVE when the opcode is
  one of ``{"op_4", "mov", "MOVE", "move"}`` -- ``"m_mov"`` is NOT in that set,
  so the gate ``_is_state_const_write`` (``operation is ValueOpKind.MOVE``)
  failed and the flat post-D810 path produced ZERO state-write-anchor facts.
* The canonical ``FlowGraph`` shape carries ``value_op_kind=ValueOpKind.MOVE``,
  so the gate passes and the fact is recovered with a normalized ``opcode``
  (``"move"``) and a portable ``operation``.

So S10 RECOVERS a state-write-anchor fact that the flat post-D810 path missed
entirely -- the strongest possible witness that the meta-less fallback was a
production gap, not merely a cosmetic one.  When the fact IS produced by both
shapes (e.g. when the flat opcode happens to be a recognized alias) value
identity stays byte-identical; that is also pinned below.
"""
from __future__ import annotations

from types import SimpleNamespace

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import (
    BlockSnapshot as CfgBlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.analyses.value_flow.state_write_anchor import StateWriteAnchorFactCollector
from d810.analyses.value_flow.induction_carrier import _MATURITY_VALUES

_FUNC_EA = 0x180012CF0
_INSN_EA = 0x180014155
_STATE_CONST = 0x5A21D9DB
_STATE_STKOFF = 0x3C


def _flat_target(opcode_name: str = "m_mov") -> SimpleNamespace:
    """The shape ``mba_to_fact_target`` emitted BEFORE S10: flat rows, no
    ``insn_snapshots``.  Routes through the meta-less legacy ``_InstructionView``
    fallback.  ``opcode_name`` defaults to ``"m_mov"`` -- the string the old
    ``fact_target._opcode_name`` produced for a MOVE, which the collector's MOVE
    alias set does NOT contain."""
    insn = SimpleNamespace(
        index=0,
        ea=_INSN_EA,
        opcode_name=opcode_name,
        dest_type="mop_S",
        dest_stkoff=_STATE_STKOFF,
        dest_size=4,
        src_l_type="mop_n",
        src_l_stkoff=None,
        src_l_value=_STATE_CONST,
        src_r_type=None,
        src_r_stkoff=None,
        src_r_value=None,
        dstr="mov #0x5A21D9DB.4, %var_7BC.4",
    )
    block = SimpleNamespace(serial=100, instructions=(insn,))
    return SimpleNamespace(blocks={100: block})


def _canonical_target() -> FlowGraph:
    """The shape ``mba_to_fact_target`` emits AFTER S10: a canonical
    ``FlowGraph`` whose block carries ``insn_snapshots`` -- routes through
    ``InstructionProjection.from_block``."""
    return FlowGraph(
        blocks={
            100: CfgBlockSnapshot(
                serial=100,
                block_type=0,
                succs=(101,),
                preds=(99,),
                flags=0,
                start_ea=0x180014000,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=_INSN_EA,
                        operands=(),
                        kind=InsnKind.UNKNOWN,
                        d=MopSnapshot(
                            t=5, size=4, stkoff=_STATE_STKOFF, kind=OperandKind.STACK
                        ),
                        l=MopSnapshot(
                            t=2, size=4, value=_STATE_CONST, kind=OperandKind.NUMBER
                        ),
                        r=None,
                        display_text="mov #0x5A21D9DB.4, %var_7BC.4",
                        value_op_kind=ValueOpKind.MOVE,
                    ),
                ),
            )
        },
        entry_serial=100,
        func_ea=_FUNC_EA,
    )


def _collect(target: object):
    return StateWriteAnchorFactCollector().collect(
        target,
        func_ea=_FUNC_EA,
        maturity=_MATURITY_VALUES["MMAT_LOCOPT"],
        phase="post_d810",
    )


def test_post_d810_canonical_recovers_fact_flat_shape_missed() -> None:
    """S10 EMBRACE (the headline fact change): the retired flat shape
    (``opcode_name="m_mov"``) produced NO state-write-anchor fact because
    ``"m_mov"`` is not a recognized MOVE alias, so the post-D810 path silently
    dropped the write.  The canonical ``FlowGraph`` shape carries
    ``ValueOpKind.MOVE`` and recovers the fact."""
    assert _collect(_flat_target("m_mov")) == ()

    (canonical,) = _collect(_canonical_target())
    assert canonical.kind == "StateWriteAnchorFact"
    assert canonical.source_block == 100
    assert canonical.source_ea == _INSN_EA
    assert canonical.payload["state_const"] == _STATE_CONST
    assert canonical.payload["state_var_stkoff"] == _STATE_STKOFF
    assert canonical.payload["dest_size"] == 4
    assert canonical.payload["opcode"] == "move"


def test_post_d810_value_identity_preserved_when_both_shapes_fire() -> None:
    """No identity drift: when the flat opcode IS a recognized MOVE alias
    (``"move"``), the flat and canonical shapes agree on every value-identity
    fact byte-for-byte -- S10 never drifts stkoff/value identity, it only adds
    recovery."""
    (flat,) = _collect(_flat_target("move"))
    (canonical,) = _collect(_canonical_target())

    assert flat.semantic_key == canonical.semantic_key
    assert flat.mop_signature == canonical.mop_signature
    assert flat.payload["state_const"] == canonical.payload["state_const"]
    assert flat.payload["state_const_hex"] == canonical.payload["state_const_hex"]
    assert flat.payload["state_var_stkoff"] == canonical.payload["state_var_stkoff"]
    assert flat.payload["dest_size"] == canonical.payload["dest_size"]
    assert flat.payload["opcode"] == canonical.payload["opcode"] == "move"
