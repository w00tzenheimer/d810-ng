"""Diag-row -> canonical Instruction projection tests (E opt-4).

Extracted from tests/unit/ir/test_insn_projection.py: ``project_diag_instruction``
and ``parse_diag_meta_operand`` now live in the backend diag lifter
(``d810.backends.hexrays.diag_lifter``).  These suites import it and therefore
live under tests/system/runtime; they are pure-offline (no IDA).
"""

import json
from dataclasses import dataclass, replace

import pytest

from d810.backends.hexrays.diag_lifter import (
    DiagSourceLifter,
    parse_diag_meta_operand,
    project_diag_instruction,
)
from d810.core.observability_models import (
    DIAG_PROVENANCE_VERSION,
    BlockSnapshot as DiagBlockSnapshot,
    InstructionSnapshot,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import InsnKind, OperandKind
from d810.ir.instructions import InstructionEffectKind
from d810.ir.varnode import Space, Varnode
from tests.system.runtime.preanalysis.facts._diag_provenance_factory import (
    diag_block,
    diag_instruction,
)


@dataclass(frozen=True)
class _DiagSource:
    blocks: tuple[DiagBlockSnapshot, ...]
    entry_serial: int
    func_ea: int


def test_diag_block_requires_explicit_independent_tail_evidence() -> None:
    row = diag_instruction(index=0, ea=0x1000, opcode=0, opcode_name="m_add")
    with pytest.raises(ValueError, match="independent tail evidence"):
        diag_block(serial=1, block_type=1, instructions=[row])


def test_diag_block_preserves_explicit_tail_evidence_and_empty_omission() -> None:
    row = diag_instruction(index=0, ea=0x1000, opcode=0, opcode_name="m_add")
    block = diag_block(
        serial=1, block_type=1, type_name="BLT_1WAY", instructions=[row],
        tail_opcode=0x44, raw_tail_opcode=0x44, tail_kind="add",
    )
    assert (block.tail_opcode, block.raw_tail_opcode, block.tail_kind) == (0x44, 0x44, "add")
    empty = diag_block(serial=2, block_type=1, type_name="BLT_1WAY", instructions=[])
    assert empty.tail_opcode is None


# ---------------------------------------------------------------------------
# Diag-DB row -> canonical Instruction lift (llr-3b41).
#
# A production diag instruction row (``observability_models.InstructionSnapshot``
# with a real ``_instruction_operands_meta``-shaped ``meta`` JSON) projects to
# the SAME canonical ``Instruction`` the live block path produces.  The canonical
# projection recovers the real ``ValueOpKind`` from the serializer ``m_add`` /
# ``m_stx`` spellings and walks the recursive ``mop_a -> sub_operand -> mop_S``
# address tree to recover address stack offsets.
#
# S11 deleted the legacy meta-less ``_InstructionView`` flat path and the shared
# ``_iter_portable_instructions`` iterator: every production fact target is now a
# canonical ``FlowGraph``, so the meta-less Branch-B comparison the earlier
# spikes pinned is no longer reachable.  The asserts below pin the canonical
# ``Instruction`` facts directly.
# ---------------------------------------------------------------------------


def _diag_meta_S(stkoff: int, size: int = 4) -> dict:
    return {"type": "mop_S", "type_num": 5, "size": size, "dstr": "x", "stkoff": stkoff}


def _diag_meta_N(value: int, size: int = 4) -> dict:
    return {
        "type": "mop_n",
        "type_num": 2,
        "size": size,
        "dstr": f"#{value:#x}",
        "value": value,
    }


def _diag_meta_R(register: int, size: int = 8) -> dict:
    return {
        "type": "mop_r",
        "type_num": 1,
        "size": size,
        "dstr": "r",
        "register": register,
    }


def _diag_row(
    *,
    opcode: int,
    opcode_name: str,
    ea: int,
    dest_type: str | None,
    dest_stkoff: int | None,
    dest_size: int | None,
    src_l_type: str | None,
    src_l_stkoff: int | None,
    src_l_value: int | None,
    src_r_type: str | None,
    src_r_stkoff: int | None,
    src_r_value: int | None,
    meta: dict,
) -> InstructionSnapshot:
    """A production-shaped diag row (matches the SQLite-sink dataclass)."""
    # The closed replay boundary requires independently recorded backend raw
    # opcode provenance.  The real serializer stores this alongside the
    # operand tree; keep the fake row shaped the same way rather than making
    # the lifter reconstruct it from the nominal opcode.
    meta = dict(meta)
    meta.setdefault("raw_opcode", opcode)
    meta.setdefault("provenance_version", DIAG_PROVENANCE_VERSION)
    return InstructionSnapshot(
        index=0,
        ea=ea,
        opcode=opcode,
        opcode_name=opcode_name,
        dest_type=dest_type,
        dest_stkoff=dest_stkoff,
        dest_size=dest_size,
        src_l_type=src_l_type,
        src_l_stkoff=src_l_stkoff,
        src_l_value=src_l_value,
        src_r_type=src_r_type,
        src_r_stkoff=src_r_stkoff,
        src_r_value=src_r_value,
        dstr=meta.get("dstr", ""),
        meta=json.dumps(meta, sort_keys=True, separators=(",", ":")),
        raw_opcode=opcode,
        provenance_version=DIAG_PROVENANCE_VERSION,
    )


def test_parse_diag_meta_operand_maps_type_num_to_operand_kind():
    assert parse_diag_meta_operand(_diag_meta_S(0x10)).kind is OperandKind.STACK
    assert parse_diag_meta_operand(_diag_meta_N(0x80)).kind is OperandKind.NUMBER
    assert parse_diag_meta_operand(_diag_meta_R(8)).kind is OperandKind.REGISTER
    assert parse_diag_meta_operand({"type": "mop_z", "type_num": 0}) is None
    assert parse_diag_meta_operand(None) is None

    glob = parse_diag_meta_operand(
        {"type": "mop_v", "type_num": 6, "size": 8, "global_ea": "0x1800140a0"}
    )
    assert glob.kind is OperandKind.GLOBAL
    assert glob.gaddr == 0x1800140A0  # "0x%x" string coerced to int

    block = parse_diag_meta_operand({"type": "mop_b", "type_num": 7, "block_num": 42})
    assert block.kind is OperandKind.BLOCK and block.block_ref == 42


def test_diag_instruction_without_recorded_raw_opcode_fails_closed():
    row = _diag_row(
        opcode=0x10,
        opcode_name="m_add",
        ea=0x1000,
        dest_type="mop_S",
        dest_stkoff=0x680,
        dest_size=4,
        src_l_type="mop_S",
        src_l_stkoff=0x680,
        src_l_value=None,
        src_r_type="mop_n",
        src_r_stkoff=None,
        src_r_value=0x80,
        meta={
            "l": _diag_meta_S(0x680),
            "r": _diag_meta_N(0x80),
            "d": _diag_meta_S(0x680),
        },
    )
    metadata = json.loads(row.meta or "{}")
    metadata.pop("raw_opcode", None)
    with pytest.raises(ValueError, match="raw opcode provenance"):
        project_diag_instruction(
            replace(row, meta=json.dumps(metadata), raw_opcode=None)
        )


def test_diag_nominal_opcode_is_required_and_explicit_synthetic_goto_is_closed():
    synthetic_meta = {
        "provenance_version": DIAG_PROVENANCE_VERSION,
        "raw_opcode": None,
        "l": {"type": "mop_b", "type_num": 7, "size": 0, "block_num": 2},
    }
    synthetic = {
        "opcode": -1,
        "opcode_name": "m_goto",
        "raw_opcode": None,
        "provenance_version": DIAG_PROVENANCE_VERSION,
        "ea": 0x1000,
        "meta": json.dumps(synthetic_meta, sort_keys=True),
    }
    assert project_diag_instruction(synthetic).control is not None
    with pytest.raises(ValueError, match="nominal opcode"):
        project_diag_instruction({key: value for key, value in synthetic.items() if key != "opcode"})
    malformed = dict(synthetic)
    malformed["meta"] = json.dumps(
        {"provenance_version": DIAG_PROVENANCE_VERSION, "raw_opcode": None},
        sort_keys=True,
    )
    with pytest.raises(ValueError, match="synthetic diag instruction"):
        project_diag_instruction(malformed)


def test_diag_source_lifter_accepts_only_exact_synthetic_l_target_shape():
    meta = {
        "provenance_version": DIAG_PROVENANCE_VERSION,
        "raw_opcode": None,
        "l": {"type": "mop_b", "type_num": 7, "size": 0, "block_num": 2},
    }
    row = InstructionSnapshot(
        index=0,
        ea=0x1000,
        opcode=-1,
        opcode_name="m_goto",
        meta=json.dumps(meta, sort_keys=True),
        raw_opcode=None,
        provenance_version=DIAG_PROVENANCE_VERSION,
    )
    block = DiagBlockSnapshot(
        serial=1,
        block_type=1,
        type_name="BLT_1WAY",
        succs=[2],
        preds=[],
        start_ea=0x1000,
        instructions=[row],
        tail_opcode=-1,
        raw_tail_opcode=None,
        tail_kind=InsnKind.GOTO.value,
        provenance_version=DIAG_PROVENANCE_VERSION,
    )
    source = _DiagSource(blocks=(block,), entry_serial=1, func_ea=0x1000)
    assert DiagSourceLifter().lift(source).blocks[1].tail_kind is InsnKind.GOTO

    mutations = {
        "wrong_target": (replace(row, meta=json.dumps({**meta, "l": {**meta["l"], "block_num": 3}})), block),
        "missing_target": (replace(row, meta=json.dumps({key: value for key, value in meta.items() if key != "l"})), block),
        "zero_successors": (row, replace(block, succs=[])),
        "two_successors": (row, replace(block, succs=[2, 3])),
        "wrong_operand_kind": (replace(row, meta=json.dumps({**meta, "l": {"type": "mop_n", "type_num": 2, "size": 0, "value": 2}})), block),
        "nonzero_width": (replace(row, meta=json.dumps({**meta, "l": {**meta["l"], "size": 4}})), block),
        "r_arity": (replace(row, meta=json.dumps({**meta, "r": {"type": "mop_n", "type_num": 2, "size": 0, "value": 1}})), block),
        "d_arity": (replace(row, meta=json.dumps({**meta, "d": {"type": "mop_b", "type_num": 7, "size": 0, "block_num": 2}})), block),
        "wrong_name": (replace(row, opcode_name="m_goto_typo"), block),
        "wrong_kind": (replace(row, opcode=-2), block),
        "raw_present": (replace(row, raw_opcode=1), block),
    }
    for name, (mutated_row, mutated_block) in mutations.items():
        try:
            DiagSourceLifter().lift(
                _DiagSource(
                    blocks=(replace(mutated_block, instructions=[mutated_row]),),
                    entry_serial=1,
                    func_ea=0x1000,
                )
            )
        except ValueError:
            continue
        raise AssertionError(f"synthetic mutation unexpectedly accepted: {name}")


def test_diag_source_lifter_preserves_complete_tail_provenance_and_rejects_loss():
    row = _diag_row(
        opcode=0x10,
        opcode_name="m_add",
        ea=0x1000,
        dest_type="mop_S",
        dest_stkoff=0x680,
        dest_size=4,
        src_l_type="mop_S",
        src_l_stkoff=0x680,
        src_l_value=None,
        src_r_type="mop_n",
        src_r_stkoff=None,
        src_r_value=0x80,
        meta={
            "l": _diag_meta_S(0x680),
            "r": _diag_meta_N(0x80),
            "d": _diag_meta_S(0x680),
        },
    )
    block = DiagBlockSnapshot(
        serial=1,
        block_type=1,
        type_name="BLT_1WAY",
        succs=(),
        preds=(),
        start_ea=0x1000,
        instructions=[row],
        tail_opcode=0x10,
        raw_tail_opcode=0x10,
        tail_kind=InsnKind.ADD.value,
        provenance_version=DIAG_PROVENANCE_VERSION,
    )
    source = _DiagSource(blocks=(block,), entry_serial=1, func_ea=0x1000)
    lifted = DiagSourceLifter().lift(source)
    lifted_block = lifted.blocks[1]
    assert lifted_block.tail_opcode == 0x10
    assert lifted_block.raw_tail_opcode == 0x10
    assert lifted_block.tail_kind is InsnKind.ADD
    with pytest.raises(ValueError, match="tail provenance"):
        DiagSourceLifter().lift(
            _DiagSource(
                blocks=(replace(block, raw_tail_opcode=None),),
                entry_serial=1,
                func_ea=0x1000,
            )
        )
    with pytest.raises(ValueError, match="schema is not eligible"):
        DiagSourceLifter().lift(
            _DiagSource(
                blocks=(replace(block, provenance_version=None),),
                entry_serial=1,
                func_ea=0x1000,
            )
        )


def test_project_diag_instruction_add_recovers_canonical_semantic_facts():
    # (a) ``m_add %S(0x680), #0x80 -> %S(0x680)`` -- self-update by constant.
    meta = {
        "opcode": 0x10,
        "opcode_name": "m_add",
        "ea": "0x1000",
        "dstr": "x = x + 0x80",
        "l": _diag_meta_S(0x680),
        "r": _diag_meta_N(0x80),
        "d": _diag_meta_S(0x680),
    }
    row = _diag_row(
        opcode=0x10,
        opcode_name="m_add",
        ea=0x1000,
        dest_type="mop_S",
        dest_stkoff=0x680,
        dest_size=4,
        src_l_type="mop_S",
        src_l_stkoff=0x680,
        src_l_value=None,
        src_r_type="mop_n",
        src_r_stkoff=None,
        src_r_value=0x80,
        meta=meta,
    )

    canonical = project_diag_instruction(row)
    # Canonical Instruction is authoritative ground truth: a meta-rich diag row
    # lifts to the SAME canonical Instruction the live block path produces.
    assert canonical.operation is ValueOpKind.ADD
    assert canonical.inputs == (
        Varnode(Space.STACK, 0x680, 4),
        Varnode(Space.CONST, 0x80, 4),
    )
    assert canonical.result == Varnode(Space.STACK, 0x680, 4)
    assert canonical.attrs["ea"] == 0x1000


def test_project_diag_instruction_stx_recovers_address_stkoff_canonically():
    # (b) ``m_stx`` storing rax through a stack address ``&%S(0x7F0)``.
    # Serializer renders the address operand as mop_a -> sub_operand -> mop_S.
    addr = {
        "type": "mop_a",
        "type_num": 10,
        "size": 8,
        "dstr": "&x",
        "sub_operand": _diag_meta_S(0x7F0, size=8),
    }
    meta = {
        "opcode": 0x13,
        "opcode_name": "m_stx",
        "ea": "0x2000",
        "dstr": "*(&x) = rax",
        "l": _diag_meta_R(8, size=8),  # value
        "r": _diag_meta_R(16, size=2),  # segment
        "d": addr,  # target address (stack)
    }
    row = _diag_row(
        opcode=0x13,
        opcode_name="m_stx",
        ea=0x2000,
        dest_type="mop_a",
        dest_stkoff=None,
        dest_size=8,
        src_l_type="mop_r",
        src_l_stkoff=None,
        src_l_value=None,
        src_r_type="mop_r",
        src_r_stkoff=None,
        src_r_value=None,
        meta=meta,
    )

    canonical = project_diag_instruction(row)
    assert canonical.operation is ValueOpKind.STORE
    assert canonical.attrs["address_stack_refs"] == (0x7F0,)
    assert canonical.effects[0].kind is InstructionEffectKind.STORE
    assert canonical.effects[0].value == Varnode(Space.REGISTER, 8, 8)

    # The ``d`` subtree referencing a stack address parses recursively, and the
    # canonical projection walks the ``mop_a -> sub_operand -> mop_S`` tree to
    # recover the address stack offset (a fact the legacy flat path could not).
    d_operand = parse_diag_meta_operand(meta["d"])
    assert d_operand.kind is OperandKind.ADDRESS
    assert d_operand.sub_l.kind is OperandKind.STACK
    assert d_operand.sub_l.stkoff == 0x7F0
    assert d_operand.stack_refs == (0x7F0,)
    assert canonical.attrs["address_stack_refs"] == (0x7F0,)
