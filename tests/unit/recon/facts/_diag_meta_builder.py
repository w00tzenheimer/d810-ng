"""Build a serializer-shaped ``meta`` operand tree from flat diag fields.

llr-3b41 S11 deleted the meta-less ``_InstructionView`` flat path: a fact
collector now lifts every diag instruction row through the canonical
``project_diag_instruction`` (which reads ONLY the ``meta`` operand tree, never
the flat ``src_l_*`` / ``dest_*`` fields).  These collector unit tests
historically built flat ``observability_models.InstructionSnapshot`` rows with no
``meta``; to keep exercising the collector logic through the live canonical lift
they now attach a ``meta`` operand tree built from the same flat fields, matching
the production ``d810.hexrays.mba_serializer._mop_to_meta`` shape.

This is a TEST helper -- the production serializer emits the real tree at
runtime; this reconstructs the equivalent tree from the flat test inputs so the
operand-tree-diag path produces the canonical ``Instruction`` the collectors
read.
"""
from __future__ import annotations

import json

# mop ``t`` type-num values (subset the collector tests use), matching
# ``ida_hexrays`` and ``parse_diag_meta_operand``'s ``_TYPE_NUM_TO_OPERAND_KIND``.
_TYPE_NUM = {
    "mop_r": 1,
    "mop_n": 2,
    "mop_d": 3,
    "mop_S": 5,
    "mop_a": 10,
}


def _operand_meta(
    type_name: str | None,
    *,
    stkoff: int | None = None,
    value: int | None = None,
    register: int | None = None,
    size: int | None = 4,
) -> dict | None:
    """Build one ``l`` / ``r`` / ``d`` operand node, or ``None`` when empty."""
    if type_name is None:
        return None
    type_num = _TYPE_NUM.get(type_name)
    if type_num is None:
        return None
    node: dict[str, object] = {
        "type": type_name,
        "type_num": type_num,
        "size": int(size or 0),
        "dstr": "",
    }
    if stkoff is not None:
        node["stkoff"] = int(stkoff)
    if value is not None:
        node["value"] = int(value)
    if register is not None:
        node["register"] = int(register)
    return node


def flat_meta(
    *,
    opcode_name: str,
    ea: int | None = None,
    dstr: str = "",
    dest_type: str | None = None,
    dest_stkoff: int | None = None,
    dest_size: int | None = 4,
    dest_register: int | None = None,
    src_l_type: str | None = None,
    src_l_stkoff: int | None = None,
    src_l_value: int | None = None,
    src_l_register: int | None = None,
    src_l_size: int | None = 4,
    src_r_type: str | None = None,
    src_r_stkoff: int | None = None,
    src_r_value: int | None = None,
    src_r_register: int | None = None,
    src_r_size: int | None = 4,
) -> str:
    """Return a JSON ``meta`` operand tree for a flat diag instruction row.

    The ``l`` / ``r`` / ``d`` nodes mirror ``_mop_to_meta`` so the row lifts
    through ``project_diag_instruction`` to the same canonical ``Instruction``
    the live block path produces.
    """
    meta: dict[str, object] = {
        "opcode_name": opcode_name,
        "ea": f"0x{int(ea or 0):x}",
        "dstr": dstr,
    }
    left = _operand_meta(
        src_l_type, stkoff=src_l_stkoff, value=src_l_value, register=src_l_register, size=src_l_size
    )
    right = _operand_meta(
        src_r_type, stkoff=src_r_stkoff, value=src_r_value, register=src_r_register, size=src_r_size
    )
    dest = _operand_meta(
        dest_type, stkoff=dest_stkoff, register=dest_register, size=dest_size
    )
    if left is not None:
        meta["l"] = left
    if right is not None:
        meta["r"] = right
    if dest is not None:
        meta["d"] = dest
    return json.dumps(meta, sort_keys=True, separators=(",", ":"))
