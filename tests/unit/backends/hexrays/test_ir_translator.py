"""Portable instruction-kind boundaries for the Hex-Rays translator."""

import ast
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    InsnKind,
    InsnSnapshot,
    OperandKind,
)


def _lift_block_without_ida():
    """Extract the pure adapter body without importing the IDA module."""
    source_path = Path(__file__).parents[4] / "src/d810/hexrays/mutation/ir_translator.py"
    tree = ast.parse(source_path.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "lift_block"
    )
    namespace = {
        "BlockSnapshot": BlockSnapshot,
        "InsnKind": InsnKind,
        "Callable": Callable,
        "get_succ_serials": lambda block: (),
        "get_pred_serials": lambda block: (),
        "capture_insn_snapshot": lambda *_args, **_kwargs: InsnSnapshot(
            opcode=7, ea=0x1000, operands=(), kind=InsnKind.NOP,
            raw_opcode=70, display_text="walked",
        ),
        "_block_kind_from_hexrays": lambda _block_type: BlockKind.ONE_WAY,
        "_insn_kind_from_hexrays": lambda _opcode: InsnKind.UNKNOWN,
    }
    exec(compile(ast.Module([function], type_ignores=[]), str(source_path), "exec"), namespace)
    return namespace["lift_block"]


def _classifier():
    source_path = Path(__file__).parents[4] / "src/d810/hexrays/mutation/ir_translator.py"
    tree = ast.parse(source_path.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "classify_backend_opcode")
    from d810.hexrays.instruction_vocabulary import (
        insn_kind_for_opcode_name,
        live_known_opcode_names,
    )

    namespace = {
        "InsnKind": InsnKind,
        "Callable": Callable,
        "insn_kind_for_opcode_name": insn_kind_for_opcode_name,
        "live_known_opcode_names": live_known_opcode_names,
    }
    exec(compile(ast.Module([function], type_ignores=[]), str(source_path), "exec"), namespace)
    return namespace["classify_backend_opcode"]


def _operand_classifier():
    source_path = Path(__file__).parents[4] / "src/d810/hexrays/mutation/ir_translator.py"
    tree = ast.parse(source_path.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_operand_kind_from_hexrays"
    )
    from d810.hexrays.instruction_vocabulary import operand_kind_for_name, operand_type_names

    sdk = SimpleNamespace(**{name: index for index, name in enumerate(operand_type_names())})
    namespace = {
        "ida_hexrays": sdk,
        "OperandKind": OperandKind,
        "operand_kind_for_name": operand_kind_for_name,
        "operand_type_names": operand_type_names,
    }
    exec(compile(ast.Module([function], type_ignores=[]), str(source_path), "exec"), namespace)
    return namespace["_operand_kind_from_hexrays"]


def _capture_mop_snapshot_without_ida():
    """Extract the live mop adapter with the smallest backend vocabulary."""
    source_path = Path(__file__).parents[4] / "src/d810/hexrays/mutation/ir_translator.py"
    tree = ast.parse(source_path.read_text())
    helper = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_capture_rotate_helper_subinstruction"
    )
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "capture_mop_snapshot"
    )
    from d810.core.bits import rotate_helper_spec
    from d810.ir.expressions import ValueOpKind

    namespace = {
        "CfgMopSnapshot": __import__("d810.ir.flowgraph", fromlist=["MopSnapshot"]).MopSnapshot,
        "ida_hexrays": SimpleNamespace(
            mop_z=0, mop_d=1, mop_r=2, mop_n=3, mop_S=4, mop_a=5,
            mop_b=6, mop_v=7, mop_l=8, mop_c=9, mop_f=10, mop_h=11,
            m_call=12, NOSIZE=-1,
        ),
        "OperandKind": OperandKind,
        "ValueOpKind": ValueOpKind,
        "_operand_kind_from_hexrays": lambda _t: OperandKind.SUBINSN,
        "_stack_refs_from_mop": lambda _mop: (),
        "rotate_helper_spec": rotate_helper_spec,
    }
    exec(
        compile(ast.Module([helper, function], type_ignores=[]), str(source_path), "exec"),
        namespace,
    )
    return namespace["capture_mop_snapshot"]


def _live_assertion_classifier_without_ida():
    source_path = (
        Path(__file__).parents[4] / "src/d810/hexrays/mutation/ir_translator.py"
    )
    tree = ast.parse(source_path.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_live_insn_is_assert"
    )
    namespace = {"ida_hexrays": SimpleNamespace(IPROP_ASSERT=0x80)}
    exec(
        compile(ast.Module([function], type_ignores=[]), str(source_path), "exec"),
        namespace,
    )
    return namespace["_live_insn_is_assert"]


def _control_flow_classifier():
    source_path = Path(__file__).parents[4] / "src/d810/hexrays/mutation/ir_translator.py"
    tree = ast.parse(source_path.read_text())
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "is_control_flow_opcode"
    )
    transfers = {1: object(), 2: object(), 3: object(), 4: object()}
    calls = {5: object(), 6: object()}
    opcode_lift = SimpleNamespace(
        control_transfer_from_opcode=lambda opcode: transfers.get(int(opcode)),
        call_kind_from_opcode=lambda opcode: calls.get(int(opcode)),
    )
    namespace = {"opcode_lift": opcode_lift}
    exec(compile(ast.Module([function], type_ignores=[]), str(source_path), "exec"), namespace)
    return namespace["is_control_flow_opcode"]


def test_ida_94_opcode_namespace_classifies_call_ret_and_unknown_without_trap() -> None:
    backend = SimpleNamespace(m_call=1, m_icall=2, m_ret=3, m_und=4)
    classify = _classifier()
    assert classify(1, backend) is InsnKind.CALL
    assert classify(2, backend) is InsnKind.CALL
    assert classify(3, backend) is InsnKind.RET
    assert classify(4, backend) is InsnKind.UNKNOWN
    assert classify(99, backend) is InsnKind.UNKNOWN


def test_classifier_delegates_complete_backend_namespace_to_canonical_vocabulary() -> None:
    from d810.hexrays.instruction_vocabulary import (
        insn_kind_for_opcode_name,
        live_known_opcode_names,
    )

    names = live_known_opcode_names()
    backend = SimpleNamespace(**{name: index + 1 for index, name in enumerate(names)})
    classify = _classifier()

    for name in names:
        assert classify(getattr(backend, name), backend) is insn_kind_for_opcode_name(name)


def test_operand_classifier_delegates_case_fp_and_unknown_types_to_vocabulary() -> None:
    classifier = _operand_classifier()

    assert classifier(12) is OperandKind.CASE_LIST
    assert classifier(13) is OperandKind.FP_CONST
    assert classifier(999) is OperandKind.UNKNOWN


def test_capture_mop_snapshot_normalizes_nested_live_scalar_types() -> None:
    """Live adapter output must meet the authority inventory's exact-int contract."""
    capture_mop_snapshot = _capture_mop_snapshot_without_ida()

    class _SwigInt(int):
        pass

    nested = SimpleNamespace(t=_SwigInt(2), size=_SwigInt(4), r=0)
    live_mop = SimpleNamespace(
        t=1,
        size=4,
        d=SimpleNamespace(l=nested, r=None),
    )

    snapshot = capture_mop_snapshot(live_mop)

    assert snapshot is not None
    assert snapshot.sub_l is not None
    assert type(snapshot.sub_l.t) is int
    assert type(snapshot.sub_l.size) is int


def test_capture_mop_snapshot_normalizes_nested_live_nosize_for_inventory() -> None:
    """The live NOSIZE sentinel becomes the portable no-size value before inventory."""
    from d810.transforms.unflatten_authority import producer_api

    capture_mop_snapshot = _capture_mop_snapshot_without_ida()
    nested = SimpleNamespace(t=2, size=-1, r=0)
    live_mop = SimpleNamespace(
        t=1,
        size=4,
        d=SimpleNamespace(l=nested, r=None),
    )

    snapshot = capture_mop_snapshot(live_mop)

    assert snapshot is not None
    assert snapshot.sub_l is not None
    assert snapshot.sub_l.size == 0
    instruction = InsnSnapshot(
        0, 0x1000, (), l=snapshot, kind=InsnKind.NOP, raw_opcode=0,
    )
    block = BlockSnapshot(
        0, 0, (), (), 0, 0x1000, (instruction,),
        tail_opcode=0, raw_tail_opcode=0, tail_kind=InsnKind.NOP,
    )
    producer_api.observe_inventory_block(
        block, owner_ref=None, owner_anchor_ea=0x1000,
    )


def test_live_assertion_classifier_reads_hexrays_instruction_identity() -> None:
    classify = _live_assertion_classifier_without_ida()

    assert classify(SimpleNamespace(is_assert=lambda: True)) is True
    assert classify(SimpleNamespace(is_assert=lambda: False)) is False
    assert classify(SimpleNamespace(iprops=0x80, is_assert=lambda: False)) is True


def test_control_flow_classifier_delegates_transfer_and_call_families() -> None:
    classifier = _control_flow_classifier()

    assert classifier(1) is True  # RET / transfer
    assert classifier(2) is True  # conditional branch
    assert classifier(5) is True  # direct call
    assert classifier(6) is True  # indirect call
    assert classifier(99) is False  # value/unknown


def test_lift_block_preserves_independent_live_tail_provenance() -> None:
    """A walked row cannot manufacture the block-tail authority."""
    from d810.transforms.unflatten_authority import producer_api

    lift_block = _lift_block_without_ida()

    class _Block:
        serial = 0
        type = 1
        flags = 0
        start = 0x1000
        head = SimpleNamespace(ea=0x1000, next=None)
        tail = None

    for opcode, raw_opcode, kind in (
        (99, 70, InsnKind.NOP),
        (7, 990, InsnKind.NOP),
        (7, 70, InsnKind.MOV),
    ):
        _Block.tail = SimpleNamespace(opcode=opcode, raw_opcode=raw_opcode, kind=kind)
        lifted = lift_block(_Block(), map_fict_ea=lambda ea: ea)
        assert lifted.insn_snapshots[-1].opcode == 7
        assert (lifted.tail_opcode, lifted.raw_tail_opcode, lifted.tail_kind) == (
            opcode, raw_opcode, kind,
        )
        with pytest.raises(ValueError, match="tail"):
            producer_api.observe_inventory_block(
                lifted, owner_ref=None, owner_anchor_ea=0x1000,
            )

    _Block.tail = None
    missing = lift_block(_Block(), map_fict_ea=lambda ea: ea)
    assert missing.tail_opcode is None
    with pytest.raises(ValueError, match="tail"):
        producer_api.observe_inventory_block(
            missing, owner_ref=None, owner_anchor_ea=0x1000,
        )


def test_portable_graph_lift_disables_transitional_rich_operands() -> None:
    source_path = Path(__file__).parents[4] / "src/d810/hexrays/mutation/ir_translator.py"
    tree = ast.parse(source_path.read_text())
    lift = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "lift"
    )
    calls = [
        node for node in ast.walk(lift)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "lift_block"
    ]

    assert len(calls) == 1
    keyword = next(
        item for item in calls[0].keywords
        if item.arg == "include_rich_operands"
    )
    assert isinstance(keyword.value, ast.Constant)
    assert keyword.value.value is False
