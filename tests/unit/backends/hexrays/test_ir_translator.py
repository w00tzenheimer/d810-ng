"""Portable instruction-kind boundaries for the Hex-Rays translator."""

import ast
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

from d810.ir.flowgraph import InsnKind


def _classifier():
    source_path = Path(__file__).parents[4] / "src/d810/hexrays/mutation/ir_translator.py"
    tree = ast.parse(source_path.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "classify_backend_opcode")
    namespace = {"InsnKind": InsnKind, "Callable": Callable}
    exec(compile(ast.Module([function], type_ignores=[]), str(source_path), "exec"), namespace)
    return namespace["classify_backend_opcode"]


def test_ida_94_opcode_namespace_classifies_call_ret_and_unknown_without_trap() -> None:
    backend = SimpleNamespace(m_call=1, m_icall=2, m_ret=3, m_und=4)
    classify = _classifier()
    assert classify(1, backend) is InsnKind.CALL
    assert classify(2, backend) is InsnKind.CALL
    assert classify(3, backend) is InsnKind.RET
    assert classify(4, backend) is InsnKind.UNKNOWN
    assert classify(99, backend) is InsnKind.UNKNOWN
