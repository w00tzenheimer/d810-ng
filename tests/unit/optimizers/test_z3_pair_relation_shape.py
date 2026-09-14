"""Source guard for the pair-only Z3 predicate optimization."""

from __future__ import annotations

import ast
from pathlib import Path


MODULE = ast.parse(
    Path("src/d810/optimizers/microcode/instructions/z3/predicates.py").read_text(
        encoding="utf-8"
    )
)


def _method(class_name: str) -> ast.FunctionDef:
    cls = next(
        node
        for node in MODULE.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    return next(
        node
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name == "check_candidate"
    )


def test_set_predicates_use_one_shot_complementary_pair_proof() -> None:
    for class_name in ("Z3setzRuleGeneric", "Z3setnzRuleGeneric"):
        method = _method(class_name)
        calls = [
            node.func.attr
            for node in ast.walk(method)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        ]
        assert calls.count("prove_equal_then_unequal") == 1
        assert "prove_equal" not in calls
        assert "prove_unequal" not in calls
