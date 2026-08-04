from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PASS_TREE = ROOT / "src" / "d810" / "ui" / "pass_tree.py"


def test_pass_tree_uses_public_identity_vocabulary() -> None:
    source = PASS_TREE.read_text(encoding="utf-8")
    ast.parse(source, filename=str(PASS_TREE))

    assert "PassTreeWidget" in source
    assert "passes, transforms, or stages" in source
    assert "private optimizer objects" in source
    assert "RuleTree" not in source
    assert "rule_selected" not in source
