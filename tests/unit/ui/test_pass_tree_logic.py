from __future__ import annotations

from types import SimpleNamespace

from d810.ui.pass_tree_logic import PassTreeNodeKind, project_pass_tree


def _entry(
    pass_id: str,
    *,
    transforms: tuple[str, ...] = (),
    stages: tuple[str, ...] = (),
):
    return SimpleNamespace(
        pass_id=pass_id,
        display_name=pass_id.replace("-", " ").title(),
        transform_ids=transforms,
        stage_ids=stages,
    )


def test_tree_uses_effective_pass_order_and_public_children() -> None:
    rows = project_pass_tree(
        (
            _entry("mba-simplify", transforms=("xor-identity",)),
            _entry("constant-simplification", stages=("constant-folding",)),
        ),
        ("constant-simplification", "mba-simplify"),
    )

    assert tuple(row.parent.pass_id for row in rows) == (
        "constant-simplification",
        "mba-simplify",
    )
    assert rows[0].children[0].kind is PassTreeNodeKind.STAGE
    assert rows[0].children[0].editable is False
    assert rows[1].children[0].kind is PassTreeNodeKind.TRANSFORM
    assert rows[1].children[0].editable is True


def test_tree_never_needs_private_implementation_names() -> None:
    rows = project_pass_tree(
        (_entry("constant-simplification", stages=("fold-readonly-data",)),),
        ("constant-simplification",),
    )

    rendered = repr(rows)
    assert "FoldReadonlyDataRule" not in rendered
    assert "fold-readonly-data" in rendered


def test_unknown_effective_pass_remains_visible_for_diagnostics() -> None:
    rows = project_pass_tree((), ("missing-pass",))

    assert rows[0].parent.pass_id == "missing-pass"
    assert rows[0].parent.enabled is True
