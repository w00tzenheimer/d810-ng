"""Architecture lock for the typed PatchPlan execution boundary."""

from pathlib import Path

_ROOT = Path(__file__).parents[3]
_PRODUCTION = _ROOT / "src" / "d810"


def test_removed_patch_plan_compatibility_names_are_absent_from_production() -> None:
    removed = (
        "LegacyBlockOperation",
        "planner_modifications",
        "as_graph_modifications",
        "VirtualBlockId",
    )
    hits: dict[str, list[str]] = {name: [] for name in removed}
    for path in _PRODUCTION.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for name in removed:
            if name in text:
                hits[name].append(str(path.relative_to(_ROOT)))
    assert hits == {name: [] for name in removed}


def test_mutation_backend_does_not_define_a_second_graph_modification_type() -> None:
    source = (_PRODUCTION / "hexrays" / "mutation" / "deferred_modifier.py").read_text(
        encoding="utf-8"
    )
    assert "class GraphModification:" not in source


def test_patch_steps_do_not_reconstruct_planner_graph_modifications() -> None:
    source = (_PRODUCTION / "transforms" / "plan.py").read_text(encoding="utf-8")
    assert "def to_graph_modification(" not in source


def test_translator_protocol_accepts_only_patch_plans() -> None:
    source = (_PRODUCTION / "transforms" / "protocol.py").read_text(encoding="utf-8")
    assert "GraphModification" not in source
    assert "lowering_input: PatchPlan" in source
