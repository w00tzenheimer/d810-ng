from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "tools" / "scripts" / "thinning_slice_dag.py"
_spec = importlib.util.spec_from_file_location("thinning_slice_dag", SCRIPT)
sd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sd)


def _row(path, role, dest, phase, deps=()):
    return {
        "path": path,
        "role": role,
        "destination_module": dest,
        "phase": phase,
        "dep_edges": list(deps),
        "gate_class": "static",
    }


def test_topo_sort_orders_dependencies_first():
    rows = [
        _row("a.py", "analyses", "analyses.x", "E", deps=["b.py"]),
        _row("b.py", "analyses", "analyses.y", "E"),
    ]
    slices = sd.build_slice_dag(rows, anchor="e58ecaab8")["slices"]
    order = [s["path"] for s in slices]
    assert order.index("b.py") < order.index("a.py")


def test_phase_ordering_is_respected():
    rows = [
        _row("m.py", "mutation", "backends.hexrays.mutation", "G"),
        _row("s.py", "shim", "DELETE", "C"),
    ]
    slices = sd.build_slice_dag(rows, anchor="x")["slices"]
    phases = [s["phase"] for s in slices]
    assert phases.index("C") < phases.index("G")


def test_cycle_raises():
    rows = [
        _row("a.py", "analyses", "x", "E", deps=["b.py"]),
        _row("b.py", "analyses", "y", "E", deps=["a.py"]),
    ]
    with pytest.raises(sd.SliceCycleError):
        sd.build_slice_dag(rows, anchor="x")


def test_stays_role_excluded_from_slices():
    rows = [_row("rule.py", "stays", "optimizers", "H")]
    out = sd.build_slice_dag(rows, anchor="x")
    assert all(s["path"] != "rule.py" for s in out["slices"])
    assert "rule.py" in out["retained"]
