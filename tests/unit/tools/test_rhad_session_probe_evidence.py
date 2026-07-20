from types import SimpleNamespace
from pathlib import Path

from tools.scripts.rhad_investigation.session_probe_evidence import (
    capture_preopt_union_preparation,
    latest_preopt_union_preparation,
    native_preanalysis_boundary_port_count,
)


_PROBE = (
    Path(__file__).resolve().parents[3]
    / "tools"
    / "scripts"
    / "rhad_investigation"
    / "probe_transfer_function.py"
)


def test_preopt_union_preparation_survives_live_session_cleanup() -> None:
    preparation = object()
    state = SimpleNamespace(preopt_union_preparation=preparation)
    captured: list[object] = []

    capture_preopt_union_preparation(state, captured)
    state.preopt_union_preparation = None

    assert latest_preopt_union_preparation(state, captured) is preparation


def test_transfer_probe_uses_direct_execution_safe_sibling_import() -> None:
    source = _PROBE.read_text(encoding="utf-8")

    assert "from session_probe_evidence import (" in source


def test_boundary_port_count_reads_canonical_session_facts_after_cleanup() -> None:
    state = SimpleNamespace(
        native_preanalysis=SimpleNamespace(
            facts=SimpleNamespace(
                boundary_ports=SimpleNamespace(
                    direct=(object(), object()),
                    conditional=(object(),),
                )
            )
        ),
        preopt_union_preparation=None,
    )

    assert native_preanalysis_boundary_port_count(state) == 3
