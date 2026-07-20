from types import SimpleNamespace

from tools.scripts.rhad_investigation.session_probe_evidence import (
    capture_preopt_union_preparation,
    latest_preopt_union_preparation,
)


def test_preopt_union_preparation_survives_live_session_cleanup() -> None:
    preparation = object()
    state = SimpleNamespace(preopt_union_preparation=preparation)
    captured: list[object] = []

    capture_preopt_union_preparation(state, captured)
    state.preopt_union_preparation = None

    assert latest_preopt_union_preparation(state, captured) is preparation
