from __future__ import annotations

import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest

from d810.mba.extension_api import (
    EgraphPersistenceService,
    MbaIslandProfile,
    NativeMbaCandidate,
    NativeMbaHostServices,
    NativeMbaReconstruction,
    TypedBvTerm,
)
from d810.mba.island_profile import profile_typed_term


def _candidate(*, destination_size: int = 4) -> NativeMbaCandidate:
    term = TypedBvTerm(None, destination_size * 8, value=0)
    return NativeMbaCandidate(
        destination_size=destination_size,
        term=term,
        raw_term=term,
        profile=profile_typed_term(term),
        native_context=object(),
    )


def test_public_api_exports_frozen_dtos_and_protocols() -> None:
    candidate = _candidate()
    reconstruction = NativeMbaReconstruction(object(), object())

    assert dataclasses.is_dataclass(candidate)
    assert dataclasses.is_dataclass(reconstruction)
    assert isinstance(candidate.profile, MbaIslandProfile)
    assert isinstance(candidate.term, TypedBvTerm)
    assert getattr(EgraphPersistenceService, "__protocol_attrs__", None) is None or (
        "get_json" in EgraphPersistenceService.__dict__
    )
    assert "capture_instruction" in NativeMbaHostServices.__dict__
    with pytest.raises(dataclasses.FrozenInstanceError):
        candidate.term = candidate.term  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    (
        {"destination_size": 0},
        {"destination_size": 3},
        {"term": TypedBvTerm(None, 64, value=0)},
        {"raw_term": TypedBvTerm(None, 64, value=0)},
        {"profile": profile_typed_term(TypedBvTerm(None, 64, value=0))},
        {"native_context": None},
    ),
)
def test_candidate_validates_width_profile_and_opaque_context(
    kwargs: dict[str, object],
) -> None:
    values = {
        "destination_size": 4,
        "term": TypedBvTerm(None, 32, value=0),
        "raw_term": TypedBvTerm(None, 32, value=0),
        "profile": profile_typed_term(TypedBvTerm(None, 32, value=0)),
        "native_context": object(),
    }
    values.update(kwargs)
    with pytest.raises((TypeError, ValueError)):
        NativeMbaCandidate(**values)  # type: ignore[arg-type]


def test_reconstruction_requires_native_objects() -> None:
    with pytest.raises(TypeError):
        NativeMbaReconstruction(None, object())
    with pytest.raises(TypeError):
        NativeMbaReconstruction(object(), None)


def test_portable_api_imports_without_ida_packages() -> None:
    source_root = Path(__file__).parents[3] / "src"
    script = """
import sys
import d810.mba.extension_api
assert 'ida_hexrays' not in sys.modules
assert 'idaapi' not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": str(Path(sys.executable).parent), "PYTHONPATH": str(source_root)},
    )
    assert result.returncode == 0, result.stderr
