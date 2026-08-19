from __future__ import annotations

import dataclasses
import math
import subprocess
import sys
from pathlib import Path

import pytest

from d810.mba import extension_api
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


def test_optimizer_runtime_contract_is_exported_through_extension_api() -> None:
    for name in (
        "MbaProviderOutcome",
        "ProviderOutcomeStatus",
        "ProviderOutcomeHistory",
        "EMPTY_MBA_STAGE_TIMINGS",
        "MbaStageTimer",
        "compiled_rules_for_families",
        "build_certified_catalogue_snapshot",
        "egraph_receipt_to_outcome",
    ):
        assert hasattr(extension_api, name), name


def test_canonical_fixed_bindings_is_an_extension_api_dto() -> None:
    from d810.mba.canonical_pattern import CanonicalFixedBindings

    assert extension_api.CanonicalFixedBindings is CanonicalFixedBindings
    assert "CanonicalFixedBindings" in extension_api.__all__


def test_host_protocol_exposes_native_maturity_resolution() -> None:
    assert "maturities_for_names" in NativeMbaHostServices.__dict__


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


def test_json_values_are_recursively_copied_frozen_and_validated() -> None:
    copy_json_value = getattr(extension_api, "_copy_json_value")
    freeze_json_value = getattr(extension_api, "_freeze_json_value")
    source = {"nested": [{"value": 1}]}

    copied = copy_json_value(source)
    source["nested"][0]["value"] = 2
    source["nested"].append({"value": 3})

    frozen = freeze_json_value(copied)
    assert frozen["nested"][0]["value"] == 1
    assert isinstance(frozen["nested"], tuple)
    with pytest.raises(TypeError):
        frozen["nested"][0]["value"] = 4

    for invalid in (
        {1: "non-string key"},
        {"nested": {"nan": math.nan}},
        {"nested": [{"inf": math.inf}]},
        {"nested": [{"neg_inf": -math.inf}]},
        {"unsupported": object()},
    ):
        with pytest.raises(TypeError):
            copy_json_value(invalid)


def test_json_value_cycles_are_rejected_as_type_errors() -> None:
    copy_json_value = getattr(extension_api, "_copy_json_value")
    direct_list: list[object] = []
    direct_list.append(direct_list)
    indirect_list: list[object] = []
    indirect_list_child: list[object] = []
    indirect_list.append(indirect_list_child)
    indirect_list_child.append(indirect_list)
    direct_dict: dict[str, object] = {}
    direct_dict["self"] = direct_dict
    indirect_dict: dict[str, object] = {}
    indirect_dict_child: dict[str, object] = {}
    indirect_dict["child"] = indirect_dict_child
    indirect_dict_child["parent"] = indirect_dict

    for cyclic in (direct_list, indirect_list, direct_dict, indirect_dict):
        with pytest.raises(TypeError):
            copy_json_value(cyclic)

    shared = {"value": []}
    copied = copy_json_value({"left": shared, "right": shared})
    assert copied["left"] == copied["right"]
    assert copied["left"] is not copied["right"]
    assert copied["left"]["value"] is not copied["right"]["value"]


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


def test_typed_term_proof_is_the_single_native_and_portable_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from d810.backends.mba import native_z3_proof_template
    from d810.mba.typed_term import fixed_shift_term

    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    valid_left = fixed_shift_term("rol", 32, x, 5)
    valid_right = fixed_shift_term("rol", 32, x, 5)
    invalid_width = TypedBvTerm(None, 16, leaf_key=("register", "x"))
    malformed = object.__new__(TypedBvTerm)
    object.__setattr__(malformed, "operation", "add")
    object.__setattr__(malformed, "width", 32)
    object.__setattr__(malformed, "value", None)
    object.__setattr__(malformed, "leaf_key", None)
    object.__setattr__(malformed, "children", ())
    object.__setattr__(malformed, "shift_count", None)

    for left, right in (
        (valid_left, valid_right),
        (valid_left, invalid_width),
        (malformed, valid_right),
    ):
        assert extension_api.prove_typed_term_equivalence(left, right) == (
            native_z3_proof_template.prove_typed_term_equivalence(left, right)
        )

    monkeypatch.setattr(
        extension_api,
        "prove_typed_term_equivalence",
        lambda _left, _right: True,
    )
    assert (
        native_z3_proof_template.prove_typed_term_equivalence(valid_left, valid_right)
        is True
    )


def test_typed_term_proof_parity_when_z3_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from d810.backends.mba import native_z3_proof_template

    term = TypedBvTerm(None, 32, value=0)
    monkeypatch.setitem(sys.modules, "z3", None)
    assert extension_api.prove_typed_term_equivalence(term, term) is False
    assert native_z3_proof_template.prove_typed_term_equivalence(term, term) is False
