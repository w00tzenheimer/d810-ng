from __future__ import annotations

import dataclasses
import math
import os
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
    reconstruct_native_provider_result,
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
    MbaResidualObservationSink,
)
from d810.mba.island_profile import profile_typed_term
from d810.mba.semantic_canonicalization import canonicalize_mba_term


def _candidate(*, destination_size: int = 4) -> NativeMbaCandidate:
    term = TypedBvTerm(None, destination_size * 8, value=0)
    return NativeMbaCandidate(
        destination_size=destination_size,
        term=term,
        raw_term=term,
        profile=profile_typed_term(term),
        native_context=object(),
    )


def _atomizable_candidate() -> NativeMbaCandidate:
    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    y = TypedBvTerm(None, 32, leaf_key=("register", "y"))
    repeated = TypedBvTerm("and", 32, children=(x, y))
    term = TypedBvTerm("add", 32, children=(repeated, repeated))
    return NativeMbaCandidate(
        destination_size=4,
        term=term,
        raw_term=term,
        profile=profile_typed_term(term),
        native_context=object(),
    )


class _FakeProviderHost:
    def __init__(self, *, proof: bool = True, proof_error: Exception | None = None):
        self.proof_result = proof
        self.proof_error = proof_error
        self.rebuild_calls: list[TypedBvTerm] = []
        self.prove_calls: list[dict[str, object]] = []
        self.reconstruction = NativeMbaReconstruction(object(), object())

    def rebuild(self, candidate, replacement):
        self.rebuild_calls.append(replacement)
        return self.reconstruction

    def prove(self, candidate, reconstruction, **kwargs):
        self.prove_calls.append(kwargs)
        if self.proof_error is not None:
            raise self.proof_error
        return self.proof_result


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


def test_residual_observation_contract_is_exported() -> None:
    assert D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY == (
        "d810.mba.residual-observation.v1"
    )
    assert "MbaResidualRecord" in extension_api.__all__
    assert "MbaResidualReceipt" in extension_api.__all__
    assert "MbaResidualObservationSink" in extension_api.__all__


def test_public_sink_protocol_exposes_only_record() -> None:
    assert "record" in MbaResidualObservationSink.__dict__
    assert "close" not in MbaResidualObservationSink.__dict__


def test_residual_contract_imports_without_ida_modules() -> None:
    code = (
        "import builtins\n"
        "real_import = builtins.__import__\n"
        "def blocked(name, *args, **kwargs):\n"
        "    if name == 'idaapi' or name.startswith('ida_'):\n"
        "        raise AssertionError(name)\n"
        "    return real_import(name, *args, **kwargs)\n"
        "builtins.__import__ = blocked\n"
        "from d810.mba.extension_api import MbaResidualRecord, MbaResidualReceipt\n"
        "assert MbaResidualReceipt('stored').status == 'stored'\n"
        "assert MbaResidualRecord.__name__ == 'MbaResidualRecord'\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).parents[3] / "src")
    result = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


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


def test_provider_result_forwards_proof_inputs_and_returns_only_after_proof() -> None:
    candidate = _atomizable_candidate()
    host = _FakeProviderHost()
    received: list[TypedBvTerm] = []

    result = reconstruct_native_provider_result(
        host,
        candidate,
        lambda term: received.append(term) or term,
        proof_certificate="cert-v1",
        known_constants={("register", "x"): 7},
        proof_timeout_ms=125,
    )

    assert result is host.reconstruction
    assert len(received) == 1
    assert host.rebuild_calls
    assert host.prove_calls == [
        {
            "certificate": "cert-v1",
            "known_constants": {("register", "x"): 7},
            "proof_timeout_ms": 125,
        }
    ]


def test_native_atomization_uses_raw_capture_without_changing_canonical_identity() -> None:
    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    y = TypedBvTerm(None, 32, leaf_key=("register", "y"))
    raw = TypedBvTerm(
        "and", 32, children=(x, TypedBvTerm("and", 32, children=(y, x)))
    )
    canonical = canonicalize_mba_term(raw).canonical_term
    candidate = NativeMbaCandidate(
        destination_size=4,
        term=canonical,
        raw_term=raw,
        profile=profile_typed_term(raw),
        native_context=object(),
    )

    atomized = extension_api.atomize_native_candidate(candidate)

    assert candidate.term == canonical
    assert atomized.view.original_term is raw
    assert atomized.term != candidate.term


def test_native_candidate_rejects_noncanonical_term() -> None:
    x = TypedBvTerm(None, 32, leaf_key=("register", "x"))
    y = TypedBvTerm(None, 32, leaf_key=("register", "y"))
    noncanonical = TypedBvTerm("add", 32, children=(y, x))

    with pytest.raises(ValueError, match="canonical"):
        NativeMbaCandidate(
            destination_size=4,
            term=noncanonical,
            raw_term=noncanonical,
            profile=profile_typed_term(noncanonical),
            native_context=object(),
        )


def test_native_candidate_rejects_unrelated_raw_term() -> None:
    term = TypedBvTerm(None, 32, value=0)
    raw = TypedBvTerm(None, 32, value=1)

    with pytest.raises(ValueError, match="raw_term"):
        NativeMbaCandidate(
            destination_size=4,
            term=term,
            raw_term=raw,
            profile=profile_typed_term(raw),
            native_context=object(),
        )


def test_native_candidate_rejects_unrelated_same_width_profile() -> None:
    term = TypedBvTerm(None, 32, value=0)
    raw = profile_typed_term(TypedBvTerm(None, 32, value=1))

    with pytest.raises(ValueError, match="profile"):
        NativeMbaCandidate(
            destination_size=4,
            term=term,
            raw_term=term,
            profile=raw,
            native_context=object(),
        )


@pytest.mark.parametrize(
    "provider",
    [
        pytest.param(lambda _term: (_ for _ in ()).throw(RuntimeError("provider")), id="provider-exception"),
        pytest.param(lambda _term: object(), id="malformed-provider-result"),
        pytest.param(
            lambda term: TypedBvTerm(
                "or",
                term.width,
                children=(
                    term,
                    TypedBvTerm(
                        None,
                        term.width,
                        leaf_key=("d810.mba.atom.v1", 99, "unknown"),
                    ),
                ),
            ),
            id="unknown-atom",
        ),
    ],
)
def test_provider_or_restoration_failure_happens_before_rebuild(provider) -> None:
    candidate = _atomizable_candidate()
    host = _FakeProviderHost()

    assert reconstruct_native_provider_result(host, candidate, provider) is None
    assert host.rebuild_calls == []
    assert host.prove_calls == []


def test_provider_rebuild_refusal_exposes_no_reconstruction() -> None:
    candidate = _atomizable_candidate()
    host = _FakeProviderHost()
    host.reconstruction = None

    assert reconstruct_native_provider_result(host, candidate, lambda term: term) is None
    assert host.rebuild_calls
    assert host.prove_calls == []


@pytest.mark.parametrize(
    "host",
    [_FakeProviderHost(proof=False), _FakeProviderHost(proof_error=RuntimeError("proof"))],
    ids=["proof-false", "proof-exception"],
)
def test_provider_proof_failure_exposes_no_reconstruction(host) -> None:
    candidate = _atomizable_candidate()

    assert reconstruct_native_provider_result(host, candidate, lambda term: term) is None
    assert host.rebuild_calls
    assert len(host.prove_calls) == 1


@pytest.mark.parametrize("timeout", [0, -1, 251, "250"])
def test_provider_rejects_illegal_proof_timeout_before_provider(timeout) -> None:
    candidate = _atomizable_candidate()
    host = _FakeProviderHost()
    called = []

    assert (
        reconstruct_native_provider_result(
            host, candidate, lambda term: called.append(term) or term, proof_timeout_ms=timeout
        )
        is None
    )
    assert called == []
    assert host.rebuild_calls == []


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
