"""Bounded qualification receipts must not turn retries or skips into evidence."""

import importlib.util
import inspect
from copy import deepcopy
from types import SimpleNamespace
from pathlib import Path
import pytest


def helpers():
    path = Path(__file__).resolve().parents[2] / "tools/bench/canonical_dac_probe.py"
    assert path.exists(), "qualification receipt helper not implemented"
    spec = importlib.util.spec_from_file_location("canonical_dac_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(observations, matches):
    return {
        "snapshot": {"fingerprint": "a" * 64},
        "ledger_occurrence": 17,
        "ledger": {name: 0 for name in helpers().LEDGER_FIELDS}
        | {"observation_count": observations, "legacy_match_count": matches},
        "project": "eidolon_v4_const_simplify_solve.json",
    }


def test_cumulative_ledger_is_not_summed():
    receipt = helpers().select_evidence([record(2, 1), record(8, 3)])
    assert receipt["ledger"]["observation_count"] == 8
    assert receipt["ledger"]["legacy_match_count"] == 3


def test_changed_snapshot_is_rejected():
    other = record(8, 3)
    other["snapshot"]["fingerprint"] = "b" * 64
    with pytest.raises(ValueError, match="snapshot"):
        helpers().select_evidence([record(2, 1), other])


def test_missing_real_evidence_is_rejected():
    with pytest.raises(ValueError, match="evidence"):
        helpers().select_evidence([])


def test_same_snapshot_different_ledger_occurrence_is_rejected():
    other = record(8, 3)
    other["ledger_occurrence"] = 18
    with pytest.raises(ValueError, match="ledger occurrence"):
        helpers().select_evidence([record(2, 1), other])


@pytest.mark.parametrize(
    "receipt",
    [
        {"exit": 0, "passed": 0, "skipped": 1, "decompiles": [{"sha256": "a"}] * 2},
        {"exit": 0, "passed": 1, "skipped": 0, "decompiles": []},
        {"exit": 1, "passed": 1, "skipped": 0, "decompiles": [{"sha256": "a"}] * 2},
    ],
)
def test_failed_empty_or_skipped_run_is_not_qualification(receipt):
    with pytest.raises(ValueError):
        helpers().validate_run(receipt)


def test_complete_run_passes():
    helpers().validate_run(
        {
            "exit": 0,
            "passed": 1,
            "skipped": 0,
            "decompiles": [{"sha256": "a" * 64}, {"sha256": "b" * 64}],
        }
    )


def segment(segment_id, observations, matches):
    module = helpers()
    latest = record(observations, matches)
    latest["ledger"] = {name: 0 for name in module.LEDGER_FIELDS} | latest["ledger"]
    latest["enrollment"] = {
        "snapshot_fingerprint": "a" * 64,
        "selected_rule_count": 2,
        "canonical_eligible_rule_count": 1,
        "legacy_only_rule_count": 1,
    }
    latest["canonical_status_by_rule_width"] = [
        {"rule_id": 0, "width": 32, "status": "eligible"},
        {"rule_id": 1, "width": 32, "status": "unsupported"},
    ]
    latest["snapshot_widths"] = [32]
    latest["adapters"] = [
        {
            "name": "eligible",
            "rule_id": 0,
            "canonical_eligible": True,
            "legacy_only_observation_count": 0,
            "legacy_only_match_count": 0,
        },
        {
            "name": "excluded",
            "rule_id": 1,
            "canonical_eligible": False,
            "legacy_only_observation_count": 5,
            "legacy_only_match_count": 1,
        },
    ]
    return {
        "segment_id": segment_id,
        "exit": 0,
        "passed": 1,
        "skipped": 0,
        "decompiles": [{"sha256": "a" * 64}, {"sha256": "b" * 64}],
        "records": [latest],
        "toolchain": {"matcher_backend": {"backend": "cython"}},
    }


def test_distinct_process_segments_combine_only_latest_cumulative_counts():
    first, second = segment("dac", 61, 0), segment("positive", 10, 2)
    earlier = deepcopy(first["records"][0])
    earlier["ledger"] = record(2, 0)["ledger"]
    first["records"].insert(0, earlier)
    result = helpers().combine_evidence([first, second])
    assert result["ledger"]["observation_count"] == 71
    assert result["ledger"]["legacy_match_count"] == 2


def test_generic_combination_uses_explicit_project_and_run_validator():
    receipt = segment("generic-node", 9, 1)
    receipt["decompiles"] = []
    receipt["records"][0]["project"] = "example_libobfuscated.json"

    result = helpers().combine_evidence(
        [receipt],
        project="example_libobfuscated.json",
        run_validator=lambda value: None,
    )

    assert result["ledger"]["observation_count"] == 9
    assert result["segments"] == ["generic-node"]


def test_explicit_project_never_selects_another_catalogue_record():
    wrong = record(7, 1)
    with pytest.raises(ValueError, match="evidence"):
        helpers().select_evidence([wrong], project="example_libobfuscated.json")


def test_same_process_segment_cannot_be_counted_twice():
    first = segment("dac", 61, 0)
    with pytest.raises(ValueError, match="segment"):
        helpers().combine_evidence([first, first])


def test_different_catalogues_cannot_share_positive_evidence():
    first, second = segment("dac", 61, 0), segment("positive", 10, 2)
    second["records"][0]["snapshot"]["fingerprint"] = "b" * 64
    with pytest.raises(ValueError, match="snapshot"):
        helpers().combine_evidence([first, second])


def test_failed_positive_run_cannot_qualify_negative_dac():
    first, second = segment("dac", 61, 0), segment("positive", 10, 2)
    second["exit"] = 1
    with pytest.raises(ValueError):
        helpers().combine_evidence([first, second])


def test_incompatible_toolchains_cannot_be_combined():
    first, second = segment("dac", 61, 0), segment("positive", 10, 2)
    second["toolchain"]["matcher_backend"]["backend"] = "python"
    with pytest.raises(ValueError, match="toolchain"):
        helpers().combine_evidence([first, second])


def test_combined_evidence_retains_partition_and_excluded_denominators():
    result = helpers().combine_evidence(
        [segment("dac", 61, 0), segment("positive", 10, 2)]
    )
    assert result["enrollment"]["selected_rule_count"] == 2
    assert result["legacy_only_observation_count"] == 10
    assert result["legacy_only_match_count"] == 2
    assert len(result["canonical_status_by_rule_width"]) == 2


def test_invalid_partition_denominator_rejected():
    receipt = segment("dac", 61, 0)
    receipt["records"][0]["enrollment"]["legacy_only_rule_count"] = 0
    with pytest.raises(ValueError, match="partition"):
        helpers().combine_evidence([receipt])


def test_excluded_matches_cannot_exceed_excluded_observations():
    receipt = segment("dac", 61, 0)
    receipt["records"][0]["adapters"][1]["legacy_only_match_count"] = 6
    with pytest.raises(ValueError, match="excluded"):
        helpers().combine_evidence([receipt])


@pytest.mark.parametrize(
    "fault",
    ["duplicate", "missing_width", "extra_rule", "unknown_status", "wrong_adapter_id"],
)
def test_malformed_status_matrix_is_rejected(fault):
    receipt = segment("dac", 61, 0)
    latest = receipt["records"][0]
    statuses = latest["canonical_status_by_rule_width"]
    if fault == "duplicate":
        statuses.append(dict(statuses[0]))
    elif fault == "missing_width":
        latest["snapshot_widths"].append(64)
    elif fault == "extra_rule":
        statuses.append({"rule_id": 2, "width": 32, "status": "unsupported"})
    elif fault == "unknown_status":
        statuses[1]["status"] = "unknown"
    else:
        latest["adapters"][1]["rule_id"] = 0
    with pytest.raises(ValueError, match="partition"):
        helpers().combine_evidence([receipt])


@pytest.mark.parametrize(
    "fault", ["ledger_reset", "excluded_reset", "partition_change"]
)
def test_cumulative_segment_cannot_hide_resets_or_partition_changes(fault):
    receipt = segment("dac", 61, 1)
    earlier = deepcopy(receipt["records"][0])
    receipt["records"].insert(0, earlier)
    if fault == "ledger_reset":
        earlier["ledger"]["legacy_binding_unknown"] = 1
    elif fault == "excluded_reset":
        earlier["adapters"][1]["legacy_only_observation_count"] = 6
    else:
        earlier["adapters"][1]["name"] = "different-excluded-rule"
    with pytest.raises(ValueError, match="cumulative|partition"):
        helpers().combine_evidence([receipt])


def test_shadow_witness_copies_verdict_and_keeps_portable_binding_details():
    adapter = SimpleNamespace(
        name="xor",
        _certified_catalogue_rule_id=3,
        _legacy_binding_paths={"x": {(0,)}},
        _shadow_structural_native_paths={"x": (1,)},
        _shadow_match_report="bounded-report",
        _shadow_lowering=SimpleNamespace(term="canonical", raw_term="raw"),
    )
    verdict = {"legacy_match": True, "structural_match": True, "same_bindings": False}
    witness = helpers().shadow_witness(adapter, verdict)
    verdict["legacy_match"] = False
    assert witness["verdict"]["legacy_match"] is True
    assert witness["rule_id"] == 3
    assert "(0,)" in witness["legacy_binding_paths"]
    assert witness["canonical_term"] == "'canonical'"


def test_shadow_witness_allows_missing_lowering_on_canonical_miss():
    witness = helpers().shadow_witness(
        SimpleNamespace(name="miss"), {"legacy_match": True, "structural_match": False}
    )
    assert witness["canonical_term"] == "None"


def test_structural_diagnostic_attempt_prefers_live_instruction_ea():
    module = helpers()
    source = SimpleNamespace(ea=0x222)
    adapter = SimpleNamespace(
        name="miss",
        _certified_catalogue_rule_id=17,
        _attempt_instruction=SimpleNamespace(ea=0x111),
    )

    attempt = module.new_structural_diagnostic_attempt(adapter, source, 64)
    module._record_structural_diagnostic(
        lambda: attempt, {"stage": "lowering", "reason": "returned_none"}
    )

    assert attempt == {
        "rule": "miss",
        "rule_id": 17,
        "requested_comparison_budget": 64,
        "input_ea": 0x111,
        "input_ea_source": "attempt_instruction",
        "source": repr(source),
        "events": [{"stage": "lowering", "reason": "returned_none"}],
    }
    adapter._attempt_instruction = None
    fallback = module.new_structural_diagnostic_attempt(adapter, source, 32)
    module._record_structural_diagnostic(
        lambda: fallback, {"stage": "lowering", "reason": "returned_none"}
    )
    assert fallback["input_ea"] == 0x222
    assert fallback["input_ea_source"] == "test_ast"


def test_structural_diagnostic_attempt_tolerates_unprintable_source():
    class UnprintableSource:
        ea = 0x333

        def __repr__(self):
            raise RuntimeError("repr unavailable")

    module = helpers()
    attempt = module.new_structural_diagnostic_attempt(
        SimpleNamespace(name="miss", _attempt_instruction=None),
        UnprintableSource(),
        64,
    )
    module._record_structural_diagnostic(
        lambda: attempt, {"stage": "lowering", "reason": "returned_none"}
    )

    assert attempt["input_ea"] == 0x333
    assert "RuntimeError" in attempt["source"]


def test_structural_diagnostic_metadata_failure_does_not_change_result():
    module = helpers()
    reads = []

    class HostileMetadata:
        def __getattribute__(self, name):
            if name.startswith("_") or name in {"ea", "name"}:
                reads.append(name)
                raise RuntimeError("metadata unavailable")
            return object.__getattribute__(self, name)

        def __repr__(self):
            reads.append("repr")
            raise RuntimeError("repr unavailable")

    hostile = HostileMetadata()
    attempt = module.new_structural_diagnostic_attempt(hostile, hostile, 64)
    assert reads == []
    result = object()
    observed = module.structural_diagnostic_boundary(
        "lowering",
        lambda: result,
        lambda: attempt,
        classify_result=lambda _result: "returned_none",
    )

    assert observed() is result
    assert reads
    assert attempt["events"] == [
        {"stage": "lowering", "reason": "returned_none"}
    ]


def test_lowering_diagnostic_classifier_tolerates_hostile_result_metadata():
    module = helpers()

    class HostileLowering:
        @property
        def term(self):
            raise RuntimeError("metadata unavailable")

    assert module.lowering_diagnostic_reason(HostileLowering()) == "term_unavailable"


def test_structural_diagnostic_boundary_records_and_reraises_exact_exception():
    module = helpers()
    attempt = {"events": []}
    failure = LookupError("native lowering failed")

    def boundary(value, *, width):
        raise failure

    observed = module.structural_diagnostic_boundary(
        "lowering", boundary, lambda: attempt
    )

    with pytest.raises(LookupError) as caught:
        observed("source", width=32)

    assert caught.value is failure
    assert inspect.signature(observed) == inspect.signature(boundary)
    assert observed.__wrapped__ is boundary
    assert attempt["events"] == [
        {
            "stage": "lowering",
            "reason": "exception",
            "exception_type": "LookupError",
            "exception_message": "native lowering failed",
        }
    ]


@pytest.mark.parametrize(
    ("result", "classifier", "reason"),
    [
        (None, "lowering_diagnostic_reason", "returned_none"),
        (
            SimpleNamespace(term=None, raw_term="raw"),
            "lowering_diagnostic_reason",
            "term_unavailable",
        ),
        (
            SimpleNamespace(comparisons=None),
            "matcher_diagnostic_reason",
            "invalid_comparison_count",
        ),
    ],
)
def test_structural_diagnostic_boundary_classifies_result_without_changing_it(
    result, classifier, reason
):
    module = helpers()
    attempt = {"events": []}

    def boundary():
        return result

    observed = module.structural_diagnostic_boundary(
        "matcher",
        boundary,
        lambda: attempt,
        classify_result=getattr(module, classifier),
    )

    assert observed() is result
    assert attempt["events"] == [{"stage": "matcher", "reason": reason}]


def test_shadow_witness_retains_diagnostic_after_structural_state_is_cleared():
    diagnostic = {
        "requested_comparison_budget": 64,
        "input_ea": 0x180012B26,
        "input_ea_source": "attempt_instruction",
        "source": "cleared-source-root",
        "events": [
            {
                "stage": "matcher",
                "reason": "exception",
                "exception_type": "ValueError",
                "exception_message": "bad report",
            }
        ],
    }

    witness = helpers().shadow_witness(
        SimpleNamespace(name="BnotXor_FactorRule_1"),
        {"legacy_match": True, "structural_match": False},
        diagnostic=diagnostic,
    )

    assert witness["input_ea"] == 0x180012B26
    assert witness["source"] == "cleared-source-root"
    assert witness["requested_comparison_budget"] == 64
    assert witness["structural_diagnostic"] == diagnostic


def test_shadow_witness_prefers_attempt_instruction_ea_over_source_ea():
    witness = helpers().shadow_witness(
        SimpleNamespace(
            name="Bnot_FactorRule_5",
            _shadow_source_ast=SimpleNamespace(ea=0x222),
        ),
        {"legacy_match": True, "structural_match": False},
        diagnostic={
            "requested_comparison_budget": 64,
            "input_ea": 0x111,
            "input_ea_source": "attempt_instruction",
            "source": "attempt-source",
            "events": [{"stage": "lowering", "reason": "returned_none"}],
        },
    )

    assert witness["input_ea"] == 0x111


def test_structural_diagnostics_receipt_field_is_strictly_opt_in():
    module = helpers()
    diagnostics = [{"stage": "lowering", "reason": "returned_none"}]

    assert module.structural_diagnostic_receipt_fields(False, diagnostics) == {}
    assert module.structural_diagnostic_receipt_fields(True, diagnostics) == {
        "structural_diagnostics": diagnostics
    }


def test_temporary_method_patches_restore_earlier_patch_after_partial_install():
    module = helpers()

    class Owner:
        method = "original"

    class RejectingType(type):
        def __setattr__(cls, name, value):
            if name == "method" and value == "replacement":
                raise RuntimeError("partial install")
            super().__setattr__(name, value)

    class RejectingOwner(metaclass=RejectingType):
        method = "original"

    with pytest.raises(RuntimeError, match="partial install"):
        with module.temporary_method_patches(
            (
                (Owner, "method", "replacement"),
                (RejectingOwner, "method", "replacement"),
            )
        ):
            pytest.fail("partial installation unexpectedly completed")

    assert Owner.method == "original"
    assert RejectingOwner.method == "original"


def test_diagnostic_patch_preserves_catalogue_digest_and_membership():
    module = helpers()
    from d810.mba import canonical_pattern
    from d810.mba.certified_catalogue import build_certified_catalogue_snapshot
    from d810.mba.rules.hodur import Xor_Hodur_1
    from tests.unit.mba._compiled_rule_fixture import admitted_rule

    rule = admitted_rule(Xor_Hodur_1, family="hodur", proof_widths=(64,))

    def snapshot_signature():
        snapshot = build_certified_catalogue_snapshot(
            (rule,), compiler_version="diagnostic-invariance-v1", widths=(64,)
        )
        return (
            snapshot.fingerprint,
            tuple(item.source_name for item in snapshot.rules_in_declaration_order),
            dict(snapshot.rule_ids_by_root_shape),
            dict(snapshot.canonical_rule_ids_by_root_shape),
            dict(snapshot.canonical_status_by_rule_width),
        )

    original = canonical_pattern.evaluate_frozen_constraints
    baseline = snapshot_signature()
    observed = module.structural_diagnostic_boundary(
        "constraint", original, lambda: None
    )
    with module.temporary_method_patches(
        ((canonical_pattern, "evaluate_frozen_constraints", observed),)
    ):
        assert snapshot_signature() == baseline

    assert canonical_pattern.evaluate_frozen_constraints is original
    assert snapshot_signature() == baseline


def test_diagnostic_workload_is_only_positive_companion():
    module = helpers()
    assert module.workload_segments(diagnostic=True) == (
        ("positive-xor", module.POSITIVE_NODE),
    )
    assert module.workload_segments(diagnostic=False) == (
        ("dac", module.NODE),
        ("positive-xor", module.POSITIVE_NODE),
    )


class _DiagnosticSnapshot:
    def __init__(self, raw):
        self.raw = deepcopy(raw)
        self.owned_mop = object()


class _DiagnosticNode:
    def __init__(
        self,
        opcode,
        *,
        left=None,
        right=None,
        dst=None,
        mop=None,
        dest_size=None,
        size=0,
        proof_origin=None,
        ea=None,
    ):
        self.opcode = opcode
        self.left = left
        self.right = right
        self.dst = dst
        self.mop = mop
        self.dest_size = dest_size
        self._size = size
        self.proof_origin = proof_origin
        self.ea = ea

    @property
    def size(self):
        return self._size

    def is_node(self):
        return True

    def is_leaf(self):
        return False

    def is_constant(self):
        return False


class _DiagnosticLeaf:
    def __init__(
        self,
        mop,
        *,
        dest_size=None,
        size=0,
        value=None,
        proof_origin=None,
    ):
        self.mop = mop
        self.dest_size = dest_size
        self._size = size
        self.value = value
        self.proof_origin = proof_origin

    @property
    def size(self):
        return self._size

    def is_node(self):
        return False

    def is_leaf(self):
        return True

    def is_constant(self):
        return self.value is not None


class _DiagnosticProxy:
    def __init__(self, target):
        self._target = target

    def __getattr__(self, name):
        return getattr(self._target, name)


def _widened_diagnostic_ast(*, ea=0x180013423):
    zero_raw = {"type": 2, "size": 4, "value": 0}
    load_raw = {
        "type": 4,
        "size": 4,
        "instruction": {
            "opcode": 2,
            "l": {"type": 1, "size": 2, "register": 256},
            "r": {"type": 5, "size": 8, "stack_offset": 696},
            "d": {"type": 0, "size": 4},
        },
    }
    setnz_raw = {
        "type": 4,
        "size": 1,
        "instruction": {
            "opcode": 32,
            "l": load_raw,
            "r": zero_raw,
            "d": {"type": 0, "size": 1},
        },
    }
    xdu_raw = {
        "type": 4,
        "size": 4,
        "instruction": {
            "opcode": 9,
            "l": setnz_raw,
            "r": {"type": 0, "size": -1},
            "d": {"type": 0, "size": 4},
        },
    }
    load = _DiagnosticNode(
        2,
        left=_DiagnosticLeaf(
            _DiagnosticSnapshot(load_raw["instruction"]["l"]), size=2
        ),
        right=_DiagnosticLeaf(
            _DiagnosticSnapshot(load_raw["instruction"]["r"]), size=8
        ),
        dst=_DiagnosticLeaf(
            _DiagnosticSnapshot(load_raw["instruction"]["d"]), size=4
        ),
        mop=_DiagnosticSnapshot(load_raw),
        dest_size=4,
        size=4,
        proof_origin="load-origin",
    )
    zero = _DiagnosticLeaf(
        _DiagnosticSnapshot(zero_raw),
        dest_size=4,
        size=4,
        value=0,
        proof_origin="zero-origin",
    )
    setnz = _DiagnosticNode(
        32,
        left=load,
        right=zero,
        dst=_DiagnosticLeaf(
            _DiagnosticSnapshot(setnz_raw["instruction"]["d"]), size=1
        ),
        mop=_DiagnosticSnapshot(setnz_raw),
        dest_size=1,
        size=1,
        proof_origin="setnz-origin",
    )
    xdu = _DiagnosticNode(
        9,
        left=setnz,
        right=None,
        dst=_DiagnosticLeaf(
            _DiagnosticSnapshot(xdu_raw["instruction"]["d"]), size=4
        ),
        mop=_DiagnosticSnapshot(xdu_raw),
        dest_size=4,
        size=4,
        proof_origin="xdu-origin",
    )
    root = _DiagnosticNode(
        19,
        left=_DiagnosticLeaf(_DiagnosticSnapshot({"type": 1, "size": 4}), size=4),
        right=_DiagnosticProxy(_DiagnosticProxy(xdu)),
        dest_size=4,
        size=4,
        ea=ea,
    )
    return root, xdu_raw, setnz_raw, load_raw, zero_raw


def _diagnostic_owned_identity(mop):
    return deepcopy(mop.raw)


def test_widened_lowering_capture_records_occurrence_bound_native_payload():
    module = helpers()
    source, xdu_raw, setnz_raw, load_raw, zero_raw = _widened_diagnostic_ast()
    store = module.new_widened_boolean_capture_store(capacity=4)
    lowering = SimpleNamespace(term=None, raw_term=None)

    result = module.capture_widened_boolean_lowering_result(
        store,
        source,
        4,
        lowering,
        xdu_opcode=9,
        owned_mop_identity=_diagnostic_owned_identity,
    )

    assert result is lowering
    capture = module.widened_boolean_capture_for_source(store, source, lowering)
    assert capture["status"] == "captured"
    assert capture["lowering_sequence"] == 1
    assert capture["input_ea"] == 0x180013423
    assert capture["destination_size"] == 4
    assert capture["visited_nodes"] == 3
    assert capture["truncated"] is False
    assert len(capture["xdu_candidates"]) == 1
    candidate = capture["xdu_candidates"][0]
    assert candidate["path"] == [1]
    assert candidate["proxy_depth"] == 2
    assert candidate["visible"]["opcode"] == 9
    assert candidate["visible"]["dest_size"] == 4
    assert candidate["visible"]["size"] == 4
    assert candidate["visible"]["right_present"] is False
    assert candidate["visible"]["proof_origin"] == "'xdu-origin'"
    assert candidate["owned_native_pod"] == xdu_raw
    assert candidate["setnz"]["visible"]["opcode"] == 32
    assert candidate["setnz"]["owned_native_pod"] == setnz_raw
    assert candidate["setnz"]["lhs"]["owned_native_pod"] == load_raw
    assert candidate["setnz"]["rhs"]["owned_native_pod"] == zero_raw
    assert candidate["native_destinations"] == {
        "xdu": {"type": 0, "size": 4},
        "setnz": {"type": 0, "size": 1},
    }
    assert candidate["identity_equalities"] == {
        "xdu_l_equals_visible_setnz": True,
        "setnz_l_equals_visible_lhs": True,
        "setnz_r_equals_visible_rhs": True,
        "setnz_d_equals_visible_dst": True,
    }


def test_widened_capture_is_cached_once_and_attached_only_to_exact_witnesses():
    module = helpers()
    source, *_ = _widened_diagnostic_ast()
    identity_calls = []

    def owned_identity(mop):
        identity_calls.append(mop)
        return deepcopy(mop.raw)

    store = module.new_widened_boolean_capture_store(capacity=4)
    lowering = SimpleNamespace(term=None, raw_term=None)
    module.capture_widened_boolean_lowering_result(
        store,
        source,
        4,
        lowering,
        xdu_opcode=9,
        owned_mop_identity=owned_identity,
    )
    call_count = len(identity_calls)
    source.right._target._target.left = None

    first = {
        "events": [{"stage": "lowering", "reason": "term_unavailable"}],
        "input_ea": 0x180013423,
    }
    second = {
        "events": [{"stage": "lowering", "reason": "term_unavailable"}],
        "input_ea": 0x180013423,
    }
    unrelated = {
        "events": [{"stage": "lowering", "reason": "term_unavailable"}],
        "input_ea": 0x180013423,
    }
    module.attach_widened_boolean_capture(
        first,
        SimpleNamespace(name="BnotXor_FactorRule_1"),
        source,
        lowering,
        store,
    )
    module.attach_widened_boolean_capture(
        second,
        SimpleNamespace(name="Bnot_FactorRule_5"),
        source,
        lowering,
        store,
    )
    module.attach_widened_boolean_capture(
        unrelated,
        SimpleNamespace(name="Bnot_FactorRule_4"),
        source,
        lowering,
        store,
    )

    assert len(identity_calls) == call_count
    assert first["widened_boolean_lowering"] == second["widened_boolean_lowering"]
    assert first["widened_boolean_lowering"]["lowering_sequence"] == 1
    assert "widened_boolean_lowering" not in unrelated


def test_widened_capture_distinguishes_occurrences_and_reports_eviction():
    module = helpers()
    first, *_ = _widened_diagnostic_ast()
    second, *_ = _widened_diagnostic_ast()
    store = module.new_widened_boolean_capture_store(capacity=1)
    first_lowering = SimpleNamespace(term=None, raw_term=None)
    second_lowering = SimpleNamespace(term=None, raw_term=None)

    module.capture_widened_boolean_lowering_result(
        store,
        first,
        4,
        first_lowering,
        xdu_opcode=9,
        owned_mop_identity=_diagnostic_owned_identity,
    )
    module.capture_widened_boolean_lowering_result(
        store,
        second,
        4,
        second_lowering,
        xdu_opcode=9,
        owned_mop_identity=_diagnostic_owned_identity,
    )

    missing = module.widened_boolean_capture_for_source(
        store, first, first_lowering
    )
    retained = module.widened_boolean_capture_for_source(
        store, second, second_lowering
    )
    assert missing == {
        "status": "missing",
        "reason": "capture_evicted_or_unavailable",
        "capacity": 1,
        "evicted": 1,
    }
    assert retained["status"] == "captured"
    assert retained["lowering_sequence"] == 2


def test_widened_capture_correlates_source_and_exact_lowering_occurrence():
    module = helpers()
    source, *_ = _widened_diagnostic_ast()
    first_lowering = SimpleNamespace(term=None, raw_term=None)
    second_lowering = SimpleNamespace(term=None, raw_term=None)
    store = module.new_widened_boolean_capture_store(capacity=4)

    module.capture_widened_boolean_lowering_result(
        store,
        source,
        4,
        first_lowering,
        xdu_opcode=9,
        owned_mop_identity=_diagnostic_owned_identity,
    )
    source.right._target._target.proof_origin = "second-occurrence"
    module.capture_widened_boolean_lowering_result(
        store,
        source,
        4,
        second_lowering,
        xdu_opcode=9,
        owned_mop_identity=_diagnostic_owned_identity,
    )

    first = module.widened_boolean_capture_for_source(
        store, source, first_lowering
    )
    second = module.widened_boolean_capture_for_source(
        store, source, second_lowering
    )
    missing = module.widened_boolean_capture_for_source(
        store, source, SimpleNamespace(term=None, raw_term=None)
    )
    assert first["lowering_sequence"] == 1
    assert first["xdu_candidates"][0]["visible"]["proof_origin"] == "'xdu-origin'"
    assert second["lowering_sequence"] == 2
    assert (
        second["xdu_candidates"][0]["visible"]["proof_origin"]
        == "'second-occurrence'"
    )
    assert missing == {
        "status": "missing",
        "reason": "lowering_occurrence_unavailable",
        "capacity": 4,
        "evicted": 0,
    }


@pytest.mark.parametrize("source_ea", [None, 0x180013499])
def test_active_shadow_lowering_captures_and_publishes_exact_occurrence(source_ea):
    module = helpers()
    source, *_ = _widened_diagnostic_ast()
    if source_ea is None:
        del source.ea
    else:
        source.ea = source_ea
    lowering = SimpleNamespace(term=None, raw_term=None)
    adapter = SimpleNamespace(
        name="Bnot_FactorRule_5",
        _certified_catalogue_rule_id=47,
        _attempt_instruction=SimpleNamespace(ea=0x180013423),
    )
    store = module.new_widened_boolean_capture_store(capacity=4)
    active = []
    published = []
    lower_calls = []

    def lower(ast, *, destination_size):
        lower_calls.append((ast, destination_size))
        return lowering

    generic_lowering = module.structural_diagnostic_boundary(
        "lowering",
        lower,
        lambda: active[-1] if active else None,
        classify_result=module.lowering_diagnostic_reason,
    )
    observed_lowering = module.widened_boolean_active_lowering_boundary(
        generic_lowering,
        store,
        lambda: active[-1] if active else None,
        xdu_opcode=9,
        owned_mop_identity=_diagnostic_owned_identity,
    )

    def observe_structural_match(test_ast, *, lowering_provided=False):
        assert lowering_provided is False
        attempt = module.new_structural_diagnostic_attempt(adapter, test_ast, 64)
        active.append(attempt)
        try:
            observed = observed_lowering(test_ast, destination_size=4)
            assert observed is lowering
            return None
        finally:
            active.pop()
            if attempt["events"]:
                published.append(attempt)

    assert observe_structural_match(source) is None
    assert lower_calls == [(source, 4)]
    assert len(store["entries"]) == 1
    assert store["entries"][0]["source"] is source
    assert store["entries"][0]["lowering"] is lowering
    assert len(published) == 1
    attempt = published[0]
    assert attempt["input_ea"] == 0x180013423
    assert attempt["input_ea_source"] == "attempt_instruction"
    assert attempt["events"] == [
        {"stage": "lowering", "reason": "term_unavailable"}
    ]
    assert attempt["widened_boolean_lowering"]["status"] == "captured"
    assert attempt["widened_boolean_lowering"]["lowering_sequence"] == 1


def test_active_shadow_lowering_is_inert_outside_exact_attempt():
    module = helpers()
    source, *_ = _widened_diagnostic_ast()
    other_source, *_ = _widened_diagnostic_ast()
    lowering = SimpleNamespace(term=None, raw_term=None)
    store = module.new_widened_boolean_capture_store(capacity=4)
    active = []
    lower_calls = []

    def lower(ast, *, destination_size):
        lower_calls.append((ast, destination_size))
        return lowering

    generic_lowering = module.structural_diagnostic_boundary(
        "lowering",
        lower,
        lambda: active[-1] if active else None,
        classify_result=module.lowering_diagnostic_reason,
    )
    observed = module.widened_boolean_active_lowering_boundary(
        generic_lowering,
        store,
        lambda: active[-1] if active else None,
        xdu_opcode=9,
        owned_mop_identity=_diagnostic_owned_identity,
    )
    assert observed(source, destination_size=4) is lowering
    assert store["entries"] == []

    target_adapter = SimpleNamespace(
        name="Bnot_FactorRule_5",
        _certified_catalogue_rule_id=47,
        _attempt_instruction=SimpleNamespace(ea=0x180013423),
    )
    mismatched = module.new_structural_diagnostic_attempt(
        target_adapter, source, 64
    )
    active.append(mismatched)
    try:
        assert observed(other_source, destination_size=object()) is lowering
    finally:
        active.pop()
    assert store["entries"] == []

    non_target_adapter = SimpleNamespace(
        name="Bnot_FactorRule_5",
        _certified_catalogue_rule_id=47,
        _attempt_instruction=SimpleNamespace(ea=0x180013424),
    )
    non_target = module.new_structural_diagnostic_attempt(
        non_target_adapter, source, 64
    )
    active.append(non_target)
    try:
        assert observed(source, destination_size=object()) is lowering
    finally:
        active.pop()
    assert store["entries"] == []
    assert len(lower_calls) == 3

    failure = LookupError("lowering raised")

    def failing_lower(_ast, *, destination_size):
        raise failure

    failing_generic = module.structural_diagnostic_boundary(
        "lowering",
        failing_lower,
        lambda: active[-1] if active else None,
        classify_result=module.lowering_diagnostic_reason,
    )
    failing_observed = module.widened_boolean_active_lowering_boundary(
        failing_generic,
        store,
        lambda: active[-1] if active else None,
        xdu_opcode=9,
        owned_mop_identity=_diagnostic_owned_identity,
    )
    failed_attempt = module.new_structural_diagnostic_attempt(
        target_adapter, source, 64
    )
    active.append(failed_attempt)
    try:
        with pytest.raises(LookupError) as caught:
            failing_observed(source, destination_size=4)
    finally:
        active.pop()
    assert caught.value is failure
    assert store["entries"] == []


def test_non_json_widened_capture_preserves_exact_observer_result_and_exception():
    module = helpers()
    source, *_ = _widened_diagnostic_ast()
    lowering = SimpleNamespace(term=None, raw_term=None)
    store = module.new_widened_boolean_capture_store(capacity=4)
    store["entries"].append(
        {
            "source": source,
            "lowering": lowering,
            "lowering_sequence": 1,
            "capture": {"status": "captured", "non_json": object()},
        }
    )
    attempt = {
        "events": [{"stage": "lowering", "reason": "term_unavailable"}],
        "input_ea": 0x180013423,
    }

    def failed_attachment():
        module.attach_widened_boolean_capture(
            attempt,
            SimpleNamespace(name="BnotXor_FactorRule_1"),
            source,
            lowering,
            store,
        )

    result = object()
    assert (
        module.call_with_inert_structural_diagnostic(
            failed_attachment,
            lambda: result,
            attempt=attempt,
            diagnostic_name="widened_boolean_lowering",
        )
        is result
    )
    assert attempt["widened_boolean_lowering"] == {
        "status": "error",
        "error_type": "TypeError",
        "error_message": "Object of type object is not JSON serializable",
    }

    failure = LookupError("observer failed")

    def failed_observer():
        raise failure

    with pytest.raises(LookupError) as caught:
        module.call_with_inert_structural_diagnostic(
            failed_attachment,
            failed_observer,
            attempt=attempt,
            diagnostic_name="widened_boolean_lowering",
        )
    assert caught.value is failure


def test_widened_lowering_capture_ignores_success_and_non_target_ea():
    module = helpers()
    non_target, *_ = _widened_diagnostic_ast(ea=0x180013424)
    target, *_ = _widened_diagnostic_ast()
    store = module.new_widened_boolean_capture_store(capacity=4)

    module.capture_widened_boolean_lowering_result(
        store,
        non_target,
        4,
        SimpleNamespace(term=None, raw_term=None),
        xdu_opcode=9,
        owned_mop_identity=_diagnostic_owned_identity,
    )
    module.capture_widened_boolean_lowering_result(
        store,
        target,
        4,
        SimpleNamespace(term=object(), raw_term=object()),
        xdu_opcode=9,
        owned_mop_identity=_diagnostic_owned_identity,
    )

    assert store["entries"] == []
    assert store["next_sequence"] == 0


def test_measurement_project_routing_is_exact_and_opt_in(monkeypatch):
    module = helpers()
    monkeypatch.delenv("D810_CANONICAL_DAC_PROJECT", raising=False)
    assert module.routed_project_name(module.BASE_PROJECT) == module.BASE_PROJECT
    monkeypatch.setenv("D810_CANONICAL_DAC_PROJECT", "generated-activation-123.json")
    assert (
        module.routed_project_name(module.BASE_PROJECT)
        == "generated-activation-123.json"
    )
    assert module.routed_project_name("unrelated.json") == "unrelated.json"


def test_generalized_project_routing_only_overrides_explicit_original(monkeypatch):
    module = helpers()
    monkeypatch.setenv(
        "D810_CANONICAL_DAC_ORIGINAL_PROJECT", "example_libobfuscated.json"
    )
    monkeypatch.setenv("D810_CANONICAL_DAC_PROJECT", "generated-activation-123.json")

    assert module.routed_project_name("example_libobfuscated.json") == (
        "generated-activation-123.json"
    )
    assert module.routed_project_name(module.BASE_PROJECT) == module.BASE_PROJECT
    assert module.routed_project_name("another-project.json") == "another-project.json"


def test_capture_project_defaults_remain_original_dac_contract(monkeypatch):
    module = helpers()
    monkeypatch.delenv("D810_CANONICAL_DAC_ORIGINAL_PROJECT", raising=False)
    monkeypatch.delenv("D810_CANONICAL_DAC_PROJECT", raising=False)

    assert module.capture_project_names() == (module.BASE_PROJECT, module.BASE_PROJECT)


def test_full_suite_activation_summary_aggregates_without_attempt_payloads():
    module = helpers()
    summary = module.new_activation_summary()

    module.accumulate_activation_summary(
        summary, comparisons=256, stop_reason="comparison_budget", matched=False
    )
    module.accumulate_activation_summary(
        summary, comparisons=7, stop_reason=None, matched=True
    )

    assert summary == {
        "call_count": 2,
        "match_count": 1,
        "comparison_count": 263,
        "exhaustion_count": 1,
        "stop_reason_counts": {"comparison_budget": 1, "none": 1},
        "counter_scope": {
            "denominator": "canonical_iterator_invocation",
            "comparison_count": "sum_per_invocation",
            "exhaustion_count": "invocations_stopped_by_comparison_budget",
            "shared_instruction_budget": (
                "multiple invocations may belong to one instruction attempt"
            ),
        },
    }


def test_positive_xor_equivalence_is_one_exact_full_output_pair_only():
    module = helpers()
    assert module.positive_xor_outputs_equivalent(
        module.POSITIVE_XOR_ALTERNATIVE, module.POSITIVE_XOR_RETAINED
    )
    changed = module.POSITIVE_XOR_ALTERNATIVE.replace(
        "return (unsigned int)(a4[1] + *a4);", "return 0;"
    )
    assert not module.positive_xor_outputs_equivalent(
        changed, module.POSITIVE_XOR_RETAINED
    )
    assert not module.positive_xor_outputs_equivalent(
        module.POSITIVE_XOR_ALTERNATIVE, module.POSITIVE_XOR_RETAINED + "\n"
    )


@pytest.mark.parametrize(
    ("selection", "route"),
    [("raw", "raw_base"), ("canonical_fallback", "canonical_fallback")],
)
def test_accepted_enrolled_receipt_keeps_raw_base_distinct_from_fallback(
    selection, route
):
    module = helpers()
    adapter = SimpleNamespace(
        name="xor",
        _certified_catalogue_rule_id=7,
        canonical_fallback_enabled=True,
        _canonical_shadow_eligible=True,
        pattern_candidates=(object(),),
    )
    outcome = SimpleNamespace(
        status=SimpleNamespace(value="applied"),
        fingerprint="provider-fingerprint",
        matcher=SimpleNamespace(selection=SimpleNamespace(value=selection)),
    )
    receipt = module.accepted_enrolled_receipt(
        adapter, outcome, input_ea=0x401000
    )
    assert receipt["route"] == route
    assert receipt["input_ea"] == 0x401000
    assert receipt["provider_fingerprint"] == "provider-fingerprint"


def _candidate_lifecycle(module, accepted, calls):
    class Adapter:
        name = "eligible"
        _certified_catalogue_rule_id = 7
        canonical_fallback_enabled = True
        _canonical_shadow_eligible = True
        pattern_candidates = (object(),)

    class Optimizer:
        _pending_replacement_rule = None

    def set_pending(optimizer, rule, *args, **kwargs):
        calls["pending"] += 1
        optimizer._pending_replacement_rule = rule

    def accept(optimizer):
        calls["accepted"] += 1
        rule = optimizer._pending_replacement_rule
        if rule is not None:
            rule._last_provider_outcome.status = SimpleNamespace(value="applied")
        optimizer._pending_replacement_rule = None

    def reject(optimizer, reason):
        calls["rejected"] += 1
        optimizer._pending_replacement_rule = None

    wrappers = module.candidate_ea_patch_methods(
        adapter_type=Adapter,
        original_set_pending=set_pending,
        original_accepted=accept,
        original_rejected=reject,
        record_accepted=lambda rule, outcome, ea: accepted.append(
            module.accepted_enrolled_receipt(rule, outcome, input_ea=ea)
        ),
    )
    return Adapter, Optimizer, wrappers


@pytest.mark.parametrize("selection", ["raw", "canonical_fallback"])
def test_candidate_ea_survives_clear_then_outer_acceptance(selection):
    module = helpers()
    accepted = []
    calls = {"pending": 0, "accepted": 0, "rejected": 0}
    Adapter, Optimizer, (observe_pending, observe_accept, _, retained) = (
        _candidate_lifecycle(module, accepted, calls)
    )
    optimizer, adapter = Optimizer(), Adapter()
    instruction = SimpleNamespace(ea=0x401234)
    adapter._attempt_instruction = instruction
    adapter._last_provider_outcome = SimpleNamespace(
        status=SimpleNamespace(value="improved"),
        matcher=SimpleNamespace(selection=SimpleNamespace(value=selection)),
    )

    observe_pending(optimizer, adapter, None, instruction, None)
    assert retained == {id(optimizer): (id(adapter), 0x401234)}
    adapter._attempt_instruction = None
    observe_accept(optimizer)

    assert accepted == [
        {
            "rule": "eligible",
            "rule_id": 7,
            "route": (
                "raw_base" if selection == "raw" else "canonical_fallback"
            ),
            "candidate_count": 1,
            "outcome_status": "applied",
            "matcher_selection": selection,
            "input_ea": 0x401234,
            "provider_fingerprint": None,
        }
    ]
    assert calls == {"pending": 1, "accepted": 1, "rejected": 0}
    assert retained == {}


def test_candidate_ea_uses_distinct_eas_and_invalidates_rejection():
    module = helpers()
    accepted = []
    calls = {"pending": 0, "accepted": 0, "rejected": 0}
    Adapter, Optimizer, (observe_pending, observe_accept, observe_reject, retained) = (
        _candidate_lifecycle(module, accepted, calls)
    )
    optimizer, adapter = Optimizer(), Adapter()
    adapter._last_provider_outcome = SimpleNamespace(
        status=SimpleNamespace(value="improved")
    )
    adapter._attempt_instruction = SimpleNamespace(ea=0x401000)
    observe_pending(optimizer, adapter, None, None, None)
    observe_reject(optimizer, "veto")
    for ea in (0x402000, 0x403000):
        adapter._attempt_instruction = SimpleNamespace(ea=ea)
        adapter._last_provider_outcome.status = SimpleNamespace(value="improved")
        observe_pending(optimizer, adapter, None, None, None)
        adapter._attempt_instruction = None
        observe_accept(optimizer)

    assert [item["input_ea"] for item in accepted] == [0x402000, 0x403000]
    assert [item["outcome_status"] for item in accepted] == ["applied", "applied"]
    assert retained == {}


@pytest.mark.parametrize("ea", [None, True, "0x401000"])
def test_candidate_ea_records_missing_or_invalid_anchor_fail_closed(ea):
    module = helpers()
    accepted = []
    calls = {"pending": 0, "accepted": 0, "rejected": 0}
    Adapter, Optimizer, (observe_pending, observe_accept, _, _) = (
        _candidate_lifecycle(module, accepted, calls)
    )
    optimizer, adapter = Optimizer(), Adapter()
    adapter._attempt_instruction = SimpleNamespace(ea=ea)
    adapter._last_provider_outcome = SimpleNamespace(
        status=SimpleNamespace(value="improved")
    )

    observe_pending(optimizer, adapter, None, None, None)
    adapter._attempt_instruction = None
    observe_accept(optimizer)

    assert accepted[0]["input_ea"] is None
    assert module.accepted_enrolled_receipt(
        adapter,
        adapter._last_provider_outcome,
        input_ea=accepted[0]["input_ea"],
    )["input_ea"] is None


def test_candidate_ea_never_reuses_uncorrelated_stale_candidate():
    module = helpers()
    accepted = []
    calls = {"pending": 0, "accepted": 0, "rejected": 0}
    Adapter, Optimizer, (observe_pending, observe_accept, _, retained) = (
        _candidate_lifecycle(module, accepted, calls)
    )
    optimizer, adapter = Optimizer(), Adapter()
    adapter._attempt_instruction = SimpleNamespace(ea=0x401000)
    adapter._last_provider_outcome = SimpleNamespace(
        status=SimpleNamespace(value="improved")
    )
    observe_pending(optimizer, adapter, None, None, None)
    replacement = Adapter()
    replacement._last_provider_outcome = SimpleNamespace(
        status=SimpleNamespace(value="improved")
    )
    optimizer._pending_replacement_rule = replacement
    adapter._attempt_instruction = None

    observe_accept(optimizer)

    assert accepted[0]["input_ea"] is None
    assert accepted[0]["outcome_status"] == "applied"
    assert retained == {}


def test_candidate_ea_hooks_restore_and_delegate_originals_once():
    module = helpers()
    calls = {"pending": 0, "accepted": 0, "rejected": 0}

    class Adapter:
        _attempt_instruction = SimpleNamespace(ea=0x401000)
        _last_provider_outcome = SimpleNamespace(
            status=SimpleNamespace(value="improved")
        )

    class Optimizer:
        _pending_replacement_rule = None

        def set_pending(self, rule, *args):
            calls["pending"] += 1
            self._pending_replacement_rule = rule

        def accept(self):
            calls["accepted"] += 1

        def reject(self, reason):
            calls["rejected"] += 1

    originals = (Optimizer.set_pending, Optimizer.accept, Optimizer.reject)
    wrappers = module.candidate_ea_patch_methods(
        adapter_type=Adapter,
        original_set_pending=originals[0],
        original_accepted=originals[1],
        original_rejected=originals[2],
        record_accepted=lambda rule, outcome, ea: None,
    )[:3]
    optimizer, adapter = Optimizer(), Adapter()
    with module.temporary_method_patches(
        tuple(
            (Optimizer, name, wrapper)
            for name, wrapper in zip(("set_pending", "accept", "reject"), wrappers)
        )
    ):
        optimizer.set_pending(adapter, None, None, None)
        adapter._attempt_instruction = None
        optimizer.accept()
        adapter._attempt_instruction = SimpleNamespace(ea=0x402000)
        optimizer.set_pending(adapter, None, None, None)
        optimizer.reject("veto")

    assert calls == {"pending": 2, "accepted": 1, "rejected": 1}
    assert (Optimizer.set_pending, Optimizer.accept, Optimizer.reject) == originals


def test_feasibility_snapshot_reads_one_live_manager_owned_optimizer_once():
    module = helpers()

    class PatternOptimizer:
        reads = 0
        _generation = 7

        @property
        def canonical_fallback_feasibility_counts(self):
            self.reads += 1
            return {name: index for index, name in enumerate(module.FEASIBILITY_FIELDS)}

    optimizer = PatternOptimizer()
    state = SimpleNamespace(
        manager=SimpleNamespace(
            instruction_optimizer=SimpleNamespace(instruction_optimizers=[optimizer])
        )
    )

    retained = {}
    snapshot = module.canonical_fallback_feasibility_snapshot(
        state, optimizer_type=PatternOptimizer, retained_occurrences=retained
    )

    assert optimizer.reads == 1
    assert snapshot == {
        "status": "available",
        "optimizer_occurrence": "pattern-optimizer-1",
        "optimizer_generation": 7,
        "counts": {
            name: index for index, name in enumerate(module.FEASIBILITY_FIELDS)
        },
    }
    assert retained == {"pattern-optimizer-1": optimizer}
    assert module.canonical_fallback_feasibility_snapshot(
        state, optimizer_type=PatternOptimizer, retained_occurrences=retained
    )["optimizer_occurrence"] == "pattern-optimizer-1"


@pytest.mark.parametrize("optimizers", [[], [object(), object()]])
def test_feasibility_snapshot_labels_unavailable_without_fabricating_zero(optimizers):
    module = helpers()

    class PatternOptimizer:
        pass

    state = SimpleNamespace(
        manager=SimpleNamespace(
            instruction_optimizer=SimpleNamespace(instruction_optimizers=optimizers)
        )
    )

    snapshot = module.canonical_fallback_feasibility_snapshot(
        state, optimizer_type=PatternOptimizer, retained_occurrences={}
    )

    assert snapshot["status"] == "unavailable"
    assert snapshot["counts"] is None
    assert snapshot["optimizer_occurrence"] is None
    assert snapshot["optimizer_generation"] is None


def test_feasibility_snapshot_assigns_replacement_a_new_retained_occurrence():
    module = helpers()

    class PatternOptimizer:
        _generation = 1

        @property
        def canonical_fallback_feasibility_counts(self):
            return {name: 0 for name in module.FEASIBILITY_FIELDS}

    first = PatternOptimizer()
    owner = SimpleNamespace(instruction_optimizers=[first])
    state = SimpleNamespace(
        manager=SimpleNamespace(instruction_optimizer=owner)
    )
    retained = {}
    first_snapshot = module.canonical_fallback_feasibility_snapshot(
        state, optimizer_type=PatternOptimizer, retained_occurrences=retained
    )
    replacement = PatternOptimizer()
    owner.instruction_optimizers[:] = [replacement]
    second_snapshot = module.canonical_fallback_feasibility_snapshot(
        state, optimizer_type=PatternOptimizer, retained_occurrences=retained
    )

    assert first_snapshot["optimizer_occurrence"] == "pattern-optimizer-1"
    assert second_snapshot["optimizer_occurrence"] == "pattern-optimizer-2"
    assert list(retained.values()) == [first, replacement]


def test_schedule_diagnostic_is_opt_in_and_method_patch_restores_on_failure():
    module = helpers()
    assert module.schedule_diagnostic_requested({}) is False
    assert (
        module.schedule_diagnostic_requested(
            {"D810_CANONICAL_DAC_SCHEDULE_DIAGNOSTIC": "1"}
        )
        is True
    )
    owner = SimpleNamespace(method=lambda: "original")

    def replacement():
        return "replacement"

    with pytest.raises(RuntimeError):
        with module.temporary_method_patch(owner, "method", replacement):
            assert owner.method() == "replacement"
            raise RuntimeError("stop")
    assert owner.method() == "original"


def test_schedule_summary_distinguishes_exclusion_from_budget_starvation():
    module = helpers()
    base = {
        "input_ea": 0x18000E088,
        "attempt_token": "schedule-17",
        "root_shape": ("sub", 32, 2),
        "ordered_bucket": [
            {"rule_id": 1, "name": "earlier"},
            {"rule_id": 176, "name": "Xor_HackersDelightRule_3"},
        ],
    }
    calls = [
        {
            "input_ea": 0x18000E088,
            "attempt_token": "schedule-17",
            "rule": "earlier",
            "requested_comparison_budget": 2,
            "comparisons": 2,
            "stop_reason": "comparison_budget",
        }
    ]
    result = module.summarize_schedule_diagnostics([base], calls)
    assert result[0]["remaining_comparison_budget"] == 0
    assert result[0]["break_reason"] == "budget_exhausted_before_target"
    excluded = dict(base, ordered_bucket=[{"rule_id": 1, "name": "earlier"}])
    assert (
        module.summarize_schedule_diagnostics([excluded], calls)[0]["break_reason"]
        == "target_absent_from_bucket"
    )
