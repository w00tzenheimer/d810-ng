"""Contracts for the test-only per-node DSL profiling harness."""

from __future__ import annotations

import importlib.util
import cProfile
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load_tool(name: str):
    path = ROOT / "tools" / "bench" / f"{name}.py"
    assert path.exists(), f"{path} not implemented"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def item(nodeid: str, project: object = "example_libobfuscated.json"):
    return SimpleNamespace(
        nodeid=nodeid,
        callspec=SimpleNamespace(params={"case": SimpleNamespace(project=project)}),
    )


def test_collection_preserves_full_nodeids_and_exact_case_projects():
    collection = load_tool("dsl_profile_collection")
    result = collection.collection_manifest(
        [
            item("test_dsl.py::TestRules::test_rule[x-y]", "first.json"),
            item("test_dsl.py::TestRules::test_rule[x/y]", "second.json"),
        ]
    )

    assert result == {
        "schema_version": 1,
        "nodes": [
            {
                "nodeid": "test_dsl.py::TestRules::test_rule[x-y]",
                "project": "first.json",
            },
            {
                "nodeid": "test_dsl.py::TestRules::test_rule[x/y]",
                "project": "second.json",
            },
        ],
    }


def test_collection_refuses_duplicate_nodeids_instead_of_overwriting():
    collection = load_tool("dsl_profile_collection")
    with pytest.raises(ValueError, match="duplicate collected nodeid"):
        collection.collection_manifest([item("same[node]"), item("same[node]")])


@pytest.mark.parametrize(
    "bad_item",
    [
        SimpleNamespace(nodeid="missing-callspec"),
        SimpleNamespace(nodeid="missing-case", callspec=SimpleNamespace(params={})),
        item("missing-project", None),
        item("empty-project", ""),
    ],
)
def test_collection_refuses_unknown_project_mapping(bad_item):
    collection = load_tool("dsl_profile_collection")
    with pytest.raises(ValueError, match="project mapping"):
        collection.collection_manifest([bad_item])


def test_collection_hook_writes_manifest_only_at_collection_finish(
    tmp_path, monkeypatch
):
    collection = load_tool("dsl_profile_collection")
    output = tmp_path / "collection.json"
    monkeypatch.setenv(collection.COLLECTION_OUT_ENV, str(output))
    session = SimpleNamespace(items=[item("one[param]", "exact.json")])

    collection.pytest_collection_finish(session)

    assert json.loads(output.read_text()) == {
        "schema_version": 1,
        "nodes": [{"nodeid": "one[param]", "project": "exact.json"}],
    }


def test_collection_command_loads_only_collection_plugin():
    driver = load_tool("dsl_per_test_profile")
    command = driver.collection_command(
        "/python3", "tests/system/e2e/test_libdeobfuscated_dsl.py"
    )

    assert command == [
        "/python3",
        "-u",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-p",
        "tools.bench.dsl_profile_collection",
        "--collect-only",
        "-q",
        "-o",
        "addopts=",
        "tests/system/e2e/test_libdeobfuscated_dsl.py",
    ]
    assert "tools.bench.canonical_dac_probe" not in command


def test_manifest_validation_rejects_empty_and_duplicate_rows():
    driver = load_tool("dsl_per_test_profile")
    with pytest.raises(ValueError, match="empty collection"):
        driver.validate_collection_manifest({"schema_version": 1, "nodes": []})
    duplicate = {
        "schema_version": 1,
        "nodes": [
            {"nodeid": "same[param]", "project": "one.json"},
            {"nodeid": "same[param]", "project": "two.json"},
        ],
    }
    with pytest.raises(ValueError, match="duplicate"):
        driver.validate_collection_manifest(duplicate)


def test_manifest_limit_is_applied_before_exact_project_grouping():
    driver = load_tool("dsl_per_test_profile")
    manifest = {
        "schema_version": 1,
        "nodes": [
            {"nodeid": "first[a]", "project": "alpha.json"},
            {"nodeid": "second[b]", "project": "beta.json"},
            {"nodeid": "third[c]", "project": "alpha.json"},
        ],
    }

    nodes = driver.validate_collection_manifest(manifest, limit=2)

    assert list(driver.group_nodes_by_project(nodes)) == ["alpha.json", "beta.json"]
    assert driver.group_nodes_by_project(nodes)["alpha.json"] == ["first[a]"]


def capture_record(project: str, *, observations: int, matches: int) -> dict:
    probe = load_tool("canonical_dac_probe")
    ledger = {name: 0 for name in probe.LEDGER_FIELDS}
    ledger.update(observation_count=observations, legacy_match_count=matches)
    return {
        "project": project,
        "snapshot": {
            "fingerprint": "a" * 64,
            "structural_authorizable": True,
            "canonicalizer_schema_version": 1,
            "runtime_semantics_digest": "b" * 64,
        },
        "ledger_occurrence": 91,
        "ledger": ledger,
        "enrollment": {
            "snapshot_fingerprint": "a" * 64,
            "selected_rule_count": 1,
            "canonical_eligible_rule_count": 1,
            "legacy_only_rule_count": 0,
        },
        "snapshot_widths": [32],
        "canonical_status_by_rule_width": [
            {"rule_id": 0, "width": 32, "status": "eligible"}
        ],
        "adapters": [
            {
                "rule_id": 0,
                "name": "Rule0",
                "canonical_eligible": True,
                "legacy_only_observation_count": 0,
                "legacy_only_match_count": 0,
            }
        ],
    }


def shadow_receipt(nodeid: str, project: str, *, observations=3, matches=0) -> dict:
    return {
        "nodeid": nodeid,
        "exit": 0,
        "passed": 1,
        "failed": 0,
        "skipped": 0,
        "records": [
            capture_record(project, observations=observations, matches=matches)
        ],
        "toolchain": {"matcher_backend": {"backend": "cython"}},
    }


def test_qualification_continues_zero_positive_then_admits_unchanged_subset():
    driver = load_tool("dsl_per_test_profile")
    project = "example_libobfuscated.json"
    calls = []

    def admit(evidence):
        calls.append(deepcopy(evidence))
        return {"snapshot_fingerprint": evidence["snapshot"]["fingerprint"]}

    result = driver.assess_qualification(
        [
            shadow_receipt("first[zero]", project, observations=3, matches=0),
            shadow_receipt("second[positive]", project, observations=5, matches=2),
            shadow_receipt("third[unused]", project, observations=9, matches=4),
        ],
        project=project,
        admission=admit,
    )

    assert result["status"] == "qualified"
    assert result["evidence_nodes"] == ["first[zero]", "second[positive]"]
    assert (
        result["coverage_limit"]
        == "bounded collection-order subset; not per-rule empirical coverage"
    )
    assert result["evidence"]["ledger"]["observation_count"] == 8
    assert len(calls) == 1


def test_qualification_records_skip_but_never_counts_it_as_evidence():
    driver = load_tool("dsl_per_test_profile")
    project = "example_libobfuscated.json"
    skipped = {
        "nodeid": "skip[node]",
        "exit": 0,
        "passed": 0,
        "failed": 0,
        "skipped": 1,
        "records": [],
    }
    result = driver.assess_qualification(
        [skipped, shadow_receipt("positive[node]", project, matches=1)],
        project=project,
        admission=lambda evidence: {"ok": True},
    )

    assert result["status"] == "qualified"
    assert result["skipped_nodes"] == ["skip[node]"]
    assert result["evidence_nodes"] == ["positive[node]"]


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (lambda receipt: receipt.update(exit=1, failed=1, passed=0), "test_failed"),
        (
            lambda receipt: receipt["records"][-1]["ledger"].update(
                legacy_binding_mismatches=1
            ),
            "unsafe_evidence",
        ),
        (
            lambda receipt: receipt["records"][-1]["snapshot"].update(
                structural_authorizable=False
            ),
            "snapshot_not_authorizable",
        ),
    ],
)
def test_qualification_refuses_failed_or_unsafe_evidence(mutation, reason):
    driver = load_tool("dsl_per_test_profile")
    project = "example_libobfuscated.json"
    receipt = shadow_receipt("bad[node]", project, matches=1)
    mutation(receipt)

    result = driver.assess_qualification(
        [receipt], project=project, admission=lambda evidence: {"must": "not run"}
    )

    assert result["status"] == "refused"
    assert result["reason"] == reason
    assert "certificate" not in result


def test_qualification_does_not_fabricate_missing_snapshot_or_certificate():
    driver = load_tool("dsl_per_test_profile")
    project = "default_unflattening_ollvm.json"
    receipt = shadow_receipt("no-catalogue[node]", project)
    receipt["records"][-1].update(snapshot=None, ledger=None)
    receipt["records"][-1]["enrollment"].update(
        selected_rule_count=0, canonical_eligible_rule_count=0
    )

    result = driver.assess_qualification(
        [receipt], project=project, admission=lambda evidence: {"fabricated": True}
    )

    assert result == {
        "project": project,
        "status": "not_applicable",
        "reason": "no_selected_catalogue",
        "evidence_nodes": [],
        "skipped_nodes": [],
    }


def test_profile_command_is_fresh_whole_process_for_each_node(tmp_path):
    driver = load_tool("dsl_per_test_profile")
    first = driver.profile_command("/python3", "one[a]", tmp_path / "one.prof")
    second = driver.profile_command("/python3", "two[b]", tmp_path / "two.prof")

    assert first[:7] == [
        "/python3",
        "-u",
        "-m",
        "cProfile",
        "-o",
        str(tmp_path / "one.prof"),
        "-m",
    ]
    assert first[-1] == "one[a]"
    assert second[-1] == "two[b]"
    assert str(tmp_path / "two.prof") in second


def test_failed_test_keeps_and_renders_readable_raw_profile(tmp_path):
    driver = load_tool("dsl_per_test_profile")
    profile = tmp_path / "failed.prof"
    profiler = cProfile.Profile()
    profiler.enable()
    sum(range(10))
    profiler.disable()
    profiler.dump_stats(profile)

    result = driver.inspect_profile(profile, test_status="failed")

    assert profile.exists()
    assert result["raw_profile"] == str(profile)
    assert result["profile_status"] == "readable"
    assert Path(result["metrics"]["views"]["self"]).exists()


def test_unreadable_profile_is_explicit_even_when_test_failed(tmp_path):
    driver = load_tool("dsl_per_test_profile")
    profile = tmp_path / "broken.prof"
    profile.write_text("not pstats")

    result = driver.inspect_profile(profile, test_status="failed")

    assert result["profile_status"] == "unreadable"
    assert "error" in result
    assert profile.exists()


def test_runtime_partition_validation_catches_silent_fallback_and_drift():
    driver = load_tool("dsl_per_test_profile")
    project = "generated.json"
    qualified = {
        "snapshot": capture_record(project, observations=3, matches=1)["snapshot"],
        "enrollment": capture_record(project, observations=3, matches=1)["enrollment"],
        "adapters": capture_record(project, observations=3, matches=1)["adapters"],
        "snapshot_widths": [32],
        "canonical_status_by_rule_width": [
            {"rule_id": 0, "width": 32, "status": "eligible"}
        ],
    }
    live = capture_record(project, observations=5, matches=1)
    live["adapters"][0].update(
        canonical_fallback_enabled=True, uses_structural_matching=True
    )
    raw = {
        "project": project,
        "records": [live],
        "toolchain": {"matcher_backend": {"backend": "cython"}},
    }

    driver.validate_runtime_partition(
        raw, expected_project=project, qualified=qualified
    )
    silent = deepcopy(raw)
    silent["records"][-1]["adapters"][0]["canonical_fallback_enabled"] = False
    with pytest.raises(ValueError, match="partition was not active"):
        driver.validate_runtime_partition(
            silent, expected_project=project, qualified=qualified
        )
    drifted = deepcopy(raw)
    drifted["records"][-1]["snapshot"]["fingerprint"] = "c" * 64
    with pytest.raises(ValueError, match="snapshot"):
        driver.validate_runtime_partition(
            drifted, expected_project=project, qualified=qualified
        )


@pytest.mark.parametrize(
    "drift", ["earlier_snapshot", "earlier_width", "latest_status", "cross_project"]
)
def test_runtime_partition_validates_every_record_and_width_matrix(drift):
    driver = load_tool("dsl_per_test_profile")
    project = "generated.json"
    expected = capture_record(project, observations=3, matches=1)
    for adapter in expected["adapters"]:
        adapter.update(canonical_fallback_enabled=True, uses_structural_matching=True)
    qualified = {
        name: deepcopy(expected[name])
        for name in (
            "snapshot",
            "enrollment",
            "adapters",
            "snapshot_widths",
            "canonical_status_by_rule_width",
        )
    }
    raw = {
        "project": project,
        "records": [deepcopy(expected), deepcopy(expected)],
        "toolchain": {"matcher_backend": {"backend": "cython"}},
    }
    if drift == "earlier_snapshot":
        raw["records"][0]["snapshot"]["fingerprint"] = "c" * 64
    elif drift == "earlier_width":
        raw["records"][0]["snapshot_widths"] = [64]
    elif drift == "cross_project":
        raw["records"][0]["project"] = "unexpected.json"
    else:
        raw["records"][-1]["canonical_status_by_rule_width"][0]["status"] = "opaque"

    with pytest.raises(ValueError, match="snapshot|width|status|project"):
        driver.validate_runtime_partition(
            raw, expected_project=project, qualified=qualified
        )


def test_legacy_partition_validates_every_record_not_only_latest():
    driver = load_tool("dsl_per_test_profile")
    project = "original.json"
    earlier = capture_record(project, observations=3, matches=1)
    latest = capture_record(project, observations=3, matches=1)
    latest.update(snapshot=None, ledger=None)
    latest["adapters"][0].update(
        canonical_fallback_enabled=False, uses_structural_matching=False
    )
    raw = {"project": project, "records": [earlier, latest]}

    with pytest.raises(ValueError, match="legacy-unqualified"):
        driver.validate_legacy_partition(raw, expected_project=project)


def test_project_manifest_binds_runtime_image_and_execution_helpers(monkeypatch):
    driver = load_tool("dsl_per_test_profile")
    monkeypatch.setenv("D810_TEST_RUNTIME_IMAGE", "idapro-9.4-speedups:latest")
    monkeypatch.setenv("D810_TEST_RUNTIME_IMAGE_ID", "sha256:" + "d" * 64)

    manifest = driver._project_manifest(
        ROOT, project="example_libobfuscated.json", nodes=["one[node]"]
    )

    assert manifest["runtime_image"] == "idapro-9.4-speedups:latest"
    assert manifest["runtime_image_id"] == "sha256:" + "d" * 64
    assert len(manifest["git_revision"]) == 40
    assert isinstance(manifest["git_dirty"], list)
    for source in (
        "tools/bench/canonical_dac_measurement.py",
        "tools/bench/dsl_profile_collection.py",
        "tools/scripts/mba_structural_matcher_certificate.py",
    ):
        assert len(manifest["sources"][source]) == 64


def test_collect_only_cli_discovers_live_cases_and_applies_limit(tmp_path, monkeypatch):
    driver = load_tool("dsl_per_test_profile")
    module = tmp_path / "test_collection_cases.py"
    module.write_text(
        "import pytest\n"
        "class Case:\n"
        "    def __init__(self, name, project):\n"
        "        self.name = name\n"
        "        self.project = project\n"
        "    def __repr__(self):\n"
        "        return self.name\n"
        "@pytest.mark.parametrize('case', [Case('a', 'alpha.json'), Case('b', 'beta.json')])\n"
        "def test_case(case):\n"
        "    pass\n",
        encoding="utf-8",
    )
    output = tmp_path / "receipt"
    monkeypatch.chdir(ROOT)

    result = driver.main(
        [
            "--output-dir",
            str(output),
            "--test-path",
            str(module),
            "--python",
            sys.executable,
            "--collect-only",
            "--limit",
            "1",
        ]
    )

    summary = json.loads((output / "summary.json").read_text())
    assert result == 0
    assert summary["status"] == "collected"
    assert summary["discovered_node_count"] == 2
    assert summary["selected_node_count"] == 1
    assert summary["project_count"] == 1
    assert not (output / "qualification").exists()


def test_collect_only_cli_runs_real_pytest_collection_and_applies_limit(tmp_path):
    driver = load_tool("dsl_per_test_profile")
    module = tmp_path / "test_cases.py"
    module.write_text(
        """import pytest
class Case:
    def __init__(self, project): self.project = project
@pytest.mark.parametrize('case', [Case('one.json'), Case('two.json')], ids=['a', 'b'])
def test_case(case):
    raise AssertionError('collect-only must not execute tests')
"""
    )
    output = tmp_path / "out"

    result = driver.main(
        [
            "--output-dir",
            str(output),
            "--test-path",
            str(module),
            "--collect-only",
            "--limit",
            "1",
            "--python",
            sys.executable,
        ]
    )

    assert result == 0
    summary = json.loads((output / "summary.json").read_text())
    assert summary["status"] == "collected"
    assert summary["discovered_node_count"] == 2
    assert summary["selected_node_count"] == 1
    assert summary["project_count"] == 1
    assert (output / "collection.json").exists()
    assert not (output / "qualification").exists()
