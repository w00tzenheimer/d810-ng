"""Offline residual miner CLI contract tests."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[3]
SCRIPT = ROOT / "tools" / "scripts" / "mba_residual_rule_miner.py"
FIXTURE = ROOT / "tests" / "fixtures" / "mba" / "residual_or_masked_subterm.json"


def _run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(FIXTURE), "--output-dir", str(tmp_path), *args],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        text=True,
        capture_output=True,
        check=False,
    )


def test_fixture_is_valid_public_codec_corpus_and_has_expected_trigger() -> None:
    from d810.mba.residual_corpus import MbaResidualCorpus
    from d810.mba.subterm_atomization import atomize_repeated_subterms
    from d810.mba.typed_term import TypedBvTerm, term_fingerprint

    raw = json.loads(FIXTURE.read_text())
    corpus = MbaResidualCorpus.from_dict(raw)
    assert len(corpus.groups) == 1
    term = corpus.groups[0].canonical_term
    assert term.width == 32
    assert term_fingerprint(term) == corpus.groups[0].fingerprint
    masked = TypedBvTerm(
        "and",
        32,
        children=(
            TypedBvTerm(None, 32, leaf_key=("register", "v135")),
            TypedBvTerm(None, 32, value=0xFFFFFBFB),
        ),
    )
    assert sum(node == masked for node in _walk(term)) == 4
    atomized = atomize_repeated_subterms(term)
    assert atomized.bindings[0].original_subterm == masked
    statuses = {outcome.status.value for item in corpus.observations for outcome in item.outcomes}
    assert statuses == {"unchanged", "over_budget"}


def _walk(term: object):
    yield term
    for child in term.children:  # type: ignore[union-attr]
        yield from _walk(child)


def _tree_snapshot(root: Path) -> dict[str, tuple[object, ...]]:
    snapshot: dict[str, tuple[object, ...]] = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        stat = path.lstat()
        if path.is_symlink():
            snapshot[relative] = ("symlink", os.readlink(path))
        elif path.is_dir():
            snapshot[relative] = ("directory", stat.st_mode)
        else:
            snapshot[relative] = ("file", path.read_bytes())
    return snapshot


def test_cli_generates_three_deterministic_artifacts_and_complete_proof_receipt(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    assert _run(first).returncode == 0
    assert _run(second).returncode == 0
    first_files = sorted(path.name for path in first.iterdir())
    second_files = sorted(path.name for path in second.iterdir())
    assert first_files == second_files
    assert first_files and all(name.endswith((".proposal.json", ".rule.py", ".fixture.json")) for name in first_files)
    assert {name for name in first_files if name.endswith(".proposal.json")}
    assert (next(first.glob("*.rule.py")).read_bytes() == next(second.glob("*.rule.py")).read_bytes())
    assert (next(first.glob("*.fixture.json")).read_bytes() == next(second.glob("*.fixture.json")).read_bytes())
    proposal = json.loads(next(first.glob("*.proposal.json")).read_text())
    proposal2 = json.loads(next(second.glob("*.proposal.json")).read_text())
    elapsed = [row["elapsed_ms"] for row in proposal["proof_receipts"]]
    assert all(type(value) is float and value > 0 for value in elapsed)
    for manifest in (proposal, proposal2):
        for receipt in manifest["proof_receipts"]:
            receipt.pop("elapsed_ms")
    assert proposal == proposal2
    assert len(proposal["proof_receipts"]) == 4
    assert [row["width"] for row in proposal["proof_receipts"]] == [8, 16, 32, 64]
    assert all(type(row["verdict"]) is bool for row in proposal["proof_receipts"])
    assert all(type(row["counterexample"]) is (dict if row["counterexample"] is not None else type(None)) for row in proposal["proof_receipts"])
    assert all(row["error"] is None for row in proposal["proof_receipts"])
    receipt = proposal["attempt_provenance"]
    assert set(receipt) == {"budget", "candidate_attempts", "generated_terms", "retained_terms", "witness_identity", "selected_candidate_fingerprint", "selected_candidate_rank", "completion_reason"}
    assert receipt["budget"]["max_candidate_attempts"] == 100_000
    assert receipt["candidate_attempts"] > 0
    assert receipt["generated_terms"] == receipt["retained_terms"]
    from d810.mba.term_codec import typed_term_from_dict
    from d810.mba.typed_term import term_fingerprint
    assert receipt["selected_candidate_fingerprint"] == term_fingerprint(
        typed_term_from_dict(proposal["replacement"])
    )
    assert receipt["selected_candidate_rank"] < receipt["retained_terms"]
    assert len(receipt["witness_identity"]) == 64
    assert receipt["completion_reason"] == "certified_candidate"
    fixture = json.loads(next(first.glob("*.fixture.json")).read_text())
    assert {"original", "atomized", "certified_atomized_replacement", "restored_replacement"} <= set(fixture)


def test_artifact_contract_is_exact_and_recomputable(tmp_path: Path) -> None:
    assert _run(tmp_path).returncode == 0
    files = {path.name for path in tmp_path.iterdir()}
    stems = {name.rsplit(".", 2)[0] for name in files}
    assert len(stems) == 1
    stem = next(iter(stems))
    assert re.fullmatch(r"[0-9a-f]{64}", stem)
    assert files == {f"{stem}.proposal.json", f"{stem}.rule.py", f"{stem}.fixture.json"}
    proposal = json.loads((tmp_path / f"{stem}.proposal.json").read_text())
    fixture = json.loads((tmp_path / f"{stem}.fixture.json").read_text())
    from d810.mba.bounded_synthesis import ProofReceipt
    from d810.mba.rule_proposal import proposal_fingerprint
    from d810.mba.subterm_atomization import MbaAtomBinding
    from d810.mba.term_codec import typed_term_from_dict
    from d810.mba.typed_term import TypedBvTerm, canonicalize_ac_term, term_fingerprint

    binding_values = tuple(
        MbaAtomBinding(
            leaf_key=tuple(row["leaf_key"]),
            original_subterm=typed_term_from_dict(row["original_subterm"]),
            occurrence_count=row["occurrence_count"],
            saved_operator_nodes=row["saved_operator_nodes"],
        )
        for row in proposal["atomization_bindings"]
    )
    proof_values = tuple(
        ProofReceipt(
            width=row["width"],
            verdict=row["verdict"],
            elapsed_ms=row["elapsed_ms"],
            counterexample=row["counterexample"],
            error=row["error"],
        )
        for row in proposal["proof_receipts"]
    )
    identity = proposal_fingerprint(
        source_fingerprints=tuple(proposal["source_fingerprints"]),
        occurrence_count=proposal["occurrence_count"],
        pattern=typed_term_from_dict(proposal["pattern"]),
        replacement=typed_term_from_dict(proposal["replacement"]),
        source_cost=tuple(proposal["source_cost"]),
        replacement_cost=tuple(proposal["replacement_cost"]),
        atomization_bindings=binding_values,
        proof_receipts=proof_values,
        class_name=proposal["class_name"],
        family=proposal["family"],
        description=proposal["description"],
        provenance=tuple(proposal["provenance"]),
        fixture=proposal["fixture"],
        width_relative_all_ones=(),
        fixed_operation_descriptors=tuple(tuple(item) for item in proposal["fixed_operation_descriptors"]),
    )
    assert identity == proposal["proposal_fingerprint"] == stem
    assert typed_term_from_dict(fixture["original"]).width == 32
    restored = typed_term_from_dict(fixture["restored_replacement"])
    expected = canonicalize_ac_term(
        TypedBvTerm(
            "or",
            32,
            children=(
                TypedBvTerm(None, 32, leaf_key=("register", "v17")),
                TypedBvTerm(
                    "and",
                    32,
                    children=(
                        TypedBvTerm(None, 32, leaf_key=("register", "v135")),
                        TypedBvTerm(None, 32, value=0xFFFFFBFB),
                    ),
                ),
            ),
        )
    )
    assert term_fingerprint(canonicalize_ac_term(restored)) == term_fingerprint(expected)
    source = (tmp_path / f"{stem}.rule.py").read_text()
    ast.parse(source)
    executed = subprocess.run(
        [sys.executable, "-c", "import sys; exec(compile(sys.stdin.read(), '<proposal>', 'exec'), {})"],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        input=source,
        text=True,
        capture_output=True,
        check=False,
    )
    assert executed.returncode == 0, executed.stderr


def test_cli_returns_one_for_valid_corpus_without_certifiable_proposal(tmp_path: Path) -> None:
    source = json.loads(FIXTURE.read_text())
    source["groups"] = []
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps(source))
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(empty), "--output-dir", str(tmp_path / "out")],
        cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src")}, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 1
    assert not (tmp_path / "out").exists()


def test_cli_returns_two_for_malformed_input_and_does_not_create_output(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(bad), "--output-dir", str(tmp_path / "out")],
        cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src")}, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 2
    assert not (tmp_path / "out").exists()


def test_cli_refuses_existing_artifacts_without_force(tmp_path: Path) -> None:
    assert _run(tmp_path).returncode == 0
    result = _run(tmp_path)
    assert result.returncode == 2
    assert "force" in (result.stderr + result.stdout).lower()
    assert _run(tmp_path, "--force").returncode == 0


def test_cli_budget_flags_and_group_limit_are_explicit(tmp_path: Path) -> None:
    result = _run(tmp_path, "--max-groups", "0", "--max-generated-terms", "0", "--max-candidate-attempts", "0")
    assert result.returncode == 1
    assert not tmp_path.exists() or not list(tmp_path.iterdir())


def test_cli_has_no_forbidden_runtime_imports() -> None:
    source = SCRIPT.read_text() if SCRIPT.exists() else ""
    for module in ("idaapi", "ida_hexrays", "d810_cobra", "d810_egglog"):
        assert f"import {module}" not in source
        assert f"from {module}" not in source


def test_cli_atomic_write_cleanup_on_simulated_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    if not SCRIPT.exists():
        pytest.fail("CLI module must exist")
    import importlib.util

    spec = importlib.util.spec_from_file_location("mba_residual_rule_miner", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "_atomic_write", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("simulated")))
    output = tmp_path / "fresh-output"
    assert module.main(["--input", str(FIXTURE), "--output-dir", str(output)]) == 2
    assert not output.exists()
    assert not list(output.parent.glob(f".{output.name}.*"))


@pytest.mark.parametrize("fail_at", (2, 3))
@pytest.mark.parametrize("populated", (False, True))
@pytest.mark.parametrize("preexisting", (False, True))
def test_publication_failure_restores_preinvocation_tree(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fail_at: int,
    populated: bool,
    preexisting: bool,
) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("mba_residual_rule_miner_txn", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "existing"
    if preexisting:
        output.mkdir()
        if populated:
            (output / "unrelated.txt").write_bytes(b"keep me")
        before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    else:
        before = None
    original = module._atomic_write
    calls = 0

    def fail_stage(path: Path, content: str) -> None:
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise OSError("stage failure")
        original(path, content)

    monkeypatch.setattr(module, "_atomic_write", fail_stage)
    assert module.main(["--input", str(FIXTURE), "--output-dir", str(output), "--force"]) == 2
    if preexisting:
        after = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
        assert after == before
    else:
        assert not output.exists()
    assert not list(tmp_path.glob(".existing.*"))


@pytest.mark.parametrize("fail_at", (1, 2))
def test_publication_failure_rolls_back_populated_force_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fail_at: int
) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("mba_residual_rule_miner_publish", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "existing"
    output.mkdir()
    (output / "unrelated.txt").write_bytes(b"keep me")
    before = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    original = module._publish_replace
    calls = 0

    def fail_publish(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise OSError("publish failure")
        original(source, destination)

    monkeypatch.setattr(module, "_publish_replace", fail_publish)
    assert module.main(["--input", str(FIXTURE), "--output-dir", str(output), "--force"]) == 2
    after = {path.relative_to(output): path.read_bytes() for path in output.rglob("*") if path.is_file()}
    assert after == before
    assert not list(tmp_path.glob(".existing.*"))


def test_partial_stage_copy_failure_preserves_exact_live_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("mba_residual_rule_miner_copy", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "existing"
    output.mkdir()
    (output / "keep.txt").write_bytes(b"keep")
    (output / "nested").mkdir()
    (output / "nested" / "keep.txt").write_bytes(b"nested")
    (output / "link").symlink_to("keep.txt")
    before = _tree_snapshot(output)

    def fail_copy(source: Path, destination: Path) -> None:
        assert source == output
        destination.mkdir()
        (destination / "partial.txt").write_bytes(b"partial")
        raise OSError("partial stage copy failure")

    monkeypatch.setattr(module, "_copy_tree", fail_copy)
    result = module.main(
        ["--input", str(FIXTURE), "--output-dir", str(output), "--force"]
    )
    assert result == 2
    assert _tree_snapshot(output) == before
    assert not list(tmp_path.glob(".existing.*"))


def test_rollback_failure_retains_exact_recovery_backup(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("mba_residual_rule_miner_rollback", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "existing"
    output.mkdir()
    (output / "keep.txt").write_bytes(b"keep")
    before = _tree_snapshot(output)
    original = module._publish_replace
    calls = 0

    def fail_publication(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls in (2, 3):
            raise OSError("injected publication/rollback failure")
        original(source, destination)

    monkeypatch.setattr(module, "_publish_replace", fail_publication)
    result = module.main(
        ["--input", str(FIXTURE), "--output-dir", str(output), "--force"]
    )
    assert result == 2
    assert not output.exists()
    backups = sorted(tmp_path.glob(".existing.backup-*"))
    assert len(backups) == 1
    assert _tree_snapshot(backups[0]) == before
    assert str(backups[0]) in capsys.readouterr().err


def test_success_preserves_unrelated_symlink_tree_shape(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    (output / "keep.txt").write_bytes(b"keep")
    (output / "link").symlink_to("keep.txt")
    assert _run(output, "--force").returncode == 0
    assert (output / "keep.txt").read_bytes() == b"keep"
    assert (output / "link").is_symlink()
    assert os.readlink(output / "link") == "keep.txt"


@pytest.mark.parametrize(
    "duplicate",
    (
        "corpus",
        "term",
        "source",
        "outcome",
        "metadata",
    ),
)
def test_cli_rejects_duplicate_json_members_at_every_boundary(tmp_path: Path, duplicate: str) -> None:
    if duplicate == "corpus":
        payload = '{"schema_version":1,"schema_version":1,"groups":[]}'
    else:
        payload = FIXTURE.read_text()
        field = {
            "term": '"width":32',
            "source": '"case_id":"fixture-residual"',
            "outcome": '"provider":"catalogue"',
            "metadata": '"fixture":"residual_or_masked_subterm"',
        }[duplicate]
        payload = payload.replace(field, field + "," + field, 1)
    source = tmp_path / "duplicate.json"
    source.write_text(payload)
    output = tmp_path / "out"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(source), "--output-dir", str(output)],
        cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src")}, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 2
    assert not output.exists()


def test_cli_rejects_nonfinite_json_constants(tmp_path: Path) -> None:
    source = tmp_path / "nan.json"
    source.write_text('{"schema_version":1,"groups":[],"metadata":NaN}')
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(source), "--output-dir", str(tmp_path / "out")],
        cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src")}, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 2


def test_cli_corpus_reader_reuses_public_strict_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("mba_residual_rule_miner_decoder", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls: list[str] = []
    original = module.MbaResidualCorpus.from_json

    def decode(value: str):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(module.MbaResidualCorpus, "from_json", decode)
    corpus = module._read_corpus(FIXTURE)

    assert corpus.groups
    assert calls == [FIXTURE.read_text(encoding="utf-8")]


@pytest.mark.parametrize("artifact", ("manifest", "fixture"))
def test_artifact_serializer_rejects_nonfinite_json_without_publication(
    artifact: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("mba_residual_rule_miner_strict", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "render_rule_source", lambda _proposal: "")
    payload = {
        "manifest": {"proof_receipts": [{"elapsed_ms": 0.0}]},
        "fixture": {"proof_widths": [8, 16, 32, 64]},
    }
    payload[artifact] = {"invalid_timing": float("nan")}
    proposal = SimpleNamespace(fingerprint="f" * 64)
    output = tmp_path / "out"

    with pytest.raises(ValueError, match="Out of range float values"):
        module._render_outputs(output, [(proposal, payload)], force=False)
    assert not output.exists()


def test_non_or_certifiable_group_gets_deterministic_non_or_family(tmp_path: Path) -> None:
    from d810.mba.provider_outcome import (
        MbaProviderKind,
        MbaProviderOutcome,
        ProviderOutcomeStatus,
    )
    from d810.mba.residual_corpus import (
        MbaResidualCorpus,
        MbaResidualObservation,
        MbaResidualSource,
    )
    from d810.mba.typed_term import TypedBvTerm

    source_term = TypedBvTerm("bnot", 32, children=(TypedBvTerm(None, 32, value=0),))
    observation = MbaResidualObservation(
        1,
        MbaResidualSource("non-or", "unit", 0x401000, 0x401001, "MMAT_BUILT"),
        source_term,
        (MbaProviderOutcome(MbaProviderKind.CATALOGUE, ProviderOutcomeStatus.UNCHANGED, "non-or"),),
    )
    corpus_path = tmp_path / "non-or.json"
    corpus_path.write_text(MbaResidualCorpus((observation,)).to_json())
    output = tmp_path / "out"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--input", str(corpus_path), "--output-dir", str(output)],
        cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src")}, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 0
    manifest = json.loads(next(output.glob("*.proposal.json")).read_text())
    assert manifest["family"] == "bnot"
    assert manifest["family"] != "or"


def test_cli_returns_two_when_proof_backend_is_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("mba_residual_rule_miner_unavailable", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from d810.mba import bounded_synthesis

    def unavailable(*args: object, **kwargs: object) -> object:
        raise ImportError("z3 backend unavailable")

    monkeypatch.setattr(bounded_synthesis, "verify_transformation", unavailable)
    output = tmp_path / "unavailable"
    assert module.main(["--input", str(FIXTURE), "--output-dir", str(output)]) == 2
    assert not output.exists()
