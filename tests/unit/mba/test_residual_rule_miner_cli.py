"""Offline residual miner CLI contract tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

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


def test_cli_generates_three_deterministic_artifacts_and_complete_proof_receipt(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    assert _run(first).returncode == 0
    assert _run(second).returncode == 0
    first_files = sorted(path.name for path in first.iterdir())
    second_files = sorted(path.name for path in second.iterdir())
    assert first_files == second_files
    assert first_files and all(name.endswith((".proposal.json", ".rule.py", ".fixture.json")) for name in first_files)
    assert {name for name in first_files if name.endswith(".proposal.json")}
    assert [path.read_bytes() for path in sorted(first.iterdir())] == [path.read_bytes() for path in sorted(second.iterdir())]
    proposal = json.loads(next(first.glob("*.proposal.json")).read_text())
    assert len(proposal["proof_receipts"]) == 4
    assert [row["width"] for row in proposal["proof_receipts"]] == [8, 16, 32, 64]
    assert "exhaustion" in proposal and "attempt" in json.dumps(proposal).lower()
    fixture = json.loads(next(first.glob("*.fixture.json")).read_text())
    assert {"original", "atomized", "certified_atomized_replacement", "restored_replacement"} <= set(fixture)


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
