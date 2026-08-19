from types import SimpleNamespace

from tests.system.e2e.egglog_native_profile import (
    build_native_egglog_profile,
    profile_native_egglog_cprofile,
)


def test_native_egglog_profile_keeps_outcomes_and_partial_stages_separate():
    stats = SimpleNamespace(
        rule_execution_log=(
            SimpleNamespace(
                rule_name="EgglogOptimizer",
                metadata={
                    "skip_reason": None,
                    "source_names": ("Add_HackersDelightRule_2",),
                    "stage_timings_ms": {"root_eligibility": 1.0},
                },
            ),
            SimpleNamespace(
                rule_name="EgglogOptimizer",
                metadata={
                    "skip_reason": "proof_failed",
                    "stage_timings_ms": {
                        "root_eligibility": 2.0,
                        "ast_construction": 3.0,
                    },
                },
            ),
            SimpleNamespace(rule_name="OtherRule", metadata={}),
        )
    )

    assert build_native_egglog_profile(stats, corpus="fixture") == {
        "corpus": "fixture",
        "execution_count": 2,
        "outcomes": {"accepted": 1, "proof_failed": 1},
        "source_names": [["Add_HackersDelightRule_2"]],
        "stage_sample_counts": {"ast_construction": 1, "root_eligibility": 2},
        "stage_timing_ms": {
            "ast_construction": {"p50_ms": 3.0, "p95_ms": 3.0, "max_ms": 3.0},
            "root_eligibility": {"p50_ms": 1.5, "p95_ms": 1.95, "max_ms": 2.0},
        },
    }


def test_native_egglog_cprofile_is_opt_in_and_writes_one_artifact(
    tmp_path, monkeypatch, capsys
):
    observed: list[str] = []
    monkeypatch.setenv("D810_EGGLOG_CPROFILE_DIR", str(tmp_path))
    monkeypatch.setenv("D810_CYTHON_PROFILE", "1")

    result = profile_native_egglog_cprofile(
        "fixture-corpus", lambda: observed.append("ran") or 42
    )

    assert result == 42
    assert observed == ["ran"]
    profile = tmp_path / "fixture-corpus.prof"
    assert profile.exists()
    assert profile.stat().st_size > 0
    output = capsys.readouterr().out
    assert '"corpus": "fixture-corpus"' in output
    assert '"cython_trace_requested": true' in output


def test_native_egglog_cprofile_does_not_allocate_without_an_artifact_dir(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("D810_EGGLOG_CPROFILE_DIR", raising=False)

    assert profile_native_egglog_cprofile("fixture", lambda: "result") == "result"
    assert not tuple(tmp_path.iterdir())
