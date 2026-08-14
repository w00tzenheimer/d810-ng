from types import SimpleNamespace

from tests.system.e2e.egglog_native_profile import build_native_egglog_profile


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
                    "skip_reason": "native_z3_failed",
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
        "outcomes": {"accepted": 1, "native_z3_failed": 1},
        "source_names": [["Add_HackersDelightRule_2"]],
        "stage_sample_counts": {"ast_construction": 1, "root_eligibility": 2},
    }
