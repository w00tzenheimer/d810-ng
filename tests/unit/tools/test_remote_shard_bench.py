"""Unit coverage for the remote sharding wall-time bench."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "tools" / "scripts" / "remote_shard_bench.py"


def _load_module():
    specification = importlib.util.spec_from_file_location(
        "remote_shard_bench", MODULE_PATH
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


bench = _load_module()


def test_shard_assignment_parses_worktree_and_ids() -> None:
    assert bench.parse_shard_assignment("wt=a::b, c::d") == ("wt", ("a::b", "c::d"))


@pytest.mark.parametrize("specification", ["no-equals", "=a::b", "wt=", "wt=,"])
def test_shard_assignment_rejects_malformed_input(specification: str) -> None:
    with pytest.raises(ValueError):
        bench.parse_shard_assignment(specification)


def test_shards_are_numbered_and_worktrees_unique() -> None:
    shards = bench.build_shards(["a=t::1", "b=t::2"])

    assert [shard.index for shard in shards] == [0, 1]
    assert [shard.output_name for shard in shards] == ["shard-0.txt", "shard-1.txt"]

    with pytest.raises(ValueError, match="one run per worktree"):
        bench.build_shards(["a=t::1", "a=t::2"])

    with pytest.raises(ValueError):
        bench.build_shards([])


def test_shard_command_matches_the_runner_contract() -> None:
    command = bench.build_shard_command(
        "/r/run.sh",
        remote="host",
        worktree="wt",
        output_name="shard-0.txt",
        test_ids=["t::a", "t::b"],
    )

    assert command == [
        "/r/run.sh",
        "test",
        "--remote",
        "host",
        "-w",
        "wt",
        "-o",
        "shard-0.txt",
        "--",
        "t::a",
        "t::b",
        "-q",
    ]


def test_local_baseline_command_omits_the_remote_flag() -> None:
    command = bench.build_shard_command(
        "/r/run.sh",
        remote=None,
        worktree="wt",
        output_name="shard-baseline.txt",
        test_ids=["t::a"],
    )

    assert "--remote" not in command
    assert command[:2] == ["/r/run.sh", "test"]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("1 passed in 12.34s\n", "1 passed in 12.34s"),
        ("==== 2 passed, 1 warning in 3.00s ====", "2 passed, 1 warning in 3.00s"),
        ("1 failed, 1 passed in 9.0s", "1 failed, 1 passed in 9.0s"),
        ("noise\n1 passed in 1.0s\nmore noise\n2 passed in 2.0s\n", "2 passed in 2.0s"),
        ("collected nothing", None),
        ("", None),
    ],
)
def test_pytest_summary_extraction(text: str, expected: str | None) -> None:
    assert bench.extract_pytest_summary(text) == expected


@pytest.mark.parametrize(
    "summary,green",
    [
        ("1 passed in 1.0s", True),
        ("1 failed, 1 passed in 1.0s", False),
        ("1 failed in 1.0s", False),
        (None, False),
    ],
)
def test_green_shard_requires_a_passing_summary(summary: str | None, green: bool) -> None:
    assert bench.summary_is_green(summary) is green


def _result(
    index: int,
    seconds: float,
    summary: str | None = "1 passed in 1.0s",
    revision: str | None = "abc1234def56",
):
    shard = bench.Shard(index=index, worktree=f"wt{index}", test_ids=("t::a",))
    return bench.ShardResult(
        shard=shard,
        seconds=seconds,
        returncode=0,
        summary=summary,
        revision=revision,
    )


def test_aggregate_reports_overhead_and_speedup() -> None:
    summary = bench.aggregate(
        [_result(0, 100.0), _result(1, 80.0)],
        parallel_wall=104.0,
        baseline_wall=182.0,
        baseline_label="remote-sequential",
        baseline_summary="2 passed in 170.0s",
    )

    assert summary.slowest_shard == 100.0
    assert summary.launch_overhead == pytest.approx(4.0)
    assert summary.speedup == pytest.approx(182.0 / 104.0)


def test_aggregate_without_a_baseline_reports_no_speedup() -> None:
    summary = bench.aggregate(
        [_result(0, 10.0)],
        parallel_wall=11.0,
        baseline_wall=None,
        baseline_label="none",
        baseline_summary=None,
    )

    assert summary.speedup is None

    with pytest.raises(ValueError):
        bench.aggregate(
            [], parallel_wall=1.0, baseline_wall=None, baseline_label="none",
            baseline_summary=None,
        )


def test_table_uses_minimal_separators_and_no_box_drawing() -> None:
    summary = bench.aggregate(
        [_result(0, 100.0), _result(1, 80.0, None)],
        parallel_wall=104.0,
        baseline_wall=182.0,
        baseline_label="remote-sequential",
        baseline_summary="2 passed in 170.0s",
    )

    table = bench.render_table(summary)

    assert "|-|-|-|-|-|-|-|" in table
    assert "|---" not in table
    assert not set(table) & set("┌┬─│└┘├┤┼")
    assert "|1|wt1|abc1234def56|1|80.0|0|MISSING|" in table
    assert "|speedup (baseline / parallel)|1.75x|" in table


def test_missing_summary_makes_the_bench_fail(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / ".worktrees" / "wt0" / ".tmp"
    worktree.mkdir(parents=True)
    (worktree / "shard-0.txt").write_text("collected 1 item\n", encoding="utf-8")

    monkeypatch.setattr(
        bench,
        "run_commands_concurrently",
        lambda commands, cwd, env: ([(1.0, 0)], 1.5),
    )
    monkeypatch.setattr(
        bench, "read_source_state", lambda worktree_dir: ("dig0", False)
    )

    status = bench.main(
        [
            "--remote",
            "host",
            "--shard",
            "wt0=tests/system/e2e/x.py::a",
            "--baseline",
            "none",
            "--repo-root",
            str(tmp_path),
        ]
    )
    printed = capsys.readouterr().out

    assert status == 1
    assert "produced no passing summary" in printed


def test_green_shard_output_makes_the_bench_pass(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worktree = tmp_path / ".worktrees" / "wt0" / ".tmp"
    worktree.mkdir(parents=True)

    def _launch(commands, cwd, env):
        (worktree / "shard-0.txt").write_text("1 passed in 42.00s\n", encoding="utf-8")
        return [(50.0, 0)], 51.0

    monkeypatch.setattr(bench, "run_commands_concurrently", _launch)
    monkeypatch.setattr(bench, "read_source_state", lambda worktree_dir: ("dig0", False))

    status = bench.main(
        [
            "--remote",
            "host",
            "--shard",
            "wt0=tests/system/e2e/x.py::a",
            "--baseline",
            "none",
            "--repo-root",
            str(tmp_path),
        ]
    )
    printed = capsys.readouterr().out

    assert status == 0
    assert "1 passed in 42.00s" in printed
    assert "|launch overhead (s)|1.0|" in printed


def test_dry_run_prints_the_planned_commands_only(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("--dry-run must not launch containers")

    monkeypatch.setattr(bench, "run_commands_concurrently", _fail)

    status = bench.main(
        [
            "--remote",
            "host",
            "--shard",
            "wt0=t::a",
            "--shard",
            "wt1=t::b",
            "--dry-run",
            "--repo-root",
            str(tmp_path),
        ]
    )
    printed = capsys.readouterr().out.splitlines()

    assert status == 0
    assert len(printed) == 3
    assert printed[0].endswith("-w wt0 -o shard-0.txt -- t::a -q")
    assert printed[1].endswith("-w wt1 -o shard-1.txt -- t::b -q")
    assert printed[2].endswith("-w wt0 -o shard-baseline.txt -- t::a t::b -q")


def test_runner_defaults_beside_this_script_not_under_repo_root(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The root checkout's runner may predate --remote; -w only moves sources."""
    status = bench.main(
        [
            "--remote",
            "host",
            "--shard",
            "wt0=t::a",
            "--baseline",
            "none",
            "--dry-run",
            "--repo-root",
            str(tmp_path),
        ]
    )
    printed = capsys.readouterr().out.strip()

    assert status == 0
    assert printed.startswith(str(bench.default_runner()))
    assert str(tmp_path) not in printed.split(" ")[0]
    assert bench.default_runner() == MODULE_PATH.parent / "run_system_tests_docker.sh"


def test_explicit_runner_is_honored(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runner = tmp_path / "custom-runner.sh"
    runner.write_text("", encoding="utf-8")

    status = bench.main(
        [
            "--remote",
            "host",
            "--shard",
            "wt0=t::a",
            "--baseline",
            "none",
            "--dry-run",
            "--runner",
            str(runner),
            "--repo-root",
            str(tmp_path),
        ]
    )
    printed = capsys.readouterr().out.strip()

    assert status == 0
    assert printed.startswith(str(runner))


def _stub_run(monkeypatch: pytest.MonkeyPatch, measurements, wall, revisions=None):
    monkeypatch.setattr(
        bench, "run_commands_concurrently", lambda commands, cwd, env: (measurements, wall)
    )
    lookup = revisions or {}
    monkeypatch.setattr(
        bench,
        "read_source_state",
        lambda worktree_dir: (lookup.get(worktree_dir.name, "dig0"), False),
    )


def _worktree(tmp_path: Path, name: str) -> Path:
    directory = tmp_path / ".worktrees" / name / ".tmp"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


@pytest.mark.parametrize(
    "counts,green",
    [
        ("1 passed in 1.0s", True),
        ("1 failed, 1 passed in 1.0s", False),
        ("2 errors in 1.0s", False),
        ("1 error in 1.0s", False),
        ("3 skipped in 1.0s", False),
        ("1 passed, 2 warnings in 1.0s", True),
    ],
)
def test_summary_counts_decide_greenness(counts: str, green: bool) -> None:
    assert bench.summary_is_green(counts) is green


def test_stale_output_is_deleted_before_launch(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A previous run's green capture must never stand in for this run."""
    directory = _worktree(tmp_path, "wt0")
    (directory / "shard-0.txt").write_text("1 passed in 42.00s\n", encoding="utf-8")

    _stub_run(monkeypatch, [(5.0, 0)], 5.5)

    status = bench.main(
        [
            "--remote", "host", "--shard", "wt0=t::a",
            "--baseline", "none", "--repo-root", str(tmp_path),
        ]
    )
    printed = capsys.readouterr().out

    assert status == 1
    assert "no passing summary" in printed
    assert not (directory / "shard-0.txt").exists()


def test_nonzero_runner_exit_fails_even_with_a_green_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _worktree(tmp_path, "wt0")

    def _launch(commands, cwd, env):
        (directory / "shard-0.txt").write_text("1 passed in 42.00s\n", encoding="utf-8")
        return [(5.0, 23)], 5.5

    monkeypatch.setattr(bench, "run_commands_concurrently", _launch)
    monkeypatch.setattr(bench, "read_source_state", lambda worktree_dir: ("dig0", False))

    status = bench.main(
        [
            "--remote", "host", "--shard", "wt0=t::a",
            "--baseline", "none", "--repo-root", str(tmp_path),
        ]
    )
    printed = capsys.readouterr().out

    assert status == 1
    assert "runner exited 23" in printed


def test_mixed_revisions_fail_unless_allowed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("wt0", "wt1"):
        _worktree(tmp_path, name)

    def _launch(commands, cwd, env):
        for index, name in enumerate(("wt0", "wt1")):
            (tmp_path / ".worktrees" / name / ".tmp" / f"shard-{index}.txt").write_text(
                "1 passed in 1.00s\n", encoding="utf-8"
            )
        return [(5.0, 0), (6.0, 0)], 6.5

    monkeypatch.setattr(bench, "run_commands_concurrently", _launch)
    monkeypatch.setattr(
        bench,
        "read_source_state",
        lambda worktree_dir: (
            ("aaaa111", False) if worktree_dir.name == "wt0" else ("bbbb222", False)
        ),
    )

    arguments = [
        "--remote", "host", "--shard", "wt0=t::a", "--shard", "wt1=t::b",
        "--baseline", "none", "--repo-root", str(tmp_path),
    ]

    assert bench.main(arguments) == 1
    assert "mixed revisions" in capsys.readouterr().out

    assert bench.main([*arguments, "--allow-mixed-revisions"]) == 0
    assert "aaaa111" in capsys.readouterr().out


def test_unknown_revision_fails_closed(tmp_path: Path) -> None:
    assert bench.revision_conflict(["a", None], False) is not None
    assert bench.revision_conflict(["a", None], True) is None
    assert bench.build_revision_argv(tmp_path)[-1] == "HEAD"


def test_failing_baseline_fails_the_bench(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _worktree(tmp_path, "wt0")

    def _launch(commands, cwd, env):
        (directory / "shard-0.txt").write_text("1 passed in 1.00s\n", encoding="utf-8")
        return [(5.0, 0)], 5.5

    class _Completed:
        returncode = 7

    monkeypatch.setattr(bench, "run_commands_concurrently", _launch)
    monkeypatch.setattr(bench, "read_source_state", lambda worktree_dir: ("dig0", False))
    monkeypatch.setattr(bench.subprocess, "run", lambda *a, **k: _Completed())

    status = bench.main(
        [
            "--remote", "host", "--shard", "wt0=t::a",
            "--repo-root", str(tmp_path),
        ]
    )
    printed = capsys.readouterr().out

    assert status == 1
    assert "baseline runner exited 7" in printed
    assert "baseline produced no passing summary" in printed


def test_source_digest_covers_uncommitted_and_untracked_content() -> None:
    base = bench.compute_source_digest("abc", "", "", [])

    assert bench.compute_source_digest("abc", "", "", []) == base
    assert bench.compute_source_digest("abd", "", "", []) != base
    assert bench.compute_source_digest("abc", " M src/x.py", "", []) != base
    assert bench.compute_source_digest("abc", "", "@@ -1 +1 @@", []) != base
    assert bench.compute_source_digest("abc", "", "", [("new.py", b"x")]) != base
    assert bench.compute_source_digest("abc", "", "", [("new.py", b"x")]) != (
        bench.compute_source_digest("abc", "", "", [("new.py", b"y")])
    )
    assert bench.build_porcelain_argv(Path("/w"))[3:] == [
        "status", "--porcelain=v1", "-z",
    ]
    assert bench.build_untracked_argv(Path("/w"))[3:] == [
        "ls-files", "--others", "--exclude-standard", "-z",
    ]


def test_dirty_worktree_is_refused_unless_allowed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = _worktree(tmp_path, "wt0")

    def _launch(commands, cwd, env):
        (directory / "shard-0.txt").write_text("1 passed in 1.00s\n", encoding="utf-8")
        return [(5.0, 0)], 5.5

    monkeypatch.setattr(bench, "run_commands_concurrently", _launch)
    monkeypatch.setattr(
        bench, "read_source_state", lambda worktree_dir: ("dirtydigest", True)
    )

    arguments = [
        "--remote", "host", "--shard", "wt0=t::a",
        "--baseline", "none", "--repo-root", str(tmp_path),
    ]

    assert bench.main(arguments) == 1
    printed = capsys.readouterr().out
    assert "uncommitted or untracked changes" in printed
    assert "--allow-dirty" in printed
    assert not (directory / "shard-0.txt").exists()

    assert bench.main([*arguments, "--allow-dirty"]) == 0
    assert "dirtydigest" in capsys.readouterr().out


def test_failed_arm_never_prints_a_ratio(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plausible speedup above an error is the reporting failure to avoid."""
    directory = _worktree(tmp_path, "wt0")

    def _launch(commands, cwd, env):
        (directory / "shard-0.txt").write_text("1 passed in 1.00s\n", encoding="utf-8")
        return [(5.0, 0)], 5.5

    class _Completed:
        returncode = 7

    monkeypatch.setattr(bench, "run_commands_concurrently", _launch)
    monkeypatch.setattr(
        bench, "read_source_state", lambda worktree_dir: ("dig0", False)
    )
    monkeypatch.setattr(bench.subprocess, "run", lambda *a, **k: _Completed())

    status = bench.main(
        ["--remote", "host", "--shard", "wt0=t::a", "--repo-root", str(tmp_path)]
    )
    printed = capsys.readouterr().out

    assert status == 1
    assert "|speedup (baseline / parallel)|invalid|" in printed
    assert "x|" not in printed.split("speedup")[1][:20]
    table_index = printed.index("|speedup")
    error_index = printed.index("ERROR:")
    assert table_index < error_index


def test_doctests_pass() -> None:
    import doctest

    results = doctest.testmod(bench, verbose=False)
    assert results.failed == 0, results
