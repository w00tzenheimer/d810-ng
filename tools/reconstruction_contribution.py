#!/usr/bin/env python3
"""Reconstruction-technique contribution harness.

Runs the Hodur dump end-to-end multiple times with different combinations of
``D810_RECON_SKIP_*`` gates set and reports a comparison matrix. This lets us
measure what each reconstruction.py technique contributes to the unflattened
output so that when we port a technique into SSR we can verify equivalence
(SSR-with-ported-technique + reconstruction-without-that-technique should
match the all-techniques-enabled baseline).

Scenarios are named so they survive across sessions::

    baseline                    all techniques enabled (control)
    no_frontier                 D810_RECON_SKIP_FRONTIER=1
    no_force_edge               D810_RECON_SKIP_FORCE_EDGE=1
    no_narrow_branch_local      D810_RECON_SKIP_NARROW_BRANCH_LOCAL=1
    ssr_only                    reconstruction.py unregistered (manual; not
                                driven by env gates — see comment below)

Typical invocation from the worktree root::

    tools/reconstruction_contribution.py \
        --function sub_7FFD3338C040 \
        --project hodur_flag2.json \
        --scenario baseline,no_frontier,no_force_edge,no_narrow_branch_local

The script shells out to ``tools/scripts/run_system_tests_docker.sh`` with
``-w unflattening-engine-extraction`` so it always reads from the worktree.
It parses the ``=== STATS: <func> ===`` block, captures the ``BEFORE``/
``AFTER`` tuples, and emits a markdown table with per-metric deltas against
``baseline``.
"""

from __future__ import annotations

import argparse
import datetime
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass, field


SCRIPT_PATH = pathlib.Path(__file__).resolve()
# Harness lives at <worktree_root>/tools/reconstruction_contribution.py; the
# worktree is <main_repo>/.worktrees/<name>. Walk up to find the main repo so
# the docker script is invoked the same way cff_debug.py invokes it.
WORKTREE_ROOT = SCRIPT_PATH.parents[1]
WORKTREE_NAME = WORKTREE_ROOT.name
if WORKTREE_ROOT.parent.name == ".worktrees":
    MAIN_REPO_ROOT = WORKTREE_ROOT.parent.parent
else:
    MAIN_REPO_ROOT = WORKTREE_ROOT
DUMP_DIR = WORKTREE_ROOT / ".tmp"
# Prefer the worktree's own docker-script copy because it contains
# recent env-var passthrough additions (D810_RECON_SKIP_*, probe vars) that
# the main-repo copy may be missing until the changes upstream.
_worktree_docker = WORKTREE_ROOT / "tools" / "scripts" / "run_system_tests_docker.sh"
_main_docker = MAIN_REPO_ROOT / "tools" / "scripts" / "run_system_tests_docker.sh"
DOCKER_SCRIPT = _worktree_docker if _worktree_docker.exists() else _main_docker


# Scenario definitions: name -> env-var dict to set to "1"
#
# The `no_primary_*` family of scenarios disables the state-write reconstruction
# primary engine (``execute_primary_reconstruction_modifications``). The
# primary does the bulk of the structural work, which means the post-primary
# fallback techniques (frontier / force-edge / narrow-branch-local) contribute
# nothing visible when primary is on. Disabling primary exposes each fallback's
# real contribution.
SCENARIOS: dict[str, dict[str, str]] = {
    "baseline": {},
    "no_frontier": {"D810_RECON_SKIP_FRONTIER": "1"},
    "no_force_edge": {"D810_RECON_SKIP_FORCE_EDGE": "1"},
    "no_narrow_branch_local": {"D810_RECON_SKIP_NARROW_BRANCH_LOCAL": "1"},
    "no_frontier_and_force_edge": {
        "D810_RECON_SKIP_FRONTIER": "1",
        "D810_RECON_SKIP_FORCE_EDGE": "1",
    },
    "no_reconstruction_techniques": {
        "D810_RECON_SKIP_FRONTIER": "1",
        "D810_RECON_SKIP_FORCE_EDGE": "1",
        "D810_RECON_SKIP_NARROW_BRANCH_LOCAL": "1",
    },
    # Primary-disabled scenarios: exposes fallback contribution in isolation.
    "no_primary": {"D810_RECON_SKIP_PRIMARY": "1"},
    "no_primary_no_frontier": {
        "D810_RECON_SKIP_PRIMARY": "1",
        "D810_RECON_SKIP_FRONTIER": "1",
    },
    "no_primary_no_force_edge": {
        "D810_RECON_SKIP_PRIMARY": "1",
        "D810_RECON_SKIP_FORCE_EDGE": "1",
    },
    "no_primary_no_narrow_branch_local": {
        "D810_RECON_SKIP_PRIMARY": "1",
        "D810_RECON_SKIP_NARROW_BRANCH_LOCAL": "1",
    },
    "no_primary_no_all_fallbacks": {
        "D810_RECON_SKIP_PRIMARY": "1",
        "D810_RECON_SKIP_FRONTIER": "1",
        "D810_RECON_SKIP_FORCE_EDGE": "1",
        "D810_RECON_SKIP_NARROW_BRANCH_LOCAL": "1",
    },
    # SRW-unregistered: StateWriteReconstructionStrategy is removed from the
    # strategy list entirely (no primary, no fallbacks, no postprocess). This
    # is the ONLY clean way to measure SSR-alone output — merely gating the
    # primary inside the strategy leaves postprocess running on an empty
    # contract and floods the CFG with rescue/redirect mods.
    "srw_unregistered": {"D810_RECON_SKIP_SRW_STRATEGY": "1"},
    # Stagger scenarios: disable exactly ONE of the 5 port-list techniques at a
    # time against the full-pipeline baseline. Zero-delta scenarios mean the
    # technique does not fire on this function; negative delta (fewer lines)
    # would mean the technique was adding noise; positive delta means the
    # technique is pulling its weight for this function.
    "no_residual_alias": {"D810_RECON_SKIP_RESIDUAL_ALIAS": "1"},  # technique 1
    "no_missing_via_pred": {"D810_RECON_SKIP_MISSING_VIA_PRED": "1"},  # technique 2
    # no_frontier / no_force_edge above cover techniques 3 and 4
    "no_island_rescue": {"D810_RECON_SKIP_ISLAND_RESCUE": "1"},  # technique 5
    "no_all_5_techniques": {
        "D810_RECON_SKIP_RESIDUAL_ALIAS": "1",
        "D810_RECON_SKIP_MISSING_VIA_PRED": "1",
        "D810_RECON_SKIP_FRONTIER": "1",
        "D810_RECON_SKIP_FORCE_EDGE": "1",
        "D810_RECON_SKIP_ISLAND_RESCUE": "1",
    },
    # SRW-unregistered stagger: each technique gate is set alongside the
    # SRW-strategy unregister. Because the 5 techniques live *inside* SRW's
    # plan() method, any gate here is a no-op — the gated code path never
    # runs. These scenarios exist so the user can verify that SRW-unregistered
    # really is a floor (all scenarios equal srw_unregistered's stats).
    "srw_unregistered_no_residual_alias": {
        "D810_RECON_SKIP_SRW_STRATEGY": "1",
        "D810_RECON_SKIP_RESIDUAL_ALIAS": "1",
    },
    "srw_unregistered_no_missing_via_pred": {
        "D810_RECON_SKIP_SRW_STRATEGY": "1",
        "D810_RECON_SKIP_MISSING_VIA_PRED": "1",
    },
    "srw_unregistered_no_frontier": {
        "D810_RECON_SKIP_SRW_STRATEGY": "1",
        "D810_RECON_SKIP_FRONTIER": "1",
    },
    "srw_unregistered_no_force_edge": {
        "D810_RECON_SKIP_SRW_STRATEGY": "1",
        "D810_RECON_SKIP_FORCE_EDGE": "1",
    },
    "srw_unregistered_no_island_rescue": {
        "D810_RECON_SKIP_SRW_STRATEGY": "1",
        "D810_RECON_SKIP_ISLAND_RESCUE": "1",
    },
}


STATS_RE = re.compile(
    r"^BEFORE:\s*lines=(?P<bl>\d+)\s+returns=(?P<br>\d+)\s+whiles=(?P<bw>\d+)"
    r"\s+gotos=(?P<bg>\d+)\s+calls=(?P<bc>\d+)\s+ifs=(?P<bi>\d+)\s*$"
    r"\s*AFTER:\s*lines=(?P<al>\d+)\s+returns=(?P<ar>\d+)\s+whiles=(?P<aw>\d+)"
    r"\s+gotos=(?P<ag>\d+)\s+calls=(?P<ac>\d+)\s+ifs=(?P<ai>\d+)\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True)
class ScenarioResult:
    name: str
    dump_path: pathlib.Path
    before: tuple[int, int, int, int, int, int]
    after: tuple[int, int, int, int, int, int]
    probe_matches: int = 0
    probe_mismatches: int = 0
    crashes: int = 0
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def delta(self) -> tuple[int, int, int, int, int, int]:
        return tuple(a - b for a, b in zip(self.after, self.before))


def run_scenario(
    name: str,
    env_extra: dict[str, str],
    *,
    function: str,
    project: str,
    timestamp: str,
    enable_probe: bool,
) -> ScenarioResult:
    """Run the docker dump for one scenario and return parsed stats."""
    dump_label = f"recon_contrib_{name}_{timestamp}.txt"
    env = os.environ.copy()
    if enable_probe:
        env["D810_RECON_ROUND_CTX_PROBE"] = "1"
    env.update(env_extra)

    cmd = [
        str(DOCKER_SCRIPT),
        "dump",
        "-w",
        WORKTREE_NAME,
        "-f",
        function,
        "-p",
        project,
        "-o",
        dump_label,
        "-l",
    ]
    print(f"[{name}] running docker dump -> {dump_label}")
    proc = subprocess.run(
        cmd,
        env=env,
        cwd=str(MAIN_REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(proc.stdout[-2000:])
        print(proc.stderr[-2000:], file=sys.stderr)
        raise RuntimeError(
            f"scenario {name!r} failed with exit code {proc.returncode}"
        )

    dump_path = DUMP_DIR / dump_label
    if not dump_path.exists():
        # Fall back to the path the docker script echoes
        m = re.search(r"^DUMP=(\S+)$", proc.stdout, re.MULTILINE)
        if m:
            dump_path = pathlib.Path(m.group(1))
    if not dump_path.exists():
        raise RuntimeError(
            f"scenario {name!r}: dump file not found at {dump_path}"
        )

    text = dump_path.read_text()
    # Locate the STATS block for the requested function
    func_marker = f"=== STATS: {function} ==="
    pos = text.find(func_marker)
    if pos < 0:
        raise RuntimeError(
            f"scenario {name!r}: missing '{func_marker}' in dump"
        )
    m = STATS_RE.search(text, pos)
    if m is None:
        raise RuntimeError(
            f"scenario {name!r}: could not parse STATS block for {function}"
        )
    before = (int(m["bl"]), int(m["br"]), int(m["bw"]), int(m["bg"]), int(m["bc"]), int(m["bi"]))
    after = (int(m["al"]), int(m["ar"]), int(m["aw"]), int(m["ag"]), int(m["ac"]), int(m["ai"]))

    probe_matches = len(re.findall(r"ROUND CTX DAG EQUIV: match=yes", text))
    probe_mismatches = len(re.findall(r"ROUND CTX DAG EQUIV: match=no", text))
    crashes = len(
        re.findall(r"INTERR|segfault|Traceback \(most recent call last\)", text)
    )

    return ScenarioResult(
        name=name,
        dump_path=dump_path,
        before=before,
        after=after,
        probe_matches=probe_matches,
        probe_mismatches=probe_mismatches,
        crashes=crashes,
    )


def format_matrix(results: list[ScenarioResult]) -> str:
    """Emit a markdown table summarising the matrix."""
    if not results:
        return "(no results)"
    baseline = next((r for r in results if r.name == "baseline"), results[0])
    lines: list[str] = []
    lines.append(
        "| scenario | lines | ret | while | goto | call | if | Δlines | Δret | Δwhile | Δgoto | probe✓ | probe✗ | crash |"
    )
    lines.append("|-|-|-|-|-|-|-|-|-|-|-|-|-|-|")
    base_after = baseline.after
    for r in results:
        delta = tuple(a - b for a, b in zip(r.after, base_after))
        lines.append(
            f"| {r.name} | {r.after[0]} | {r.after[1]} | {r.after[2]} | {r.after[3]} | "
            f"{r.after[4]} | {r.after[5]} | "
            f"{delta[0]:+d} | {delta[1]:+d} | {delta[2]:+d} | {delta[3]:+d} | "
            f"{r.probe_matches} | {r.probe_mismatches} | {r.crashes} |"
        )
    # Add BEFORE row as a reference line
    lines.append(
        f"| BEFORE (baseline) | {baseline.before[0]} | {baseline.before[1]} | "
        f"{baseline.before[2]} | {baseline.before[3]} | {baseline.before[4]} | "
        f"{baseline.before[5]} | — | — | — | — | — | — | — |"
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Measure per-technique contribution of reconstruction.py by running "
            "the Hodur dump with different D810_RECON_SKIP_* gates set."
        ),
    )
    parser.add_argument(
        "--function",
        default="sub_7FFD3338C040",
        help="Function name to extract stats for (default: sub_7FFD3338C040)",
    )
    parser.add_argument(
        "--project",
        default="hodur_flag2.json",
        help="D810 project JSON (default: hodur_flag2.json)",
    )
    parser.add_argument(
        "--scenario",
        default="baseline,no_frontier,no_force_edge,no_narrow_branch_local",
        help=(
            "Comma-separated scenario names. Available: "
            f"{', '.join(SCENARIOS.keys())}"
        ),
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="Disable D810_RECON_ROUND_CTX_PROBE for faster runs",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    scenarios = [s.strip() for s in args.scenario.split(",") if s.strip()]
    unknown = [s for s in scenarios if s not in SCENARIOS]
    if unknown:
        print(f"error: unknown scenarios: {unknown}", file=sys.stderr)
        print(f"available: {list(SCENARIOS.keys())}", file=sys.stderr)
        return 2

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    results: list[ScenarioResult] = []
    for name in scenarios:
        try:
            result = run_scenario(
                name,
                SCENARIOS[name],
                function=args.function,
                project=args.project,
                timestamp=timestamp,
                enable_probe=not args.no_probe,
            )
        except Exception as exc:
            print(f"[{name}] FAILED: {exc}", file=sys.stderr)
            continue
        results.append(result)
        print(
            f"[{name}] AFTER lines={result.after[0]} returns={result.after[1]} "
            f"whiles={result.after[2]} gotos={result.after[3]} calls={result.after[4]} "
            f"ifs={result.after[5]} | probe=yes:{result.probe_matches}/no:{result.probe_mismatches} "
            f"crashes={result.crashes}"
        )

    print()
    print(format_matrix(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
