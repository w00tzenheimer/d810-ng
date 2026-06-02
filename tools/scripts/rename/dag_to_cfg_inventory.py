#!/usr/bin/env python3
"""DAG -> CFG rename inventory (P0 of ticket llr-b8oi).

Reproducibly enumerates the rename surface for the "stop calling the recovered
state-transition graph a DAG" campaign (handoff
``2026-06-02-dag-to-cfg-rename-flowgraph-base.md``).  Run on-demand rather than
trusting the frozen snapshot in the handoff -- the surface drifts as companion
work (e.g. the §1a ``read_dag.py`` thread) lands.

    PYTHONPATH=src python tools/scripts/rename/dag_to_cfg_inventory.py

Outputs three sections:
  1. DAG-named source + test files (the physical-rename surface for P2).
  2. Headline ``dag`` symbol frequencies (the AST/codemod surface).
  3. ``dag_*`` diag tables in ``core/diag/schema.py``.

DIAG-TABLE-NAME POLICY (P0 decision, per handoff §5 P0 recommendation):
  Rename *code* (modules + symbols) now; KEEP the ``dag_*`` diag table names
  initially.  Renaming tables would break (a) the RCA scripts under
  ``tools/scripts/rca/`` that query ``dag_edges``/``dag_nodes``, (b) existing
  ``*.diag.sqlite3`` artifacts, and (c) ``core/diag`` consumers -- churn with
  no semantic payoff.  If table names are revisited later, add CFG-named
  *views* over the existing tables rather than an in-place rename, so old DBs
  keep loading.  This script flags the tables so the policy stays visible.
"""
from __future__ import annotations

import re
import subprocess
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SRC = REPO / "src" / "d810"
TESTS = REPO / "tests"

# Headline symbols worth tracking by frequency (handoff §3).
HEADLINE = (
    "SemanticEdgeKind",
    "dag_edges",
    "linearized_state_dag",
    "dag_nodes",
    "build_live_linearized_state_dag_from_graph",
    "observe_dag",
    "read_dag",
    "state_dag_key",
)


def _rg(pattern: str, *paths: Path) -> list[str]:
    """Run ripgrep, returning matching lines (empty list on no match)."""
    cmd = ["rg", "--no-heading", "-n", pattern, *(str(p) for p in paths)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):  # 1 == no matches
        raise RuntimeError(proc.stderr)
    return [ln for ln in proc.stdout.splitlines() if ln]


def dag_named_files() -> list[Path]:
    out: list[Path] = []
    for root in (SRC, TESTS):
        out.extend(
            p for p in root.rglob("*.py") if "dag" in p.name.lower()
        )
    return sorted(out)


def symbol_frequencies() -> Counter[str]:
    counts: Counter[str] = Counter()
    for sym in HEADLINE:
        counts[sym] = len(_rg(rf"\b{re.escape(sym)}\b", SRC, TESTS))
    return counts


def diag_tables() -> list[str]:
    schema = SRC / "core" / "diag" / "schema.py"
    if not schema.exists():
        return []
    names = re.findall(r"CREATE TABLE[^(]*?(dag_\w+)", schema.read_text())
    return sorted(set(names))


def main() -> None:
    print("== DAG-named files (physical rename surface, P2) ==")
    for p in dag_named_files():
        print(f"  {p.relative_to(REPO)}")

    print("\n== Headline symbol frequencies (codemod surface) ==")
    for sym, n in symbol_frequencies().most_common():
        print(f"  {n:5d}  {sym}")

    print("\n== dag_* diag tables (KEEP names; see module docstring) ==")
    for t in diag_tables():
        print(f"  {t}")


if __name__ == "__main__":
    main()
