#!/usr/bin/env python3
"""Codemod: rename diag ``dag_*`` SQL tables -> ``state_cfg_*`` (ticket llr-l48z).

The 9 diag tables that store the recovered state-transition CFG are misnamed
"dag" (they are cyclic). This renames them to ``state_cfg_*`` everywhere the
name appears **inside a string literal** -- i.e. SQL statements (``FROM
dag_edges``, ``INSERT INTO dag_nodes``), dynamic table-name strings
(``table_name="dag_edges"``, the ``query.py`` table list), the schema DDL, and
incidental docstrings/narratives.

Crucially it is scoped to string literals via libcst, so it does NOT touch
Python identifiers that happen to share the token: local vars / kwargs
(``dag_edges = ...``, ``dag_edges=dag_edges``), or helper names
(``classify_dag_edges``, ``load_dag_edges``). Those belong to the broader
symbol rename, not the table rename. ``semantic_regions.py`` (a log-format
string + Python symbols, no SQL) and the RCA scripts (no ``dag_*`` refs) are
deliberately excluded.

The back-compat ``dag_*`` VIEWs and the legacy-DB migration are added by hand
in ``core/diag/schema.py`` (too bespoke for a codemod); see ``create_tables``.

Usage:
    python tools/scripts/rename/dag_tables_to_state_cfg.py            # dry-run (show changes)
    python tools/scripts/rename/dag_tables_to_state_cfg.py --apply    # write files
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import libcst as cst

REPO = Path(__file__).resolve().parents[3]

# 9 recovered-CFG tables (longest-first so the alternation is unambiguous;
# whole-word anchoring already prevents sub-token matches).
_TABLES = (
    "dag_frontier_closure_diagnostics",
    "dag_edge_alternate_correlations",
    "dag_edge_alternate_selections",
    "dag_edge_diagnostics",
    "dag_node_blocks",
    "dag_local_segments",
    "dag_local_edges",
    "dag_nodes",
    "dag_edges",
)
_TABLE_RE = re.compile(r"\b(" + "|".join(_TABLES) + r")\b")


def _rename_tokens(text: str) -> str:
    """Rename dag_* table tokens + idx_dag_ index prefix inside one string."""
    # Index names first (distinctive prefix; not word-bounded by design).
    text = text.replace("idx_dag_", "idx_state_cfg_")
    return _TABLE_RE.sub(lambda m: "state_cfg_" + m.group(1)[len("dag_"):], text)


class _StringTableRenamer(cst.CSTTransformer):
    """Rewrite dag_* table tokens inside string literals only."""

    def __init__(self) -> None:
        self.changes: list[tuple[str, str]] = []

    def _maybe(self, value: str) -> str:
        new = _rename_tokens(value)
        if new != value:
            self.changes.append((value, new))
        return new

    def leave_SimpleString(
        self, original: cst.SimpleString, updated: cst.SimpleString
    ) -> cst.SimpleString:
        return updated.with_changes(value=self._maybe(updated.value))

    def leave_FormattedStringText(
        self, original: cst.FormattedStringText, updated: cst.FormattedStringText
    ) -> cst.FormattedStringText:
        return updated.with_changes(value=self._maybe(updated.value))


# SQL-bearing files only (verified to contain dag_* SQL/table-name string
# literals). Excludes semantic_regions.py (log string only) + rca/* (no refs).
ALLOWLIST = [
    "src/d810/core/diag/schema.py",
    "src/d810/core/diag/snapshot.py",
    "src/d810/diagnostics/query.py",
    "src/d810/diagnostics/edge_diagnostics.py",
    "src/d810/diagnostics/frontier_diagnostics.py",
    "src/d810/diagnostics/alternate_correlation.py",
    "src/d810/diagnostics/alternate_selection.py",
    "src/d810/diagnostics/selected_alternate_edge_override.py",
    "src/d810/diagnostics/redirect_reconcile.py",
    "src/d810/diagnostics/residual_worksheet.py",
    "src/d810/diagnostics/hcc_region_admission_explainer.py",
    "src/d810/diagnostics/hcc_unsupported_edge_kind_explainer.py",
    "src/d810/diagnostics/__main__.py",
    "tests/unit/core/diag/test_schema.py",
    "tests/unit/core/diag/test_snapshot.py",
    "tests/unit/core/diag/test_event_handlers.py",
    "tests/unit/core/diag/fixtures.py",
    "tests/unit/recon/flow/test_edge_diagnostics.py",
    "tests/unit/recon/flow/test_alternate_selection.py",
    "tests/unit/recon/flow/test_alternate_correlation.py",
    "tests/unit/recon/flow/test_selected_alternate_edge_override.py",
    "tests/unit/diagnostics/test_residual_worksheet.py",
    "tests/unit/diagnostics/test_redirect_reconcile.py",
    "tests/unit/diagnostics/test_hcc_region_admission_explainer.py",
    "tests/unit/diagnostics/test_hcc_unsupported_edge_kind_explainer.py",
    "tests/unit/diagnostics/test_frontier_diagnostics.py",
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="write changes (default: dry-run)")
    args = ap.parse_args()

    total = 0
    for rel in ALLOWLIST:
        path = REPO / rel
        if not path.exists():
            continue
        src = path.read_text()
        module = cst.parse_module(src)
        renamer = _StringTableRenamer()
        new_module = module.visit(renamer)
        if not renamer.changes:
            continue
        total += len(renamer.changes)
        print(f"\n{rel}  ({len(renamer.changes)} string(s))")
        for old, new in renamer.changes[:8]:
            o = old.replace("\n", "\\n")
            n = new.replace("\n", "\\n")
            print(f"  - {o[:100]}")
            print(f"  + {n[:100]}")
        if len(renamer.changes) > 8:
            print(f"  ... +{len(renamer.changes) - 8} more")
        if args.apply:
            path.write_text(new_module.code)

    verb = "applied" if args.apply else "would change"
    print(f"\n{verb} {total} string literal(s) across {len(ALLOWLIST)} candidate files.")
    if not args.apply:
        print("Re-run with --apply to write.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
