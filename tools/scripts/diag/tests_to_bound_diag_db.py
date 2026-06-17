#!/usr/bin/env python3
"""Point ORM-exercising unit tests at the bound-diag-DB singleton (Phase D).

After ``create_diag_database`` stopped applying a process-global Model bind,
tests that create an in-memory diag DB and then call ORM reader inner-functions
(or ``Model.select`` directly) must bind explicitly. They now obtain their DB
from ``make_bound_diag_db`` (``tests.unit.core.diag._orm_bind``), a per-test
singleton that binds the Models on creation and is disconnected at teardown by
the autouse ``_release_diag_test_binds`` fixture.

Transform per file: swap ``create_diag_database(":memory:")`` ->
``make_bound_diag_db()`` and fix the import. ``frontier_diagnostics`` also uses
``create_diag_database(<path>)`` for a CLI test (run() binds itself), so it keeps
the original import and gains the helper import alongside.

Exact ``str.replace`` (count-checked), NOT regex/AST.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

IMPORT_OLD = "from d810.core.diag import create_diag_database"
HELPER_IMPORT = "from tests.unit.core.diag._orm_bind import make_bound_diag_db"
CALL_OLD = 'create_diag_database(":memory:")'
CALL_NEW = "make_bound_diag_db()"

# (relpath, keep_create_import?)
REPLACE_FILES = [
    ("tests/unit/recon/flow/test_edge_diagnostics.py", False),
    ("tests/unit/recon/flow/test_condition_chain_resolution.py", False),
    ("tests/unit/recon/flow/test_alternate_selection.py", False),
    ("tests/unit/recon/flow/test_alternate_correlation.py", False),
    ("tests/unit/recon/flow/test_selected_alternate_edge_override.py", False),
    ("tests/unit/diagnostics/test_state_dispatcher_resolution.py", False),
    ("tests/unit/diagnostics/test_scenarios.py", False),
    ("tests/unit/diagnostics/test_inspect_state_node.py", False),
    ("tests/unit/diagnostics/test_hcc_compose_evidence_explainer.py", False),
    ("tests/unit/diagnostics/test_hcc_region_admission_explainer.py", False),
    ("tests/unit/diagnostics/test_hcc_unsupported_edge_kind_explainer.py", False),
    ("tests/unit/diagnostics/test_hcc_anchor_snapshot_context.py", False),
    ("tests/unit/diagnostics/test_frontier_diagnostics.py", True),  # keeps create_diag_database
]


def convert(rel: str, keep_create: bool) -> None:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    name = Path(rel).name
    if HELPER_IMPORT in text:
        print(f"{name}: already converted, skipping")
        return
    if IMPORT_OLD not in text:
        raise SystemExit(f"{name}: import anchor not found")
    n = text.count(CALL_OLD)
    if n < 1:
        raise SystemExit(f"{name}: expected >=1 '{CALL_OLD}', found {n}")
    text = text.replace(CALL_OLD, CALL_NEW)
    # Stale comments that described create_diag_database's (now-removed) binding.
    text = text.replace(
        "create_diag_database binds the peewee Models",
        "make_bound_diag_db binds the peewee Models",
    )
    # Auto-detect: a remaining genuine CALL (with paren) means create is still
    # needed (e.g. a file-path CLI test), so keep its import and add the helper;
    # otherwise the name is gone (or only in a comment) -> swap the import.
    still_calls_create = "create_diag_database(" in text
    if still_calls_create:
        text = text.replace(IMPORT_OLD, IMPORT_OLD + "\n" + HELPER_IMPORT, 1)
    else:
        text = text.replace(IMPORT_OLD, HELPER_IMPORT, 1)
    path.write_text(text, encoding="utf-8")
    kept = ", kept create import" if still_calls_create else ""
    print(f"{name}: converted ({n} call-site(s){kept})")


def main() -> int:
    for rel, keep in REPLACE_FILES:
        convert(rel, keep)
    return 0


if __name__ == "__main__":
    sys.exit(main())
