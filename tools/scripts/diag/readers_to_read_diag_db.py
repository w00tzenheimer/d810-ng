#!/usr/bin/env python3
"""Convert diag CLI readers from the global-bind ``open_diag_database`` pattern
to the bind-safe ``read_diag_db`` context manager (Phase D, item 2).

Each reader currently does::

    db = open_diag_database(str(db_path))
    conn = db.connection()          # optional; sometimes inside the try
    try:
        <body>                      # already at the try indent
    finally:
        db.close()

The ``with read_diag_db(...) as db:`` CM binds the Models via ``bind_ctx`` for
the block and closes the db on exit, so the body keeps the SAME indentation and
no process-global Model bind is relied upon. The transform is therefore:

  1. swap the import symbol,
  2. rewrite the open/try header (two variants: conn-before-try, conn-in/after-try),
  3. drop the now-dangling ``finally: db.close()``.

Exact ``str.replace`` (count-checked), NOT regex/AST -- the strings were
extracted verbatim and each occurs once per file. The two structurally-special
readers (residual_worksheet: two opens; hcc_anchor_snapshot_context: inline
one-liner) are handled separately, not here.
"""
from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[3] / "src" / "d810" / "diagnostics"

IMPORT_OLD = "from d810.core.diag import open_diag_database"
IMPORT_NEW = "from d810.core.diag import read_diag_db"

# Header variant A: a `conn = db.connection()` line precedes the `try:`.
HEADER_A_OLD = (
    "    db = open_diag_database(str(db_path))\n"
    "    conn = db.connection()\n"
    "    try:"
)
HEADER_A_NEW = (
    "    with read_diag_db(str(db_path)) as db:\n"
    "        conn = db.connection()"
)

# Header variant B: `try:` directly follows the open (conn is created inside).
HEADER_B_OLD = "    db = open_diag_database(str(db_path))\n    try:"
HEADER_B_NEW = "    with read_diag_db(str(db_path)) as db:"

# Dangling finally to drop (leading newline removed so spacing stays clean).
FINALLY_OLD = "\n    finally:\n        db.close()"
FINALLY_NEW = ""

VARIANT_A = [
    "terminal_tail_audit",
    "inspect_state_node",
    "snap_render",
    "return_ledger",
    "hcc_byte_cascade_trace",
    "cascade_egress_plan",
    "redirect_reconcile",
    "indirect_state_transfer_map",
]
VARIANT_B = [
    "hcc_region_admission_explainer",
    "hcc_unsupported_edge_kind_explainer",
    "frontier_diagnostics",
]
# hcc_compose_evidence_explainer already converted by hand (whole-block edit).


def _replace_once(text: str, old: str, new: str, *, what: str, mod: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{mod}: expected exactly 1 '{what}', found {count}")
    return text.replace(old, new)


def convert(mod: str, header_old: str, header_new: str) -> None:
    path = SRC / f"{mod}.py"
    text = path.read_text(encoding="utf-8")
    if IMPORT_NEW in text and "open_diag_database" not in text:
        print(f"{mod}: already converted, skipping")
        return
    text = _replace_once(text, IMPORT_OLD, IMPORT_NEW, what="import", mod=mod)
    text = _replace_once(text, header_old, header_new, what="header", mod=mod)
    text = _replace_once(text, FINALLY_OLD, FINALLY_NEW, what="finally", mod=mod)
    path.write_text(text, encoding="utf-8")
    print(f"{mod}: converted")


# residual_worksheet opens two DBs (different var names + a row_factory line).
# Its opens are SEQUENTIAL (each closed before the next), so read_diag_db fits.
RESIDUAL_OPEN1_OLD = (
    "    diag_db = open_diag_database(str(diag_db_path))\n"
    "    # Bind Models for the ORM readers; the remaining raw resolver/metadata\n"
    "    # queries below use name-based row access, so set the Row factory.\n"
    "    diag_conn = diag_db.connection()\n"
    "    diag_conn.row_factory = sqlite3.Row\n"
    "    try:"
)
RESIDUAL_OPEN1_NEW = (
    "    with read_diag_db(str(diag_db_path)) as diag_db:\n"
    "        # Bind Models for the ORM readers; the remaining raw resolver/metadata\n"
    "        # queries below use name-based row access, so set the Row factory.\n"
    "        diag_conn = diag_db.connection()\n"
    "        diag_conn.row_factory = sqlite3.Row"
)
RESIDUAL_FINALLY1_OLD = "\n    finally:\n        diag_db.close()"

RESIDUAL_OPEN2_OLD = (
    "        ls_db = open_diag_database(str(diag_db_path))\n"
    "        try:\n"
    "            for row in list_snapshots(ls_db.connection()):"
)
RESIDUAL_OPEN2_NEW = (
    "        with read_diag_db(str(diag_db_path)) as ls_db:\n"
    "            for row in list_snapshots(ls_db.connection()):"
)
RESIDUAL_FINALLY2_OLD = "\n        finally:\n            ls_db.close()"


def convert_residual() -> None:
    mod = "residual_worksheet"
    path = SRC / f"{mod}.py"
    text = path.read_text(encoding="utf-8")
    if "open_diag_database" not in text:
        print(f"{mod}: already converted, skipping")
        return
    text = _replace_once(text, IMPORT_OLD, IMPORT_NEW, what="import", mod=mod)
    text = _replace_once(text, RESIDUAL_OPEN1_OLD, RESIDUAL_OPEN1_NEW, what="open1", mod=mod)
    text = _replace_once(text, RESIDUAL_FINALLY1_OLD, "", what="finally1", mod=mod)
    text = _replace_once(text, RESIDUAL_OPEN2_OLD, RESIDUAL_OPEN2_NEW, what="open2", mod=mod)
    text = _replace_once(text, RESIDUAL_FINALLY2_OLD, "", what="finally2", mod=mod)
    path.write_text(text, encoding="utf-8")
    print(f"{mod}: converted (2 opens)")


def main() -> int:
    for mod in VARIANT_A:
        convert(mod, HEADER_A_OLD, HEADER_A_NEW)
    for mod in VARIANT_B:
        convert(mod, HEADER_B_OLD, HEADER_B_NEW)
    convert_residual()
    return 0


if __name__ == "__main__":
    sys.exit(main())
