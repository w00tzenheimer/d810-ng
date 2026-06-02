#!/usr/bin/env python3
"""Codemod: migrate diag tests from raw sqlite3 to the peewee factory (llr-t3nw).

``create_tables`` now takes a peewee ``SqliteDatabase`` (peewee owns the diag
connection). The dominant test pattern is two adjacent statements:

    conn = sqlite3.connect(<EXPR>)
    create_tables(conn)

which becomes a single call to the production factory (which creates the
schema and returns a peewee-backed raw connection):

    conn = create_diag_database(<EXPR>).connection()

Adds ``from d810.core.diag import create_diag_database`` to each changed file.
EXCLUDES test_state_cfg_migration.py (needs raw connect → inject legacy tables
→ create_tables(db); handled by hand). Reports any remaining ``create_tables(
<var>)`` sites (non-adjacent / scenario-caller) for manual fixup.

    python tools/scripts/rename/diag_create_tables_to_peewee.py [--apply]
"""
from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
EXCLUDE = {"tests/unit/core/diag/test_state_cfg_migration.py"}

_PAT = re.compile(
    r"^(?P<ind>[ \t]*)(?P<var>[A-Za-z_]\w*) = sqlite3\.connect\((?P<arg>.*)\)\n"
    r"(?P=ind)create_tables\((?P=var)\)[ \t]*$",
    re.M,
)
_IMPORT = "from d810.core.diag import create_diag_database"


def _discover() -> list[Path]:
    cmd = ["rg", "-l", r"create_tables\(", "tests", "--glob", "!**/__pycache__/**"]
    out = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO)
    files = []
    for rel in out.stdout.splitlines():
        if rel and rel not in EXCLUDE:
            files.append(REPO / rel)
    return files


def _add_import(text: str) -> str:
    if _IMPORT in text:
        return text
    lines = text.splitlines(keepends=True)
    # Insert after the last top-level `from d810.core.diag` import, else after
    # the first `import sqlite3`.
    anchor = None
    for i, ln in enumerate(lines):
        if ln.startswith("from d810.core.diag"):
            anchor = i
    if anchor is None:
        for i, ln in enumerate(lines):
            if ln.startswith("import sqlite3"):
                anchor = i
                break
    if anchor is None:
        return text  # leave; manual
    lines.insert(anchor + 1, _IMPORT + "\n")
    return "".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()

    total = 0
    for path in _discover():
        text = path.read_text()
        new, n = _PAT.subn(
            r"\g<ind>\g<var> = create_diag_database(\g<arg>).connection()", text
        )
        if n:
            new = _add_import(new)
            total += n
            rel = path.relative_to(REPO)
            remaining = len(re.findall(r"create_tables\(\w+\)", new))
            note = f"  (still {remaining} create_tables(var) for manual review)" if remaining else ""
            print(f"{rel}: {n} site(s){note}")
            if args.apply:
                path.write_text(new)
    # Report files that still reference create_tables(<var>) but had 0 rewrites.
    print("\n-- files with create_tables(var) NOT matched by adjacent pattern --")
    for path in _discover():
        text = path.read_text()
        if _PAT.search(text) is None and re.search(r"create_tables\(\w+\)", text):
            print(f"  MANUAL: {path.relative_to(REPO)}")
    verb = "applied" if args.apply else "would rewrite"
    print(f"\n{verb} {total} adjacent connect+create_tables site(s).")


if __name__ == "__main__":
    main()
