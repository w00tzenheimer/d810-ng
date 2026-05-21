from __future__ import annotations

from pathlib import Path
import re


def _repo_root() -> Path:
    cur = Path(__file__).resolve()
    while cur != cur.parent:
        if (cur / "src" / "d810").exists():
            return cur
        cur = cur.parent
    raise RuntimeError("repo root not found from test path")


def test_ollvm_father_history_has_no_direct_jtbl_target_assignment():
    backend_path = (
        _repo_root()
        / "src"
        / "d810"
        / "optimizers"
        / "microcode"
        / "flow"
        / "flattening"
        / "ollvm_father_history_backend.py"
    )
    pattern = re.compile(r"\b(?:targets|cases\.targets)\s*\[[^\]]+\]\s*=")
    violations: list[str] = []

    with backend_path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if pattern.search(line):
                violations.append(f"{lineno}: {line.rstrip()}")

    assert not violations, (
        "Direct jump-table target assignment is not allowed in "
        "ollvm_father_history_backend.py. Route all jtbl target rewrites "
        "through cfg_mutations helpers.\n"
        + "\n".join(violations)
    )
