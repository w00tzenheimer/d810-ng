#!/usr/bin/env python3
"""Guard OLLVM carrier evidence against global/generic registration leaks."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OLD_BACKEND_MODULE = "d810.backends.hexrays.evidence.ollvm_carrier_backend"

GENERIC_FILE_BANS = {
    Path("src/d810/manager.py"): (
        "OllvmValueFlowEvidenceCollector",
        "OllvmCarrierRawEvidenceCollector",
        "OllvmCarrierProfileFactCollector",
        "ollvm_semantic_carrier",
        "ollvm_carrier_backend",
    ),
    Path("src/d810/analyses/value_flow/collectors.py"): (
        "Ollvm",
        "ollvm",
    ),
    Path("src/d810/analyses/value_flow/projection.py"): (
        "Ollvm",
        "ollvm",
        "OllvmValueFlowEvidence",
        "_ollvm",
    ),
    Path("src/d810/analyses/control_flow/branch_ownership_oracle.py"): (
        "Ollvm",
        "ollvm_carrier",
        "OllvmValueFlowEvidence",
        "project_value_flow_facts",
    ),
}


def _iter_text_files(root: Path, *suffixes: str) -> tuple[Path, ...]:
    return tuple(
        sorted(
            path
            for suffix in suffixes
            for path in root.rglob(f"*{suffix}")
            if path.is_file()
        )
    )


def main() -> int:
    failures: list[str] = []

    old_backend_path = ROOT / "src/d810/backends/hexrays/evidence/ollvm_carrier_backend.py"
    if old_backend_path.exists():
        failures.append(f"{old_backend_path.relative_to(ROOT)}: old backend adapter still exists")

    value_flow_dir = ROOT / "src/d810/analyses/value_flow"
    for path in sorted(value_flow_dir.glob("ollvm*.py")):
        failures.append(f"{path.relative_to(ROOT)}: OLLVM module must not live in analyses/value_flow")

    for path in _iter_text_files(ROOT / "src/d810/conf", ".json"):
        text = path.read_text(encoding="utf-8")
        if OLD_BACKEND_MODULE in text:
            failures.append(f"{path.relative_to(ROOT)}: references old backend module")

    for rel_path, banned_terms in GENERIC_FILE_BANS.items():
        path = ROOT / rel_path
        if not path.exists():
            failures.append(f"{rel_path}: expected guard target is missing")
            continue
        text = path.read_text(encoding="utf-8")
        for term in banned_terms:
            if term in text:
                failures.append(f"{rel_path}: forbidden global OLLVM carrier term: {term}")

    if failures:
        for failure in failures:
            print(failure)
        return 1
    print("no global OLLVM carrier leaks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
