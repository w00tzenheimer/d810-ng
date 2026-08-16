from __future__ import annotations

from pathlib import Path

from tests.speedup_parity import speedup_parity_modules


def test_new_direct_speedup_boundary_test_is_discovered_without_manifest_edit(
    tmp_path: Path,
) -> None:
    test_path = tmp_path / "tests" / "system" / "runtime" / "test_new_boundary.py"
    test_path.parent.mkdir(parents=True)
    test_path.write_text(
        "from d810.core.cymode import CythonMode\n\ndef test_boundary(): pass\n",
        encoding="utf-8",
    )

    assert speedup_parity_modules(tmp_path) == frozenset(
        {"tests/system/runtime/test_new_boundary.py"}
    )


def test_current_speedup_parity_manifest_has_no_missing_paths() -> None:
    repository_root = Path(__file__).resolve().parents[2]

    modules = speedup_parity_modules(repository_root)

    assert modules
    assert all((repository_root / module).is_file() for module in modules)
