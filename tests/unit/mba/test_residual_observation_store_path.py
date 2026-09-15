from pathlib import Path

from d810.mba.residual_observation_lifecycle import (
    resolve_mba_discovery_store_path,
)


def test_discovery_store_uses_manager_log_directory_without_override(
    tmp_path: Path,
) -> None:
    manager_log_dir = tmp_path / "shared" / "d810_logs"

    assert (
        resolve_mba_discovery_store_path(
            manager_log_dir,
            environment={},
        )
        == manager_log_dir / "d810_mba_discovery.sqlite3"
    )


def test_discovery_store_uses_isolated_diagnostic_directory(
    tmp_path: Path,
) -> None:
    manager_log_dir = tmp_path / "shared" / "d810_logs"
    batch_log_dir = tmp_path / "shard-3" / "runs" / "batch-7" / "d810_logs"

    assert (
        resolve_mba_discovery_store_path(
            manager_log_dir,
            environment={"D810_DIAG_LOG_DIR": str(batch_log_dir)},
        )
        == batch_log_dir / "d810_mba_discovery.sqlite3"
    )


def test_discovery_store_ignores_blank_diagnostic_override(tmp_path: Path) -> None:
    manager_log_dir = tmp_path / "shared" / "d810_logs"

    assert (
        resolve_mba_discovery_store_path(
            manager_log_dir,
            environment={"D810_DIAG_LOG_DIR": "  "},
        )
        == manager_log_dir / "d810_mba_discovery.sqlite3"
    )
