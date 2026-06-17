from __future__ import annotations

from d810.passes.recon_runtime_factory import (
    DEFAULT_FACT_COLLECTOR_NAMES,
    DEFAULT_RECON_COLLECTOR_NAMES,
    build_recon_phase,
    build_recon_runtime_bundle,
)


def test_build_recon_phase_registers_default_collectors(tmp_path) -> None:
    phase = build_recon_phase(tmp_path)

    assert phase is not None
    assert tuple(collector.name for collector in phase._collectors) == (
        DEFAULT_RECON_COLLECTOR_NAMES
    )
    phase._store.close()


def test_build_recon_runtime_bundle_registers_fact_collectors(tmp_path) -> None:
    bundle = build_recon_runtime_bundle(log_dir=tmp_path, config={})

    assert bundle is not None
    assert bundle.db_path == tmp_path / "d810_recon.db"
    assert tuple(collector.name for collector in bundle.recon_phase._collectors) == (
        DEFAULT_RECON_COLLECTOR_NAMES
    )
    fact_runtime = bundle.recon_runtime._fact_lifecycle
    assert tuple(collector.name for collector in fact_runtime._collectors) == (
        DEFAULT_FACT_COLLECTOR_NAMES
    )
    assert bundle.default_fact_collector_count == len(DEFAULT_FACT_COLLECTOR_NAMES)
    bundle.close()
