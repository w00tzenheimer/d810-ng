from __future__ import annotations

from types import SimpleNamespace

from d810.transforms.graph_modification import ConvertToGoto
from d810.backends.hexrays.evidence import spurious_backedge_redirect
from d810.backends.hexrays.evidence.spurious_backedge_redirect import (
    SpuriousBackedgeRedirectStrategy,
)


class _FakeLiveAnalysisBackend:
    def __init__(self) -> None:
        self.topology_calls = 0
        self.predicate_calls = 0

    def collect_block_topology(self, mba):
        self.topology_calls += 1
        assert mba is _MBA
        return (
            SimpleNamespace(serial=13, block_type="BLT_1WAY", succs=(15,)),
            SimpleNamespace(serial=14, block_type="BLT_1WAY", succs=(13,)),
            SimpleNamespace(serial=15, block_type="BLT_2WAY", succs=(16, 13)),
            SimpleNamespace(serial=16, block_type="BLT_STOP", succs=()),
        )

    def collect_predicate_read_write_evidence(self, mba):
        self.predicate_calls += 1
        assert mba is _MBA
        return (
            SimpleNamespace(
                block_serial=13,
                writes=frozenset(),
                predicate_reads=frozenset({"%var_F0"}),
            ),
            SimpleNamespace(
                block_serial=14,
                writes=frozenset(),
                predicate_reads=frozenset(),
            ),
            SimpleNamespace(
                block_serial=15,
                writes=frozenset({"%var_5B8"}),
                predicate_reads=frozenset({"%var_330"}),
            ),
            SimpleNamespace(
                block_serial=16,
                writes=frozenset(),
                predicate_reads=frozenset(),
            ),
        )


_MBA = object()


def test_spurious_backedge_strategy_consumes_backend_evidence(monkeypatch) -> None:
    backend = _FakeLiveAnalysisBackend()
    monkeypatch.setenv("D810_HODUR_ENABLE_SPURIOUS_REDIRECT", "1")
    monkeypatch.setattr(
        spurious_backedge_redirect,
        "_LIVE_ANALYSIS_BACKEND",
        backend,
    )
    snapshot = SimpleNamespace(mba=_MBA, flow_graph=SimpleNamespace(blocks={}))

    fragment = SpuriousBackedgeRedirectStrategy().plan(snapshot)

    assert backend.topology_calls == 1
    assert backend.predicate_calls == 1
    assert fragment is not None
    assert fragment.metadata["execution_policy"] == "spurious_backedge_redirect"
    assert fragment.ownership.blocks == frozenset({15})
    assert fragment.expected_benefit.transitions_resolved == 1
    assert fragment.modifications == (
        [ConvertToGoto(block_serial=15, goto_target=16)]
    )
