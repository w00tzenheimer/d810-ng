"""Tests for the ``FlowGraph.metadata`` contract pinned by ``lift`` (E2b).

E2b slice of ``docs/plans/recon-portability-end-state.md``: the lifter
guarantees every ``FlowGraph`` it produces carries three metadata
fields so recon consumers never reach back into the live ``mba_t``:

* ``maturity``       -- ``int``  (raw ``mba.maturity``)
* ``maturity_name``  -- ``str``  (``MMAT_*`` name)
* ``cpu_arch_name``  -- ``str``  (``idaapi.inf_get_procname()``)

Lives in ``tests/system/runtime/hexrays/`` because ``lift`` imports
``ida_hexrays`` / ``idaapi``; the ``unit-tests-no-hexrays``
import-linter contract forbids ``tests/unit/`` from importing
``d810.hexrays``.

Tests use a stub ``mba`` + monkeypatched ``idaapi.inf_get_procname``
so they exercise the *contract* without needing a live decompilation.
"""

from __future__ import annotations

import pytest

from d810.ir.flowgraph import FlowGraph


class _StubMba:
    """Minimal ``mba_t``-shaped stub: enough attributes for ``lift``
    to run without producing any blocks (``qty == 0`` short-circuits
    the lift loop)."""

    def __init__(self, *, entry_ea: int = 0x140002000, maturity: int = 14):
        self.qty = 0
        self.entry_ea = entry_ea
        self.maturity = maturity

    def get_mblock(self, _i: int):  # pragma: no cover - qty==0 means unused
        raise AssertionError("get_mblock called on stub with qty=0")


class TestLifterMetadataContract:
    """Every ``FlowGraph`` produced by ``lift`` carries the E2b
    metadata fields.  Recon consumers can depend on this contract;
    consumers MUST NOT reach back into ``mba_t`` for these values."""

    def test_all_three_keys_present(self, monkeypatch) -> None:
        from d810.hexrays.mutation import ir_translator

        monkeypatch.setattr(
            ir_translator.idaapi, "inf_get_procname", lambda: "metapc"
        )

        flow_graph = ir_translator.lift(_StubMba())

        assert "maturity" in flow_graph.metadata
        assert "maturity_name" in flow_graph.metadata
        assert "cpu_arch_name" in flow_graph.metadata

    def test_maturity_int_round_trips_from_mba(self, monkeypatch) -> None:
        from d810.hexrays.mutation import ir_translator

        monkeypatch.setattr(
            ir_translator.idaapi, "inf_get_procname", lambda: "metapc"
        )

        stub = _StubMba(maturity=14)
        flow_graph = ir_translator.lift(stub)

        assert flow_graph.metadata["maturity"] == 14
        assert isinstance(flow_graph.metadata["maturity"], int)

    def test_maturity_name_uses_mmat_string_helper(self, monkeypatch) -> None:
        """Names come from the project's canonical ``maturity_to_string``
        so a future change in MMAT naming flows through one place."""
        from d810.hexrays.mutation import ir_translator
        from d810.hexrays.utils.hexrays_formatters import maturity_to_string

        monkeypatch.setattr(
            ir_translator.idaapi, "inf_get_procname", lambda: "metapc"
        )

        stub = _StubMba(maturity=14)
        flow_graph = ir_translator.lift(stub)

        assert flow_graph.metadata["maturity_name"] == maturity_to_string(14)
        assert isinstance(flow_graph.metadata["maturity_name"], str)
        assert flow_graph.metadata["maturity_name"]  # non-empty

    def test_cpu_arch_name_is_string(self, monkeypatch) -> None:
        from d810.hexrays.mutation import ir_translator

        monkeypatch.setattr(
            ir_translator.idaapi, "inf_get_procname", lambda: "metapc"
        )

        flow_graph = ir_translator.lift(_StubMba())

        assert flow_graph.metadata["cpu_arch_name"] == "metapc"
        assert isinstance(flow_graph.metadata["cpu_arch_name"], str)

    def test_cpu_arch_name_decodes_bytes(self, monkeypatch) -> None:
        """Some IDA builds return ``inf_get_procname`` as ``bytes``;
        the lifter normalises to ``str`` so consumers get a stable
        type."""
        from d810.hexrays.mutation import ir_translator

        monkeypatch.setattr(
            ir_translator.idaapi, "inf_get_procname", lambda: b"ARM"
        )

        flow_graph = ir_translator.lift(_StubMba())

        assert flow_graph.metadata["cpu_arch_name"] == "ARM"
        assert isinstance(flow_graph.metadata["cpu_arch_name"], str)

    def test_cpu_arch_name_falls_back_to_unknown_sentinel(
        self, monkeypatch
    ) -> None:
        """If ``inf_get_procname`` raises, the lifter MUST NOT gate
        decompilation -- it falls back to the deterministic
        ``"unknown"`` sentinel.  Non-empty so consumers can do
        string compares without special-casing ``""``."""
        from d810.hexrays.mutation import ir_translator

        def raising_procname():
            raise RuntimeError("simulated IDA failure")

        monkeypatch.setattr(
            ir_translator.idaapi, "inf_get_procname", raising_procname
        )

        flow_graph = ir_translator.lift(_StubMba())

        assert flow_graph.metadata["cpu_arch_name"] == "unknown"

    def test_cpu_arch_name_unknown_when_inf_returns_none(
        self, monkeypatch
    ) -> None:
        """``inf_get_procname`` returning a falsy value also normalises
        to ``"unknown"`` (some IDA builds may return ``None`` or an
        empty string instead of raising)."""
        from d810.hexrays.mutation import ir_translator

        monkeypatch.setattr(
            ir_translator.idaapi, "inf_get_procname", lambda: None
        )

        flow_graph = ir_translator.lift(_StubMba())

        assert flow_graph.metadata["cpu_arch_name"] == "unknown"

    def test_lift_returns_flowgraph_instance(self, monkeypatch) -> None:
        """Regression cover: the lifter contract is ``lift(mba) ->
        FlowGraph``; no consumer should ever get back an ``mba`` or
        a free-form dict."""
        from d810.hexrays.mutation import ir_translator

        monkeypatch.setattr(
            ir_translator.idaapi, "inf_get_procname", lambda: "metapc"
        )

        flow_graph = ir_translator.lift(_StubMba())

        assert isinstance(flow_graph, FlowGraph)
        # ``func_ea`` is the only required field that comes from the
        # ``mba`` -- the rest of the contract is the metadata above.
        assert flow_graph.func_ea == 0x140002000


class TestProviderNeutralStageMetadata:
    """E2d: the lifter exposes provider-neutral stage metadata
    (``producer`` / ``producer_stage_id`` / ``producer_stage_name`` /
    ``snapshot_stage``) as the canonical contract.  The E2b
    ``maturity`` / ``maturity_name`` keys remain as aliases and MUST be
    provably equal to the neutral fields so legacy callers keep working
    while new code migrates to the neutral names."""

    def _lift(self, monkeypatch, maturity: int = 14):
        from d810.hexrays.mutation import ir_translator

        monkeypatch.setattr(
            ir_translator.idaapi, "inf_get_procname", lambda: "metapc"
        )
        return ir_translator.lift(_StubMba(maturity=maturity))

    def test_neutral_fields_present(self, monkeypatch) -> None:
        meta = self._lift(monkeypatch).metadata
        for key in (
            "producer",
            "producer_stage_id",
            "producer_stage_name",
            "snapshot_stage",
        ):
            assert key in meta, key

    def test_producer_is_hexrays(self, monkeypatch) -> None:
        assert self._lift(monkeypatch).metadata["producer"] == "hexrays"

    def test_neutral_aliases_have_parity(self, monkeypatch) -> None:
        """The E2b aliases equal the neutral fields exactly, so callers
        on either name observe the same value (the merge-gate contract)."""
        meta = self._lift(monkeypatch).metadata
        assert meta["producer_stage_id"] == meta["maturity"]
        assert meta["producer_stage_name"] == meta["maturity_name"]

    def test_snapshot_stage_is_portable_family(self, monkeypatch) -> None:
        from d810.ir.flowgraph import SnapshotStage
        from d810.hexrays.mutation import ir_translator

        meta = self._lift(monkeypatch).metadata
        stage = meta["snapshot_stage"]
        assert isinstance(stage, SnapshotStage)
        # Derived from the producer stage name via the lifter's mapping.
        assert stage is ir_translator._snapshot_stage_for_maturity_name(
            meta["producer_stage_name"]
        )

    def test_snapshot_stage_mapping_is_coarse_and_neutral(self, monkeypatch) -> None:
        """Spot-check the coarse mapping: GLBOPT* are optimized IR,
        LVARS is lvar-recovered -- no MMAT string leaks into the
        portable family value."""
        from d810.ir.flowgraph import SnapshotStage
        from d810.hexrays.mutation import ir_translator

        m = ir_translator._snapshot_stage_for_maturity_name
        assert m("MMAT_GLBOPT1") is SnapshotStage.OPTIMIZED_IR
        assert m("MMAT_GLBOPT2") is SnapshotStage.OPTIMIZED_IR
        assert m("MMAT_LVARS") is SnapshotStage.LVAR_RECOVERED
        assert m("MMAT_PREOPTIMIZED") is SnapshotStage.NORMALIZED_IR
        assert m("bogus") is SnapshotStage.UNKNOWN


class TestLifterMetadataImmutability:
    """Metadata is exposed through a ``MappingProxyType`` so consumers
    can't mutate it; the contract is read-only."""

    def test_metadata_is_read_only(self, monkeypatch) -> None:
        from d810.hexrays.mutation import ir_translator

        monkeypatch.setattr(
            ir_translator.idaapi, "inf_get_procname", lambda: "metapc"
        )

        flow_graph = ir_translator.lift(_StubMba())

        with pytest.raises(TypeError):
            flow_graph.metadata["maturity"] = 99  # type: ignore[index]
