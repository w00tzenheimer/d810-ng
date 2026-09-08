"""Unit tests for terminal_return_proof -- types, topology layer, report."""

from __future__ import annotations

import pytest
from types import SimpleNamespace
from dataclasses import replace

import d810.evaluator.hexrays_microcode.terminal_return_proof as proof_module

from d810.evaluator.hexrays_microcode.terminal_return_proof import (
    DefSiteLike,
    ReturnCarrierRegister,
    TerminalReturnProofStatus,
    ProofLayer,
    TerminalReturnProofReport,
    TerminalReturnValueProof,
    prove_terminal_returns,
)
from d810.analyses.control_flow.terminal_return_audit import (
    TerminalReturnSourceKind,
    TerminalReturnSiteAudit,
    TerminalReturnAuditReport,
)


@pytest.mark.parametrize(
    "field,value",
    [
        ("proof_layer_used", "made_up"),
        ("ambiguous", "false"),
        ("topology_kind", "direct_return"),
    ],
)
def test_terminal_proof_rejects_untyped_evidence(field, value):
    values = dict(
        handler_serial=1,
        carrier=ReturnCarrierRegister(0, 8),
        def_sites=(),
        ambiguous=False,
        topology_kind=TerminalReturnSourceKind.DIRECT_RETURN,
        proof_layer_used=ProofLayer.TOPOLOGY,
    )
    values[field] = value
    with pytest.raises(TypeError):
        TerminalReturnValueProof(**values)


def test_terminal_live_proof_does_not_reuse_stale_audit_serial(monkeypatch):
    site = TerminalReturnSiteAudit(
        handler_serial=0,
        exit_serial=1,
        source_kind=TerminalReturnSourceKind.EPILOGUE_CORRIDOR,
        return_block_serial=1,
        handler_ea=0x1010,
        return_ea=0x1020,
    )
    audit = TerminalReturnAuditReport(0x1000, 1, 1, (site,))
    calls = []
    monkeypatch.setattr(
        proof_module, "_single_pred_walk_for_carrier", lambda *_: calls.append(True)
    )
    mba = SimpleNamespace(
        entry_ea=0x1000,
        qty=2,
        get_mblock=lambda serial: SimpleNamespace(serial=serial, start=0x3000 + serial),
    )
    prove_terminal_returns(mba, audit)
    assert calls == []


# ---------------------------------------------------------------------------
# ProofLayer enum
# ---------------------------------------------------------------------------


class TestProofLayerEnum:
    """Verify ProofLayer enum has all expected members."""

    def test_proof_layer_enum_values(self) -> None:
        expected = {
            "TOPOLOGY",
            "SINGLE_PRED_WALK",
            "CHAIN_BACKED",
            "REACHING_DEF",
            "EMULATOR",
            "UNRESOLVED",
        }
        actual = {m.name for m in ProofLayer}
        assert actual == expected

    def test_proof_layer_is_str_enum(self) -> None:
        assert isinstance(ProofLayer.TOPOLOGY, str)
        assert ProofLayer.TOPOLOGY == "topology"


# ---------------------------------------------------------------------------
# DefSiteLike NamedTuple
# ---------------------------------------------------------------------------


class TestDefSiteLike:
    """Verify DefSiteLike construction and defaults."""

    def test_basic_construction(self) -> None:
        ds = DefSiteLike(block_serial=5, ins_ea=0x1000, opcode=42)
        assert ds.block_serial == 5
        assert ds.ins_ea == 0x1000
        assert ds.opcode == 42

    def test_opcode_default_none(self) -> None:
        ds = DefSiteLike(block_serial=3, ins_ea=0x2000)
        assert ds.opcode is None


# ---------------------------------------------------------------------------
# TerminalReturnValueProof frozen dataclass
# ---------------------------------------------------------------------------


class TestTerminalReturnValueProof:
    """Verify the proof dataclass is frozen and fields work."""

    def test_terminal_return_value_proof_frozen(self) -> None:
        proof = TerminalReturnValueProof(
            handler_serial=10,
            carrier=ReturnCarrierRegister(0, 8),
            def_sites=(),
            ambiguous=False,
            topology_kind=TerminalReturnSourceKind.DIRECT_RETURN,
            proof_layer_used=ProofLayer.TOPOLOGY,
            notes="test",
        )
        with pytest.raises(AttributeError):
            # noinspection PyDataclass
            proof.handler_serial = 99  # type: ignore[misc]

    def test_fields_accessible(self) -> None:
        proof = TerminalReturnValueProof(
            handler_serial=7,
            carrier=ReturnCarrierRegister(0, 8),
            def_sites=(DefSiteLike(1, 0x100, 3),),
            ambiguous=True,
            topology_kind=TerminalReturnSourceKind.EPILOGUE_CORRIDOR,
            proof_layer_used=ProofLayer.CHAIN_BACKED,
            notes="two defs",
        )
        assert proof.handler_serial == 7
        assert proof.ambiguous is True
        assert len(proof.def_sites) == 1
        assert proof.proof_layer_used == ProofLayer.CHAIN_BACKED


# ---------------------------------------------------------------------------
# TerminalReturnProofReport summary
# ---------------------------------------------------------------------------


class TestTerminalReturnProofReport:
    """Verify report summary formatting."""

    def test_proof_report_summary(self) -> None:
        proofs = (
            TerminalReturnValueProof(
                handler_serial=1,
                carrier=ReturnCarrierRegister(0, 8),
                def_sites=(),
                ambiguous=False,
                topology_kind=TerminalReturnSourceKind.DIRECT_RETURN,
                proof_layer_used=ProofLayer.TOPOLOGY,
            ),
            TerminalReturnValueProof(
                handler_serial=2,
                carrier=ReturnCarrierRegister(0, 8),
                def_sites=(DefSiteLike(3, 0x200), DefSiteLike(4, 0x300)),
                ambiguous=True,
                topology_kind=TerminalReturnSourceKind.SHARED_EPILOGUE,
                proof_layer_used=ProofLayer.CHAIN_BACKED,
            ),
            TerminalReturnValueProof(
                handler_serial=3,
                carrier=ReturnCarrierRegister(0, 8),
                def_sites=(),
                ambiguous=False,
                topology_kind=TerminalReturnSourceKind.UNREACHABLE,
                proof_layer_used=ProofLayer.UNRESOLVED,
            ),
        )
        report = TerminalReturnProofReport(function_ea=0x401000, proofs=proofs)
        summary = report.summary()
        assert "3 handlers" in summary
        assert "0 resolved" in summary
        assert "1 topology-only" in summary
        assert "1 ambiguous" in summary
        assert "1 unresolved" in summary

    def test_empty_report_summary(self) -> None:
        report = TerminalReturnProofReport(function_ea=0x0, proofs=())
        assert "0 handlers" in report.summary()


# ---------------------------------------------------------------------------
# Orchestrator: topology layer (no IDA needed)
# ---------------------------------------------------------------------------


class TestTopologyLayer:
    """Test topology-only proof resolution via prove_terminal_returns."""

    @staticmethod
    def _make_audit(
        source_kind: TerminalReturnSourceKind,
        has_rax_write: bool | None,
        handler_serial: int = 10,
    ) -> TerminalReturnAuditReport:
        site = TerminalReturnSiteAudit(
            handler_serial=handler_serial,
            exit_serial=11,
            source_kind=source_kind,
            return_block_serial=12,
            exit_path_length=0,
            has_rax_write=has_rax_write,
        )
        return TerminalReturnAuditReport(
            function_ea=0x401000,
            total_handlers=5,
            terminal_handlers=1,
            sites=(site,),
        )

    def test_topology_layer_resolves_direct_return_with_rax_write(self) -> None:
        audit = self._make_audit(
            TerminalReturnSourceKind.DIRECT_RETURN,
            has_rax_write=True,
        )
        # mba=None disables layers 2-4, so only topology can fire.
        report = prove_terminal_returns(mba=None, audit_report=audit)
        assert len(report.proofs) == 1
        proof = report.proofs[0]
        assert proof.proof_layer_used == ProofLayer.TOPOLOGY
        assert proof.handler_serial == 10
        assert proof.ambiguous is False

    def test_unresolved_when_no_layers_match(self) -> None:
        audit = self._make_audit(
            TerminalReturnSourceKind.UNREACHABLE,
            has_rax_write=None,
        )
        report = prove_terminal_returns(mba=None, audit_report=audit)
        assert len(report.proofs) == 1
        proof = report.proofs[0]
        assert proof.proof_layer_used == ProofLayer.UNRESOLVED

    def test_topology_requires_both_conditions(self) -> None:
        # has_rax_write=True but source_kind is SHARED_EPILOGUE -> topology won't fire.
        audit = self._make_audit(
            TerminalReturnSourceKind.SHARED_EPILOGUE,
            has_rax_write=True,
        )
        report = prove_terminal_returns(mba=None, audit_report=audit)
        proof = report.proofs[0]
        assert proof.proof_layer_used == ProofLayer.UNRESOLVED

    def test_topology_requires_rax_write_true(self) -> None:
        # source_kind=DIRECT_RETURN but has_rax_write=None -> topology won't fire.
        audit = self._make_audit(
            TerminalReturnSourceKind.DIRECT_RETURN,
            has_rax_write=None,
        )
        report = prove_terminal_returns(mba=None, audit_report=audit)
        proof = report.proofs[0]
        assert proof.proof_layer_used == ProofLayer.UNRESOLVED
