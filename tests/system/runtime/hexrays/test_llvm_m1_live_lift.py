"""LLVM M1b live-lift maturity probe over real Hex-Rays snapshots."""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")
import idaapi

from d810.backends.hexrays.lifter import lift_function
from d810.backends.llvm import (
    LLVM_M1_PREFERRED_MATURITY,
    LlvmIdentityParityStatus,
    UnsupportedLiftKind,
    assess_flowgraph_maturity,
    check_identity_roundtrip,
    emit_flowgraph_to_llvm,
    verify_llvm_ir,
)
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.ir.maturity import IRMaturity
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


_PROBED_MATURITIES = (
    ida_hexrays.MMAT_CALLS,
    ida_hexrays.MMAT_GLBOPT1,
    ida_hexrays.MMAT_GLBOPT2,
)


@dataclass(frozen=True, slots=True)
class _ProbeRow:
    maturity_name: str
    ir_maturity: IRMaturity | None
    block_count: int
    accepted: bool
    preferred: bool
    supported: bool
    unsupported_reasons: tuple[str, ...]

    def summary(self) -> str:
        ir_name = self.ir_maturity.name if self.ir_maturity is not None else "<none>"
        reasons = "; ".join(self.unsupported_reasons[:6]) or "-"
        return (
            f"{self.maturity_name}: ir={ir_name} blocks={self.block_count} "
            f"accepted={self.accepted} preferred={self.preferred} "
            f"supported={self.supported} reasons={reasons}"
        )


@dataclass(frozen=True, slots=True)
class _CensusRow:
    function_name: str
    maturity_name: str
    block_count: int
    supported: bool
    missing: bool
    unsupported_kind_counts: tuple[tuple[str, int], ...]
    unsupported_operation_counts: tuple[tuple[str, int], ...]

    def summary(self) -> str:
        if self.missing:
            return f"{self.function_name}: missing/skipped"
        histogram = ",".join(
            f"{kind}={count}" for kind, count in self.unsupported_kind_counts
        ) or "-"
        operations = ",".join(
            f"{operation}={count}"
            for operation, count in self.unsupported_operation_counts
        ) or "-"
        return (
            f"{self.function_name}: maturity={self.maturity_name} "
            f"blocks={self.block_count} supported={self.supported} "
            f"kinds={histogram} operations={operations}"
        )


@dataclass(frozen=True, slots=True)
class _ParityRow:
    function_name: str
    block_count: int
    supported: bool
    missing: bool
    parity_status: str
    mismatch_count: int
    reason: str

    def summary(self) -> str:
        if self.missing:
            return f"{self.function_name}: missing/skipped"
        return (
            f"{self.function_name}: blocks={self.block_count} "
            f"supported={self.supported} parity={self.parity_status} "
            f"mismatches={self.mismatch_count} reason={self.reason or '-'}"
        )


class TestLLVMM1LiveLiftProbe:
    """Probe M1 freeze candidates on one real restructuring-lab function."""

    binary_name = "restructuring_lab.dll"

    def test_lab_if_diamond_has_a_supported_live_lift_candidate(
        self, ida_database, configure_hexrays, tmp_path
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        func_ea = get_func_ea("lab_if_diamond")
        assert func_ea != idaapi.BADADDR

        rows: list[_ProbeRow] = []
        preferred_row: _ProbeRow | None = None
        preferred_ir: str | None = None
        for maturity in _PROBED_MATURITIES:
            maturity_name = maturity_to_string(int(maturity))
            mba = gen_microcode_at_maturity(func_ea, int(maturity))
            if mba is None:
                rows.append(
                    _ProbeRow(
                        maturity_name=maturity_name,
                        ir_maturity=None,
                        block_count=0,
                        accepted=False,
                        preferred=False,
                        supported=False,
                        unsupported_reasons=("gen_microcode returned None",),
                    )
                )
                continue

            flow_graph = lift_function(mba).flow_graph
            assessment = assess_flowgraph_maturity(flow_graph)
            result = emit_flowgraph_to_llvm(
                flow_graph,
                function_name=f"lab_if_diamond_{maturity_name.lower()}",
            )
            reasons = tuple(
                f"blk{reason.block_serial}:{reason.operation}:{reason.reason}"
                for reason in result.unsupported
            )
            row = _ProbeRow(
                maturity_name=maturity_name,
                ir_maturity=assessment.observed,
                block_count=flow_graph.block_count,
                accepted=assessment.accepted,
                preferred=assessment.preferred,
                supported=result.supported,
                unsupported_reasons=reasons,
            )
            rows.append(row)
            if assessment.observed is LLVM_M1_PREFERRED_MATURITY:
                preferred_row = row
                if assessment.accepted and result.supported:
                    preferred_ir = result.ir_text

        print("\n=== LLVM M1b live-lift support matrix ===")
        for row in rows:
            print(row.summary())

        assert any(row.accepted for row in rows), "\n".join(row.summary() for row in rows)
        assert any(row.accepted and row.supported for row in rows), (
            "No accepted maturity emitted supported LLVM IR for lab_if_diamond:\n"
            + "\n".join(row.summary() for row in rows)
        )
        assert preferred_row is not None, (
            f"Preferred maturity {LLVM_M1_PREFERRED_MATURITY.name} was not probed:\n"
            + "\n".join(row.summary() for row in rows)
        )
        assert preferred_row.accepted, (
            "Preferred LLVM M1 freeze point was not accepted:\n"
            + "\n".join(row.summary() for row in rows)
        )
        assert preferred_row.supported and preferred_ir is not None, (
            "Preferred LLVM M1 freeze point did not emit supported LLVM IR:\n"
            + "\n".join(row.summary() for row in rows)
        )

        verification = verify_llvm_ir(
            preferred_ir,
            function_name="lab_if_diamond_m1_preferred",
            tmp_dir=tmp_path,
        )
        print(
            "LLVM verification: "
            f"status={verification.status.value} "
            f"opt={verification.opt_path or '<none>'} "
            f"reason={verification.reason or '-'}"
        )
        if verification.skipped and os.environ.get("D810_REQUIRE_LLVM_OPT") == "1":
            raise AssertionError(
                "D810_REQUIRE_LLVM_OPT=1 requires LLVM verification to run; "
                f"reason={verification.reason or '-'}"
            )
        if verification.failed:
            raise AssertionError(
                verification.reason or verification.stderr or verification.stdout
            )


class TestLLVMM1CoverageCensus:
    """Census selected restructuring-lab functions at the preferred M1 maturity."""

    binary_name = "restructuring_lab.dll"

    _FUNCTIONS = (
        "lab_if_diamond",
        "lab_flat_branchless",
        "lab_flat_jtbl",
        "lab_flat_mini",
        "lab_flat_cond",
        "lab_flat_loop",
        "lab_flat_region",
        "hexrays_lab_side_effect_boundary_anchor",
    )

    def test_restructuring_lab_preferred_maturity_census(
        self, ida_database, configure_hexrays
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        rows: list[_CensusRow] = []
        total_kind_counts: Counter[str] = Counter()
        for function_name in self._FUNCTIONS:
            func_ea = get_func_ea(function_name)
            if func_ea == idaapi.BADADDR:
                rows.append(
                    _CensusRow(
                        function_name=function_name,
                        maturity_name="MMAT_GLBOPT1",
                        block_count=0,
                        supported=False,
                        missing=True,
                        unsupported_kind_counts=(),
                        unsupported_operation_counts=(),
                    )
                )
                continue

            mba = gen_microcode_at_maturity(func_ea, int(ida_hexrays.MMAT_GLBOPT1))
            if mba is None:
                rows.append(
                    _CensusRow(
                        function_name=function_name,
                        maturity_name="MMAT_GLBOPT1",
                        block_count=0,
                        supported=False,
                        missing=True,
                        unsupported_kind_counts=(("microcode_unavailable", 1),),
                        unsupported_operation_counts=(),
                    )
                )
                continue

            flow_graph = lift_function(mba).flow_graph
            result = emit_flowgraph_to_llvm(flow_graph, function_name=function_name)
            kind_counts = Counter(reason.kind.value for reason in result.unsupported)
            operation_counts = Counter(
                reason.operation for reason in result.unsupported
            )
            total_kind_counts.update(kind_counts)
            rows.append(
                _CensusRow(
                    function_name=function_name,
                    maturity_name="MMAT_GLBOPT1",
                    block_count=flow_graph.block_count,
                    supported=result.supported,
                    missing=False,
                    unsupported_kind_counts=tuple(sorted(kind_counts.items())),
                    unsupported_operation_counts=tuple(
                        sorted(operation_counts.items())
                    ),
                )
            )

        print("\n=== LLVM M1 preferred-maturity coverage census ===")
        for row in rows:
            print(row.summary())
        total_histogram = ", ".join(
            f"{kind}={count}" for kind, count in sorted(total_kind_counts.items())
        ) or "-"
        print(f"TOTAL unsupported-kind histogram: {total_histogram}")

        present_rows = [row for row in rows if not row.missing]
        assert present_rows, "No census functions were present in restructuring_lab.dll"
        assert any(row.function_name == "lab_if_diamond" for row in present_rows), (
            "Known-supported lab_if_diamond was not present:\n"
            + "\n".join(row.summary() for row in rows)
        )
        assert any(row.supported for row in present_rows), "\n".join(
            row.summary() for row in rows
        )
        for row in present_rows:
            if row.supported:
                continue
            assert row.unsupported_kind_counts, (
                "Unsupported census row lacked structured diagnostics:\n"
                + row.summary()
            )
            for kind, _count in row.unsupported_kind_counts:
                assert kind in {item.value for item in UnsupportedLiftKind}


class TestLLVMM1IdentityParity:
    """Check portable identity parity for preferred-maturity live M1 lifts."""

    binary_name = "restructuring_lab.dll"

    _FUNCTIONS = TestLLVMM1CoverageCensus._FUNCTIONS

    def test_restructuring_lab_preferred_maturity_identity_parity(
        self, ida_database, configure_hexrays
    ):
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        rows: list[_ParityRow] = []
        for function_name in self._FUNCTIONS:
            func_ea = get_func_ea(function_name)
            if func_ea == idaapi.BADADDR:
                rows.append(
                    _ParityRow(
                        function_name=function_name,
                        block_count=0,
                        supported=False,
                        missing=True,
                        parity_status="missing",
                        mismatch_count=0,
                        reason="function not present in fixture",
                    )
                )
                continue

            mba = gen_microcode_at_maturity(func_ea, int(ida_hexrays.MMAT_GLBOPT1))
            if mba is None:
                rows.append(
                    _ParityRow(
                        function_name=function_name,
                        block_count=0,
                        supported=False,
                        missing=True,
                        parity_status="missing",
                        mismatch_count=0,
                        reason="gen_microcode returned None",
                    )
                )
                continue

            flow_graph = lift_function(mba).flow_graph
            lift = emit_flowgraph_to_llvm(flow_graph, function_name=function_name)
            parity = check_identity_roundtrip(
                flow_graph,
                function_name=function_name,
                lift_result=lift,
            )
            rows.append(
                _ParityRow(
                    function_name=function_name,
                    block_count=flow_graph.block_count,
                    supported=lift.supported,
                    missing=False,
                    parity_status=parity.status.value,
                    mismatch_count=len(parity.mismatches),
                    reason=parity.reason or "",
                )
            )

        print("\n=== LLVM M1 preferred-maturity identity parity ===")
        for row in rows:
            print(row.summary())

        present_rows = [row for row in rows if not row.missing]
        assert present_rows, "No parity functions were present in restructuring_lab.dll"
        lab_if_rows = [row for row in present_rows if row.function_name == "lab_if_diamond"]
        assert lab_if_rows, (
            "Known-supported lab_if_diamond was not present:\n"
            + "\n".join(row.summary() for row in rows)
        )
        assert lab_if_rows[0].parity_status == LlvmIdentityParityStatus.PASSED.value, (
            "lab_if_diamond did not pass portable identity parity:\n"
            + "\n".join(row.summary() for row in rows)
        )
        for row in present_rows:
            if not row.supported:
                assert row.parity_status == LlvmIdentityParityStatus.UNSUPPORTED.value, (
                    "Unsupported lift reported misleading parity success:\n"
                    + row.summary()
                )
                continue
            assert row.parity_status == LlvmIdentityParityStatus.PASSED.value, (
                "Supported lift failed portable identity parity:\n"
                + "\n".join(row.summary() for row in rows)
            )
