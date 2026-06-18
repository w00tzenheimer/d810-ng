"""LLVM M1b live-lift maturity probe over real Hex-Rays snapshots."""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")
import idaapi

from d810.backends.hexrays.lifter import lift_function
from d810.backends.llvm import (
    LLVM_M1_PREFERRED_MATURITY,
    assess_flowgraph_maturity,
    emit_flowgraph_to_llvm,
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


def _find_opt() -> Path | None:
    candidates = [
        os.environ.get("LLVM_OPT"),
        "/opt/homebrew/opt/llvm/bin/opt",
        shutil.which("opt"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return path
    return None


def _verify_with_opt(opt: Path, ir_text: str, tmp_path: Path) -> None:
    ir_path = tmp_path / "lab_if_diamond.m1b.ll"
    ir_path.write_text(ir_text, encoding="utf-8")
    proc = subprocess.run(
        [str(opt), "-S", "-passes=verify", str(ir_path), "-o", "-"],
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


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

        opt = _find_opt()
        if opt is not None:
            _verify_with_opt(opt, preferred_ir, tmp_path)
        else:
            print("LLVM opt not found; live supported-lift gate passed without opt -verify")
