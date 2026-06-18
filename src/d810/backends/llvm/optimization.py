"""Structured LLVM opt pipeline helpers for M2.

This module is intentionally IDA-free. It runs external ``opt`` over textual
LLVM IR, captures stable metrics before/after optimization, and reports
structured skipped/failed results without making LLVM a runtime dependency.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from d810.backends.llvm.verification import find_llvm_opt


class LlvmOptimizationStatus(str, Enum):
    PASSED = "passed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class LlvmOptPipeline:
    name: str
    passes: tuple[str, ...]

    @property
    def pass_spec(self) -> str:
        return ",".join(self.passes)


@dataclass(frozen=True, slots=True)
class LlvmIrMetrics:
    block_count: int
    instruction_count: int
    terminator_count: int
    branch_count: int
    switch_count: int
    call_count: int
    load_count: int
    store_count: int
    alloca_count: int
    add_count: int
    and_count: int
    xor_count: int


@dataclass(frozen=True, slots=True)
class LlvmOptimizationResult:
    status: LlvmOptimizationStatus
    opt_path: Path | None
    command: tuple[str, ...]
    input_ir: str
    optimized_ir: str
    stdout: str
    stderr: str
    reason: str
    before_metrics: LlvmIrMetrics
    after_metrics: LlvmIrMetrics
    pipeline: LlvmOptPipeline

    @property
    def passed(self) -> bool:
        return self.status is LlvmOptimizationStatus.PASSED

    @property
    def skipped(self) -> bool:
        return self.status is LlvmOptimizationStatus.SKIPPED

    @property
    def failed(self) -> bool:
        return self.status is LlvmOptimizationStatus.FAILED


LLVM_M2A_STOCK_PIPELINE = LlvmOptPipeline(
    name="m2a_stock_instcombine_reassociate_sccp_simplifycfg_adce",
    passes=("instcombine", "reassociate", "sccp", "simplifycfg", "adce"),
)

_LABEL_RE = re.compile(r"^[A-Za-z$._-][A-Za-z0-9$._-]*:\s*(?:;.*)?$")
_TERMINATORS = ("ret ", "br ", "switch ", "indirectbr ", "invoke ", "resume ", "unreachable")


def normalize_llvm_ir(text: str) -> str:
    """Normalize non-semantic ``opt`` output noise for generic comparison."""
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.startswith("; ModuleID = "):
            lines.append("; ModuleID = '<normalized>'")
            continue
        lines.append(stripped)
    return "\n".join(lines).strip() + "\n"


def measure_llvm_ir(ir_text: str) -> LlvmIrMetrics:
    """Measure coarse LLVM IR structure without parsing full LLVM syntax."""
    block_count = 0
    instruction_count = 0
    terminator_count = 0
    branch_count = 0
    switch_count = 0
    call_count = 0
    load_count = 0
    store_count = 0
    alloca_count = 0
    add_count = 0
    and_count = 0
    xor_count = 0

    for raw_line in ir_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        if _LABEL_RE.match(line):
            block_count += 1
            continue
        if line.startswith(("define ", "declare ", "target ", "source_filename", "@", "}")):
            continue

        instruction_count += 1
        opcode = line.split("=", 1)[-1].strip() if "=" in line else line
        if opcode.startswith(_TERMINATORS):
            terminator_count += 1
        if opcode.startswith("br "):
            branch_count += 1
        if opcode.startswith("switch "):
            switch_count += 1
        if " call " in f" {opcode} " or opcode.startswith("call "):
            call_count += 1
        if " load " in f" {opcode} " or opcode.startswith("load "):
            load_count += 1
        if opcode.startswith("store "):
            store_count += 1
        if " alloca " in f" {opcode} " or opcode.startswith("alloca "):
            alloca_count += 1
        if opcode.startswith("add "):
            add_count += 1
        if opcode.startswith("and "):
            and_count += 1
        if opcode.startswith("xor "):
            xor_count += 1

    return LlvmIrMetrics(
        block_count=block_count,
        instruction_count=instruction_count,
        terminator_count=terminator_count,
        branch_count=branch_count,
        switch_count=switch_count,
        call_count=call_count,
        load_count=load_count,
        store_count=store_count,
        alloca_count=alloca_count,
        add_count=add_count,
        and_count=and_count,
        xor_count=xor_count,
    )


def run_llvm_opt_pipeline(
    ir_text: str,
    *,
    pipeline: LlvmOptPipeline = LLVM_M2A_STOCK_PIPELINE,
    opt_path: Path | None = None,
    tmp_dir: Path | None = None,
) -> LlvmOptimizationResult:
    """Run a stock LLVM opt pipeline and return structured metrics/results."""
    before = measure_llvm_ir(ir_text)
    opt = opt_path or find_llvm_opt()
    if opt is None:
        return LlvmOptimizationResult(
            status=LlvmOptimizationStatus.SKIPPED,
            opt_path=None,
            command=(),
            input_ir=ir_text,
            optimized_ir="",
            stdout="",
            stderr="",
            reason="LLVM opt not found; set LLVM_OPT or install opt in PATH/Homebrew LLVM",
            before_metrics=before,
            after_metrics=measure_llvm_ir(""),
            pipeline=pipeline,
        )
    if not opt.is_file() or not os.access(opt, os.X_OK):
        return LlvmOptimizationResult(
            status=LlvmOptimizationStatus.SKIPPED,
            opt_path=opt,
            command=(),
            input_ir=ir_text,
            optimized_ir="",
            stdout="",
            stderr="",
            reason=f"LLVM opt is not executable: {opt}",
            before_metrics=before,
            after_metrics=measure_llvm_ir(""),
            pipeline=pipeline,
        )

    def _run_in(directory: Path) -> LlvmOptimizationResult:
        directory.mkdir(parents=True, exist_ok=True)
        input_path = directory / "d810-opt-input.ll"
        output_path = directory / "d810-opt-output.ll"
        input_path.write_text(ir_text, encoding="utf-8")
        command = (
            str(opt),
            "-S",
            f"-passes={pipeline.pass_spec}",
            str(input_path),
            "-o",
            str(output_path),
        )
        proc = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            return LlvmOptimizationResult(
                status=LlvmOptimizationStatus.FAILED,
                opt_path=opt,
                command=command,
                input_ir=ir_text,
                optimized_ir="",
                stdout=proc.stdout,
                stderr=proc.stderr,
                reason=proc.stderr or proc.stdout or f"opt exited with {proc.returncode}",
                before_metrics=before,
                after_metrics=measure_llvm_ir(""),
                pipeline=pipeline,
            )
        optimized = output_path.read_text(encoding="utf-8")
        return LlvmOptimizationResult(
            status=LlvmOptimizationStatus.PASSED,
            opt_path=opt,
            command=command,
            input_ir=ir_text,
            optimized_ir=optimized,
            stdout=proc.stdout,
            stderr=proc.stderr,
            reason="",
            before_metrics=before,
            after_metrics=measure_llvm_ir(optimized),
            pipeline=pipeline,
        )

    if tmp_dir is not None:
        return _run_in(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="d810-llvm-opt-") as temp:
        return _run_in(Path(temp))
