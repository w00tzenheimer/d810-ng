"""Structured LLVM IR verification helpers.

This module is intentionally IDA-free. It wraps the external ``opt`` verifier
used by M1 tests and live probes without making LLVM a runtime dependency.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from d810.core.typing import Mapping


class LlvmVerificationStatus(str, Enum):
    PASSED = "passed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class LlvmVerificationResult:
    status: LlvmVerificationStatus
    opt_path: Path | None
    command: tuple[str, ...]
    stdout: str
    stderr: str
    reason: str

    @property
    def passed(self) -> bool:
        return self.status is LlvmVerificationStatus.PASSED

    @property
    def skipped(self) -> bool:
        return self.status is LlvmVerificationStatus.SKIPPED

    @property
    def failed(self) -> bool:
        return self.status is LlvmVerificationStatus.FAILED


def find_llvm_opt(env: Mapping[str, str] | None = None) -> Path | None:
    """Find an LLVM ``opt`` executable without requiring LLVM at runtime."""
    lookup_env = env if env is not None else os.environ
    path_env = lookup_env.get("PATH") if env is not None else None
    candidates = [
        lookup_env.get("LLVM_OPT"),
        "/opt/homebrew/opt/llvm/bin/opt",
        shutil.which("opt", path=path_env),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return path
    return None


def verify_llvm_ir(
    ir_text: str,
    *,
    function_name: str = "d810_fn",
    opt_path: Path | None = None,
    tmp_dir: Path | None = None,
) -> LlvmVerificationResult:
    """Verify textual LLVM IR with ``opt -passes=verify`` when available."""
    opt = opt_path or find_llvm_opt()
    if opt is None:
        return LlvmVerificationResult(
            status=LlvmVerificationStatus.SKIPPED,
            opt_path=None,
            command=(),
            stdout="",
            stderr="",
            reason="LLVM opt not found; set LLVM_OPT or install opt in PATH/Homebrew LLVM",
        )
    if not opt.is_file() or not os.access(opt, os.X_OK):
        return LlvmVerificationResult(
            status=LlvmVerificationStatus.SKIPPED,
            opt_path=opt,
            command=(),
            stdout="",
            stderr="",
            reason=f"LLVM opt is not executable: {opt}",
        )

    def _run_in(directory: Path) -> LlvmVerificationResult:
        directory.mkdir(parents=True, exist_ok=True)
        ir_path = directory / "d810-verify.ll"
        ir_path.write_text(ir_text, encoding="utf-8")
        command = (str(opt), "-S", "-passes=verify", str(ir_path), "-o", "-")
        proc = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode == 0:
            return LlvmVerificationResult(
                status=LlvmVerificationStatus.PASSED,
                opt_path=opt,
                command=command,
                stdout=proc.stdout,
                stderr=proc.stderr,
                reason="",
            )
        return LlvmVerificationResult(
            status=LlvmVerificationStatus.FAILED,
            opt_path=opt,
            command=command,
            stdout=proc.stdout,
            stderr=proc.stderr,
            reason=proc.stderr or proc.stdout or f"opt exited with {proc.returncode}",
        )

    if tmp_dir is not None:
        return _run_in(tmp_dir)

    with tempfile.TemporaryDirectory(prefix="d810-llvm-verify-") as temp:
        return _run_in(Path(temp))
