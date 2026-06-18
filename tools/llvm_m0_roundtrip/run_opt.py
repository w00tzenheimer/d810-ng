"""Run the LLVM-M0 lab round-trip fixture through a conservative opt pipeline.

This script is intentionally a lab tool, not a d810 runtime dependency.  It
finds an external LLVM ``opt`` binary, verifies the hand-authored fixture, runs a
small middle-end pipeline, and compares the result with the checked-in
``after.ll`` artifact.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

PIPELINE = "instcombine,reassociate,sccp,simplifycfg,adce"


@dataclass(frozen=True, slots=True)
class OptResult:
    opt: Path
    before: Path
    after: Path
    optimized: str


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def fixture_dir() -> Path:
    return Path(__file__).resolve().parent / "fixtures"


def default_before() -> Path:
    return fixture_dir() / "lab_flat_branchless.before.ll"


def default_after() -> Path:
    return fixture_dir() / "lab_flat_branchless.after.ll"


def find_opt() -> Path | None:
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


def normalize_ir(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("; ModuleID = "):
            lines.append("; ModuleID = 'lab_flat_branchless.before.ll'")
            continue
        lines.append(line.rstrip())
    return "\n".join(lines).strip() + "\n"


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def run_opt(
    *,
    opt: Path | None = None,
    before: Path | None = None,
    after: Path | None = None,
) -> OptResult:
    opt_path = opt or find_opt()
    if opt_path is None:
        raise FileNotFoundError(
            "LLVM opt not found; set LLVM_OPT or install opt in PATH/"
            "/opt/homebrew/opt/llvm/bin/opt"
        )
    before_path = before or default_before()
    after_path = after or default_after()

    verify = _run([str(opt_path), "-S", "-passes=verify", str(before_path), "-o", "-"])
    if verify.returncode != 0:
        raise RuntimeError(
            f"opt verify failed for {before_path}:\n{verify.stderr or verify.stdout}"
        )

    with tempfile.TemporaryDirectory(prefix="d810-llvm-m0-") as tmp:
        out_path = Path(tmp) / "optimized.ll"
        proc = _run(
            [
                str(opt_path),
                "-S",
                f"-passes={PIPELINE}",
                str(before_path),
                "-o",
                str(out_path),
            ]
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"opt pipeline failed for {before_path}:\n{proc.stderr or proc.stdout}"
            )
        optimized = normalize_ir(out_path.read_text(encoding="utf-8"))

    expected = normalize_ir(after_path.read_text(encoding="utf-8"))
    if optimized != expected:
        raise AssertionError(
            "optimized IR differs from checked-in after.ll; refresh intentionally "
            "only after reviewing the semantic diff"
        )
    return OptResult(opt=opt_path, before=before_path, after=after_path, optimized=optimized)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, default=default_before())
    parser.add_argument("--after", type=Path, default=default_after())
    parser.add_argument("--opt", type=Path, default=None)
    parser.add_argument(
        "--print",
        action="store_true",
        help="print the normalized optimized IR after verification",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_opt(opt=args.opt, before=args.before, after=args.after)
    except Exception as exc:  # pragma: no cover - exercised through CLI behavior
        print(f"llvm-m0 run failed: {exc}", file=sys.stderr)
        return 1
    if args.print:
        print(result.optimized, end="")
    else:
        print(
            f"llvm-m0 ok: {result.before.relative_to(repo_root())} -> "
            f"{result.after.relative_to(repo_root())} via {result.opt}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
