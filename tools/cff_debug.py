#!/usr/bin/env python3
"""One-line CLI for the CFF dump + analysis workflow (Docker harness).

Subcommands wrap the recurring loop of:
    1. kick a docker dump run
    2. locate the latest dump .txt and diag .sqlite3 for a worktree
    3. extract the AFTER pseudocode, STATS, residuals, witness variables
    4. inspect a semantic state node via the diag DB
    5. passthrough to `python -m d810.core.diag` with PYTHONPATH pre-wired

All commands operate against a worktree under `<repo>/.worktrees/<name>/`
(default: `unflattening-engine-extraction`). Absolute paths are derived from
this script's location so it works regardless of cwd.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import subprocess
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
TOOLS_DIR = SCRIPT_PATH.parent
TOOLS_SCRIPTS_DIR = TOOLS_DIR / "scripts"
REPO_ROOT = SCRIPT_PATH.parents[1]
DEFAULT_WORKTREE = "unflattening-engine-extraction"
DEFAULT_FUNCTION = "sub_7FFD3338C040"
DEFAULT_PROJECT = "hodur_flag2.json"
DEFAULT_CAPTURE_POST_MATURITY = "8"  # MMAT_GLBOPT1
DEFAULT_EXTRAS = [
    "--dump-microcode-maturity",
    "CALLS,GLBOPT1",
    "--dump-microcode-d810",
    "--dump-terminal-return-valranges",
    "--dump-bst-maturity",
    "GLBOPT1",
]

EXTRACT_AFTER = TOOLS_SCRIPTS_DIR / "extract_after_pseudocode.py"
INSPECT_STATE = TOOLS_SCRIPTS_DIR / "inspect_linearized_state_node.py"
DOCKER_RUNNER = TOOLS_SCRIPTS_DIR / "run_system_tests_docker.sh"


# ---------------------------------------------------------------------------
# path helpers
# ---------------------------------------------------------------------------

def _die(msg: str, code: int = 1) -> None:
    print(f"cff-debug: error: {msg}", file=sys.stderr)
    raise SystemExit(code)


def worktree_dir(name: str) -> Path:
    root = REPO_ROOT / ".worktrees" / name
    if not root.is_dir():
        _die(f"worktree not found: {root}")
    return root


def worktree_tmp(name: str) -> Path:
    return worktree_dir(name) / ".tmp"


def worktree_log_dir(name: str) -> Path:
    return worktree_tmp(name) / "logs" / "d810_logs"


def _latest(paths: list[Path]) -> Path | None:
    if not paths:
        return None
    return max(paths, key=lambda p: p.stat().st_mtime)


def latest_dump(name: str) -> Path:
    tmp = worktree_tmp(name)
    if not tmp.is_dir():
        _die(f"worktree .tmp dir not found: {tmp}")
    cand = list(tmp.glob("*.txt"))
    p = _latest(cand)
    if p is None:
        _die(f"no *.txt dumps under {tmp}")
    return p  # type: ignore[return-value]


def latest_db(name: str) -> Path:
    d = worktree_log_dir(name)
    if not d.is_dir():
        _die(f"diag log dir not found: {d}")
    cand = list(d.glob("*.diag.sqlite3"))
    p = _latest(cand)
    if p is None:
        _die(f"no diag sqlite3 DBs under {d}")
    return p  # type: ignore[return-value]


def resolve_dump(name: str, explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.is_file():
            _die(f"dump not found: {p}")
        return p
    return latest_dump(name)


def resolve_db(name: str, explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit).expanduser().resolve()
        if not p.is_file():
            _die(f"db not found: {p}")
        return p
    return latest_db(name)


# ---------------------------------------------------------------------------
# dump body extraction (local, duplicates extract_after for internal use)
# ---------------------------------------------------------------------------

AFTER_START = "--- AFTER ---"
AFTER_END_PREFIX = "=== STATS:"


def read_dump_lines(dump: Path) -> list[str]:
    return dump.read_text(errors="replace").splitlines()


def after_slice(lines: list[str]) -> tuple[int, int]:
    start: int | None = None
    end: int | None = None
    for i, raw in enumerate(lines):
        if raw.strip() == AFTER_START:
            start = i + 1
            continue
        if start is not None and raw.startswith(AFTER_END_PREFIX):
            end = i
            break
    if start is None:
        _die("dump has no '--- AFTER ---' marker")
    if end is None:
        end = len(lines)
    return start, end  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# subcommands
# ---------------------------------------------------------------------------

def cmd_paths(args: argparse.Namespace) -> int:
    dump = resolve_dump(args.worktree, None)
    db = resolve_db(args.worktree, None)
    print(f"DUMP={dump}")
    print(f"DB={db}")
    return 0


def cmd_dump(args: argparse.Namespace) -> int:
    wt = args.worktree
    work_dir = worktree_dir(wt)
    tmp = worktree_tmp(wt)
    tmp.mkdir(parents=True, exist_ok=True)

    log_dir = worktree_log_dir(wt)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "d810.log"
    try:
        log_file.write_text("")
    except OSError as exc:
        _die(f"failed truncating {log_file}: {exc}")

    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"{args.prefix}_{args.label}_{ts}.txt"

    extras = args.extra if args.extra else list(DEFAULT_EXTRAS)

    argv: list[str] = [
        str(DOCKER_RUNNER),
        "dump",
        "-f", args.function,
        "-p", args.project,
        "-w", wt,
        "-o", out_name,
    ]
    if not args.no_debug_logging:
        argv.append("-l")
        argv.append("--enable-debug-logging")
    argv.append("--")
    argv.extend(extras)

    env = os.environ.copy()
    env["D810_CAPTURE_POST_MATURITY"] = str(args.capture_post_maturity)
    env.setdefault("D810_REPO_ROOT", str(REPO_ROOT))

    print(f"cff-debug: dump -> {tmp / out_name}", file=sys.stderr)
    print(f"cff-debug: D810_CAPTURE_POST_MATURITY={env['D810_CAPTURE_POST_MATURITY']}", file=sys.stderr)
    print(f"cff-debug: argv: {' '.join(argv)}", file=sys.stderr)

    rc = subprocess.call(argv, env=env, cwd=str(REPO_ROOT))

    dump_path = tmp / out_name
    print(f"DUMP={dump_path}")
    try:
        db = latest_db(wt)
        print(f"DB={db}")
    except SystemExit:
        print("DB=(none)")
    return rc


def cmd_after(args: argparse.Namespace) -> int:
    dump = resolve_dump(args.worktree, args.dump)
    argv = [sys.executable, str(EXTRACT_AFTER), str(dump)]
    if args.line_numbers:
        argv.append("-n")
    return subprocess.call(argv)


def cmd_stats(args: argparse.Namespace) -> int:
    dump = resolve_dump(args.worktree, args.dump)
    lines = read_dump_lines(dump)
    emitting = False
    emitted_any = False
    for i, raw in enumerate(lines, start=1):
        if raw.startswith("=== STATS:"):
            emitting = True
            print(f"{i}: {raw}")
            emitted_any = True
            continue
        if emitting:
            if raw.startswith("==="):
                print(f"{i}: {raw}")
                break
            print(f"{i}: {raw}")
    if not emitted_any:
        _die(f"no '=== STATS:' block in {dump}")
    return 0


def _iter_after_numbered(dump: Path):
    lines = read_dump_lines(dump)
    start, end = after_slice(lines)
    for i in range(start, end):
        yield i + 1, lines[i]


def cmd_residuals(args: argparse.Namespace) -> int:
    import re
    dump = resolve_dump(args.worktree, args.dump)
    vars_ = args.var or ["i"]
    # match `<var> = 0x...;` — allow leading whitespace, tolerate trailing comment
    patterns = [re.compile(rf"\b{re.escape(v)}\s*=\s*0x[0-9A-Fa-f]+") for v in vars_]
    # also generic `vNN = 0x...;` when user didn't override
    if args.var is None:
        patterns.append(re.compile(r"\bv\d+\s*=\s*0x[0-9A-Fa-f]+"))
    any_hit = False
    for line_no, text in _iter_after_numbered(dump):
        if any(p.search(text) for p in patterns):
            print(f"{line_no}: {text}")
            any_hit = True
    if not any_hit:
        print("(no residual assignments found)", file=sys.stderr)
    return 0


def cmd_witness(args: argparse.Namespace) -> int:
    import re
    dump = resolve_dump(args.worktree, args.dump)
    vars_ = args.var or ["v187", "v50", "v49"]
    patterns = [re.compile(rf"\b{re.escape(v)}\b") for v in vars_]
    any_hit = False
    for line_no, text in _iter_after_numbered(dump):
        if any(p.search(text) for p in patterns):
            print(f"{line_no}: {text}")
            any_hit = True
    if not any_hit:
        print("(no witness matches)", file=sys.stderr)
    return 0


def cmd_state(args: argparse.Namespace) -> int:
    dump = resolve_dump(args.worktree, args.dump)
    db = resolve_db(args.worktree, args.db)
    argv = [
        sys.executable,
        str(INSPECT_STATE),
        "--db", str(db),
        "--state", args.state,
        "--dump", str(dump),
        "--context", str(args.context),
    ]
    return subprocess.call(argv)


def cmd_db(args: argparse.Namespace) -> int:
    wt = args.worktree
    worktree = worktree_dir(wt)
    passthrough = list(args.args or [])
    if not any(tok == "--db" for tok in passthrough):
        db = resolve_db(wt, None)
        passthrough = passthrough + ["--db", str(db)]
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    argv = [sys.executable, "-m", "d810.core.diag", *passthrough]
    return subprocess.call(argv, env=env)


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def _add_worktree(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--worktree",
        default=DEFAULT_WORKTREE,
        help=f"worktree name under .worktrees/ (default: {DEFAULT_WORKTREE})",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cff-debug",
        description="One-line CLI for the CFF dump + analysis workflow (Docker harness).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("paths", help="print resolved latest DUMP= and DB= paths")
    _add_worktree(sp)
    sp.set_defaults(func=cmd_paths)

    sp = sub.add_parser("dump", help="run the docker pseudocode dump")
    _add_worktree(sp)
    sp.add_argument("-f", "--function", default=DEFAULT_FUNCTION)
    sp.add_argument("-p", "--project", default=DEFAULT_PROJECT)
    sp.add_argument("--prefix", default="dump",
                    help="dump filename prefix: {prefix}_{label}_{ts}.txt (default: dump)")
    sp.add_argument("--label", default="catchup",
                    help="label embedded in the output filename (default: catchup)")
    sp.add_argument("--capture-post-maturity", default=DEFAULT_CAPTURE_POST_MATURITY,
                    help="D810_CAPTURE_POST_MATURITY value (default: 8 = MMAT_GLBOPT1)")
    sp.add_argument("--no-debug-logging", action="store_true",
                    help="do not pass -l / --enable-debug-logging to the docker runner")
    sp.add_argument("--extra", action="append",
                    help="extra pytest arg (repeatable); if any provided, replaces defaults")
    sp.set_defaults(func=cmd_dump)

    sp = sub.add_parser("after", help="print AFTER pseudocode body from the latest dump")
    _add_worktree(sp)
    sp.add_argument("--dump", help="explicit dump file (default: latest in worktree)")
    sp.add_argument("-n", "--line-numbers", action="store_true")
    sp.set_defaults(func=cmd_after)

    sp = sub.add_parser("stats", help="print the '=== STATS: ===' block from the latest dump")
    _add_worktree(sp)
    sp.add_argument("--dump", help="explicit dump file (default: latest in worktree)")
    sp.set_defaults(func=cmd_stats)

    sp = sub.add_parser(
        "residuals",
        help="print 'i = 0x...;' (or --var) residual assignments inside AFTER pseudocode",
    )
    _add_worktree(sp)
    sp.add_argument("--dump", help="explicit dump file (default: latest in worktree)")
    sp.add_argument("--var", action="append",
                    help="variable name to match (default: i plus vNN)")
    sp.set_defaults(func=cmd_residuals)

    sp = sub.add_parser(
        "witness",
        help="print preservation-witness lines (v187/v50/v49 by default) inside AFTER",
    )
    _add_worktree(sp)
    sp.add_argument("--dump", help="explicit dump file (default: latest in worktree)")
    sp.add_argument("--var", action="append",
                    help="variable name to match (default: v187, v50, v49)")
    sp.set_defaults(func=cmd_witness)

    sp = sub.add_parser(
        "state",
        help="wrap inspect_linearized_state_node.py with auto DB + dump",
    )
    _add_worktree(sp)
    sp.add_argument("state", help="state constant, e.g. 0x4C77464F")
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument("--dump", help="explicit dump file (default: latest in worktree)")
    sp.add_argument("--context", type=int, default=6)
    sp.set_defaults(func=cmd_state)

    sp = sub.add_parser(
        "db",
        help="passthrough to `python -m d810.core.diag`; args after `--`",
    )
    _add_worktree(sp)
    sp.add_argument("args", nargs=argparse.REMAINDER,
                    help="all args after `--` are forwarded to d810.core.diag")
    sp.set_defaults(func=cmd_db)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # argparse.REMAINDER captures the literal `--`; strip it if present.
    if getattr(args, "args", None):
        if args.args and args.args[0] == "--":
            args.args = args.args[1:]
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
