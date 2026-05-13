#!/usr/bin/env python3
"""One-line CLI for the CFF dump + analysis workflow (Docker harness).

Subcommands wrap the recurring loop of:
    1. kick a docker dump run
    2. locate the latest dump .txt and diag .sqlite3 for a worktree
    3. extract the AFTER pseudocode, STATS, residuals, witness variables
    4. inspect a semantic state node via the diag DB
    5. passthrough to `python -m d810.diagnostics` with PYTHONPATH pre-wired

All commands operate against a worktree under `<repo>/.worktrees/<name>/`
(default: `unflattening-engine-extraction`). Absolute paths are derived from
this script's location so it works regardless of cwd.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve()
TOOLS_DIR = SCRIPT_PATH.parent
TOOLS_SCRIPTS_DIR = TOOLS_DIR / "scripts"

# Detect whether cff_debug is being run from inside an existing worktree
# checkout (under ``<repo>/.worktrees/<name>/tools/cff_debug.py``) or from a
# bare repo checkout (``<repo>/tools/cff_debug.py``).  When inside a worktree
# the "real" repo root is two parents above ``.worktrees/``, and the worktree
# name is the immediate parent of ``.worktrees/``.
if len(SCRIPT_PATH.parents) >= 4 and SCRIPT_PATH.parents[2].name == ".worktrees":
    REPO_ROOT = SCRIPT_PATH.parents[3]
    _CURRENT_WORKTREE: str | None = SCRIPT_PATH.parents[1].name
else:
    REPO_ROOT = SCRIPT_PATH.parents[1]
    _CURRENT_WORKTREE = None
DEFAULT_WORKTREE = _CURRENT_WORKTREE or "unflattening-engine-extraction"
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
    cand = [
        p for p in d.glob("*.diag.sqlite3")
        if p.is_file() and p.stat().st_size > 0
    ]
    p = _latest(cand)
    if p is None:
        _die(f"no non-empty diag sqlite3 DBs under {d}")
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
    """Workflow wrapper for `python -m d810.diagnostics dump-after`.

    Resolves the latest dump for the worktree (or honours --dump) and
    forwards the file path + ``-n`` flag. Parsing lives in
    ``d810.diagnostics.dump_after``.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    dump = resolve_dump(wt, args.dump)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "dump-after",
        str(dump),
    ]
    if args.line_numbers:
        diag_argv.append("-n")
    rc = subprocess.call(diag_argv, env=env)
    if rc != 0:
        return rc
    if args.stats:
        print()
        return cmd_stats(argparse.Namespace(worktree=wt, dump=str(dump)))
    return 0


def cmd_snap_render(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics snap-render`.

    Resolves the latest diag DB for the worktree (or honours --db) and
    forwards the snapshot id / label / focus serials.  Rendering lives
    in ``d810.diagnostics.snap_render`` -- this wrapper is pure path
    resolution + subprocess shell-out, per the cff_debug architecture
    rule (no SQL / parsing here).
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    db = resolve_db(wt, args.db)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "snap-render",
        "--db", str(db),
    ]
    if args.snapshot_id is not None:
        diag_argv += ["--snapshot-id", str(args.snapshot_id)]
    if args.label:
        diag_argv += ["--label", args.label]
    if args.serials:
        diag_argv += ["--serials", args.serials]
    if args.include_eas:
        diag_argv.append("--include-eas")
    return subprocess.call(diag_argv, env=env)


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
    """Workflow wrapper for `python -m d810.diagnostics inspect-state-node`.

    Resolves the latest dump + diag DB for the worktree (or honours
    --dump / --db). All SQL + dump parsing lives in
    ``d810.diagnostics.inspect_state_node``.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    dump = resolve_dump(wt, args.dump)
    db = resolve_db(wt, args.db)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "inspect-state-node",
        "--db", str(db),
        "--state", args.state,
        "--dump", str(dump),
        "--context", str(args.context),
    ]
    return subprocess.call(diag_argv, env=env)


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
    argv = [sys.executable, "-m", "d810.diagnostics", *passthrough]
    return subprocess.call(argv, env=env)


def cmd_trace(args: argparse.Namespace) -> int:
    """Dump + HCC byte-cascade trace in one shot."""
    os.environ["D810_HCC_BYTE_CASCADE_TRACE"] = "1"
    rc = cmd_dump(args)
    if rc != 0:
        print(
            f"cff-debug: trace: dump returned {rc}; skipping diag report",
            file=sys.stderr,
        )
        return rc
    wt = args.worktree
    worktree = worktree_dir(wt)
    log_file = worktree_log_dir(wt) / "d810.log"
    if not log_file.exists():
        _die(f"trace: log not found: {log_file}")
    try:
        db = latest_db(wt)
    except SystemExit:
        db = None
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "hcc-byte-cascade-trace",
        "--log",
        str(log_file),
        "--func-label",
        args.function,
    ]
    if db is not None:
        diag_argv += ["--db", str(db)]
    if args.json_output:
        diag_argv.append("--json")
    print(
        f"cff-debug: trace: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_residual_worksheet(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics residual-worksheet`.

    Resolves the latest diag DB + worktree d810.log (or honours --diag-db
    / --log) and forwards the snapshot/format/output flags untouched.
    All correlation logic lives in
    ``d810.diagnostics.residual_worksheet``.

    Distinct from `cff_debug.py residuals`, which is a text grep over
    AFTER pseudocode for `<var> = 0x...` patterns.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    diag_db = (
        Path(args.diag_db).expanduser().resolve()
        if args.diag_db
        else resolve_db(wt, None)
    )
    log_path: Path | None
    if args.log:
        log_path = Path(args.log).expanduser().resolve()
    else:
        candidate = worktree_log_dir(wt) / "d810.log"
        log_path = candidate if candidate.exists() else None
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "residual-worksheet",
        "--diag-db", str(diag_db),
    ]
    if args.recon_db:
        diag_argv += ["--recon-db", args.recon_db]
    if log_path is not None:
        diag_argv += ["--log", str(log_path)]
    if args.func_ea is not None:
        diag_argv += ["--func-ea", args.func_ea]
    if args.snapshot_id is not None:
        diag_argv += ["--snapshot-id", str(args.snapshot_id)]
    if args.format:
        diag_argv += ["--format", args.format]
    if args.output:
        diag_argv += ["--output", args.output]
    if args.list_snapshots:
        diag_argv.append("--list-snapshots")
    print(f"DIAG_DB={diag_db}", file=sys.stderr)
    if log_path is not None:
        print(f"LOG={log_path}", file=sys.stderr)
    print(
        f"cff-debug: residual-worksheet: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_oracle(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics region-diff`.

    Resolves the latest diag SQLite for the worktree (or honours --db) and
    forwards the snapshot/label/output/microblocks/persist flags untouched.
    All REF comparison logic and SQL live in
    ``d810.cfg.region_oracle_cli``; this wrapper only resolves paths.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    db = resolve_db(wt, args.db)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "region-diff",
        "--db", str(db),
    ]
    if args.func_ea:
        diag_argv += ["--func-ea", args.func_ea]
    if args.snap17 is not None:
        diag_argv += ["--snap17", str(args.snap17)]
    if args.snap18 is not None:
        diag_argv += ["--snap18", str(args.snap18)]
    if args.snap17_label:
        diag_argv += ["--snap17-label", args.snap17_label]
    if args.snap18_label:
        diag_argv += ["--snap18-label", args.snap18_label]
    if args.output:
        diag_argv += ["--output", args.output]
    if args.microblocks:
        diag_argv.append("--microblocks")
    if args.persist:
        diag_argv.append("--persist")
    if args.json_output:
        diag_argv.append("--json")
    print(f"DB={db}", file=sys.stderr)
    print(
        f"cff-debug: oracle: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_egress_plan(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics cascade-egress-plan`.

    Defaults --db to the latest diag SQLite for the worktree. Snapshot
    selection is delegated to the diag command (it picks the most recent
    GLBOPT1/pre_d810 fact snapshot + post_bundle_stabilize CFG snapshot).
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    db = resolve_db(wt, args.db)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable, "-m", "d810.diagnostics", "cascade-egress-plan",
        "--db", str(db),
    ]
    if args.fact_snapshot_id is not None:
        diag_argv += ["--fact-snapshot-id", str(args.fact_snapshot_id)]
    if args.target_snapshot_id is not None:
        diag_argv += ["--target-snapshot-id", str(args.target_snapshot_id)]
    print(f"DB={db}", file=sys.stderr)
    print(
        f"cff-debug: egress-plan: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_frontier_diagnostics(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics frontier-diagnostics`."""
    wt = args.worktree
    worktree = worktree_dir(wt)
    db = resolve_db(wt, args.db)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "frontier-diagnostics",
        "--db",
        str(db),
    ]
    if args.snapshot_id is not None:
        diag_argv += ["--snapshot-id", str(args.snapshot_id)]
    if args.kind:
        diag_argv += ["--kind", args.kind]
    if args.all_kinds:
        diag_argv.append("--all-kinds")
    if args.json_output:
        diag_argv.append("--json")
    print(f"DB={db}", file=sys.stderr)
    print(
        f"cff-debug: frontier-diagnostics: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_returns(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics return-ledger`.

    Defaults --db to the latest diag SQLite and --dump to the latest
    AFTER-pseudocode dump for the worktree, so the wrapper just works
    after `cff-debug dump`.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    db = resolve_db(wt, args.db)
    dump_arg: list[str] = []
    if not args.no_dump:
        try:
            dump = (
                Path(args.dump).expanduser().resolve()
                if args.dump
                else latest_dump(wt)
            )
        except SystemExit:
            dump = None
        if dump is not None:
            dump_arg = ["--dump", str(dump)]
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable, "-m", "d810.diagnostics", "return-ledger",
        "--db", str(db),
        *dump_arg,
    ]
    if args.snapshot_id is not None:
        diag_argv += ["--snapshot-id", str(args.snapshot_id)]
    if args.list_snapshots:
        diag_argv.append("--list-snapshots")
    if args.json_output:
        diag_argv.append("--json")
    print(f"DB={db}", file=sys.stderr)
    if dump_arg:
        print(f"DUMP={dump_arg[1]}", file=sys.stderr)
    print(
        f"cff-debug: returns: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_reconcile(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics redirect-reconcile`.

    Defaults --db to the latest diag SQLite for the worktree and --log to
    the worktree's d810.log so a fresh `cff-debug dump` followed by
    `cff-debug reconcile` Just Works.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    db = resolve_db(wt, args.db)
    log_path = (
        Path(args.log).expanduser().resolve()
        if args.log
        else worktree_log_dir(wt) / "d810.log"
    )
    if not log_path.exists():
        _die(f"reconcile: log not found: {log_path}")
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "redirect-reconcile",
        "--db", str(db),
        "--log", str(log_path),
        "--snap-id", str(args.snap_id),
        "--state-var-stkoff", args.state_var_stkoff,
        "--min-dispatcher-preds", str(args.min_dispatcher_preds),
    ]
    if args.show_edges:
        diag_argv.append("--show-edges")
    print(f"DB={db}", file=sys.stderr)
    print(f"LOG={log_path}", file=sys.stderr)
    print(
        f"cff-debug: reconcile: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_gates(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics gate-audit`.

    Defaults the log path to the worktree's ``d810_logs/`` directory so the
    wrapper picks up whatever the last dump produced. Performs no parsing
    of its own.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    if args.log_path:
        log_path = Path(args.log_path).expanduser().resolve()
    else:
        log_path = worktree_log_dir(wt)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "gate-audit",
        str(log_path),
    ]
    if args.strict:
        diag_argv.append("--strict")
    if args.json_output:
        diag_argv.append("--json")
    print(f"LOG_PATH={log_path}", file=sys.stderr)
    print(
        f"cff-debug: gates: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_byte_audit(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics terminal-tail-audit`.

    Resolves the latest diag SQLite for the worktree (or honours --db) and
    forwards optional flags. Performs no parsing of its own.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    db = resolve_db(wt, args.db)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "terminal-tail-audit",
        "--db",
        str(db),
    ]
    if args.show_edges:
        diag_argv.append("--show-edges")
    if args.localize:
        diag_argv.append("--localize")
    if args.initial_snap_id is not None:
        diag_argv += ["--initial-snap-id", str(args.initial_snap_id)]
    print(f"DB={db}", file=sys.stderr)
    print(
        f"cff-debug: byte-audit: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_compose_evidence_explain(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics compose-evidence-explain`.

    For every byte the byte-cascade trace marks
    ``final_refined=unmaterialized_original_block``, attribute the
    materialization gap to a single named composition-failure bucket plus
    the responsible composition step. Reads the worktree's ``d810.log``
    and the latest diag SQLite by default.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    log_file = (
        Path(args.log).expanduser().resolve()
        if args.log
        else worktree_log_dir(wt) / "d810.log"
    )
    if not log_file.exists():
        _die(f"compose-evidence-explain: log not found: {log_file}")
    db = resolve_db(wt, args.db)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "compose-evidence-explain",
        "--log",
        str(log_file),
        "--db",
        str(db),
    ]
    if args.bytes:
        diag_argv += ["--bytes", args.bytes]
    if args.func_label:
        diag_argv += ["--func-label", args.func_label]
    if args.json_output:
        diag_argv.append("--json")
    print(f"DB={db}", file=sys.stderr)
    print(f"LOG={log_file}", file=sys.stderr)
    print(
        f"cff-debug: compose-evidence-explain: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_unsupported_edge_kind_explain(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics unsupported-edge-kind-explain`.

    For every byte the byte-cascade trace marks with
    ``candidate_rejection=unsupported_edge_kind``, list the rejected
    outgoing DAG edges, the actual edge kind, the kinds the rejection
    check accepts, and whether the rejection appears safe to relax based
    on existing TerminalByteEmitterFact evidence on the target state.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    log_file = (
        Path(args.log).expanduser().resolve()
        if args.log
        else worktree_log_dir(wt) / "d810.log"
    )
    if not log_file.exists():
        _die(f"unsupported-edge-kind-explain: log not found: {log_file}")
    db = resolve_db(wt, args.db)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "unsupported-edge-kind-explain",
        "--log",
        str(log_file),
        "--db",
        str(db),
    ]
    if args.bytes:
        diag_argv += ["--bytes", args.bytes]
    if args.func_label:
        diag_argv += ["--func-label", args.func_label]
    if args.json_output:
        diag_argv.append("--json")
    print(f"DB={db}", file=sys.stderr)
    print(f"LOG={log_file}", file=sys.stderr)
    print(
        "cff-debug: unsupported-edge-kind-explain: diag argv:"
        f" {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


def cmd_admission_explain(args: argparse.Namespace) -> int:
    """Workflow wrapper for `python -m d810.diagnostics admission-explain`.

    For each byte the byte-cascade trace classified as
    ``region_detection_gap``, attribute the gap to a single named
    admission-failure bucket plus the first responsible HCC stage. Defaults
    pull the latest diag DB and the worktree's ``d810.log``.
    """
    wt = args.worktree
    worktree = worktree_dir(wt)
    log_file = (
        Path(args.log).expanduser().resolve()
        if args.log
        else worktree_log_dir(wt) / "d810.log"
    )
    if not log_file.exists():
        _die(f"admission-explain: log not found: {log_file}")
    db = resolve_db(wt, args.db)
    env = os.environ.copy()
    src_path = str(worktree / "src")
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{src_path}:{existing}" if existing else src_path
    diag_argv = [
        sys.executable,
        "-m",
        "d810.diagnostics",
        "admission-explain",
        "--log",
        str(log_file),
        "--db",
        str(db),
    ]
    if args.bytes:
        diag_argv += ["--bytes", args.bytes]
    if args.func_label:
        diag_argv += ["--func-label", args.func_label]
    if args.json_output:
        diag_argv.append("--json")
    print(f"DB={db}", file=sys.stderr)
    print(f"LOG={log_file}", file=sys.stderr)
    print(
        f"cff-debug: admission-explain: diag argv: {' '.join(diag_argv)}",
        file=sys.stderr,
    )
    return subprocess.call(diag_argv, env=env)


_INSPECT_PROBES: tuple[tuple[str, str], ...] = (
    ("Gate Failures", r"Gate accounting: \d+ passed, [1-9]\d* failed, \d+ bypassed"),
    ("Provenance", r"Provenance:"),
    ("PruneUnreachable", r"PruneUnreachable:"),
    ("Metrics", r"(BEFORE|AFTER|DELTA):.*lines="),
    ("INTERR", r"INTERR"),
    ("Serial Remap", r"serial remap"),
    ("Transient Denylist", r"transient (corridor entries|denylist)"),
    ("DSVE Guard", r"DSVE guard (KEPT|OVERRIDDEN)"),
    ("PTS Gate", r"PTS gate"),
    ("Rejected Stages", r"rejected stage"),
    ("Applied Modifications", r"Applied \d+/\d+ modifications"),
    ("Failed Modifications", r"RESULT: FAILED"),
    ("RECON DAG", r"RECON DAG: accepted"),
    ("Exceptions", r"EXCEPTION|exception \d+|RuntimeError|RESULT: EXCEPTION"),
    ("Decompile Status", r"Failed to decompile|PASSED|FAILED.*test_dump"),
    ("Valrange Probe", r"VALRANGE_PROBE"),
    ("POST-APPLY", r"POST-APPLY"),
    ("verify_failed", r"(?i)verify_failed"),
    ("Return Frontier", r"RETURN_FRONTIER"),
)


def cmd_inspect(args: argparse.Namespace) -> int:
    """Grep-style convenience report for a Hodur dump file.

    Ports ``tools/scripts/inspect_hodur_dump.sh`` into cff_debug; runs the
    same probes via ``rg`` so output matches byte-for-byte (when rg is on
    the path) and falls back to plain Python regex otherwise.
    """
    dump = resolve_dump(args.worktree, args.dump)
    text: str | None = None
    rg_available = shutil.which("rg") is not None
    if not rg_available:
        text = dump.read_text(errors="replace")
    for banner, pattern in _INSPECT_PROBES:
        print(f"=== {banner} ===")
        if rg_available:
            rc = subprocess.call(["rg", pattern, str(dump)])
            if rc != 0:
                print("(none)")
        else:
            assert text is not None
            matched = False
            regex = re.compile(pattern, re.MULTILINE)
            for line in text.splitlines():
                if regex.search(line):
                    print(line)
                    matched = True
            if not matched:
                print("(none)")
        print()
    return 0


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
    sp.add_argument(
        "--stats",
        action="store_true",
        help="append the dump's STATS block after the AFTER pseudocode",
    )
    sp.set_defaults(func=cmd_after)

    sp = sub.add_parser(
        "snap-render",
        help=(
            "Render a diag-DB snapshot's microcode as a block-by-block"
            " listing -- bypasses IDA's post-D810 pipeline so callers can"
            " inspect the linearized program as D810 emitted it"
            " (typical: snap17 = post_bundle_stabilize at MMAT_GLBOPT1)."
        ),
    )
    _add_worktree(sp)
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sel = sp.add_mutually_exclusive_group()
    sel.add_argument(
        "--snapshot-id", type=int,
        help="render this specific snapshot id; default is the most recent",
    )
    sel.add_argument(
        "--label",
        help=(
            "resolve snapshot by label (e.g. 'post_bundle_stabilize');"
            " picks the HIGHEST matching id when the label repeats"
        ),
    )
    sp.add_argument(
        "--serials",
        help=(
            "comma-separated block serials to focus on"
            " (e.g. '116,118,238,56')"
        ),
    )
    sp.add_argument(
        "--include-eas", action="store_true",
        help="emit each instruction's ea_hex alongside opcode + dstr",
    )
    sp.set_defaults(func=cmd_snap_render)

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
        help=(
            "Inspect one semantic state node in the latest diag DB and"
            " cross-reference the latest AFTER pseudocode. Wraps `python -m"
            " d810.diagnostics inspect-state-node`."
        ),
    )
    _add_worktree(sp)
    sp.add_argument("state", help="state constant, e.g. 0x4C77464F")
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument("--dump", help="explicit dump file (default: latest in worktree)")
    sp.add_argument("--context", type=int, default=6)
    sp.set_defaults(func=cmd_state)

    sp = sub.add_parser(
        "db",
        help="passthrough to `python -m d810.diagnostics`; args after `--`",
    )
    _add_worktree(sp)
    sp.add_argument("args", nargs=argparse.REMAINDER,
                    help="all args after `--` are forwarded to d810.diagnostics")
    sp.set_defaults(func=cmd_db)

    sp = sub.add_parser(
        "trace",
        help=(
            "run dump with D810_HCC_BYTE_CASCADE_TRACE=1, then render the"
            " HCC byte-cascade trace via `d810.diagnostics hcc-byte-cascade-trace`"
        ),
    )
    _add_worktree(sp)
    sp.add_argument("-f", "--function", default=DEFAULT_FUNCTION)
    sp.add_argument("-p", "--project", default=DEFAULT_PROJECT)
    sp.add_argument("--prefix", default="trace",
                    help="dump filename prefix (default: trace)")
    sp.add_argument("--label", default="hcc",
                    help="label embedded in the output filename (default: hcc)")
    sp.add_argument("--capture-post-maturity", default=DEFAULT_CAPTURE_POST_MATURITY,
                    help="D810_CAPTURE_POST_MATURITY value (default: 8 = MMAT_GLBOPT1)")
    sp.add_argument("--no-debug-logging", action="store_true",
                    help="do not pass -l / --enable-debug-logging to the docker runner")
    sp.add_argument("--extra", action="append",
                    help="extra pytest arg (repeatable); if any provided, replaces defaults")
    sp.add_argument("--json", action="store_true", dest="json_output",
                    help="emit the trace report as JSON instead of markdown")
    sp.set_defaults(func=cmd_trace)

    sp = sub.add_parser(
        "inspect",
        help=(
            "grep-style probes for common dump diagnostics (gate failures,"
            " INTERR, applied/failed mods, RECON DAG, ...) -- ports"
            " tools/scripts/inspect_hodur_dump.sh"
        ),
    )
    _add_worktree(sp)
    sp.add_argument("--dump", help="explicit dump file (default: latest in worktree)")
    sp.set_defaults(func=cmd_inspect)

    sp = sub.add_parser(
        "byte-audit",
        help=(
            "Audit TerminalByteEmitterFact rows in the latest diag DB:"
            " intermediate-snapshot loss localization is ON by default --"
            " this is the report you usually want for snap17 -> snap18 DCE"
            " analysis. Wraps `python -m d810.diagnostics terminal-tail-audit`."
        ),
    )
    _add_worktree(sp)
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument(
        "--show-edges", action="store_true",
        help="print every observation with snap/maturity/phase/role/src_form",
    )
    sp.add_argument(
        "--localize", action=argparse.BooleanOptionalAction, default=True,
        help=(
            "run intermediate-snapshot loss localization (default: True;"
            " pass --no-localize to print only the bare timeline). The bare"
            " timeline often prints `survives_pipeline` for bytes that are"
            " actually DCE'd between snap17 and snap18 by IDA's"
            " optimize_global -- you want --localize for that case."
        ),
    )
    sp.add_argument(
        "--initial-snap-id", type=int, default=5,
        help="snapshot id of the initial pre-D810 state (default: 5)",
    )
    sp.set_defaults(func=cmd_byte_audit)

    sp = sub.add_parser(
        "admission-explain",
        help=(
            "For every byte the HCC byte-cascade trace classified as"
            " region_detection_gap, attribute the gap to a single named"
            " bucket (not_in_chain / chain_too_short /"
            " no_accepted_pred_or_succ / payload_or_intermediate_filter /"
            " call_barrier_collision / region_table_merge_loss /"
            " candidate_rejected_pre_raw_region) plus the first"
            " responsible HCC stage. Wraps `python -m d810.diagnostics"
            " admission-explain`."
        ),
    )
    _add_worktree(sp)
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument(
        "--log",
        help=(
            "explicit d810.log path (default: <worktree>/.tmp/logs/"
            "d810_logs/d810.log)"
        ),
    )
    sp.add_argument(
        "--bytes", default=None,
        help=(
            "comma-separated byte indices to explain (e.g. '2,4,5')."
            " Default: every row whose final_status_refined =="
            " region_detection_gap."
        ),
    )
    sp.add_argument(
        "--func-label", default=None,
        help="optional function label rendered in the report title",
    )
    sp.add_argument(
        "--json", action="store_true", dest="json_output",
        help="emit JSON instead of the human-readable text table",
    )
    sp.set_defaults(func=cmd_admission_explain)

    sp = sub.add_parser(
        "compose-evidence-explain",
        help=(
            "For every byte the trace marks"
            " final_refined=unmaterialized_original_block, attribute the"
            " materialization gap to a single named composition-failure"
            " bucket (no_mod_touches_block /"
            " redirect_target_only_no_evidence /"
            " insertblock_succ_no_byte_evidence / redirected_away_only /"
            " insertblock_with_evidence_inconsistency / unclassified)"
            " plus the responsible composition step. Wraps `python -m"
            " d810.diagnostics compose-evidence-explain`."
        ),
    )
    _add_worktree(sp)
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument(
        "--log",
        help=(
            "explicit d810.log path (default: <worktree>/.tmp/logs/"
            "d810_logs/d810.log)"
        ),
    )
    sp.add_argument(
        "--bytes", default=None,
        help=(
            "comma-separated byte indices to explain (e.g. '2,4,5')."
            " Default: every row whose final_refined =="
            " unmaterialized_original_block."
        ),
    )
    sp.add_argument(
        "--func-label", default=None,
        help="optional function label rendered in the report title",
    )
    sp.add_argument(
        "--json", action="store_true", dest="json_output",
        help="emit JSON instead of the human-readable text table",
    )
    sp.set_defaults(func=cmd_compose_evidence_explain)

    sp = sub.add_parser(
        "unsupported-edge-kind-explain",
        help=(
            "For every byte the byte-cascade trace marks with"
            " candidate_rejection=unsupported_edge_kind, list the rejected"
            " outgoing DAG edges, the actual edge kind, the kinds the check"
            " accepts, and whether the rejection appears safe to relax"
            " (based on TerminalByteEmitterFact evidence on the target"
            " state). Wraps `python -m d810.diagnostics"
            " unsupported-edge-kind-explain`."
        ),
    )
    _add_worktree(sp)
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument(
        "--log",
        help=(
            "explicit d810.log path (default: <worktree>/.tmp/logs/"
            "d810_logs/d810.log)"
        ),
    )
    sp.add_argument(
        "--bytes", default=None,
        help=(
            "comma-separated byte indices to explain (e.g. '0,2,3')."
            " Default: every row whose candidate_rejection =="
            " unsupported_edge_kind."
        ),
    )
    sp.add_argument(
        "--func-label", default=None,
        help="optional function label rendered in the report title",
    )
    sp.add_argument(
        "--json", action="store_true", dest="json_output",
        help="emit JSON instead of the human-readable text table",
    )
    sp.set_defaults(func=cmd_unsupported_edge_kind_explain)

    sp = sub.add_parser(
        "gates",
        help=(
            "Audit gate outcomes from the worktree's d810.log (or an explicit"
            " log path). Wraps `python -m d810.diagnostics gate-audit`."
        ),
    )
    _add_worktree(sp)
    sp.add_argument(
        "log_path",
        nargs="?",
        default=None,
        help=(
            "Path to a log file or directory containing *.log files. Default:"
            " the worktree's d810_logs/ directory."
        ),
    )
    sp.add_argument(
        "--strict", action="store_true",
        help="fail on ANY bypass, not just untracked ones",
    )
    sp.add_argument(
        "--json", action="store_true", dest="json_output",
        help="emit JSON instead of the human-readable text table",
    )
    sp.set_defaults(func=cmd_gates)

    sp = sub.add_parser(
        "reconcile",
        help=(
            "Reconcile resolver predictions against live"
            " dispatcher_trampoline_skip emissions for the latest diag DB +"
            " d810.log of the worktree. Wraps `python -m d810.diagnostics"
            " redirect-reconcile`."
        ),
    )
    _add_worktree(sp)
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument("--log", help="explicit d810.log (default: worktree's d810.log)")
    sp.add_argument(
        "--snap-id", type=int, default=5,
        help="snapshot id to reconcile (default: 5 = MMAT_GLBOPT1 pre_d810)",
    )
    sp.add_argument(
        "--state-var-stkoff", default="0x3C",
        help="state variable stack offset (hex). Default 0x3C for sub_7FFD.",
    )
    sp.add_argument(
        "--min-dispatcher-preds", type=int, default=5,
        help="minimum in-degree to count a block as dispatcher region",
    )
    sp.add_argument(
        "--show-edges", action="store_true",
        help="print every edge with bucket and evidence",
    )
    sp.set_defaults(func=cmd_reconcile)

    sp = sub.add_parser(
        "returns",
        help=(
            "Return-family ledger for the latest diag DB + AFTER pseudocode."
            " Wraps `python -m d810.diagnostics return-ledger`."
        ),
    )
    _add_worktree(sp)
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument(
        "--dump", help="explicit Hodur dump file (default: latest in worktree)",
    )
    sp.add_argument(
        "--no-dump", action="store_true",
        help="don't correlate against AFTER pseudocode (skip dump file lookup)",
    )
    sp.add_argument(
        "--snapshot-id", type=int, default=None,
        help="explicit snapshot id (default: last pre-gut_and_wire post_apply > 200 blocks)",
    )
    sp.add_argument(
        "--list-snapshots", action="store_true",
        help="list every snapshot in the DB and exit",
    )
    sp.add_argument(
        "--json", action="store_true", dest="json_output",
        help="emit JSON instead of the human-readable text table",
    )
    sp.set_defaults(func=cmd_returns)

    sp = sub.add_parser(
        "residual-worksheet",
        help=(
            "Build a residual dispatcher worksheet from the latest diag"
            " DB + worktree d810.log. Wraps `python -m d810.diagnostics"
            " residual-worksheet`. Distinct from `cff_debug.py residuals`,"
            " which is a text grep over AFTER pseudocode."
        ),
    )
    _add_worktree(sp)
    sp.add_argument(
        "--diag-db", default=None,
        help="explicit diag SQLite DB (default: latest in worktree)",
    )
    sp.add_argument(
        "--recon-db", default=None,
        help="explicit recon SQLite DB (default: auto-detect)",
    )
    sp.add_argument(
        "--log", default=None,
        help="explicit text log/dump (default: worktree's d810.log)",
    )
    sp.add_argument(
        "--func-ea", default=None,
        help="function EA in hex (default: derived from snapshot metadata)",
    )
    sp.add_argument(
        "--snapshot-id", type=int, default=None,
        help="primary worksheet snapshot ID (default: resolved by maturity/phase)",
    )
    sp.add_argument(
        "--format", choices=("markdown", "tsv", "json"), default=None,
        help="output format (default: markdown)",
    )
    sp.add_argument(
        "--output", default=None,
        help="write output to this path instead of stdout",
    )
    sp.add_argument(
        "--list-snapshots", action="store_true",
        help="list snapshots in the diag DB and exit",
    )
    sp.set_defaults(func=cmd_residual_worksheet)

    sp = sub.add_parser(
        "oracle",
        help=(
            "Recompute REF region-shape oracle for the latest diag DB."
            " Wraps `python -m d810.diagnostics region-diff`."
        ),
    )
    _add_worktree(sp)
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument(
        "--func-ea", default=None,
        help="function EA in hex (default: spec-resolved via diag DB)",
    )
    sp.add_argument(
        "--snap17", type=int, default=None,
        help="snap17 (last D810-controlled) snapshot id override",
    )
    sp.add_argument(
        "--snap18", type=int, default=None,
        help="snap18 (post_d810) snapshot id override",
    )
    sp.add_argument(
        "--snap17-label", default=None,
        help="resolve snap17 by snapshot label",
    )
    sp.add_argument(
        "--snap18-label", default=None,
        help="resolve snap18 by snapshot label",
    )
    sp.add_argument(
        "--output", default=None,
        help="write report to this path instead of stdout",
    )
    sp.add_argument(
        "--microblocks", action="store_true",
        help="emit per-microblock detail in the oracle report",
    )
    sp.add_argument(
        "--persist", action="store_true",
        help=(
            "persist scoped region_shape_features + terminal_tail_dce_causes"
            " rows into the diag DB"
        ),
    )
    sp.add_argument(
        "--json", action="store_true", dest="json_output",
        help="emit JSON instead of a markdown report",
    )
    sp.set_defaults(func=cmd_oracle)

    sp = sub.add_parser(
        "frontier-diagnostics",
        help="Print persisted DAG-frontier closure diagnostics.",
    )
    _add_worktree(sp)
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument(
        "--snapshot-id",
        type=int,
        default=None,
        help="Filter to one snapshot id (default: all snapshots).",
    )
    sp.add_argument(
        "--kind",
        default="unresolved,resolved",
        help=(
            "Filter by diagnostic kind, comma-separated "
            "(default: unresolved,resolved)."
        ),
    )
    sp.add_argument(
        "--all-kinds",
        action="store_true",
        help="Show every diagnostic kind instead of only unresolved rows.",
    )
    sp.add_argument("--json", action="store_true", dest="json_output")
    sp.set_defaults(func=cmd_frontier_diagnostics)

    sp = sub.add_parser(
        "egress-plan",
        help=(
            "Read-only terminal-tail cascade egress plan from the latest"
            " diag DB. Wraps `python -m d810.diagnostics cascade-egress-plan`."
        ),
    )
    _add_worktree(sp)
    sp.add_argument("--db", help="explicit diag DB (default: latest in worktree)")
    sp.add_argument(
        "--fact-snapshot-id", type=int, default=None,
        help=(
            "snapshot containing TerminalByteEmitterFact rows"
            " (default: auto-pick GLBOPT1/pre_d810)"
        ),
    )
    sp.add_argument(
        "--target-snapshot-id", type=int, default=None,
        help=(
            "CFG snapshot to evaluate (default: auto-pick"
            " post_bundle_stabilize)"
        ),
    )
    sp.set_defaults(func=cmd_egress_plan)

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
