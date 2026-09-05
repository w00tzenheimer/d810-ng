#!/usr/bin/env python3
"""Decide whether SQLite locking actually fails on the cifs mount.

``nobrl`` disables byte-range locking, which is the mechanism SQLite uses for
isolation, so it must not be added on the strength of one 'database is locked'
message. This probe distinguishes the possibilities: correct blocking (a writer
waits, then succeeds), a hard CIFS failure (an immediate error that never
resolves), and lost isolation (two writers both succeed). Every probe runs on
the cifs path and on a container-local path, so the mount is the only variable.

Run inside the container, e.g.::

    run_system_tests_docker.sh exec --remote HOST -w WT -- \\
        /app/ida/.venv/bin/python /work/tools/scripts/sqlite_cifs_probe.py
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

BUSY_TIMEOUT_MS = 2000
BLOCKING_TOLERANCE_S = 1.5


@dataclass(frozen=True)
class ProbeResult:
    name: str
    outcome: str
    detail: str
    seconds: float = 0.0


def classify_contention(
    error: str | None, seconds: float, rows_seen: int, expected_rows: int
) -> str:
    """Classify a second writer's attempt while the first holds the write lock.

    >>> classify_contention("database is locked", 2.1, 1, 1)
    'blocked-then-locked'
    >>> classify_contention("database is locked", 0.01, 1, 1)
    'immediate-error'
    >>> classify_contention(None, 0.1, 2, 1)
    'lost-isolation'
    >>> classify_contention(None, 0.1, 1, 1)
    'unexpected-success'
    """
    if error is not None:
        if "locked" in error or "busy" in error:
            if seconds >= BLOCKING_TOLERANCE_S:
                return "blocked-then-locked"
            return "immediate-error"
        return "error"
    if rows_seen > expected_rows:
        return "lost-isolation"
    return "unexpected-success"


def verdict_for(cifs: str, local: str) -> str:
    """A probe only indicts cifs when it behaves differently from local.

    >>> verdict_for("blocked-then-locked", "blocked-then-locked")
    'same as local'
    >>> verdict_for("immediate-error", "blocked-then-locked")
    'CIFS FAILURE'
    >>> verdict_for("lost-isolation", "blocked-then-locked")
    'CIFS FAILURE (isolation lost)'
    >>> verdict_for("ok", "ok")
    'same as local'
    """
    if cifs == local:
        return "same as local"
    if cifs == "lost-isolation":
        return "CIFS FAILURE (isolation lost)"
    if cifs in ("immediate-error", "error", "failed"):
        return "CIFS FAILURE"
    return f"differs ({cifs} vs {local})"


def render_table(rows: Sequence[tuple[str, str, str, str]]) -> str:
    """Render the probe matrix with minimal separators."""
    lines = ["|probe|cifs result|local result|verdict|", "|-|-|-|-|"]
    for probe, cifs, local, verdict in rows:
        lines.append(f"|{probe}|{cifs}|{local}|{verdict}|")
    return "\n".join(lines)


def overall_verdict(rows: Sequence[tuple[str, str, str, str]]) -> str:
    """One line the reader can act on.

    >>> overall_verdict([("p3", "blocked-then-locked", "blocked-then-locked", "same as local")])
    'VERDICT: cifs locking OK'
    >>> overall_verdict([("p3", "immediate-error", "blocked-then-locked", "CIFS FAILURE")])
    'VERDICT: cifs locking FAILURE demonstrated'
    >>> overall_verdict([("p1", "integrity-or-rowcount-failed", "ok", "differs")])
    'VERDICT: cifs locking FAILURE demonstrated'
    """
    if any(verdict.startswith("CIFS FAILURE") for _p, _c, _l, verdict in rows):
        return "VERDICT: cifs locking FAILURE demonstrated"
    if any(cifs == "integrity-or-rowcount-failed" for _p, cifs, _l, _v in rows):
        return "VERDICT: cifs locking FAILURE demonstrated"
    return "VERDICT: cifs locking OK"


def _fresh_database(directory: Path, case: str) -> Path:
    """One never-before-used database file per case."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{case.lower()}_{int(time.time()*1000)}_{os.getpid()}.sqlite3"
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            candidate.unlink()
    return path


def _connect(path: Path, *, busy_timeout: int = 0) -> sqlite3.Connection:
    connection = sqlite3.connect(str(path), timeout=busy_timeout / 1000.0)
    connection.execute("create table if not exists t(x integer)")
    connection.commit()
    return connection


def probe_single(directory: Path, journal_mode: str) -> ProbeResult:
    # Every case gets its own database: reuse would let one case's corruption
    # or leftover lock decide another case's verdict.
    name = "P1" if journal_mode == "delete" else "P2"
    path = _fresh_database(directory, name)
    try:
        connection = sqlite3.connect(str(path))
        mode = connection.execute(
            f"PRAGMA journal_mode={journal_mode}"
        ).fetchone()[0]
        connection.execute("create table if not exists t(x integer)")
        connection.execute("insert into t values (1)")
        connection.commit()
        rows = connection.execute("select count(*) from t").fetchone()[0]
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        connection.close()
        passed = rows == 1 and integrity == "ok"
        return ProbeResult(
            name=name,
            outcome="ok" if passed else "integrity-or-rowcount-failed",
            detail=f"journal_mode={mode} rows={rows} (expected 1) integrity={integrity}",
        )
    except Exception as error:  # noqa: BLE001 - the message is the evidence
        return ProbeResult(
            name=name,
            outcome="failed",
            detail=f"{type(error).__name__}: {error}",
        )


def probe_two_connections(directory: Path) -> ProbeResult:
    path = _fresh_database(directory, "P3")
    holder = _connect(path)
    holder.execute("delete from t")
    holder.commit()
    holder.execute("BEGIN IMMEDIATE")
    holder.execute("insert into t values (1)")
    contender = _connect(path, busy_timeout=BUSY_TIMEOUT_MS)
    started = time.monotonic()
    error: str | None = None
    try:
        contender.execute("insert into t values (2)")
        contender.commit()
    except Exception as failure:  # noqa: BLE001
        error = f"{type(failure).__name__}: {failure}"
    seconds = time.monotonic() - started
    holder.commit()
    rows = holder.execute("select count(*) from t").fetchone()[0]
    integrity = holder.execute("PRAGMA integrity_check").fetchone()[0]
    holder.close()
    contender.close()
    outcome = classify_contention(error, seconds, rows, 1)
    if outcome == "blocked-then-locked" and (rows != 1 or integrity != "ok"):
        outcome = "integrity-or-rowcount-failed"
    return ProbeResult(
        name="P3",
        outcome=outcome,
        detail=(
            f"waited={seconds:.2f}s rows={rows} (expected 1) "
            f"integrity={integrity} error={error}"
        ),
        seconds=seconds,
    )


def probe_two_processes(directory: Path) -> ProbeResult:
    path = _fresh_database(directory, "P4")
    holder = _connect(path)
    holder.execute("delete from t")
    holder.commit()
    holder.execute("BEGIN IMMEDIATE")
    holder.execute("insert into t values (1)")
    child = subprocess.run(
        [
            sys.executable,
            __file__,
            "--child-insert",
            str(path),
        ],
        capture_output=True,
        text=True,
    )
    payload = json.loads(child.stdout or '{"error": "no output", "seconds": 0}')
    holder.commit()
    rows = holder.execute("select count(*) from t").fetchone()[0]
    integrity = holder.execute("PRAGMA integrity_check").fetchone()[0]
    holder.close()
    outcome = classify_contention(payload.get("error"), payload.get("seconds", 0.0), rows, 1)
    if outcome == "blocked-then-locked" and (rows != 1 or integrity != "ok"):
        outcome = "integrity-or-rowcount-failed"
    return ProbeResult(
        name="P4",
        outcome=outcome,
        detail=(
            f"waited={payload.get('seconds', 0):.2f}s rows={rows} (expected 1) "
            f"integrity={integrity} error={payload.get('error')}"
        ),
    )


def _child_insert(path: str) -> int:
    connection = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000.0)
    started = time.monotonic()
    error = None
    try:
        connection.execute("insert into t values (2)")
        connection.commit()
    except Exception as failure:  # noqa: BLE001
        error = f"{type(failure).__name__}: {failure}"
    print(json.dumps({"error": error, "seconds": time.monotonic() - started}))
    connection.close()
    return 0


def run_suite(directory: Path) -> list[ProbeResult]:
    directory.mkdir(parents=True, exist_ok=True)
    return [
        probe_single(directory, "delete"),
        probe_single(directory, "wal"),
        probe_two_connections(directory),
        probe_two_processes(directory),
    ]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cifs-dir", default="/work/.tmp/sqlite-probe")
    parser.add_argument("--local-dir", default="/work/probe-local")
    parser.add_argument("--child-insert", default=None)
    arguments = parser.parse_args(argv)
    if arguments.child_insert:
        return _child_insert(arguments.child_insert)

    print(f"sqlite_version={sqlite3.sqlite_version} pid={os.getpid()}")
    cifs = run_suite(Path(arguments.cifs_dir))
    local = run_suite(Path(arguments.local_dir))
    rows = [
        (c.name, c.outcome, l.outcome, verdict_for(c.outcome, l.outcome))
        for c, l in zip(cifs, local)
    ]
    rows.append(("P5", "not-run (needs two containers)", "n/a", "not measured"))
    print(render_table(rows))
    print()
    for label, results in (("cifs", cifs), ("local", local)):
        for result in results:
            print(f"[{label}] {result.name}: {result.outcome} :: {result.detail}")
    print()
    print(overall_verdict(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
