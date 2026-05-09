"""IDA-coupled adapter implementations for byte_emit_tail_isolation.

Lives in d810.cfg.transform alongside the pure algorithm. This module
imports IDA SDK; the pure algorithm in
``byte_emit_tail_isolation.py`` does not.
"""
from __future__ import annotations

import json
import os
import sqlite3

from d810.core import logging
from d810.core.typing import Any, Iterable

from d810.cfg.transform.byte_emit_tail_isolation import (
    BlockView,
    FactRow,
    isolate_byte_emit_tail,
    parse_tail_distinct_byte_env,
)


logger = logging.getLogger(__name__)


class DiagDbFactView:
    """FactView backed by a diag-DB ``fact_observations`` table.

    Resolves the highest snapshot.id whose label matches the GLBOPT1
    ``pre_d810`` capture (with sensible fallbacks), then yields all
    ``TerminalByteEmitterFact`` rows whose payload byte_index matches
    the requested byte.

    Pure SQLite — no IDA imports.
    """

    _LABEL_CANDIDATES = (
        "maturity_MMAT_GLBOPT1_pre_d810",
        "MMAT_GLBOPT1_pre_d810",
        "pre_d810",
    )

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        func_ea_hex: str,
    ) -> None:
        self._conn = conn
        self._func_ea_hex = func_ea_hex

    def terminal_byte_emit_facts(
        self, byte_index: int,
    ) -> Iterable[FactRow]:
        snap_id: int | None = None
        for label in self._LABEL_CANDIDATES:
            row = self._conn.execute(
                "SELECT MAX(id) FROM snapshots WHERE label = ?",
                (label,),
            ).fetchone()
            if row is not None and row[0] is not None:
                snap_id = int(row[0])
                break
        if snap_id is None:
            return ()

        rows: list[FactRow] = []
        for (payload_json,) in self._conn.execute(
            "SELECT payload FROM fact_observations "
            "WHERE kind='TerminalByteEmitterFact' AND snapshot_id=? "
            "  AND func_ea_hex=? "
            "ORDER BY fact_id",
            (snap_id, self._func_ea_hex),
        ):
            try:
                payload = json.loads(payload_json or "{}")
            except json.JSONDecodeError:
                continue
            try:
                bi = int(payload.get("byte_index"))
                bs = int(payload.get("block_serial", 0))
            except (TypeError, ValueError):
                continue
            if bi != byte_index:
                continue
            rows.append(
                FactRow(
                    snapshot_id=snap_id,
                    byte_index=bi,
                    block_serial=bs,
                    start_ea_hex=str(payload.get("start_ea_hex") or ""),
                    corridor_role=str(payload.get("corridor_role") or ""),
                )
            )
        return rows


class LiveMbaAdapter:
    """MicrocodeAdapter backed by a live ``mba_t``.

    Imports IDA SDK lazily inside methods so this module can be imported
    at unit-test time before IDA is available.

    The mutator (``insert_trampoline_after``) is NOT yet wired — it
    raises ``NotImplementedError``.  See Track B.3 for the real IDA
    SDK call (likely ``mba.insert_block`` + ``copy_block`` rewire,
    plus a tail ``m_goto`` to the original successor).
    """

    def __init__(self, mba) -> None:  # mba: ida_hexrays.mba_t
        self._mba = mba

    def find_block_by_ea(self, ea: int) -> BlockView | None:
        """Walk ``mba.blocks`` and return a pure ``BlockView`` for the
        first block whose ``start`` equals ``ea``.

        Returns ``None`` when no block matches.
        """
        import ida_hexrays  # noqa: F401  (kept for future tail-opcode logic)

        mba = self._mba
        qty = int(getattr(mba, "qty", 0) or 0)
        for i in range(qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue
            blk_start = int(getattr(blk, "start", 0) or 0)
            if blk_start != int(ea):
                continue

            nsucc = int(blk.nsucc()) if callable(getattr(blk, "nsucc", None)) else 0
            succ_serial: int | None = None
            succ_npred: int | None = None
            if nsucc == 1 and callable(getattr(blk, "succ", None)):
                succ_serial = int(blk.succ(0))
                succ_blk = mba.get_mblock(succ_serial)
                if succ_blk is not None and callable(
                    getattr(succ_blk, "npred", None)
                ):
                    succ_npred = int(succ_blk.npred())

            tail_kind = "unknown"
            tail = getattr(blk, "tail", None)
            if tail is None:
                tail_kind = "fallthrough"
            else:
                try:
                    if int(tail.opcode) == int(ida_hexrays.m_goto):
                        tail_kind = "goto"
                    elif int(tail.opcode) in {
                        int(ida_hexrays.m_jcnd),
                        int(ida_hexrays.m_jz),
                        int(ida_hexrays.m_jnz),
                        int(ida_hexrays.m_jb),
                        int(ida_hexrays.m_jae),
                        int(ida_hexrays.m_jl),
                        int(ida_hexrays.m_jg),
                        int(ida_hexrays.m_jle),
                        int(ida_hexrays.m_jge),
                    }:
                        tail_kind = "cond_branch"
                    else:
                        tail_kind = "fallthrough"
                except AttributeError:
                    tail_kind = "unknown"

            return BlockView(
                serial=int(getattr(blk, "serial", i)),
                start_ea=blk_start,
                nsucc=nsucc,
                succ_serial=succ_serial,
                succ_npred=succ_npred,
                tail_kind=tail_kind,
            )
        return None

    def insert_trampoline_after(
        self, *, predecessor_serial: int, successor_serial: int,
    ) -> int:
        """Insert an empty BLT_1WAY trampoline between predecessor and
        successor; the trampoline contains exactly one ``m_goto`` to
        ``successor_serial``.

        NOT YET IMPLEMENTED.  See Track B.3 — needs the IDA SDK call
        family ``mba.insert_block(serial)`` + ``mblock_t.insert_into_block``
        for an ``m_goto`` tail, plus rewire of the predecessor's existing
        ``m_goto`` operand (or ``succset``) to point at the new
        trampoline serial.  Reference pattern lives in
        ``abc_block_splitter.py:745``.
        """
        raise NotImplementedError(
            "LiveMbaAdapter.insert_trampoline_after not yet wired — "
            "see Track B.3 follow-up (mba.insert_block + m_goto rewire)"
        )

    def successor_npred(self, successor_serial: int) -> int:
        mba = self._mba
        blk = mba.get_mblock(int(successor_serial))
        if blk is None or not callable(getattr(blk, "npred", None)):
            return 0
        return int(blk.npred())


def maybe_run_tail_distinct(mba: Any) -> None:
    """Env-gated hook: ``D810_TAIL_DISTINCT_BYTE`` topology-only experiment.

    Default-off.  When ``D810_TAIL_DISTINCT_BYTE`` is set to a valid byte
    index in ``[0, 6]`` this resolves the matching
    ``TerminalByteEmitterFact`` from the diag DB, finds the live block,
    and inserts a single empty trampoline between byte_emit[k] and its
    shared successor.

    Lives in ``d810.cfg.transform`` (not ``d810.manager``) so the
    optimizer call site can import it without violating the layered
    import contract (optimizers must not depend on UI, and manager
    transitively imports UI).

    Any failure (no fact, block missing, preconditions unmet, adapter
    not yet wired) is logged and swallowed — the manager pipeline never
    breaks because of this experiment.
    """
    raw = os.environ.get("D810_TAIL_DISTINCT_BYTE")
    byte_index = parse_tail_distinct_byte_env(raw)
    if byte_index is None:
        return  # default-off: no log, no mutation

    try:
        from d810.core.diag import get_diag_db

        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        diag_conn = get_diag_db(func_ea)
    except Exception:
        logger.exception("tail_distinct: cannot acquire diag DB; skipping")
        return

    if diag_conn is None:
        logger.warning(
            "tail_distinct: D810_TAIL_DISTINCT_BYTE=%r set but diag DB "
            "unavailable; skipping",
            raw,
        )
        return

    func_ea_hex = f"0x{int(getattr(mba, 'entry_ea', 0) or 0):016x}"
    fact_view = DiagDbFactView(diag_conn, func_ea_hex=func_ea_hex)
    adapter = LiveMbaAdapter(mba)
    try:
        report = isolate_byte_emit_tail(
            byte_index=byte_index,
            fact_view=fact_view,
            adapter=adapter,
        )
    except NotImplementedError as exc:
        logger.warning("tail_distinct: adapter not wired: %s", exc)
        return
    except Exception:
        logger.exception("tail_distinct: unexpected failure; continuing")
        return

    logger.info("tail_distinct: %s", report)
