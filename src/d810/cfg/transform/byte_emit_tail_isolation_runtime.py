"""IDA-coupled adapter implementations for byte_emit_tail_isolation.

Lives in d810.cfg.transform alongside the pure algorithm. This module
imports IDA SDK; the pure algorithm in
``byte_emit_tail_isolation.py`` does not.
"""
from __future__ import annotations

import dataclasses
import json
import os
import sqlite3

from d810.core import logging
from d810.core.typing import Any, Iterable

from d810.cfg.transform.byte_emit_tail_isolation import (
    BlockView,
    FactRow,
    duplicate_convergence_for_byte_path,
    execute_state_cascade,
    isolate_byte_emit_tail,
    parse_state_cascade_pair_env,
    parse_tail_distinct_byte_env,
    parse_tail_duplicate_convergence_byte_env,
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
            # The TerminalByteEmitterFact payload uses ``block_ea`` (int).
            # Older paths stored ``start_ea_hex``; honor either when present.
            ea_hex = str(payload.get("start_ea_hex") or "")
            if not ea_hex:
                raw_ea = payload.get("block_ea")
                if isinstance(raw_ea, int):
                    ea_hex = f"0x{raw_ea & ((1 << 64) - 1):016x}"
                elif isinstance(raw_ea, str) and raw_ea:
                    try:
                        ea_hex = f"0x{int(raw_ea, 0) & ((1 << 64) - 1):016x}"
                    except ValueError:
                        ea_hex = ""
            rows.append(
                FactRow(
                    snapshot_id=snap_id,
                    byte_index=bi,
                    block_serial=bs,
                    start_ea_hex=ea_hex,
                    corridor_role=str(payload.get("corridor_role") or ""),
                )
            )
        return rows


class LiveMbaAdapter:
    """MicrocodeAdapter backed by a live ``mba_t``.

    Imports IDA SDK lazily inside methods so this module can be imported
    at unit-test time before IDA is available.

    The mutator (``insert_trampoline_after``) clones the predecessor at
    the end of the MBA via ``mba.copy_block``, NOPs all inherited
    instructions, appends a single ``m_goto`` to the successor, and
    rewires pred/succ sets.  Mid-CFG ``mba.insert_block`` is avoided
    because it corrupts IDA internal state (see
    ``abc_block_splitter.py:669``).
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

        Topology before:
            predecessor -> successor
        Topology after:
            predecessor -> trampoline -> successor

        Implementation notes:
        - Uses ``mba.copy_block(blk, mba.qty - 1)`` to append the new
          block at the end of the MBA. ``mba.insert_block(serial)`` in
          mid-CFG positions causes IDA internal state corruption and
          subsequent ``mba.verify()`` failures (see
          ``abc_block_splitter.py:669`` for the historical note).
        - The cloned block inherits the predecessor's contents; we NOP
          every instruction so the trampoline carries zero semantics.
        - We rely on the precondition gate (``_check_preconditions``)
          to ensure ``nsucc==1`` and ``tail_kind in {goto, fallthrough}``;
          this method does not re-validate.
        - Cannot import from ``d810.hexrays`` (layered-architecture
          contract puts ``d810.cfg`` *below* ``d810.hexrays``), so the
          mechanics here mirror — but do not call — the helpers in
          ``hexrays.mutation.cfg_mutations.insert_nop_blk``.

        Raises ``RuntimeError`` if the SDK call family fails part-way
        through; the caller (``maybe_run_tail_distinct``) catches and
        logs.  Best-effort atomicity: a failed
        ``copy_block`` / ``predset`` op aborts before any pred/succ
        rewiring, so the mba is left untouched on the typical failure.
        """
        import ida_hexrays  # lazy import — module must load without IDA

        mba = self._mba
        pred_blk = mba.get_mblock(int(predecessor_serial))
        succ_blk = mba.get_mblock(int(successor_serial))
        if pred_blk is None or succ_blk is None:
            raise RuntimeError(
                "insert_trampoline_after: cannot resolve "
                f"pred={predecessor_serial} or succ={successor_serial}"
            )

        # 1. Clone predecessor at the end of the MBA (just before the
        #    dummy last block). copy_block(ref, dest_serial) inserts the
        #    new block *before* dest_serial in the block list.
        end_serial = int(mba.qty) - 1
        tramp = mba.copy_block(pred_blk, end_serial)
        if tramp is None:
            raise RuntimeError(
                "insert_trampoline_after: mba.copy_block failed for "
                f"pred={predecessor_serial}"
            )

        # 2. NOP every instruction the clone inherited so the trampoline
        #    carries zero semantics.
        cur = tramp.head
        while cur is not None:
            tramp.make_nop(cur)
            cur = cur.next

        # 3. Mark as a 1-way block and clear stale pred/succ entries
        #    that copy_block carried over from the source block.
        tramp.type = ida_hexrays.BLT_1WAY
        for stale_succ in [int(x) for x in tramp.succset]:
            tramp.succset._del(stale_succ)
            other = mba.get_mblock(stale_succ)
            if other is not None:
                other.predset._del(tramp.serial)
                if other.serial != mba.qty - 1:
                    other.mark_lists_dirty()
        for stale_pred in [int(x) for x in tramp.predset]:
            tramp.predset._del(stale_pred)

        # 4. Append a single m_goto to ``successor_serial`` as the
        #    trampoline's only live instruction.
        safe_ea = int(getattr(mba, "entry_ea", 0) or 0)
        goto_ins = ida_hexrays.minsn_t(safe_ea)
        goto_ins.ea = safe_ea
        tramp.insert_into_block(goto_ins, tramp.tail)
        # nop-then-mutate avoids INTERR 52123 (see insert_goto_instruction)
        tramp.make_nop(tramp.tail)
        goto_ins.opcode = ida_hexrays.m_goto
        goto_ins.l = ida_hexrays.mop_t()
        goto_ins.l.make_blkref(int(successor_serial))
        goto_ins.r = ida_hexrays.mop_t()
        goto_ins.r.erase()
        goto_ins.d = ida_hexrays.mop_t()
        goto_ins.d.erase()
        tramp.flags |= ida_hexrays.MBL_GOTO

        # 5. Wire trampoline -> successor.
        tramp.succset.push_back(int(successor_serial))

        # 6. Rewire predecessor: its sole successor was successor_serial;
        #    now it must be tramp.serial.  The precondition gate already
        #    ensured nsucc == 1 and tail_kind in {goto, fallthrough}.
        pred_blk.succset._del(int(successor_serial))
        pred_blk.succset.push_back(int(tramp.serial))
        if (
            pred_blk.tail is not None
            and pred_blk.tail.opcode == ida_hexrays.m_goto
            and pred_blk.tail.l is not None
            and pred_blk.tail.l.t == ida_hexrays.mop_b
            and int(pred_blk.tail.l.b) == int(successor_serial)
        ):
            pred_blk.tail.l.make_blkref(int(tramp.serial))
        pred_blk.mark_lists_dirty()

        # 7. Update successor's predset: predecessor no longer points at
        #    it directly; the trampoline does.
        succ_blk.predset._del(int(predecessor_serial))
        succ_blk.predset.push_back(int(tramp.serial))
        if succ_blk.serial != mba.qty - 1:
            succ_blk.mark_lists_dirty()

        # 8. Trampoline's own pred set: predecessor.
        tramp.predset.push_back(int(predecessor_serial))
        tramp.mark_lists_dirty()
        mba.mark_chains_dirty()

        return int(tramp.serial)

    def successor_npred(self, successor_serial: int) -> int:
        mba = self._mba
        blk = mba.get_mblock(int(successor_serial))
        if blk is None or not callable(getattr(blk, "npred", None)):
            return 0
        return int(blk.npred())

    def split_block_at_tail_jcnd(self, block_serial: int) -> int:
        """Split a 2-way block at its tail conditional jump.

        Uses the native ``mba.split_block(blk, start_insn)`` SDK API
        (``hexrays.hpp:5303``).  The instruction sequence is partitioned:
        bytes-emission instructions stay in the original block (which
        becomes BLT_1WAY); the tail conditional and its two-arm
        successor list move to a fresh block inserted immediately after.

        Layered-architecture note: ``d810.cfg`` is below ``d810.hexrays``,
        so we cannot import ``CONDITIONAL_JUMP_OPCODES`` from
        ``d810.hexrays.utils.hexrays_helpers`` nor the ``cfg_verify.n``
        helper.  The cond-opcode set is inlined here (mirroring the set
        already used by ``find_block_by_ea`` on this same adapter), and
        post-split verification is left to downstream stages.

        Returns the new tail block's serial.

        Raises ``RuntimeError`` if the block cannot be resolved, is not
        2-way, contains no conditional jump in its instruction stream,
        or if ``mba.split_block`` itself fails.
        """
        import ida_hexrays  # lazy: IDA may be absent at unit-test time

        mba = self._mba
        blk = mba.get_mblock(int(block_serial))
        if blk is None:
            raise RuntimeError(
                "split_block_at_tail_jcnd: cannot resolve block "
                f"{block_serial}"
            )

        nsucc = (
            int(blk.nsucc())
            if callable(getattr(blk, "nsucc", None))
            else int(getattr(blk, "nsucc", 0) or 0)
        )
        if nsucc != 2:
            raise RuntimeError(
                f"split_block_at_tail_jcnd: block {block_serial} nsucc="
                f"{nsucc}, expected 2"
            )

        # Walk head -> tail to locate the conditional jump.  DO NOT call
        # dstr() / print on instructions before the split; ``maybe_use``
        # / ``maybe_def`` are side-effecting on inspection per the IDA
        # microcode SDK contract.
        cond_opcodes = {
            int(ida_hexrays.m_jnz),
            int(ida_hexrays.m_jz),
            int(ida_hexrays.m_jl),
            int(ida_hexrays.m_jle),
            int(ida_hexrays.m_jg),
            int(ida_hexrays.m_jge),
            int(ida_hexrays.m_jb),
            int(ida_hexrays.m_jbe),
            int(ida_hexrays.m_ja),
            int(ida_hexrays.m_jae),
            int(ida_hexrays.m_jcnd),
            int(ida_hexrays.m_jtbl),
        }
        cur = blk.head
        target = None
        while cur is not None:
            if int(cur.opcode) in cond_opcodes:
                target = cur
                break
            cur = cur.next
        if target is None:
            raise RuntimeError(
                "split_block_at_tail_jcnd: no conditional jump in "
                f"block {block_serial}"
            )

        new_blk = mba.split_block(blk, target)
        if new_blk is None:
            raise RuntimeError(
                "split_block_at_tail_jcnd: mba.split_block returned "
                f"None for block {block_serial}"
            )

        blk.mark_lists_dirty()
        new_blk.mark_lists_dirty()
        mba.mark_chains_dirty()

        return int(new_blk.serial)

    # ------------------------------------------------------------------
    # ConvergenceAdapter Protocol implementation (uee-32r3 Track CTD)
    # ------------------------------------------------------------------

    def block_has_m_stx(self, block_serial: int) -> bool:
        """True iff the block contains an ``m_stx`` instruction.

        Walks ``head -> tail`` checking opcode integers only.  We never
        call ``dstr()`` / ``print`` / ``maybe_use`` / ``maybe_def`` —
        those are side-effecting on inspection per the IDA microcode
        SDK contract.
        """
        import ida_hexrays  # lazy: IDA may be absent at unit-test time

        blk = self._mba.get_mblock(int(block_serial))
        if blk is None:
            return False
        cur = blk.head
        target_opcode = int(ida_hexrays.m_stx)
        while cur is not None:
            try:
                if int(cur.opcode) == target_opcode:
                    return True
            except AttributeError:
                pass
            cur = cur.next
        return False

    def forward_walk_until_convergence(
        self,
        start_serial: int,
        *,
        max_depth: int = 8,
    ) -> tuple[int | None, str]:
        """BFS forward from ``start_serial`` for the first convergence.

        A "convergence" is a block with ``npred > 1`` (i.e. genuinely
        shared with sibling paths) that also reaches ``BLT_STOP`` within
        a small bounded forward walk.

        Reasons:
          - ``"ok"`` (with serial): valid convergence found.
          - ``"no_npred_gt_1_within_depth"``: BFS exhausted ``max_depth``
            without ever seeing a ``npred>1`` candidate.
          - ``"convergence_does_not_reach_return"``: at least one
            ``npred>1`` candidate was visited but none reached
            ``BLT_STOP``.
        """
        import ida_hexrays  # lazy: IDA may be absent at unit-test time
        from collections import deque

        mba = self._mba

        def _succs_of(serial: int) -> tuple[int, ...]:
            b = mba.get_mblock(int(serial))
            if b is None:
                return ()
            n = int(b.nsucc()) if callable(getattr(b, "nsucc", None)) else 0
            return tuple(int(b.succ(i)) for i in range(n))

        def _reaches_stop(start: int, depth_cap: int = 12) -> bool:
            seen: set[int] = set()
            q: deque[tuple[int, int]] = deque([(int(start), 0)])
            while q:
                s, d = q.popleft()
                if s in seen or d > depth_cap:
                    continue
                seen.add(s)
                b = mba.get_mblock(s)
                if b is None:
                    continue
                blk_type = int(getattr(b, "type", -1))
                if blk_type == int(ida_hexrays.BLT_STOP):
                    return True
                for ns in _succs_of(s):
                    q.append((ns, d + 1))
            return False

        saw_candidate = False
        seen: set[int] = set()
        q: deque[tuple[int, int]] = deque([(int(start_serial), 0)])
        while q:
            s, d = q.popleft()
            if s in seen or d > max_depth:
                continue
            seen.add(s)
            b = mba.get_mblock(s)
            if b is None:
                continue
            npred = (
                int(b.npred()) if callable(getattr(b, "npred", None)) else 0
            )
            if d > 0 and npred > 1:
                saw_candidate = True
                if _reaches_stop(s):
                    return (s, "ok")
                # else: keep searching deeper for a different convergence
                continue
            for ns in _succs_of(s):
                q.append((ns, d + 1))

        if saw_candidate:
            return (None, "convergence_does_not_reach_return")
        return (None, "no_npred_gt_1_within_depth")

    def clone_convergence_for_byte_path(
        self,
        *,
        predecessor_serial: int,
        convergence_serial: int,
    ) -> int:
        """Clone the convergence block; rewire predecessor's edge to it.

        Topology before:
            predecessor -> convergence -> [convergence's succs]
            (other preds) -> convergence
        Topology after:
            predecessor -> clone -> [convergence's succs]
            (other preds) -> convergence -> [convergence's succs]

        Mirrors the predset/succset pattern used by
        ``insert_trampoline_after`` (push_back / _del).  ``copy_block``
        is verified to auto-update goto operands in other blocks; the
        explicit goto rewrite below is a belt-and-braces guard for the
        ``predecessor -> convergence`` edge specifically.
        """
        import ida_hexrays  # lazy: IDA may be absent at unit-test time

        mba = self._mba
        pred_blk = mba.get_mblock(int(predecessor_serial))
        conv_blk = mba.get_mblock(int(convergence_serial))
        if pred_blk is None or conv_blk is None:
            raise RuntimeError(
                "clone_convergence_for_byte_path: cannot resolve "
                f"pred={predecessor_serial} conv={convergence_serial}"
            )

        # 1. Append clone at end of MBA via copy_block(ref, dest_serial).
        end_serial = int(mba.qty) - 1
        clone = mba.copy_block(conv_blk, end_serial)
        if clone is None:
            raise RuntimeError(
                "clone_convergence_for_byte_path: mba.copy_block failed "
                f"for conv={convergence_serial}"
            )
        clone_serial = int(getattr(clone, "serial", end_serial))

        # 2. Reset clone's predset to {predecessor_serial}.
        # copy_block carries the source's predset over to the clone;
        # we want the clone to be reachable only from `predecessor`.
        for stale_pred in [int(x) for x in clone.predset]:
            clone.predset._del(stale_pred)
        clone.predset.push_back(int(predecessor_serial))

        # 3. Convergence loses `predecessor` from its predset (clone now
        # owns that edge).
        conv_blk.predset._del(int(predecessor_serial))

        # 4. Each successor of clone gains `clone_serial` in its predset.
        # copy_block already wired clone -> conv's successors (clone.succset
        # mirrors conv.succset).
        for succ_serial in [int(x) for x in clone.succset]:
            succ_blk = mba.get_mblock(succ_serial)
            if succ_blk is None:
                continue
            succ_blk.predset.push_back(clone_serial)
            if succ_blk.serial != mba.qty - 1:
                succ_blk.mark_lists_dirty()

        # 5. Rewire predecessor: succset entry conv_serial -> clone_serial.
        pred_blk.succset._del(int(convergence_serial))
        pred_blk.succset.push_back(clone_serial)

        # 6. If predecessor's tail is an explicit m_goto to the
        # convergence, rewrite the operand.  copy_block auto-rewires
        # goto operands when blocks are renumbered, but the goto on
        # `predecessor` predates the clone and still names
        # `convergence_serial` — fix it explicitly.
        if (
            pred_blk.tail is not None
            and int(pred_blk.tail.opcode) == int(ida_hexrays.m_goto)
            and pred_blk.tail.l is not None
            and pred_blk.tail.l.t == ida_hexrays.mop_b
            and int(pred_blk.tail.l.b) == int(convergence_serial)
        ):
            pred_blk.tail.l.make_blkref(clone_serial)

        pred_blk.mark_lists_dirty()
        conv_blk.mark_lists_dirty()
        clone.mark_lists_dirty()
        mba.mark_chains_dirty()

        return clone_serial


    # ------------------------------------------------------------------
    # State-cascade adapter Protocol implementation (byte5->byte6 probe)
    # ------------------------------------------------------------------

    def clone_state_write_block(
        self,
        *,
        template_serial: int,
        tail_goto_target: int,
    ) -> int:
        """Clone the planner-supplied state-write block; set the clone's
        tail to ``m_goto @tail_goto_target``; append at end of mba.

        The clone holds the SAME instructions as the template (no
        synthesis). Mirrors the ``mba.copy_block`` idiom used by
        ``insert_trampoline_after`` and ``clone_convergence_for_byte_path``.

        Returned clone has empty predset (caller wires the predecessor)
        and a single-successor succset pointing at ``tail_goto_target``.
        """
        import ida_hexrays  # lazy: IDA may be absent at unit-test time

        mba = self._mba
        template = mba.get_mblock(int(template_serial))
        tail_target_blk = mba.get_mblock(int(tail_goto_target))
        if template is None or tail_target_blk is None:
            raise RuntimeError(
                "clone_state_write_block: cannot resolve template="
                f"{template_serial} or tail_target={tail_goto_target}"
            )

        # 1. Append clone at the end of the MBA.
        end_serial = int(mba.qty) - 1
        clone = mba.copy_block(template, end_serial)
        if clone is None:
            raise RuntimeError(
                "clone_state_write_block: mba.copy_block failed for "
                f"template={template_serial}"
            )
        clone_serial = int(getattr(clone, "serial", end_serial))

        # 2. Reset clone's predset (caller wires the predecessor).
        for stale_pred in [int(x) for x in clone.predset]:
            clone.predset._del(stale_pred)

        # 3. Drop any inherited successor edges so we can replace them
        #    with a single m_goto edge to ``tail_goto_target``. Each old
        #    successor loses ``clone_serial`` from its predset.
        for stale_succ in [int(x) for x in clone.succset]:
            clone.succset._del(stale_succ)
            other = mba.get_mblock(stale_succ)
            if other is not None:
                other.predset._del(clone_serial)
                if other.serial != mba.qty - 1:
                    other.mark_lists_dirty()

        # 4. Mark BLT_1WAY and rewrite/append the tail to a single m_goto.
        clone.type = ida_hexrays.BLT_1WAY

        # If the cloned tail is already a goto, rewrite the operand;
        # otherwise append a fresh m_goto. We do not delete the cloned
        # state-write instructions — the whole point is to keep them.
        if (
            clone.tail is not None
            and int(clone.tail.opcode) == int(ida_hexrays.m_goto)
        ):
            clone.tail.l = ida_hexrays.mop_t()
            clone.tail.l.make_blkref(int(tail_goto_target))
            clone.tail.r = ida_hexrays.mop_t()
            clone.tail.r.erase()
            clone.tail.d = ida_hexrays.mop_t()
            clone.tail.d.erase()
        else:
            safe_ea = int(getattr(mba, "entry_ea", 0) or 0)
            goto_ins = ida_hexrays.minsn_t(safe_ea)
            goto_ins.ea = safe_ea
            clone.insert_into_block(goto_ins, clone.tail)
            # nop-then-mutate avoids INTERR 52123 (see insert_trampoline_after)
            clone.make_nop(clone.tail)
            goto_ins.opcode = ida_hexrays.m_goto
            goto_ins.l = ida_hexrays.mop_t()
            goto_ins.l.make_blkref(int(tail_goto_target))
            goto_ins.r = ida_hexrays.mop_t()
            goto_ins.r.erase()
            goto_ins.d = ida_hexrays.mop_t()
            goto_ins.d.erase()
        clone.flags |= ida_hexrays.MBL_GOTO

        # 5. Wire clone -> tail_goto_target.
        clone.succset.push_back(int(tail_goto_target))
        tail_target_blk.predset.push_back(clone_serial)
        if tail_target_blk.serial != mba.qty - 1:
            tail_target_blk.mark_lists_dirty()
        clone.mark_lists_dirty()
        mba.mark_chains_dirty()

        return clone_serial

    def redirect_advance_edge(
        self,
        *,
        source_serial: int,
        old_target_serial: int,
        new_target_serial: int,
    ) -> None:
        """Rewire ``source_serial``'s advance edge from ``old_target`` to
        ``new_target``.

        For a 1-way block whose tail is ``m_goto @old_target``, this
        rewrites the goto operand. For a 2-way block whose conditional
        tail names ``old_target`` in its branch operand, only that arm is
        redirected; the early-return arm remains untouched. Falls back to
        a succset-only rewrite when the tail is a plain fallthrough.

        Updates predset/succset symmetrically and marks affected blocks
        dirty. ``mba.mark_chains_dirty`` is invoked at the end.
        """
        import ida_hexrays  # lazy: IDA may be absent at unit-test time

        mba = self._mba
        src = mba.get_mblock(int(source_serial))
        old_blk = mba.get_mblock(int(old_target_serial))
        new_blk = mba.get_mblock(int(new_target_serial))
        if src is None or old_blk is None or new_blk is None:
            raise RuntimeError(
                "redirect_advance_edge: cannot resolve "
                f"src={source_serial} old={old_target_serial} "
                f"new={new_target_serial}"
            )

        # Rewrite tail operand (best-effort; falls through to succset
        # rewrite for fallthrough tails).
        tail = src.tail
        if tail is not None:
            try:
                opc = int(tail.opcode)
            except AttributeError:
                opc = -1
            cond_opcodes = {
                int(ida_hexrays.m_jnz),
                int(ida_hexrays.m_jz),
                int(ida_hexrays.m_jl),
                int(ida_hexrays.m_jle),
                int(ida_hexrays.m_jg),
                int(ida_hexrays.m_jge),
                int(ida_hexrays.m_jb),
                int(ida_hexrays.m_jbe),
                int(ida_hexrays.m_ja),
                int(ida_hexrays.m_jae),
                int(ida_hexrays.m_jcnd),
            }
            if opc == int(ida_hexrays.m_goto):
                # m_goto: branch target is in tail.l (mop_b).
                if (
                    tail.l is not None
                    and tail.l.t == ida_hexrays.mop_b
                    and int(tail.l.b) == int(old_target_serial)
                ):
                    tail.l.make_blkref(int(new_target_serial))
            elif opc in cond_opcodes:
                # Conditional jump: branch target is in tail.d (mop_b).
                # The other arm (early return / fallthrough) goes to
                # serial+1; do NOT touch it.
                if (
                    tail.d is not None
                    and tail.d.t == ida_hexrays.mop_b
                    and int(tail.d.b) == int(old_target_serial)
                ):
                    tail.d.make_blkref(int(new_target_serial))
            # Fallthrough tails (no branch operand) are handled by the
            # succset rewrite below alone.

        # Symmetrically update succset/predset.
        src.succset._del(int(old_target_serial))
        src.succset.push_back(int(new_target_serial))
        old_blk.predset._del(int(source_serial))
        new_blk.predset.push_back(int(source_serial))

        src.mark_lists_dirty()
        if old_blk.serial != mba.qty - 1:
            old_blk.mark_lists_dirty()
        if new_blk.serial != mba.qty - 1:
            new_blk.mark_lists_dirty()
        mba.mark_chains_dirty()


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


def maybe_run_tail_duplicate_convergence(mba: Any) -> None:
    """Env-gated hook: ``D810_TAIL_DUPLICATE_CONVERGENCE_BYTE`` probe.

    Default-off.  When set to exactly ``"6"`` and
    ``D810_TAIL_DISTINCT_BYTE`` is NOT set, this resolves the matching
    ``TerminalByteEmitterFact`` for byte 6 from the diag DB, walks
    forward to the first shared convergence block that reaches
    ``BLT_STOP``, clones that convergence, and rewires the
    byte-side predecessor's edge onto the clone.  The original
    convergence remains intact for sibling paths.

    Mutual exclusion with ``D810_TAIL_DISTINCT_BYTE``: if both are set
    we refuse to run either probe (the call site invokes both hooks
    unconditionally; this guard prevents double-mutation of the same
    block).

    Any failure (no fact, block missing, walk dead-ends, adapter not
    wired) is logged and swallowed — the manager pipeline never breaks
    because of this experiment.
    """
    raw = os.environ.get("D810_TAIL_DUPLICATE_CONVERGENCE_BYTE")
    byte_index = parse_tail_duplicate_convergence_byte_env(raw)
    if byte_index is None:
        return  # default-off: no log, no mutation

    if os.environ.get("D810_TAIL_DISTINCT_BYTE"):
        logger.warning(
            "tail_duplicate_convergence: D810_TAIL_DUPLICATE_CONVERGENCE_BYTE "
            "and D810_TAIL_DISTINCT_BYTE are both set; refusing to run "
            "either probe."
        )
        return

    try:
        from d810.core.diag import get_diag_db

        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        diag_conn = get_diag_db(func_ea)
    except Exception:
        logger.exception(
            "tail_duplicate_convergence: cannot acquire diag DB; skipping"
        )
        return

    if diag_conn is None:
        logger.warning(
            "tail_duplicate_convergence: D810_TAIL_DUPLICATE_CONVERGENCE_BYTE="
            "%r set but diag DB unavailable; skipping",
            raw,
        )
        return

    func_ea_hex = f"0x{int(getattr(mba, 'entry_ea', 0) or 0):016x}"
    fact_view = DiagDbFactView(diag_conn, func_ea_hex=func_ea_hex)
    adapter = LiveMbaAdapter(mba)
    try:
        report = duplicate_convergence_for_byte_path(
            byte_index=byte_index,
            fact_view=fact_view,
            adapter=adapter,
        )
    except NotImplementedError as exc:
        logger.warning(
            "tail_duplicate_convergence: adapter not wired: %s", exc,
        )
        return
    except Exception:
        logger.exception(
            "tail_duplicate_convergence: unexpected failure; continuing"
        )
        return

    logger.info("tail_duplicate_convergence: %s", report)


# ---------------------------------------------------------------------------
# TerminalTailStateCascade env-gated hook (byte5 -> byte6)
# ---------------------------------------------------------------------------


_STATE_CASCADE_FACT_LABELS = (
    "maturity_MMAT_GLBOPT1_pre_d810",
    "MMAT_GLBOPT1_pre_d810",
    "pre_d810",
)


def _json_int_tuple(value) -> tuple[int, ...]:
    if not value:
        return ()
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return ()
    if not isinstance(parsed, list):
        return ()
    out: list[int] = []
    for item in parsed:
        try:
            out.append(int(item))
        except (TypeError, ValueError):
            continue
    return tuple(out)


def _load_planner_blocks(
    conn,  # sqlite3.Connection
    snapshot_id: int,
):
    """Read block + instruction rows from a CFG snapshot into the
    pure planner's ``TerminalTailBlock`` shape.

    The diag DB is per-IDB per-run, so ``snapshot_id`` already
    uniquely identifies the function under analysis — neither
    ``blocks`` nor ``instructions`` have a ``func_ea_hex`` column.
    """
    from d810.cfg.terminal_tail_cascade_egress_planner import TerminalTailBlock

    rows = conn.execute(
        "SELECT serial, type_name, start_ea_hex, succs, preds "
        "FROM blocks WHERE snapshot_id=? "
        "ORDER BY serial",
        (snapshot_id,),
    ).fetchall()
    op_rows = conn.execute(
        "SELECT block_serial, opcode_name, COALESCE(dstr, '') "
        "FROM instructions WHERE snapshot_id=? "
        "ORDER BY block_serial, insn_index",
        (snapshot_id,),
    ).fetchall()
    opcodes_by_block: dict[int, list[str]] = {}
    text_by_block: dict[int, list[str]] = {}
    for block_serial, opcode, dstr in op_rows:
        bs = int(block_serial)
        opcodes_by_block.setdefault(bs, []).append(str(opcode or ""))
        text_by_block.setdefault(bs, []).append(str(dstr or ""))

    blocks = {}
    for serial, type_name, start_ea_hex, succs, preds in rows:
        bs = int(serial)
        blocks[bs] = TerminalTailBlock(
            serial=bs,
            succs=_json_int_tuple(succs),
            preds=_json_int_tuple(preds),
            type_name=str(type_name or ""),
            start_ea_hex=start_ea_hex,
            insn_opcodes=tuple(opcodes_by_block.get(bs, ())),
            insn_text=tuple(text_by_block.get(bs, ())),
        )
    return blocks


def _load_planner_sites(
    conn,  # sqlite3.Connection
    snapshot_id: int,
    func_ea_hex: str,
):
    """Yield ``TerminalByteEmitSite`` rows from a fact snapshot."""
    from d810.cfg.terminal_tail_cascade_egress_planner import (
        terminal_byte_emit_site_from_payload,
    )

    rows = conn.execute(
        "SELECT fact_id, payload, source_ea_hex, confidence "
        "FROM fact_observations "
        "WHERE snapshot_id=? AND kind='TerminalByteEmitterFact' "
        "  AND func_ea_hex=? "
        "ORDER BY fact_id",
        (snapshot_id, func_ea_hex),
    ).fetchall()
    sites: list = []
    for fact_id, payload_json, source_ea_hex, confidence in rows:
        try:
            payload = json.loads(payload_json or "{}")
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        site = terminal_byte_emit_site_from_payload(
            str(fact_id),
            payload,
            source_ea_hex=source_ea_hex,
            confidence=float(confidence or 0.0),
        )
        if site is not None:
            sites.append(site)
    return sites


def _resolve_planner_snapshots(
    conn, func_ea_hex: str,
) -> tuple[int | None, int | None]:
    """Resolve (fact_snapshot_id, target_snapshot_id) for a func_ea.

    fact_snapshot is the highest-id snapshot whose label matches a
    GLBOPT1 pre_d810 capture and which has a
    ``TerminalByteEmitterFact`` row for this function.
    target_snapshot is the highest-id snapshot whose label is
    ``post_bundle_stabilize`` and which has block rows for this
    function.
    """
    fact_snap: int | None = None
    for label in _STATE_CASCADE_FACT_LABELS:
        row = conn.execute(
            "SELECT MAX(s.id) FROM snapshots s "
            "JOIN fact_observations f ON f.snapshot_id = s.id "
            "WHERE s.label = ? "
            "  AND f.kind = 'TerminalByteEmitterFact' "
            "  AND f.func_ea_hex = ?",
            (label, func_ea_hex),
        ).fetchone()
        if row is not None and row[0] is not None:
            fact_snap = int(row[0])
            break

    target_snap: int | None = None
    row = conn.execute(
        "SELECT MAX(s.id) FROM snapshots s "
        "WHERE s.label = 'post_bundle_stabilize' "
        "  AND EXISTS (SELECT 1 FROM blocks b "
        "              WHERE b.snapshot_id = s.id)",
    ).fetchone()
    if row is not None and row[0] is not None:
        target_snap = int(row[0])

    return (fact_snap, target_snap)


def _bridge_plan_row_to_live_mba(
    plan_row,
    *,
    diag_conn,
    snap17_id: int,
    adapter,
    logger_,
) -> tuple[object, str]:
    """Translate snap17 serials in plan_row to live MBA serials.

    The planner reads ``post_bundle_stabilize`` (snap17) blocks and
    produces a row whose ``source_block``,
    ``current_continuation_target``, ``intended_target``, and
    ``state_write_block`` are snap17 serials. Bundle-stabilize between
    live-mba and snap17 remaps serials, so we cannot pass snap17 serials
    straight to a live ``mba.get_mblock(serial)`` call. This helper
    bridges via the start-EA: snap17 serial -> snap17 ``start_ea_i64``
    -> live MBA serial via ``adapter.find_block_by_ea``.

    Returns ``(mapped_row, "ok")`` on success, or ``(None, reason)`` if
    any required field cannot map. The mapped row preserves all
    non-serial fields unchanged.

    ``state_write_block`` is only required when
    ``state_write_bypassed`` is True; otherwise its value passes
    through unchanged (typically None).
    """
    fields_to_map: list[str] = [
        "source_block",
        "current_continuation_target",
        "intended_target",
    ]
    state_write_required = bool(getattr(plan_row, "state_write_bypassed", False))
    state_write_serial = getattr(plan_row, "state_write_block", None)
    if state_write_required and state_write_serial is None:
        return (
            None,
            "live_block_not_resolvable:state_write_block:None:required_when_bypassed",
        )
    if state_write_required:
        fields_to_map.append("state_write_block")

    mapped_serials: dict[str, int | None] = {}
    for field_name in fields_to_map:
        snap_serial = getattr(plan_row, field_name, None)
        if snap_serial is None:
            return (
                None,
                f"live_block_not_resolvable:{field_name}:None:planner_serial_none",
            )
        snap_serial_i = int(snap_serial)
        row = diag_conn.execute(
            "SELECT start_ea_i64 FROM blocks "
            "WHERE snapshot_id=? AND serial=?",
            (int(snap17_id), snap_serial_i),
        ).fetchone()
        if row is None or row[0] is None:
            return (
                None,
                f"live_block_not_resolvable:{field_name}:{snap_serial_i}:no_snap17_row",
            )
        ea_signed = int(row[0])
        ea = ea_signed & ((1 << 64) - 1)
        view = adapter.find_block_by_ea(ea)
        if view is None:
            return (
                None,
                f"live_block_not_resolvable:{field_name}:{snap_serial_i}:"
                f"ea_{ea:#x}_not_in_live_mba",
            )
        live_serial = int(getattr(view, "serial", -1))
        if logger_ is not None:
            logger_.info(
                "tail_state_cascade EA-bridge: field=%s snap17=%s ea=%#x live=%s",
                field_name, snap_serial_i, ea, live_serial,
            )
        mapped_serials[field_name] = live_serial

    # state_write_block passthrough when not required.
    if not state_write_required:
        mapped_serials["state_write_block"] = state_write_serial

    mapped_row = dataclasses.replace(
        plan_row,
        source_block=mapped_serials["source_block"],
        current_continuation_target=mapped_serials["current_continuation_target"],
        intended_target=mapped_serials["intended_target"],
        state_write_block=mapped_serials["state_write_block"],
    )
    return (mapped_row, "ok")


def maybe_run_tail_state_cascade(mba: Any) -> None:
    """Env-gated hook: ``D810_TERMINAL_TAIL_STATE_CASCADE_PAIR`` probe.

    Default-off. When set to exactly ``"5:6"`` and neither
    ``D810_TAIL_DISTINCT_BYTE`` nor ``D810_TAIL_DUPLICATE_CONVERGENCE_BYTE``
    is set, this:

    1. Resolves the latest GLBOPT1 fact snapshot and the latest
       ``post_bundle_stabilize`` block snapshot from the diag DB.
    2. Builds planner inputs (TerminalTailBlock map + TerminalByteEmitSite
       list) and runs ``TerminalTailCascadeEgressPlanner.build_plan()``.
    3. Selects the byte-5 row.
    4. Hands off to the pure ``execute_state_cascade`` orchestrator,
       which gates on the planner's ``SAFE_TARGET_POST_GUARD`` verdict
       and rewires byte5's advance edge through ``LiveMbaAdapter``.

    Any failure (env not set, no diag DB, no fact snapshot, planner
    returns no byte-5 row, verdict not safe, …) is logged and swallowed
    so the manager pipeline never breaks.
    """
    raw = os.environ.get("D810_TERMINAL_TAIL_STATE_CASCADE_PAIR")
    pair = parse_state_cascade_pair_env(raw)
    if pair is None:
        return  # default-off: no log, no mutation

    if (
        os.environ.get("D810_TAIL_DISTINCT_BYTE")
        or os.environ.get("D810_TAIL_DUPLICATE_CONVERGENCE_BYTE")
    ):
        logger.warning(
            "tail_state_cascade: D810_TERMINAL_TAIL_STATE_CASCADE_PAIR is "
            "set together with another tail-shaping probe; refusing to "
            "run any."
        )
        return

    try:
        from d810.core.diag import get_diag_db

        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        diag_conn = get_diag_db(func_ea)
    except Exception:
        logger.exception(
            "tail_state_cascade: cannot acquire diag DB; skipping"
        )
        return

    if diag_conn is None:
        logger.warning(
            "tail_state_cascade: D810_TERMINAL_TAIL_STATE_CASCADE_PAIR=%r "
            "set but diag DB unavailable; skipping",
            raw,
        )
        return

    func_ea_hex = f"0x{int(getattr(mba, 'entry_ea', 0) or 0):016x}"
    fact_snap, target_snap = _resolve_planner_snapshots(diag_conn, func_ea_hex)
    if fact_snap is None or target_snap is None:
        logger.warning(
            "tail_state_cascade: missing planner snapshots "
            "fact_snap=%s target_snap=%s; skipping",
            fact_snap, target_snap,
        )
        return

    try:
        from d810.cfg.terminal_tail_cascade_egress_planner import (
            TerminalTailCascadeEgressPlanner,
        )

        blocks = _load_planner_blocks(diag_conn, target_snap)
        sites = _load_planner_sites(diag_conn, fact_snap, func_ea_hex)
        plan = TerminalTailCascadeEgressPlanner(blocks, sites).build_plan()
    except Exception:
        logger.exception(
            "tail_state_cascade: planner failed; skipping"
        )
        return

    byte5_row = next(
        (row for row in plan.rows if row.byte_index == 5), None,
    )
    if byte5_row is None:
        logger.warning(
            "tail_state_cascade: planner produced no byte-5 row; skipping"
        )
        return

    logger.info(
        "tail_state_cascade: planner row byte_index=5 "
        "verdict=%s source_block=%s intended_target=%s "
        "current_continuation=%s state_variable=%s "
        "state_required_value=%s state_write_block=%s "
        "state_write_bypassed=%s",
        byte5_row.state_update_verdict,
        byte5_row.source_block,
        byte5_row.intended_target,
        byte5_row.current_continuation_target,
        byte5_row.state_variable,
        byte5_row.state_required_value,
        byte5_row.state_write_block,
        byte5_row.state_write_bypassed,
    )

    adapter = LiveMbaAdapter(mba)

    # Bridge: planner serials are in snap17 space (post_bundle_stabilize).
    # The live MBA at hook-fire time uses a different serial space, so we
    # translate via start_ea_i64 -> find_block_by_ea before handing off
    # to the orchestrator. Without this, redirect_advance_edge would
    # call mba.get_mblock(<snap17_serial>) and trigger INTERR 52719.
    snap17_row = diag_conn.execute(
        "SELECT MAX(id) FROM snapshots WHERE label = 'post_bundle_stabilize'"
    ).fetchone()
    snap17_id = (
        int(snap17_row[0]) if snap17_row and snap17_row[0] is not None else None
    )
    if snap17_id is None:
        logger.info(
            "tail_state_cascade: no_snap17_snapshot_in_db; emitting no-op report"
        )
        from d810.cfg.transform.byte_emit_tail_isolation import StateCascadeReport
        report = StateCascadeReport(
            applied=False, pair="5:6", reason="no_snap17_snapshot_in_db",
        )
        logger.info("tail_state_cascade: %s", report)
        return

    mapped_row, bridge_reason = _bridge_plan_row_to_live_mba(
        byte5_row,
        diag_conn=diag_conn,
        snap17_id=snap17_id,
        adapter=adapter,
        logger_=logger,
    )
    if mapped_row is None:
        logger.info(
            "tail_state_cascade: EA-bridge rejected: %s", bridge_reason,
        )
        from d810.cfg.transform.byte_emit_tail_isolation import StateCascadeReport
        report = StateCascadeReport(
            applied=False, pair="5:6", reason=bridge_reason,
        )
        logger.info("tail_state_cascade: %s", report)
        return

    logger.info(
        "tail_state_cascade: EA-bridge mapped row "
        "source_block=%s->%s continuation=%s->%s intended=%s->%s "
        "state_write=%s->%s",
        byte5_row.source_block, mapped_row.source_block,
        byte5_row.current_continuation_target, mapped_row.current_continuation_target,
        byte5_row.intended_target, mapped_row.intended_target,
        byte5_row.state_write_block, mapped_row.state_write_block,
    )

    try:
        report = execute_state_cascade(
            pair=pair,
            plan_row=mapped_row,
            adapter=adapter,
        )
    except Exception:
        logger.exception(
            "tail_state_cascade: unexpected failure; continuing"
        )
        return

    logger.info("tail_state_cascade: %s", report)
