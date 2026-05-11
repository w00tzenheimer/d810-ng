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

from d810.cfg.transform.byte_emit_live_use_anchor import (
    execute_byte_store_replica_anchor,
    execute_live_host_anchor,
    execute_multi_byte_live_host_anchor,
    execute_single_xor_anchor,
    execute_split_xor_anchor,
    parse_byte_anchor_env,
    parse_byte_store_env,
    parse_live_host_env,
    parse_multi_byte_env,
    parse_multi_host_env,
    parse_single_xor_env,
)
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

    # ------------------------------------------------------------------
    # Byte-store anchor (Track D byte_store mechanism — reference-style
    # buffer write replication for bytes 2-6).
    # ------------------------------------------------------------------

    def _find_byte_emit_template_block(self, byte_index: int):
        """Search the entire mba for the BLOCK containing an m_stx
        instance whose dstr references v190 at the given byte_index.
        Returns the mblock_t (so the ENTIRE block can be cloned via
        copy_block), or None.

        This is the right granularity for byte_store: the entire
        byte_emit block has a self-contained def chain (m_sar
        precomputes counter>>3, m_shl precomputes the shifted byte,
        m_stx writes to buffer). Cloning the whole block preserves
        all the local SSA/use-def relationships IDA's verifier
        requires.
        """
        import ida_hexrays as _ih

        if byte_index == 0:
            needles = ("[ds.2:%var_190.8].1",)
        else:
            needles = (f"%var_190.8+#{byte_index}.8",)
        qty = int(getattr(self._mba, "qty", 0) or 0)
        for serial in range(qty):
            blk = self._mba.get_mblock(serial)
            if blk is None:
                continue
            insn = blk.head
            while insn is not None:
                if int(insn.opcode) == int(_ih.m_stx):
                    try:
                        ds = insn.dstr() if callable(getattr(insn, "dstr", None)) else ""
                    except Exception:
                        ds = ""
                    if any(n in ds for n in needles):
                        return blk
                insn = insn.next
        return None

    def _find_byte_emit_stx_template(self, byte_index: int):
        """Search the entire mba for an m_stx instance whose dstr
        references v190 at the given byte_index. Returns the minsn_t
        directly (so it can be cloned), or None.

        Used by insert_byte_emit_replica_anchor: the host block doesn't
        necessarily CONTAIN the template m_stx; the template lives in
        a (possibly soon-to-be-DCE'd) byte_emit block that we can still
        clone at hook time.
        """
        import ida_hexrays as _ih

        if byte_index == 0:
            needles = ("[ds.2:%var_190.8].1",)
        else:
            needles = (f"%var_190.8+#{byte_index}.8",)
        qty = int(getattr(self._mba, "qty", 0) or 0)
        for serial in range(qty):
            blk = self._mba.get_mblock(serial)
            if blk is None:
                continue
            insn = blk.head
            while insn is not None:
                if int(insn.opcode) == int(_ih.m_stx):
                    try:
                        ds = insn.dstr() if callable(getattr(insn, "dstr", None)) else ""
                    except Exception:
                        ds = ""
                    if any(n in ds for n in needles):
                        return insn
                insn = insn.next
        return None

    def insert_byte_emit_replica_anchor(
        self,
        *,
        predecessor_serial: int,
        successor_serial: int,
        template_byte_index: int,
        target_byte_index: int,
    ) -> int:
        """Insert an anchor block whose body is a CLONE of the
        predecessor's byte-emit m_stx, with the byte-index operand
        patched from ``template_byte_index`` to ``target_byte_index``.

        Use case: predecessor is byte 1's emit block (which survives
        IDA DCE). We want bytes 2-6 to appear as buffer writes in AFTER
        pseudocode. Cloning byte 1's m_stx and patching the byte index
        gives us a structurally identical buffer write but referencing
        the target byte's source-byte read.

        The buffer offset is NOT adjusted (same slot as template) -- the
        goal is making the m_stx (and hence the source-byte load)
        survive optimize_global, not preserving exact reference
        semantics.
        """
        import ida_hexrays as _ih

        mba = self._mba
        pred_blk = mba.get_mblock(int(predecessor_serial))
        if pred_blk is None:
            raise RuntimeError(
                f"insert_byte_emit_replica_anchor: pred {predecessor_serial} not resolvable"
            )

        if int(successor_serial) == -1:
            pred_succs = [int(s) for s in pred_blk.succset]
            if len(pred_succs) != 1:
                raise RuntimeError(
                    "sentinel successor=-1 requires 1-way pred; "
                    f"block {predecessor_serial} has {len(pred_succs)} succs"
                )
            successor_serial = pred_succs[0]

        succ_blk = mba.get_mblock(int(successor_serial))
        if succ_blk is None:
            raise RuntimeError(
                f"insert_byte_emit_replica_anchor: succ {successor_serial} not resolvable"
            )

        # Find the template BLOCK (the entire byte_emit block) for the
        # template byte. We'll clone this whole block so the def chain
        # (m_sar precomputes counter>>3, m_shl precomputes shifted byte,
        # m_stx writes to buffer) is self-contained.
        template_block = self._find_byte_emit_template_block(template_byte_index)
        if template_block is None:
            raise RuntimeError(
                f"insert_byte_emit_replica_anchor: no template block "
                f"containing m_stx for v190+#{template_byte_index}.8"
            )

        end_serial = int(mba.qty) - 1
        anchor = mba.copy_block(template_block, end_serial)
        if anchor is None:
            raise RuntimeError(
                f"copy_block failed for template={template_block.serial}"
            )

        # CRITICAL: mba.copy_block may shallow-share nested mop_t objects
        # between the template and the clone. Break that sharing by
        # deep-cloning every operand tree in the new anchor.
        cur_dc = anchor.head
        while cur_dc is not None:
            _deepclone_minsn_operands(cur_dc, _ih)
            cur_dc = cur_dc.next

        # Refresh serials post-copy_block (BLT_STOP shifts).
        successor_serial = int(succ_blk.serial)
        predecessor_serial = int(pred_blk.serial)

        # Walk the clone: KEEP byte_emit instructions (m_sar, m_shl,
        # m_xdu, m_ldx, m_stx), NOP everything else (state-write m_mov
        # with literal constants, original m_goto, etc.). Then patch
        # the byte index in any kept instruction.
        byte_emit_opcodes = {
            int(_ih.m_sar), int(_ih.m_shl), int(_ih.m_xdu),
            int(_ih.m_ldx), int(_ih.m_stx),
            # Also keep arithmetic helpers that may appear:
            int(_ih.m_add), int(_ih.m_and), int(_ih.m_mul),
        }
        cur = anchor.head
        patch_count = 0
        # All anchors write to the same slot as the host (host's slot is
        # observed by downstream code). To prevent IDA from dedup'ing
        # consecutive writes-to-same-slot, each anchor's byte goes to a
        # DIFFERENT bit-position within the slot via a shift delta.
        # All anchors write to the SAME slot AND the same bit position as
        # the host. Different bytes OR'd into the same bit positions
        # accumulate (IDA can't prove redundancy across distinct loads),
        # making each byte's read observable via the slot's downstream use.
        offset_delta = 0
        shift_delta = 0
        while cur is not None:
            if int(cur.opcode) in byte_emit_opcodes:
                # Patch byte_index in operand trees.
                for op in (cur.l, cur.r, cur.d):
                    if op is not None:
                        if _patch_v190_byte_const(
                            op, template_byte_index, target_byte_index, _ih,
                        ):
                            patch_count += 1
                # Add (k-1)*8 to the m_stx ADDRESS operand so each
                # anchor writes to a distinct slot (otherwise IDA dedups
                # all 5 to one).
                # m_stx layout per SDK: l=value, r=segment(2), d=address.
                # So we wrap cur.d (the address), NOT cur.r (segment).
                if int(cur.opcode) == int(_ih.m_stx) and offset_delta != 0:
                    if cur.d is not None:
                        _wrap_address_with_offset(
                            cur.d, offset_delta, _ih,
                            ea=int(getattr(cur, "ea", 0) or 0),
                        )
                # For ANY m_shl (top-level OR nested inside m_stx's value
                # tree), add shift_delta to its shift count (m_shl.r) so
                # each byte ORs into a unique bit position within the
                # buffer slot.
                if shift_delta != 0:
                    _wrap_all_nested_shifts(
                        cur, shift_delta, _ih,
                        ea=int(getattr(cur, "ea", 0) or 0),
                    )
            else:
                anchor.make_nop(cur)
            cur = cur.next
        logger.info(
            "byte_anchor[byte_store]: clone of block %d for byte %d->%d: %d patches applied",
            template_block.serial, template_byte_index, target_byte_index, patch_count,
        )
        # Dump ALL kept instructions + walk every operand tree level.
        cur = anchor.head
        idx = 0
        while cur is not None:
            if int(cur.opcode) in byte_emit_opcodes:
                try:
                    ds = cur.dstr() if callable(getattr(cur, "dstr", None)) else ""
                except Exception:
                    ds = "<err>"
                logger.info(
                    "byte_anchor[byte_store]:   anchor[%d] kept insn[%d]: %s",
                    anchor.serial, idx, ds[:300],
                )
                # Walk and log every operand in the tree.
                if idx == 1:  # the m_shl (smaller; has the v190 reference)
                    _dump_mop_tree(cur.l, "l", 0, _ih)
                    _dump_mop_tree(cur.r, "r", 0, _ih)
                    _dump_mop_tree(cur.d, "d", 0, _ih)
                idx += 1
            cur = cur.next

        # Now wire BLT_1WAY topology and append goto.
        anchor.type = _ih.BLT_1WAY
        for stale_succ in [int(x) for x in anchor.succset]:
            anchor.succset._del(stale_succ)
            other = mba.get_mblock(stale_succ)
            if other is not None:
                other.predset._del(anchor.serial)
                if other.serial != mba.qty - 1:
                    other.mark_lists_dirty()
        for stale_pred in [int(x) for x in anchor.predset]:
            anchor.predset._del(stale_pred)

        safe_ea = int(getattr(mba, "entry_ea", 0) or 0)
        goto_ins = _ih.minsn_t(safe_ea)
        goto_ins.ea = safe_ea
        anchor.insert_into_block(goto_ins, anchor.tail)
        anchor.make_nop(anchor.tail)
        goto_ins.opcode = _ih.m_goto
        goto_ins.l = _ih.mop_t()
        goto_ins.l.make_blkref(int(successor_serial))
        goto_ins.r = _ih.mop_t()
        goto_ins.r.erase()
        goto_ins.d = _ih.mop_t()
        goto_ins.d.erase()
        anchor.flags |= _ih.MBL_GOTO

        anchor.succset.push_back(int(successor_serial))
        pred_blk.succset._del(int(successor_serial))
        pred_blk.succset.push_back(int(anchor.serial))
        if (
            pred_blk.tail is not None
            and int(pred_blk.tail.opcode) == int(_ih.m_goto)
            and pred_blk.tail.l is not None
            and int(pred_blk.tail.l.t) == int(_ih.mop_b)
            and int(pred_blk.tail.l.b) == int(successor_serial)
        ):
            pred_blk.tail.l.make_blkref(int(anchor.serial))
        pred_blk.mark_lists_dirty()

        succ_blk.predset._del(int(predecessor_serial))
        succ_blk.predset.push_back(int(anchor.serial))
        if succ_blk.serial != mba.qty - 1:
            succ_blk.mark_lists_dirty()

        anchor.predset.push_back(int(predecessor_serial))
        anchor.mark_lists_dirty()
        mba.mark_chains_dirty()

        return int(anchor.serial)

    # ------------------------------------------------------------------
    # LiveUseAnchorAdapter (Track D byte 6 split-XOR anchor probe)
    # ------------------------------------------------------------------

    def find_byte_emit_block_by_v190_offset(self, byte_index: int):
        """Walk every block; for each block walk every top-level minsn
        and its full operand-tree recursively, seeking an m_ldx whose
        r operand resolves to v190+#byte_index. Return that block.

        Fallback: textual dstr match.
        """
        import ida_hexrays as _ih

        mba = self._mba
        qty = int(getattr(mba, "qty", 0) or 0)
        insn_count = 0
        v190_byte_indices_seen: set[int] = set()
        dstr_match_serial: int | None = None
        for serial in range(qty):
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            insn = blk.head
            while insn is not None:
                insn_count += 1
                found = _find_v190_ldx_in_insn(insn, byte_index, v190_byte_indices_seen)
                if found is not None:
                    return self.find_block_by_ea(
                        int(getattr(blk, "start", 0) or 0),
                    )
                try:
                    dstr = insn.dstr() if callable(getattr(insn, "dstr", None)) else ""
                except Exception:
                    dstr = ""
                needle = f"%var_190.8+#{byte_index}.8"
                if needle in dstr and dstr_match_serial is None:
                    dstr_match_serial = serial
                insn = insn.next
        if dstr_match_serial is not None:
            logger.warning(
                "byte_anchor: structural walker missed byte %d but dstr "
                "matches in block %d (insns walked: %d, byte indices the "
                "structural walker DID find: %s). Falling back.",
                byte_index, dstr_match_serial, insn_count,
                sorted(v190_byte_indices_seen),
            )
            blk = mba.get_mblock(dstr_match_serial)
            return self.find_block_by_ea(
                int(getattr(blk, "start", 0) or 0),
            )
        logger.info(
            "byte_anchor: no insn found with m_ldx of v190+#%d "
            "(walked %d insns, structural byte indices found: %s).",
            byte_index, insn_count, sorted(v190_byte_indices_seen),
        )
        return None

    def extract_v190_indexed_operand(
        self, byte_emit_serial: int, byte_index: int,
    ):
        """Find an operand whose dstr equals ``(%var_190.8+#k.8)``
        anywhere in any insn's operand tree (in the byte_emit block
        first, then any other block as fallback). Return a clone.

        We dstr-match rather than structural-match because the operand
        is stored in a wide variety of nested mop_t/minsn_t shapes the
        structural recognizer doesn't fully cover, but ``mop_t.dstr()``
        always renders to a stable textual form.
        """
        import ida_hexrays as _ih

        target = f"(%var_190.8+#{byte_index}.8)"
        # First pass: search the named byte_emit block.
        blk = self._mba.get_mblock(int(byte_emit_serial))
        if blk is not None:
            found = _find_mop_by_dstr_in_block(blk, target, _ih)
            if found is not None:
                clone = _ih.mop_t()
                clone.assign(found)
                return clone
        # Second pass: search any block in the mba.
        qty = int(getattr(self._mba, "qty", 0) or 0)
        for serial in range(qty):
            blk = self._mba.get_mblock(serial)
            if blk is None:
                continue
            found = _find_mop_by_dstr_in_block(blk, target, _ih)
            if found is not None:
                logger.warning(
                    "byte_anchor: extract_v190_indexed_operand: target "
                    "%s found in block %d (not the byte_emit block %d).",
                    target, serial, byte_emit_serial,
                )
                clone = _ih.mop_t()
                clone.assign(found)
                return clone
        raise RuntimeError(
            f"no operand matching {target!r} found anywhere in mba"
        )

    def find_pre_return_block(self) -> int:
        """Return the unique BLT_STOP predecessor's serial.

        Raises RuntimeError if zero or more than one BLT_STOP exists,
        or if BLT_STOP has anything other than exactly one predecessor.
        """
        import ida_hexrays as _ih

        mba = self._mba
        qty = int(getattr(mba, "qty", 0) or 0)
        stop_serials = [
            s for s in range(qty)
            if mba.get_mblock(s) is not None
            and int(mba.get_mblock(s).type) == int(_ih.BLT_STOP)
        ]
        if len(stop_serials) != 1:
            raise RuntimeError(
                f"expected exactly one BLT_STOP block; got {len(stop_serials)}"
            )
        stop_blk = mba.get_mblock(stop_serials[0])
        preds = [int(p) for p in stop_blk.predset]
        if len(preds) != 1:
            raise RuntimeError(
                f"expected exactly one BLT_STOP predecessor; got {len(preds)}"
            )
        return preds[0]

    def insert_anchor_block_xor_pair(
        self,
        *,
        predecessor_serial: int,
        successor_serial: int,
        source_addr_operand,
        accumulator_stkoff: int,
    ) -> int:
        """Insert an anchor block carrying:

            m_ldx  kreg(1),  ds.2, source_addr_operand
            m_xdu  kreg(8),  kreg(1)
            m_xor  var(8),   var(8), kreg(8)
            m_goto @successor

        between predecessor and successor.

        Mirrors ``insert_trampoline_after``'s clone-and-NOP-then-decorate
        pattern (mba.copy_block + make_nop + insert_into_block +
        nop-then-mutate) to avoid INTERR 52123.

        ``successor_serial == -1`` is a sentinel meaning: use
        ``predecessor_serial``'s current sole successor.
        """
        import ida_hexrays as _ih

        mba = self._mba
        pred_blk = mba.get_mblock(int(predecessor_serial))
        if pred_blk is None:
            raise RuntimeError(
                f"insert_anchor_block_xor_pair: pred {predecessor_serial} "
                "not resolvable"
            )

        # Resolve sentinel.
        if int(successor_serial) == -1:
            pred_succs = [int(s) for s in pred_blk.succset]
            if len(pred_succs) != 1:
                raise RuntimeError(
                    "sentinel successor=-1 requires 1-way pred; "
                    f"block {predecessor_serial} has {len(pred_succs)} succs"
                )
            successor_serial = pred_succs[0]

        succ_blk = mba.get_mblock(int(successor_serial))
        if succ_blk is None:
            raise RuntimeError(
                f"insert_anchor_block_xor_pair: succ {successor_serial} "
                "not resolvable"
            )

        # 1. Clone predecessor at end of mba.
        end_serial = int(mba.qty) - 1
        anchor = mba.copy_block(pred_blk, end_serial)
        if anchor is None:
            raise RuntimeError(
                f"insert_anchor_block_xor_pair: copy_block failed for "
                f"pred={predecessor_serial}"
            )

        # CRITICAL: mba.copy_block can shift the serials of blocks at
        # and beyond end_serial (the dummy BLT_STOP block in particular
        # always shifts by +1). The integer `successor_serial` captured
        # before copy_block may now point at a DIFFERENT block. Block
        # references (succ_blk, pred_blk) auto-track shifts; refresh the
        # integer from succ_blk.serial.
        successor_serial = int(succ_blk.serial)
        predecessor_serial = int(pred_blk.serial)

        # 2. NOP every inherited instruction.
        cur = anchor.head
        while cur is not None:
            anchor.make_nop(cur)
            cur = cur.next

        # 3. Mark as 1-way; clear stale pred/succ entries copy_block carried over.
        anchor.type = _ih.BLT_1WAY
        for stale_succ in [int(x) for x in anchor.succset]:
            anchor.succset._del(stale_succ)
            other = mba.get_mblock(stale_succ)
            if other is not None:
                other.predset._del(anchor.serial)
                if other.serial != mba.qty - 1:
                    other.mark_lists_dirty()
        for stale_pred in [int(x) for x in anchor.predset]:
            anchor.predset._del(stale_pred)

        # 4. Allocate a fresh kreg pair for the byte load + zero-extend.
        safe_ea = int(getattr(mba, "entry_ea", 0) or 0)
        kreg_id = int(mba.alloc_kreg(8))

        # 5. m_ldx kreg(1) <- [seg : source_addr_operand]
        # Clone segment operand from any existing m_stx/m_ldx in the mba
        # since the IDA segment-register constant (mr_ds) is not always
        # exposed in the Python bindings on every IDA version.
        seg_template = _find_segment_operand_template(mba, _ih)
        if seg_template is None:
            raise RuntimeError(
                "insert_anchor_block_xor_pair: no m_stx/m_ldx in mba to "
                "clone segment operand from"
            )
        ldx_ins = _ih.minsn_t(safe_ea)
        ldx_ins.ea = safe_ea
        anchor.insert_into_block(ldx_ins, anchor.tail)
        anchor.make_nop(anchor.tail)
        ldx_ins.opcode = _ih.m_ldx
        ldx_ins.l = _ih.mop_t()
        ldx_ins.l.assign(seg_template)
        ldx_ins.r = _ih.mop_t()
        ldx_ins.r.assign(source_addr_operand)
        ldx_ins.d = _ih.mop_t()
        ldx_ins.d.make_reg(kreg_id, 1)

        # 6. m_xdu kreg(8) <- kreg(1)
        xdu_ins = _ih.minsn_t(safe_ea)
        xdu_ins.ea = safe_ea
        anchor.insert_into_block(xdu_ins, anchor.tail)
        anchor.make_nop(anchor.tail)
        xdu_ins.opcode = _ih.m_xdu
        xdu_ins.l = _ih.mop_t()
        xdu_ins.l.make_reg(kreg_id, 1)
        xdu_ins.r = _ih.mop_t()
        xdu_ins.r.erase()
        xdu_ins.d = _ih.mop_t()
        xdu_ins.d.make_reg(kreg_id, 8)

        # 7. m_xor stkvar(8) <- stkvar(8) ^ kreg(8)
        xor_ins = _ih.minsn_t(safe_ea)
        xor_ins.ea = safe_ea
        anchor.insert_into_block(xor_ins, anchor.tail)
        anchor.make_nop(anchor.tail)
        xor_ins.opcode = _ih.m_xor
        xor_ins.l = _ih.mop_t()
        xor_ins.l.make_stkvar(mba, int(accumulator_stkoff))
        xor_ins.l.size = 8
        xor_ins.r = _ih.mop_t()
        xor_ins.r.make_reg(kreg_id, 8)
        xor_ins.d = _ih.mop_t()
        xor_ins.d.make_stkvar(mba, int(accumulator_stkoff))
        xor_ins.d.size = 8

        # 8. m_goto @successor
        goto_ins = _ih.minsn_t(safe_ea)
        goto_ins.ea = safe_ea
        anchor.insert_into_block(goto_ins, anchor.tail)
        anchor.make_nop(anchor.tail)
        goto_ins.opcode = _ih.m_goto
        goto_ins.l = _ih.mop_t()
        goto_ins.l.make_blkref(int(successor_serial))
        goto_ins.r = _ih.mop_t()
        goto_ins.r.erase()
        goto_ins.d = _ih.mop_t()
        goto_ins.d.erase()
        anchor.flags |= _ih.MBL_GOTO

        # 9. Wire anchor -> successor.
        anchor.succset.push_back(int(successor_serial))

        # 10. Rewire predecessor: pred->succ becomes pred->anchor->succ.
        pred_blk.succset._del(int(successor_serial))
        pred_blk.succset.push_back(int(anchor.serial))
        if (
            pred_blk.tail is not None
            and int(pred_blk.tail.opcode) == int(_ih.m_goto)
            and pred_blk.tail.l is not None
            and int(pred_blk.tail.l.t) == int(_ih.mop_b)
            and int(pred_blk.tail.l.b) == int(successor_serial)
        ):
            pred_blk.tail.l.make_blkref(int(anchor.serial))
        pred_blk.mark_lists_dirty()

        # 11. Update successor's predset.
        succ_blk.predset._del(int(predecessor_serial))
        succ_blk.predset.push_back(int(anchor.serial))
        if succ_blk.serial != mba.qty - 1:
            succ_blk.mark_lists_dirty()

        # 12. Anchor's own pred set.
        anchor.predset.push_back(int(predecessor_serial))
        anchor.mark_lists_dirty()
        mba.mark_chains_dirty()

        return int(anchor.serial)


def _dump_mop_tree(op, label: str, depth: int, _ih, max_depth: int = 8) -> None:
    """Recursively log every operand in a tree with type + dstr + key fields."""
    if op is None or depth > max_depth:
        return
    t = int(getattr(op, "t", -1))
    type_names = {
        0: "mop_z", 1: "mop_r", 2: "mop_n", 3: "mop_str",
        4: "mop_d", 5: "mop_S", 6: "mop_v", 7: "mop_b",
        8: "mop_f", 9: "mop_l", 10: "mop_a", 11: "mop_h",
        12: "mop_c", 13: "mop_fn", 14: "mop_p", 15: "mop_sc",
    }
    type_name = type_names.get(t, f"mop_t={t}")
    try:
        ds = op.dstr() if callable(getattr(op, "dstr", None)) else ""
    except Exception:
        ds = "<err>"
    extras = []
    if t == int(_ih.mop_S):
        s = getattr(op, "s", None)
        if s is not None:
            extras.append(f"s.off=0x{int(getattr(s, 'off', 0)):x}")
    if t == int(_ih.mop_a):
        a = getattr(op, "a", None)
        if a is not None:
            extras.append(f"a.t={int(getattr(a, 't', -1))}")
            try:
                inner = a.dstr() if callable(getattr(a, "dstr", None)) else ""
                extras.append(f"a.dstr={inner[:30]}")
            except Exception:
                pass
            inner_s = getattr(a, "s", None)
            if inner_s is not None:
                extras.append(f"a.s.off=0x{int(getattr(inner_s, 'off', 0)):x}")
    if t == int(_ih.mop_n):
        nnn = getattr(op, "nnn", None)
        if nnn is not None:
            extras.append(f"nnn={int(getattr(nnn, 'value', 0))}")
    indent = "  " * depth
    logger.info("MOPTRACE %s%s.%s [%s] size=%s dstr=%s",
                indent, label, type_name, ",".join(extras),
                int(getattr(op, "size", 0) or 0), ds[:60])
    # Recurse if this is mop_d (wraps a sub-instruction).
    if t == int(_ih.mop_d):
        sub = getattr(op, "d", None)
        if sub is not None:
            try:
                op_name = type_names.get(int(getattr(sub, "opcode", -1)), "?")
            except Exception:
                op_name = "?"
            logger.info("MOPTRACE %s  %s.sub opcode=%s", indent, label,
                        int(getattr(sub, "opcode", -1)))
            _dump_mop_tree(getattr(sub, "l", None), f"{label}.sub.l", depth + 1, _ih, max_depth)
            _dump_mop_tree(getattr(sub, "r", None), f"{label}.sub.r", depth + 1, _ih, max_depth)
            _dump_mop_tree(getattr(sub, "d", None), f"{label}.sub.d", depth + 1, _ih, max_depth)
    # Recurse into mop_a (address-of) target.
    if t == int(_ih.mop_a):
        inner = getattr(op, "a", None)
        if inner is not None:
            _dump_mop_tree(inner, f"{label}.a", depth + 1, _ih, max_depth)


def _wrap_all_nested_shifts(insn, delta: int, _ih, ea: int = 0) -> None:
    """Walk an instruction's operand tree recursively; wrap m_shl.r
    (shift count) with m_add(orig, #delta) for every m_shl encountered.

    Used by byte_store anchors: each cloned anchor has both a top-level
    m_shl AND a nested m_shl inside the m_stx's value tree. Both need
    the shift-count offset to make the byte OR into a distinct bit
    position within the buffer slot.
    """
    if insn is None:
        return
    if int(getattr(insn, "opcode", -1)) == int(_ih.m_shl):
        if insn.r is not None:
            _wrap_address_with_offset(insn.r, delta, _ih, ea=ea)
    for op_name in ("l", "r", "d"):
        op = getattr(insn, op_name, None)
        if op is None:
            continue
        if int(getattr(op, "t", -1)) != int(_ih.mop_d):
            continue
        sub = getattr(op, "d", None)
        if sub is not None:
            _wrap_all_nested_shifts(sub, delta, _ih, ea=ea)


def _deepclone_mop(mop, _ih) -> None:
    """Force a mop_t's wrapped sub-instruction to be a fresh, independent
    copy (no shared state with the original).

    For mop_d operands, SWIG returns the wrapped ``minsn_t*`` directly --
    so two mop_t's that wrap the same minsn_t share its operand tree.
    To break this sharing we must allocate a fresh minsn_t and use
    ``minsn_t.copy()`` (which does a deep copy via HEXDSP) to populate
    it, then replace the original pointer.

    Recurses into the freshly cloned sub-instruction's operands.
    """
    if mop is None:
        return
    if int(getattr(mop, "t", -1)) != int(_ih.mop_d):
        return  # only mop_d wraps a sub-instruction
    shared_inner = getattr(mop, "d", None)
    if shared_inner is None:
        return
    try:
        ea = int(getattr(shared_inner, "ea", 0) or 0)
        fresh_inner = _ih.minsn_t(ea)
        fresh_inner.copy(shared_inner)  # HEXDSP deep-copy of contents
        mop.d = fresh_inner
    except Exception:
        return
    # Recurse into the FRESH inner's operands -- any nested mop_d may
    # still wrap a shared minsn_t until we recurse.
    _deepclone_mop(getattr(fresh_inner, "l", None), _ih)
    _deepclone_mop(getattr(fresh_inner, "r", None), _ih)
    _deepclone_mop(getattr(fresh_inner, "d", None), _ih)


def _deepclone_minsn_operands(insn, _ih) -> None:
    """Deep-clone all three operands of an instruction (post-copy_block)."""
    if insn is None:
        return
    _deepclone_mop(getattr(insn, "l", None), _ih)
    _deepclone_mop(getattr(insn, "r", None), _ih)
    _deepclone_mop(getattr(insn, "d", None), _ih)


def _wrap_address_with_offset(op, delta: int, _ih, ea: int = 0) -> bool:
    """Wrap ``op`` (an m_stx address operand) as
    ``m_add(original_op_contents, mop_n=delta)`` -- adds a constant
    offset to the address so this m_stx writes to a different buffer
    slot than the template.

    ``ea`` must be a valid mba address (the verifier checks
    INTERR 50863 'wrong instruction address' for ea outside mba range).
    """
    if op is None or int(delta) == 0:
        return False
    try:
        original_size = int(getattr(op, "size", 0) or 8)
        original = _ih.mop_t()
        original.assign(op)
        add_insn = _ih.minsn_t(int(ea))
        add_insn.ea = int(ea)
        add_insn.opcode = _ih.m_add
        add_insn.l = original
        add_insn.r = _ih.mop_t()
        add_insn.r.make_number(int(delta), original_size)
        add_insn.d = _ih.mop_t()
        add_insn.d.erase()
        add_insn.d.size = original_size
        op.create_from_insn(add_insn)
        op.size = original_size
        return True
    except Exception:
        logger.exception("_wrap_address_with_offset failed for delta=%d", delta)
        return False


def _is_v190_mop_S(op, _ih) -> bool:
    """Return True if op is the mop_S rendering as '%var_190.8'.

    The internal stkoff for var_190 is function-specific (e.g. 0x668
    in sub_7FFD3338C040 -- the s.off field uses a different offset
    convention than the displayed name). dstr-based matching is the
    only reliable way to identify the byte-source-pointer stkvar.
    """
    if op is None:
        return False
    if int(getattr(op, "t", -1)) != int(_ih.mop_S):
        return False
    try:
        ds = op.dstr() if callable(getattr(op, "dstr", None)) else ""
    except Exception:
        return False
    return ds == "%var_190.8"


def _patch_v190_byte_const(op, old_index: int, new_index: int, _ih) -> bool:
    """Walk a mop_t tree; find any reference to (v190+#old_index.8) and
    rewrite it to (v190+#new_index.8).

    The operand shape we look for is mop_d wrapping m_add(v190, #k),
    where v190 is identified by mop_t.dstr()=='%var_190.8' (not by
    stkoff -- the internal stkoff doesn't match the displayed-name
    offset).

    Returns True if any patch was applied.
    """
    if op is None:
        return False
    t = int(getattr(op, "t", -1))
    patched = False

    # Match: mop_d wrapping m_add(v190, mop_n=old_index). The v190 leaf
    # is identified by dstr=='%var_190.8' (the displayed-name offset
    # convention differs from the internal mop_S.s.off; only dstr is
    # a reliable identifier).
    if t == int(_ih.mop_d):
        sub = getattr(op, "d", None)
        if sub is not None:
            if int(getattr(sub, "opcode", -1)) == int(_ih.m_add):
                l = getattr(sub, "l", None)
                r = getattr(sub, "r", None)
                # Standard order: l=v190, r=mop_n
                if (
                    _is_v190_mop_S(l, _ih)
                    and r is not None
                    and int(getattr(r, "t", -1)) == int(_ih.mop_n)
                    and getattr(r, "nnn", None) is not None
                    and int(r.nnn.value) == int(old_index)
                ):
                    r.make_number(int(new_index), int(r.size or 8))
                    patched = True
                # Reversed order (commutative)
                if (
                    _is_v190_mop_S(r, _ih)
                    and l is not None
                    and int(getattr(l, "t", -1)) == int(_ih.mop_n)
                    and getattr(l, "nnn", None) is not None
                    and int(l.nnn.value) == int(old_index)
                ):
                    l.make_number(int(new_index), int(l.size or 8))
                    patched = True
            # Recurse into sub-instruction's operands.
            for child in (sub.l, sub.r, sub.d):
                if _patch_v190_byte_const(child, old_index, new_index, _ih):
                    patched = True
    return patched


def _mop_dstr(mop) -> str:
    """Best-effort textual rendering of a mop_t (returns '' on failure)."""
    try:
        ds = mop.dstr() if callable(getattr(mop, "dstr", None)) else ""
        return ds if isinstance(ds, str) else ""
    except Exception:
        return ""


def _find_mop_by_dstr_in_block(blk, target: str, _ih):
    """Walk every minsn in the block and every nested mop_t operand
    tree; return the first mop_t whose dstr() equals or contains
    ``target``. Returns None if no match.
    """
    insn = blk.head
    while insn is not None:
        for op in (
            getattr(insn, "l", None),
            getattr(insn, "r", None),
            getattr(insn, "d", None),
        ):
            found = _find_mop_by_dstr(op, target, _ih)
            if found is not None:
                return found
        insn = insn.next
    return None


def _find_mop_by_dstr(mop, target: str, _ih, depth: int = 15):
    """Walk a mop_t recursively (descending into mop_d sub-instructions
    and their operand trees) seeking a mop whose dstr matches target.
    """
    if depth <= 0 or mop is None:
        return None
    ds = _mop_dstr(mop)
    if target in ds:
        # Prefer the most specific match: the operand whose own dstr
        # equals target exactly. If we found a parent containing target
        # as a substring, descend to find a tighter match.
        if ds == target:
            return mop
        # Descend.
        if int(getattr(mop, "t", -1)) == int(_ih.mop_d):
            sub = getattr(mop, "d", None)
            if sub is not None:
                for child in (
                    getattr(sub, "l", None),
                    getattr(sub, "r", None),
                    getattr(sub, "d", None),
                ):
                    inner = _find_mop_by_dstr(child, target, _ih, depth - 1)
                    if inner is not None:
                        return inner
        # No tighter match -> return the substring-matching parent.
        return mop
    # Target not in this mop's dstr; still descend into sub-insns in
    # case the operand tree's dstr collapsed the inner form.
    if int(getattr(mop, "t", -1)) == int(_ih.mop_d):
        sub = getattr(mop, "d", None)
        if sub is not None:
            for child in (
                getattr(sub, "l", None),
                getattr(sub, "r", None),
                getattr(sub, "d", None),
            ):
                inner = _find_mop_by_dstr(child, target, _ih, depth - 1)
                if inner is not None:
                    return inner
    return None


def _find_v190_ldx_in_insn(
    insn,
    byte_index: int,
    observed_byte_indices: set[int] | None = None,
    depth: int = 15,
):
    """Recursively walk an minsn_t and every nested mop_d/sub-instruction
    seeking an m_ldx whose r operand is v190+#byte_index.

    ``observed_byte_indices`` (optional) is populated with any byte index
    k for which a v190+#k m_ldx was seen during the walk -- a diagnostic
    aid so the caller can log "we saw bytes 0,1,2 but not 6".
    """
    import ida_hexrays as _ih

    if depth <= 0 or insn is None:
        return None
    if int(getattr(insn, "opcode", -1)) == int(_ih.m_ldx):
        r = getattr(insn, "r", None)
        if r is not None and _is_v190_plus_k(r, byte_index):
            return r
        if observed_byte_indices is not None and r is not None:
            for k in range(7):
                if _is_v190_plus_k(r, k):
                    observed_byte_indices.add(k)
    for op in (
        getattr(insn, "l", None),
        getattr(insn, "r", None),
        getattr(insn, "d", None),
    ):
        if op is None:
            continue
        if int(getattr(op, "t", -1)) != int(_ih.mop_d):
            continue
        sub = getattr(op, "d", None)
        if sub is None:
            continue
        found = _find_v190_ldx_in_insn(
            sub, byte_index, observed_byte_indices, depth - 1,
        )
        if found is not None:
            return found
    return None


def _find_segment_operand_template(mba, _ih):
    """Return a clone of the segment operand from any existing
    m_stx or m_ldx in the mba.

    The segment register constant ``mr_ds`` is not always exposed as a
    Python attribute on ``ida_hexrays`` (depends on IDA version /
    architecture), but every binary that touches the data segment has
    at least one m_stx/m_ldx in its microcode whose segment operand is
    a well-formed register reference we can clone.

    Returns None if no candidate insn is found.
    """
    qty = int(getattr(mba, "qty", 0) or 0)
    for serial in range(qty):
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        insn = blk.head
        while insn is not None:
            opc = int(getattr(insn, "opcode", -1))
            if opc == int(_ih.m_stx) or opc == int(_ih.m_ldx):
                seg = getattr(insn, "l", None)
                if seg is not None:
                    clone = _ih.mop_t()
                    clone.assign(seg)
                    return clone
            insn = insn.next
    return None


def _synthesize_v190_plus_k_operand(mba, byte_index: int, _ih):
    """Build a fresh ``mop_d(m_add(stkvar@0x190, #byte_index.8))`` mop_t.

    Used as a fallback when the structural walker can't find an existing
    m_ldx of v190+#k to clone (which happens when IDA materializes the
    intermediate through a temp kreg, dropping the inline form).

    The synthetic operand is semantically equivalent to the original
    byte_emit's address operand for IDA's alias analysis purposes.
    """
    add_insn = _ih.minsn_t(int(getattr(mba, "entry_ea", 0) or 0))
    add_insn.opcode = _ih.m_add
    add_insn.l = _ih.mop_t()
    add_insn.l.make_stkvar(mba, 0x190)
    add_insn.l.size = 8
    add_insn.r = _ih.mop_t()
    add_insn.r.make_number(int(byte_index), 8)
    add_insn.d = _ih.mop_t()
    add_insn.d.erase()

    result = _ih.mop_t()
    result.create_from_insn(add_insn)
    return result


def _walk_mop_for_v190_ldx(addr_op, byte_index: int, depth: int = 8):
    """Recursively search ``addr_op`` for an m_ldx whose r operand
    matches v190 + #byte_index. Returns that r operand (the address)
    or None.
    """
    import ida_hexrays as _ih

    if depth <= 0 or addr_op is None:
        return None
    if int(getattr(addr_op, "t", -1)) != int(_ih.mop_d):
        return None
    sub = getattr(addr_op, "d", None)
    if sub is None:
        return None
    if int(getattr(sub, "opcode", -1)) == int(_ih.m_ldx):
        r = getattr(sub, "r", None)
        if r is not None and _is_v190_plus_k(r, byte_index):
            return r
    for child in (getattr(sub, "l", None), getattr(sub, "r", None), getattr(sub, "d", None)):
        found = _walk_mop_for_v190_ldx(child, byte_index, depth - 1)
        if found is not None:
            return found
    return None


def _is_v190_plus_k(op, byte_index: int) -> bool:
    """True if ``op`` algebraically equals ``v190 + #byte_index``.

    Accepts two folded forms produced by IDA microcode:
      1. mop_S with stkoff == 0x190 + byte_index  (constant-folded)
      2. mop_d/m_add(mop_S@0x190, mop_n=byte_index)  (unfolded)
    """
    import ida_hexrays as _ih

    if op is None:
        return False
    t = int(getattr(op, "t", -1))
    if t == int(_ih.mop_S):
        stkvar = getattr(op, "s", None)
        if stkvar is None:
            return False
        if int(getattr(stkvar, "off", 0)) == 0x190 + int(byte_index):
            return True
        return False
    if t == int(_ih.mop_d):
        sub = getattr(op, "d", None)
        if sub is None:
            return False
        if int(getattr(sub, "opcode", -1)) != int(_ih.m_add):
            return False
        l = getattr(sub, "l", None)
        r = getattr(sub, "r", None)
        if l is None or r is None:
            return False
        if (
            int(getattr(l, "t", -1)) == int(_ih.mop_S)
            and getattr(l, "s", None) is not None
            and int(l.s.off) == 0x190
            and int(getattr(r, "t", -1)) == int(_ih.mop_n)
            and getattr(r, "nnn", None) is not None
            and int(r.nnn.value) == int(byte_index)
        ):
            return True
        if (
            int(getattr(r, "t", -1)) == int(_ih.mop_S)
            and getattr(r, "s", None) is not None
            and int(r.s.off) == 0x190
            and int(getattr(l, "t", -1)) == int(_ih.mop_n)
            and getattr(l, "nnn", None) is not None
            and int(l.nnn.value) == int(byte_index)
        ):
            return True
    return False


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


def maybe_run_byte_anchor(mba: Any) -> None:
    """Env-gated hook: ``D810_TAIL_ANCHOR_BYTE6_SPLIT_XOR`` probe.

    Default-off. When set to exactly ``"1"`` and NO prior tail-shape
    probe gate is set, inserts two split-XOR anchor blocks around
    byte 6's emit block to keep its source-byte read alive through
    IDA's ``optimize_global()`` at the snap17 -> snap18 transition.

    Mutually exclusive with ``D810_TAIL_DISTINCT_BYTE``,
    ``D810_TAIL_DUPLICATE_CONVERGENCE_BYTE``, and
    ``D810_TERMINAL_TAIL_STATE_CASCADE_PAIR`` (refuses to run if any
    of them is also set).

    Any failure is logged and swallowed -- the manager pipeline never
    breaks because of this probe.
    """
    split_mechanism = parse_byte_anchor_env(
        os.environ.get("D810_TAIL_ANCHOR_BYTE6_SPLIT_XOR")
    )
    single_mechanism = parse_single_xor_env(
        os.environ.get("D810_TAIL_ANCHOR_BYTE6_SINGLE_XOR")
    )
    live_host_byte = parse_live_host_env(
        os.environ.get("D810_TAIL_ANCHOR_BYTE6_LIVE_HOST")
    )
    multi_bytes = parse_multi_byte_env(
        os.environ.get("D810_TAIL_ANCHOR_READ_BYTES")
    )
    store_bytes = parse_byte_store_env(
        os.environ.get("D810_TAIL_ANCHOR_STORE_BYTES")
    )
    multi_host_explicit = parse_multi_host_env(
        os.environ.get("D810_TAIL_ANCHOR_LIVE_HOST")
    )
    multi_host = multi_host_explicit if multi_host_explicit is not None else 1
    active = sum(
        1 for m in (split_mechanism, single_mechanism, live_host_byte, multi_bytes, store_bytes)
        if m is not None
    )
    if active > 1:
        logger.warning(
            "byte_anchor: multiple anchor-mechanism envs set; refusing."
        )
        return
    if active == 0:
        return  # default-off

    conflicting = [
        n for n in (
            "D810_TAIL_DISTINCT_BYTE",
            "D810_TAIL_DUPLICATE_CONVERGENCE_BYTE",
            "D810_TERMINAL_TAIL_STATE_CASCADE_PAIR",
        )
        if os.environ.get(n)
    ]
    if conflicting:
        logger.warning(
            "byte_anchor: refusing to run; conflicting tail-shape probes "
            "set: %s",
            ", ".join(conflicting),
        )
        return

    adapter = LiveMbaAdapter(mba)
    try:
        if split_mechanism is not None:
            report = execute_split_xor_anchor(byte_index=6, adapter=adapter)
        elif single_mechanism is not None:
            report = execute_single_xor_anchor(byte_index=6, adapter=adapter)
        elif multi_bytes is not None:
            report = execute_multi_byte_live_host_anchor(
                host_byte_index=multi_host,
                read_byte_indices=multi_bytes,
                adapter=adapter,
            )
        elif store_bytes is not None:
            report = execute_byte_store_replica_anchor(
                host_byte_index=multi_host,
                target_byte_indices=store_bytes,
                adapter=adapter,
            )
        else:
            report = execute_live_host_anchor(
                host_byte_index=int(live_host_byte),
                read_byte_index=6,
                adapter=adapter,
            )
    except Exception:
        logger.exception("byte_anchor: unexpected failure; continuing")
        return

    logger.info("byte_anchor: %s", report)

    # Post-mutation dump: when applied, log the contents of the new anchor
    # blocks AND the affected neighbors so we can see exactly what we built
    # even if IDA's decompile() later rejects the result.
    if report.applied and report.anchor_a_serial is not None and report.anchor_b_serial is not None:
        diag_serials = [
            report.byte_emit_serial,
            report.anchor_a_serial,
            report.anchor_b_serial,
        ]
        # Also include each anchor's successor and predecessor for wiring check.
        for s in (report.anchor_a_serial, report.anchor_b_serial):
            blk = mba.get_mblock(int(s))
            if blk is not None:
                diag_serials.extend(int(x) for x in blk.predset)
                diag_serials.extend(int(x) for x in blk.succset)
        seen: set[int] = set()
        for s in diag_serials:
            if s is None or s in seen:
                continue
            seen.add(int(s))
            blk = mba.get_mblock(int(s))
            if blk is None:
                continue
            try:
                preds = list(int(p) for p in blk.predset)
                succs = list(int(p) for p in blk.succset)
                btype = int(getattr(blk, "type", -1))
                logger.info(
                    "byte_anchor: block %d type=%d preds=%s succs=%s",
                    s, btype, preds, succs,
                )
                insn = blk.head
                idx = 0
                while insn is not None and idx < 12:
                    try:
                        ds = insn.dstr() if callable(getattr(insn, "dstr", None)) else "<no-dstr>"
                    except Exception:
                        ds = "<dstr-raised>"
                    logger.info("byte_anchor:   blk[%d] insn[%d]: %s", s, idx, ds)
                    insn = insn.next
                    idx += 1
            except Exception:
                logger.exception("byte_anchor: block %d dump failed", s)
