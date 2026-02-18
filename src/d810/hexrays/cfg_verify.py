"""Verification and diagnostics for CFG operations.

This module contains functions for verifying microcode array correctness and
capturing failure artifacts for post-mortem debugging. Split from cfg_utils.py
as part of the CFG Pass Pipeline refactor (Phase 1).
"""
from __future__ import annotations

import contextlib
import json
import os
from datetime import datetime, timezone

from d810.core.typing import Any
import ida_hexrays

from d810.core import getLogger
from d810.hexrays.hexrays_formatters import block_printer

helper_logger = getLogger(__name__)


def log_block_info(blk: ida_hexrays.mblock_t, logger_func=helper_logger.info, ctx: str = ""):
    if blk is None:
        logger_func("Block is None")
        return
    if ctx:
        logger_func("%s", ctx)
    vp = block_printer()
    blk._print(vp)
    logger_func(
        "Block %s with successors %s and predecessors %s:\n%s",
        blk.serial,
        list(blk.succset),
        list(blk.predset),
        vp.get_block_mc(),
    )


def safe_verify(
    mba: ida_hexrays.mba_t,
    ctx: str,
    logger_func=helper_logger.error,
    capture_blocks: list[int] | set[int] | tuple[int, ...] | None = None,
    capture_metadata: dict[str, Any] | None = None,
) -> None:
    """Run mba.verify(True) and produce helpful diagnostics on failure."""
    try:
        mba.verify(True)
    except RuntimeError as e:
        logger_func("verify failed after %s: %s", ctx, e, exc_info=True)
        capture_failure_artifact(
            mba,
            f"verify failure after {ctx}",
            e,
            logger_func=logger_func,
            capture_blocks=capture_blocks,
            capture_metadata=capture_metadata,
        )
        # attempt to locate problematic blocks: dump the last two blocks if possible
        with contextlib.suppress(Exception):
            divider = "-" * 14
            if (num_blocks := mba.qty) != 0:
                if num_blocks >= 2:
                    log_block_info(
                        mba.get_mblock(num_blocks - 2),
                        logger_func,
                        f"{divider}[blk -2]{divider}",
                    )
                    log_block_info(
                        mba.get_mblock(num_blocks - 1),
                        logger_func,
                        f"{divider}[blk -1]{divider}",
                    )
                log_block_info(
                    mba.get_mblock(0), logger_func, f"{divider}[blk 0]{divider}"
                )
        raise


def _snapshot_insn(insn: ida_hexrays.minsn_t | None) -> dict[str, Any] | None:
    if insn is None:
        return None
    data: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        data["ea"] = int(insn.ea)
        data["ea_hex"] = hex(int(insn.ea))
    with contextlib.suppress(Exception):
        data["opcode"] = int(insn.opcode)
    with contextlib.suppress(Exception):
        if insn.l is not None and insn.l.t == ida_hexrays.mop_b:
            data["goto_target"] = int(insn.l.b)
    with contextlib.suppress(Exception):
        if insn.d is not None and insn.d.t == ida_hexrays.mop_b:
            data["conditional_target"] = int(insn.d.b)
    return data


def snapshot_block_for_capture(blk: ida_hexrays.mblock_t | None) -> dict[str, Any]:
    """Return a JSON-safe snapshot of a block for failure artifact capture."""
    if blk is None:
        return {"serial": None}

    data: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        data["serial"] = int(blk.serial)
    with contextlib.suppress(Exception):
        data["type"] = int(blk.type)
    with contextlib.suppress(Exception):
        data["nsucc"] = int(blk.nsucc())
    with contextlib.suppress(Exception):
        data["npred"] = int(blk.npred())
    with contextlib.suppress(Exception):
        data["succs"] = [int(x) for x in blk.succset]
    with contextlib.suppress(Exception):
        data["preds"] = [int(x) for x in blk.predset]
    with contextlib.suppress(Exception):
        data["nextb"] = int(blk.nextb.serial) if blk.nextb is not None else None
    with contextlib.suppress(Exception):
        data["prevb"] = int(blk.prevb.serial) if blk.prevb is not None else None
    with contextlib.suppress(Exception):
        data["tail"] = _snapshot_insn(blk.tail)

    return data


def _collect_related_blocks(
    mba: ida_hexrays.mba_t, initial_blocks: list[int] | set[int] | tuple[int, ...]
) -> list[int]:
    related: set[int] = set()
    for serial in initial_blocks:
        with contextlib.suppress(Exception):
            if serial is None:
                continue
            serial_i = int(serial)
            if serial_i < 0 or serial_i >= mba.qty:
                continue
            related.add(serial_i)
            blk = mba.get_mblock(serial_i)
            for succ in getattr(blk, "succset", []):
                related.add(int(succ))
            for pred in getattr(blk, "predset", []):
                related.add(int(pred))
            if getattr(blk, "nextb", None) is not None:
                related.add(int(blk.nextb.serial))
            if getattr(blk, "prevb", None) is not None:
                related.add(int(blk.prevb.serial))
    return sorted(
        s
        for s in related
        if isinstance(s, int) and 0 <= s < getattr(mba, "qty", 0)  # ast-grep-ignore
    )


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):  # ast-grep-ignore
        return value
    if isinstance(value, dict):  # ast-grep-ignore
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):  # ast-grep-ignore
        return [_json_safe(v) for v in value]
    return repr(value)


def capture_failure_artifact(
    mba: ida_hexrays.mba_t,
    ctx: str,
    error: Exception,
    logger_func=helper_logger.error,
    capture_blocks: list[int] | set[int] | tuple[int, ...] | None = None,
    capture_metadata: dict[str, Any] | None = None,
) -> str | None:
    """Persist a compact CFG failure artifact for post-mortem debugging."""
    if str(os.environ.get("D810_VERIFY_CAPTURE", "1")).lower() in {"0", "false", "off", "no"}:
        return None

    output_dir = os.environ.get(
        "D810_VERIFY_CAPTURE_DIR",
        os.path.expanduser("~/.idapro/logs/d810_logs/verify_failures"),
    )
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as dir_exc:
        logger_func("failed to create verify capture directory %s: %s", output_dir, dir_exc)
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    entry_ea = 0
    with contextlib.suppress(Exception):
        entry_ea = int(getattr(mba, "entry_ea", 0) or 0)
    filename = f"verify_fail_{timestamp}_{entry_ea:016X}_{os.getpid()}.json"
    path = os.path.join(output_dir, filename)

    focus_blocks = sorted(
        {
            int(b)
            for b in (capture_blocks or [])
            if b is not None and isinstance(b, int)  # ast-grep-ignore
        }
    )
    related_blocks = _collect_related_blocks(mba, focus_blocks)
    if not related_blocks:
        related_blocks = [b for b in (getattr(mba, "qty", 0) - 2, getattr(mba, "qty", 1), 0) if 0 <= b < getattr(mba, "qty", 0)]

    payload: dict[str, Any] = {
        "schema_version": 1,
        "timestamp_utc": timestamp,
        "context": ctx,
        "error_type": type(error).__name__,
        "error_message": str(error),
        "mba": {
            "entry_ea": entry_ea,
            "entry_ea_hex": hex(entry_ea),
            "maturity": int(getattr(mba, "maturity", -1)),
            "qty": int(getattr(mba, "qty", 0)),
        },
        "focus_blocks": focus_blocks,
        "captured_blocks": [],
        "metadata": _json_safe(capture_metadata or {}),
    }

    for serial in related_blocks:
        with contextlib.suppress(Exception):
            payload["captured_blocks"].append(snapshot_block_for_capture(mba.get_mblock(serial)))

    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        logger_func("verify failure artifact saved: %s", path)
    except OSError as write_exc:
        logger_func("failed to write verify failure artifact %s: %s", path, write_exc)
        return None
    return path


__all__ = [
    "safe_verify",
    "capture_failure_artifact",
    "snapshot_block_for_capture",
    "log_block_info",
    "_snapshot_insn",
    "_collect_related_blocks",
    "_json_safe",
]
