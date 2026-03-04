#!/usr/bin/env python3
"""Phase 9 codemod: inline lift_portable_cfg into mutation/ir_translator.py.

Default mode is dry-run. Use --apply to write changes.
Use --delete-source to remove src/d810/hexrays/ir/lift_portable_cfg.py after inline.
Run with: pyenv exec python tools/scripts/codemod_phase9_inline_lift_portable_cfg.py --dry-run
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path


HELPER_BLOCK = '''
try:
    import ida_hexrays

    _IDA_AVAILABLE = True
except ImportError:
    _IDA_AVAILABLE = False


def lift_block(blk: "ida_hexrays.mblock_t") -> BlockSnapshot:
    if not _IDA_AVAILABLE:
        raise RuntimeError("lift_block requires IDA Hexrays (ida_hexrays module not available)")

    serial = blk.serial
    block_type = blk.type
    flags = blk.flags
    start_ea = blk.start

    succs = get_succ_serials(blk)
    preds = get_pred_serials(blk)

    insn_snapshots = []
    insn = blk.head
    while insn:
        opcode = insn.opcode
        ea = insn.ea

        operands = tuple(
            MopSnapshot.from_mop(mop)
            for mop in (insn.l, insn.r, insn.d)
            if mop.t != ida_hexrays.mop_z  # type: ignore[attr-defined]
        )

        insn_snapshots.append(InsnSnapshot(opcode=opcode, ea=ea, operands=operands))
        insn = insn.next

    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=flags,
        start_ea=start_ea,
        insn_snapshots=tuple(insn_snapshots),
    )


def lift(mba: "ida_hexrays.mba_t") -> PortableCFG:
    if not _IDA_AVAILABLE:
        raise RuntimeError("lift requires IDA Hexrays (ida_hexrays module not available)")

    blocks = {}
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        blocks[blk.serial] = lift_block(blk)

    return PortableCFG(
        blocks=blocks,
        entry_serial=0,
        func_ea=mba.entry_ea,
        metadata={"maturity": mba.maturity},
    )
'''


def rewrite_translator(src: str) -> str:
    out = src
    out = out.replace(
        "from d810.cfg.flowgraph import PortableCFG\nfrom d810.hexrays.ir.lift_portable_cfg import lift\n",
        "from d810.cfg.flowgraph import BlockSnapshot, InsnSnapshot, PortableCFG\n"
        "from d810.hexrays.ir.block_helpers import get_pred_serials, get_succ_serials\n"
        "from d810.hexrays.ir.mop_snapshot import MopSnapshot\n",
    )
    out = out.replace("return _lift(mba)", "return lift(mba)")
    marker = "logger = getLogger(__name__)\n\n\nclass IDAIRTranslator:"
    if marker in out and "def lift(" not in out:
        out = out.replace(marker, f"logger = getLogger(__name__)\n{HELPER_BLOCK}\n\n\nclass IDAIRTranslator:")
    out = out.replace('__all__ = ["IDAIRTranslator"]', '__all__ = ["IDAIRTranslator", "lift", "lift_block"]')
    return out


def rewrite_deferred_modifier(src: str) -> str:
    return src.replace(
        "from d810.hexrays.ir.lift_portable_cfg import lift",
        "from d810.hexrays.mutation.ir_translator import lift",
    )


def rewrite_lift_tests(src: str) -> str:
    out = src.replace(
        "from d810.hexrays.ir import lift_portable_cfg as portable_cfg",
        "from d810.hexrays.mutation import ir_translator as portable_cfg",
    )
    out = out.replace(
        '"""Unit tests for lift_portable_cfg lift functions.',
        '"""Unit tests for IDAIRTranslator lift helpers.',
    )
    return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Repository root")
    parser.add_argument("--apply", action="store_true", help="Apply changes")
    parser.add_argument(
        "--delete-source",
        action="store_true",
        help="Delete src/d810/hexrays/ir/lift_portable_cfg.py after rewrite",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    apply = args.apply

    translator = root / "src/d810/hexrays/mutation/ir_translator.py"
    src = translator.read_text(encoding="utf-8")
    out = rewrite_translator(src)

    if out != src:
        if apply:
            translator.write_text(out, encoding="utf-8")
            print(f"rewrote {translator}")
        else:
            print(f"would rewrite {translator}")
            diff = difflib.unified_diff(
                src.splitlines(),
                out.splitlines(),
                fromfile=str(translator),
                tofile=str(translator),
                lineterm="",
            )
            for line in diff:
                print(line)
    else:
        print("no translator rewrite needed")

    deferred_modifier = root / "src/d810/hexrays/mutation/deferred_modifier.py"
    dm_src = deferred_modifier.read_text(encoding="utf-8")
    dm_out = rewrite_deferred_modifier(dm_src)
    if dm_out != dm_src:
        if apply:
            deferred_modifier.write_text(dm_out, encoding="utf-8")
            print(f"rewrote {deferred_modifier}")
        else:
            print(f"would rewrite {deferred_modifier}")

    lift_test = root / "tests/unit/hexrays/test_portable_cfg_lift.py"
    if lift_test.exists():
        lt_src = lift_test.read_text(encoding="utf-8")
        lt_out = rewrite_lift_tests(lt_src)
        if lt_out != lt_src:
            if apply:
                lift_test.write_text(lt_out, encoding="utf-8")
                print(f"rewrote {lift_test}")
            else:
                print(f"would rewrite {lift_test}")

    if args.delete_source:
        source = root / "src/d810/hexrays/ir/lift_portable_cfg.py"
        if source.exists():
            if apply:
                source.unlink()
                print(f"deleted {source}")
            else:
                print(f"would delete {source}")

    mode = "applied" if apply else "dry-run"
    print(f"{mode}: phase9 complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
