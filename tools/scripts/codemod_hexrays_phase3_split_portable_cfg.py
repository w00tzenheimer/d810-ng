#!/usr/bin/env python3
"""Phase 3 codemod: split portable CFG into pure cfg model + Hex-Rays lift adapter.

Default mode is dry-run. Use --apply to write changes.
Run with `pyenv exec` so LibCST is available.
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path

import libcst as cst

IMPORT_OLD = "d810.hexrays.ir.portable_cfg"
IMPORT_NEW = "d810.cfg.portable_cfg"

CFG_PORTABLE_CFG = '''"""Backend-agnostic IR for CFG snapshots (pure model layer)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from d810.core.logging import getLogger

logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class InsnSnapshot:
    """Snapshot of a single microcode instruction."""

    opcode: int
    ea: int
    operands: tuple[object, ...]

    def __post_init__(self) -> None:
        if self.opcode < 0:
            raise ValueError(f"InsnSnapshot: opcode must be non-negative, got {self.opcode}")
        if self.ea < 0:
            raise ValueError(f"InsnSnapshot: ea must be non-negative, got {self.ea}")
        if not isinstance(self.operands, tuple):
            raise TypeError(f"InsnSnapshot: operands must be tuple, got {type(self.operands)}")

    def __repr__(self) -> str:
        return f"InsnSnapshot(op=0x{self.opcode:x}, ea=0x{self.ea:x}, nops={len(self.operands)})"


@dataclass(frozen=True, slots=True)
class BlockSnapshot:
    """Snapshot of a single basic block topology and instructions."""

    serial: int
    block_type: int
    succs: tuple[int, ...]
    preds: tuple[int, ...]
    flags: int
    start_ea: int
    insn_snapshots: tuple[InsnSnapshot, ...]

    def __post_init__(self) -> None:
        if self.serial < 0:
            raise ValueError(f"BlockSnapshot: serial must be non-negative, got {self.serial}")
        if self.block_type < 0 or self.block_type > 6:
            raise ValueError(f"BlockSnapshot: block_type must be 0-6, got {self.block_type}")
        if self.start_ea < 0:
            raise ValueError(f"BlockSnapshot: start_ea must be non-negative, got {self.start_ea}")
        if not isinstance(self.succs, tuple):
            raise TypeError(f"BlockSnapshot: succs must be tuple, got {type(self.succs)}")
        if not isinstance(self.preds, tuple):
            raise TypeError(f"BlockSnapshot: preds must be tuple, got {type(self.preds)}")
        if not isinstance(self.insn_snapshots, tuple):
            raise TypeError(
                f"BlockSnapshot: insn_snapshots must be tuple, got {type(self.insn_snapshots)}"
            )

    @property
    def nsucc(self) -> int:
        return len(self.succs)

    @property
    def npred(self) -> int:
        return len(self.preds)

    def __repr__(self) -> str:
        return (
            f"BlockSnapshot(serial={self.serial}, type={self.block_type}, "
            f"succs={self.succs}, preds={self.preds}, "
            f"ninsns={len(self.insn_snapshots)})"
        )


@dataclass(frozen=True, slots=True)
class PortableCFG:
    """Complete snapshot of a control flow graph."""

    blocks: Mapping[int, BlockSnapshot]
    entry_serial: int
    func_ea: int
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.func_ea < 0:
            raise ValueError(f"PortableCFG: func_ea must be non-negative, got {self.func_ea}")

        object.__setattr__(self, "blocks", MappingProxyType(dict(self.blocks)))
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

        if self.blocks and self.entry_serial not in self.blocks:
            raise ValueError(
                f"PortableCFG: entry_serial {self.entry_serial} not in blocks {list(self.blocks.keys())}"
            )

        for serial, blk in self.blocks.items():
            for succ in blk.succs:
                if succ not in self.blocks:
                    logger.warning(
                        "PortableCFG: block %s references non-existent successor %s", serial, succ
                    )
            for pred in blk.preds:
                if pred not in self.blocks:
                    logger.warning(
                        "PortableCFG: block %s references non-existent predecessor %s", serial, pred
                    )

    @property
    def num_blocks(self) -> int:
        return len(self.blocks)

    def get_block(self, serial: int) -> BlockSnapshot | None:
        return self.blocks.get(serial)

    def successors(self, serial: int) -> tuple[int, ...]:
        blk = self.blocks.get(serial)
        return blk.succs if blk else ()

    def predecessors(self, serial: int) -> tuple[int, ...]:
        blk = self.blocks.get(serial)
        return blk.preds if blk else ()

    def as_adjacency_dict(self) -> dict[int, list[int]]:
        return {s: list(b.succs) for s, b in self.blocks.items()}

    def __repr__(self) -> str:
        return (
            f"PortableCFG(nblocks={self.num_blocks}, "
            f"entry={self.entry_serial}, func_ea=0x{self.func_ea:x})"
        )


__all__ = ["InsnSnapshot", "BlockSnapshot", "PortableCFG"]
'''

LIFT_PORTABLE_CFG = '''"""Hex-Rays adapter that lifts mba/mblock structures into PortableCFG snapshots."""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import TYPE_CHECKING

from d810.cfg.portable_cfg import BlockSnapshot, InsnSnapshot, PortableCFG
from d810.hexrays.ir.block_helpers import get_pred_serials, get_succ_serials
from d810.hexrays.ir.mop_snapshot import MopSnapshot

if TYPE_CHECKING:
    import ida_hexrays

logger = getLogger(__name__)

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


__all__ = ["lift", "lift_block"]
'''

HEXRAYS_PORTABLE_CFG_SHIM = '''"""Compatibility shim for portable CFG model + Hex-Rays lift helpers."""
from __future__ import annotations

from d810.cfg.portable_cfg import BlockSnapshot, InsnSnapshot, PortableCFG
from d810.hexrays.ir.lift_portable_cfg import lift, lift_block

__all__ = [
    "InsnSnapshot",
    "BlockSnapshot",
    "PortableCFG",
    "lift",
    "lift_block",
]
'''


class ImportRewriter(cst.CSTTransformer):
    def leave_ImportAlias(
        self, original_node: cst.ImportAlias, updated_node: cst.ImportAlias
    ) -> cst.ImportAlias:
        name_code = cst.Module([]).code_for_node(updated_node.name)
        if name_code == IMPORT_OLD or name_code.startswith(IMPORT_OLD + "."):
            return updated_node.with_changes(
                name=cst.parse_expression(name_code.replace(IMPORT_OLD, IMPORT_NEW, 1))
            )
        return updated_node

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom:
        if updated_node.module is None:
            return updated_node
        module_code = cst.Module([]).code_for_node(updated_node.module)
        if module_code == IMPORT_OLD or module_code.startswith(IMPORT_OLD + "."):
            return updated_node.with_changes(
                module=cst.parse_expression(module_code.replace(IMPORT_OLD, IMPORT_NEW, 1))
            )
        return updated_node


def iter_cfg_files(root: Path) -> list[Path]:
    return sorted((root / "src" / "d810" / "cfg").rglob("*.py"))


def rewrite_cfg_imports(root: Path, apply: bool) -> int:
    changed = 0
    for path in iter_cfg_files(root):
        src = path.read_text(encoding="utf-8")
        if IMPORT_OLD not in src:
            continue
        module = cst.parse_module(src)
        out = module.visit(ImportRewriter()).code
        out = out.replace(IMPORT_OLD, IMPORT_NEW)
        if out == src:
            continue

        changed += 1
        if apply:
            path.write_text(out, encoding="utf-8")
            print(f"rewrote {path}")
        else:
            print(f"would rewrite {path}")
            diff = difflib.unified_diff(
                src.splitlines(), out.splitlines(),
                fromfile=str(path), tofile=str(path), lineterm=""
            )
            for line in diff:
                print(line)
    return changed


def write_templates(root: Path, apply: bool) -> None:
    targets = {
        root / "src" / "d810" / "cfg" / "portable_cfg.py": CFG_PORTABLE_CFG,
        root / "src" / "d810" / "hexrays" / "ir" / "lift_portable_cfg.py": LIFT_PORTABLE_CFG,
        root / "src" / "d810" / "hexrays" / "ir" / "portable_cfg.py": HEXRAYS_PORTABLE_CFG_SHIM,
    }
    for path, content in targets.items():
        if apply:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            print(f"wrote {path}")
        else:
            print(f"would write {path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Repository root")
    parser.add_argument("--apply", action="store_true", help="Apply changes (default dry-run)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    apply = args.apply

    write_templates(root, apply)
    changed = rewrite_cfg_imports(root, apply)

    mode = "applied" if apply else "dry-run"
    print(f"{mode}: rewrote {changed} cfg file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
