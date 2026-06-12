#!/usr/bin/env python3
"""Codemod (libcst): vendor-name STRING-LITERAL comparisons in portable-core ->
ENUM MEMBERS ("enums over strings, always").

Run with the pyenv interpreter:  pyenv exec python tools/scripts/codemod_vendor_string_to_enum.py

Wired for the ``m_*`` micro-opcode family -> ``d810.ir.opcode_name.OpcodeName``
(member values valued at the mnemonic, so the swap is behaviour-neutral: a
``(str, Enum)`` member ``==``/hashes equal to its string value).

SOUNDNESS (the ``(str, Enum)`` ``__str__`` gotcha): ``str(OpcodeName.JZ)`` is
``"OpcodeName.JZ"`` != ``"m_jz"`` while equality/hashing are identical.  So a
literal is swapped ONLY in a COMPARISON / MEMBERSHIP position:
  * ``x == "m_jz"`` / ``"m_jz" == x``      (Comparison left / ComparisonTarget)
  * ``x in ("m_jz", "m_jnz")``            (Element of a collection that is a
                                           comparison comparator)
NOT swapped (reported for hand review): dict KEYS, module-level frozenset
constants, f-strings, ``str(...)`` args, docstrings -- none are comparison
operands, so libcst's ParentNodeProvider check skips them.

Read-only by default; ``--apply`` writes (libcst preserves formatting and adds
the import via AddImportsVisitor).
"""
from __future__ import annotations

import argparse
import difflib
import pathlib

import libcst as cst
from libcst.codemod import CodemodContext, VisitorBasedCodemodCommand
from libcst.codemod.visitors import AddImportsVisitor
from libcst.metadata import ParentNodeProvider

ROOT = pathlib.Path(__file__).resolve().parents[2]
PORTABLE_CORE = ("ir", "analyses", "transforms", "passes", "capabilities", "families", "support")
SKIP_DIR_PARTS = ("backends", "__pycache__")

FAMILY = {
    "m": {
        "module": "d810.ir.opcode_name",
        "enum": "OpcodeName",
        "skip_file": "opcode_name.py",
        "map": {
            "m_add": "ADD", "m_sub": "SUB", "m_mul": "MUL", "m_or": "OR",
            "m_and": "AND", "m_xor": "XOR", "m_mov": "MOV", "m_stx": "STX",
            "m_xdu": "XDU", "m_xds": "XDS", "m_nop": "NOP", "m_setb": "SETB",
            "m_setae": "SETAE", "m_seta": "SETA", "m_setbe": "SETBE",
            "m_setg": "SETG", "m_setge": "SETGE", "m_setl": "SETL",
            "m_setle": "SETLE", "m_jcnd": "JCND", "m_jz": "JZ", "m_jnz": "JNZ",
            "m_jb": "JB", "m_jae": "JAE", "m_ja": "JA", "m_jbe": "JBE",
            "m_jg": "JG", "m_jge": "JGE", "m_jl": "JL", "m_jle": "JLE",
            "m_goto": "GOTO", "m_ijmp": "IJMP", "m_call": "CALL",
            "m_icall": "ICALL", "m_ret": "RET",
        },
    },
}


class VendorStringToEnum(VisitorBasedCodemodCommand):
    METADATA_DEPENDENCIES = (ParentNodeProvider,)

    def __init__(self, context: CodemodContext, fam: dict) -> None:
        super().__init__(context)
        self.vmap = fam["map"]
        self.enum = fam["enum"]
        self.import_module = fam["module"]
        self.hits: list[str] = []

    def _is_comparison_operand(self, node: cst.SimpleString) -> bool:
        parent = self.get_metadata(ParentNodeProvider, node)
        if isinstance(parent, (cst.Comparison, cst.ComparisonTarget)):
            return True
        # element of a collection used directly as a comparison comparator:  x in ("a","b")
        if isinstance(parent, cst.Element):
            coll = self.get_metadata(ParentNodeProvider, parent)
            gp = self.get_metadata(ParentNodeProvider, coll)
            return isinstance(gp, (cst.Comparison, cst.ComparisonTarget))
        return False

    def leave_SimpleString(
        self, original_node: cst.SimpleString, updated_node: cst.SimpleString
    ) -> cst.BaseExpression:
        try:
            value = original_node.evaluated_value
        except Exception:
            return updated_node
        if not isinstance(value, str) or value not in self.vmap:
            return updated_node
        if not self._is_comparison_operand(original_node):
            return updated_node
        self.hits.append(value)
        AddImportsVisitor.add_needed_import(self.context, self.import_module, self.enum)
        return cst.Attribute(value=cst.Name(self.enum), attr=cst.Name(self.vmap[value]))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--family", default="m", choices=sorted(FAMILY))
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--show-diff", action="store_true", help="print unified diffs")
    args = ap.parse_args()
    fam = FAMILY[args.family]

    targets: list[pathlib.Path] = []
    for pkg in PORTABLE_CORE:
        base = ROOT / "src" / "d810" / pkg
        if base.exists():
            targets += [
                p for p in base.rglob("*.py")
                if not any(part in SKIP_DIR_PARTS for part in p.parts)
                and p.name != fam["skip_file"]
            ]

    total_hits = total_files = 0
    for path in sorted(targets):
        src = path.read_text(encoding="utf-8")
        module = cst.parse_module(src)
        command = VendorStringToEnum(CodemodContext(), fam)
        new_module = command.transform_module(module)
        if not command.hits:
            continue
        total_files += 1
        total_hits += len(command.hits)
        rel = path.relative_to(ROOT)
        print(f"{rel}: {len(command.hits)} comparison literal(s) -> {fam['enum']} "
              f"({', '.join(sorted(set(command.hits)))})")
        if args.show_diff:
            print("".join(difflib.unified_diff(
                src.splitlines(keepends=True), new_module.code.splitlines(keepends=True),
                fromfile=str(rel), tofile=str(rel), n=1)))
        if args.apply:
            path.write_text(new_module.code, encoding="utf-8")

    print(f"\n{total_hits} comparison literals across {total_files} files "
          f"{'REWRITTEN' if args.apply else 'would change'} (family {args.family!r}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
