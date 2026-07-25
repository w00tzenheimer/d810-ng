#!/usr/bin/env python3
"""Headless idalib worker for `d810cli.py fixture` (ticket d81-rtfh).

Two IDA-only jobs, each opens the idb once and prints a single JSON line last:
  extract  --idb P --func EA|NAME --out ASM   -> write compilable MASM
  resolve  --idb P --vas 0x..,0x..            -> VA -> {name,is_import,retargetable}

Run under an idalib-capable python (same env as gen_masm_from_idb.py):
  PYTHONPATH=src python3 samples/scripts/fixture_idb_worker.py extract ...
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_MASK64 = (1 << 64) - 1


def _add_src_to_path() -> None:
    src = str(Path(__file__).resolve().parents[2] / "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _resolve_ea(target: str):
    import idaapi
    import ida_name

    if target.lower().startswith("0x"):
        return int(target, 16)
    return ida_name.get_name_ea(idaapi.BADADDR, target)


def cmd_extract(args) -> int:
    import idapro
    import idaapi

    idapro.open_database(args.idb, False)
    try:
        idaapi.auto_wait()
        _add_src_to_path()
        from d810.ui.export_disasm_masm_emit import generate_masm_for_function

        ea = _resolve_ea(args.func)
        if ea == idaapi.BADADDR:
            print(f"function not found: {args.func}", file=sys.stderr)
            return 1
        name = idaapi.get_name(ea) or args.func
        asm = generate_masm_for_function(ea, materialize_data=True, const_data=True)
    finally:
        idapro.close_database(False)
    Path(args.out).write_text(asm, encoding="utf-8")
    print(json.dumps({"function": name, "ea": int(ea), "asm": args.out}))
    return 0


def _classify(va: int) -> dict:
    import ida_name
    import ida_bytes

    name = ida_name.get_ea_name(va, ida_name.GN_VISIBLE) or ""
    flags = ida_bytes.get_flags(va)
    is_import = (
        bool(ida_bytes.is_extern(flags)) if hasattr(ida_bytes, "is_extern") else False
    )
    retargetable = bool(name) and (
        is_import
        or not name.startswith(
            ("sub_", "loc_", "unk_", "off_", "byte_", "word_", "dword_", "qword_")
        )
    )
    return {
        "va": va,
        "name": name,
        "is_import": is_import,
        "retargetable": retargetable,
    }


def cmd_resolve(args) -> int:
    import idapro
    import idaapi

    idapro.open_database(args.idb, False)
    try:
        idaapi.auto_wait()
        _add_src_to_path()
        out: dict[str, dict] = {}
        for tok in args.vas.split(","):
            tok = tok.strip()
            if not tok:
                continue
            va = int(tok, 16) & _MASK64
            out[str(va)] = _classify(va)
    finally:
        idapro.close_database(False)
    print(json.dumps(out))
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="fixture_idb_worker")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract")
    e.add_argument("--idb", required=True)
    e.add_argument("--func", required=True)
    e.add_argument("--out", required=True)
    e.set_defaults(handler=cmd_extract)
    r = sub.add_parser("resolve")
    r.add_argument("--idb", required=True)
    r.add_argument("--vas", required=True)
    r.set_defaults(handler=cmd_resolve)
    args = p.parse_args(argv[1:])
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
