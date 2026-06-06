#!/usr/bin/env python3
"""Generate compilable x64 ml64 MASM for a function in an IDB (headless).

Drives the d810 structural exporter (``export_disasm_masm_emit``) against an
IDA database without the GUI, and optionally assembles the result with
``llvm-ml64`` / ``ml64`` as a smoke test.

Usage:
    PYTHONPATH=src python3 samples/scripts/gen_masm_from_idb.py \
        <database.i64> <func_name_or_hex_ea> [out.asm] [--assemble] [--const]

Example:
    PYTHONPATH=src python3 samples/scripts/gen_masm_from_idb.py \
        samples/bins/libobfuscated.dll.2026-06-03.i64 sub_180001900 /tmp/f.asm --assemble
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    do_assemble = "--assemble" in argv
    const_data = "--const" in argv
    if len(args) < 2:
        print(__doc__)
        return 2
    db_path, target = args[0], args[1]
    out_path = Path(args[2]) if len(args) > 2 else Path("/tmp/gen_masm.asm")

    import idapro
    import idaapi
    import ida_name

    idapro.open_database(db_path, False)
    try:
        idaapi.auto_wait()
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
        from d810.ui.export_disasm_masm_emit import (
            generate_masm_for_function,
        )

        ea = (
            int(target, 16)
            if target.lower().startswith("0x")
            else ida_name.get_name_ea(idaapi.BADADDR, target)
        )
        if ea == idaapi.BADADDR:
            print(f"function not found: {target}")
            return 1
        source = generate_masm_for_function(ea, const_data=const_data)
    finally:
        idapro.close_database(False)

    out_path.write_text(source, encoding="utf-8")
    print(f"wrote {out_path} ({len(source.splitlines())} lines)")

    if do_assemble:
        ml = shutil.which("llvm-ml64") or "/opt/homebrew/opt/llvm/bin/llvm-ml64"
        obj = out_path.with_suffix(".obj")
        res = subprocess.run(
            [ml, "-m64", "/c", "/Fo", str(obj), str(out_path)],
            capture_output=True,
            text=True,
        )
        print(res.stdout, res.stderr, sep="")
        print(f"assemble: {'OK' if obj.exists() and obj.stat().st_size else 'FAIL'}")
        return 0 if obj.exists() and obj.stat().st_size else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
