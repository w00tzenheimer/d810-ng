#!/usr/bin/env python3
"""
d810-debug: Diagnostic tool for D810 deobfuscation.

Usage:
    # Compare deobfuscation results (default D810 vs No-D810)
    python3 tools/d810_debug.py compare <binary_path> --func <name_or_ea>

    # Compare with specific config
    python3 tools/d810_debug.py compare <binary_path> --func <name_or_ea> --config <project.json>

    # Isolate crashing/failing rules
    python3 tools/d810_debug.py bisect <binary_path> --func <name_or_ea> --config <project.json>

This tool runs IDA Pro in headless mode. Ensure 'idat' or 'idat64' is in your PATH
or set via IDA_PATH environment variable.

There are three functional pillars for the new `d810-debug` tool:

    1. The Comparator (Visual Diff): Replaces test_dump_function_pseudocode.py. It provides a side-by-side or unified diff of pseudocode before and after deobfuscation.
    2. The Isolator (Rule Bisect): Replaces the manual logic in test_resize_buffer_cff.py. It automatically identifies which rule causes decompile() to return None or triggers an INTERR.
    3. The Inspector (Recon/Maturity Trace): Leverages the new Blackboard and OptimizationPipeline to show why a rule didn't fire or what the microcode looked like at a specific maturity level.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# The actual logic needs to run *inside* IDA's Python environment.
# This script acts as a driver to spawn IDA with a "worker" script.

WORKER_SCRIPT_CONTENT = r"""
import os
import sys
import json
import traceback
import time
import difflib

# Add src to path so we can import d810
sys.path.insert(0, os.path.join(os.getcwd(), "src"))

try:
    import idaapi
    import idc
    import ida_hexrays
    from d810.core.project import ProjectManager
    from d810.core import D810Manager
    from d810.hexrays.utils.hexrays_formatters import maturity_to_string
except ImportError as e:
    print(f"ERROR: Failed to import IDA/D810 modules: {e}")
    idc.qexit(1)

def get_func_ea(name_or_ea):
    if not name_or_ea:
        return idc.get_screen_ea()
    try:
        if name_or_ea.startswith("0x"):
            return int(name_or_ea, 16)
        if name_or_ea.isdigit():
            return int(name_or_ea)
    except ValueError:
        pass
    
    ea = idc.get_name_ea_simple(name_or_ea)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name_or_ea)
    return ea

def try_decompile(ea):
    try:
        # Use DECOMP_NO_CACHE to ensure we see the effect of D810 rules
        res = idaapi.decompile(ea, flags=idaapi.DECOMP_NO_CACHE)
        if res is None:
            return None, "FAILED (None)"
        return str(res), "OK"
    except Exception as e:
        return None, f"CRASH ({str(e)})"

def cmd_compare(args):
    func_ea = get_func_ea(args['func'])
    if func_ea == idaapi.BADADDR:
        print(f"ERROR: Function '{args['func']}' not found")
        return

    print(f"[*] Analyzing {hex(func_ea)}")
    manager = D810Manager()
    
    # 1. Baseline
    manager.stop_d810()
    base_code, status = try_decompile(func_ea)
    print(f"[*] Baseline Status: {status}")

    # 2. D810
    if args.get('config'):
        # Assuming we can find project by name or path
        try:
            p_idx = manager.project_manager.index(args['config'])
            manager.load_project(p_idx)
        except Exception as e:
            print(f"WARNING: Could not load config {args['config']}: {e}")
            
    manager.start_d810()
    d810_code, status = try_decompile(func_ea)
    print(f"[*] D810 Status: {status}")
    
    if base_code and d810_code:
        if base_code == d810_code:
            print("[=] No changes detected.")
        else:
            print("[+] Changes detected. Unified diff:")
            diff = difflib.unified_diff(
                base_code.splitlines(),
                d810_code.splitlines(),
                fromfile="baseline",
                tofile="d810",
                lineterm=""
            )
            for line in diff:
                print(line)

def cmd_bisect(args):
    func_ea = get_func_ea(args['func'])
    if func_ea == idaapi.BADADDR:
        print(f"ERROR: Function '{args['func']}' not found")
        return

    manager = D810Manager()
    if args.get('config'):
        try:
            p_idx = manager.project_manager.index(args['config'])
            manager.load_project(p_idx)
        except Exception: pass
        
    manager.start_d810()
    
    # Verify it actually fails first
    _, status = try_decompile(func_ea)
    if status == "OK":
        print("[!] Function decompiles successfully with current config. Nothing to bisect.")
        return

    print(f"[*] Starting bisect for failure: {status}")
    
    # Capture all active rules
    original_ins = list(manager.instruction_optimizer.rules)
    original_blk = list(manager.block_optimizer.cfg_rules)
    
    print(f"[*] Active rules: {len(original_ins)} instruction, {len(original_blk)} block")
    
    # Strategy: 
    # 1. Disable all block rules, see if it still fails (if so, it's an instruction rule)
    manager.block_optimizer.cfg_rules = []
    _, status = try_decompile(func_ea)
    
    if status != "OK":
        print("[*] Failure persists with NO block rules. Bisecting instruction rules...")
        culprit = bisect_rules(func_ea, manager, "instruction", original_ins)
    else:
        print("[*] Works without block rules. Bisecting block rules...")
        culprit = bisect_rules(func_ea, manager, "block", original_blk)
        
    if culprit:
        print(f"\n[!] CULPRIT FOUND: {culprit.name}")
    else:
        print("\n[?] Could not isolate a single culprit. May be an interaction between rules.")

def bisect_rules(ea, manager, rule_type, rule_list):
    def check(subset):
        if rule_type == "instruction":
            manager.instruction_optimizer.rules = subset
        else:
            manager.block_optimizer.cfg_rules = subset
        _, status = try_decompile(ea)
        return status != "OK"

    # Linear search for now (safest)
    for i, rule in enumerate(rule_list):
        print(f"    Testing rule {i+1}/{len(rule_list)}: {rule.name}...", end="\r")
        if check([rule]):
            print(f"\n    [!] Rule {rule.name} fails in isolation.")
            return rule
    return None

def main():
    idaapi.auto_wait()
    try:
        args = json.loads(os.environ.get("D810_DEBUG_ARGS", "{}"))
        cmd = args.get("command")
        if cmd == "compare": cmd_compare(args)
        elif cmd == "bisect": cmd_bisect(args)
    except Exception:
        traceback.print_exc()
    finally:
        idc.qexit(0)

if __name__ == "__main__":
    main()
"""


def find_ida_binary():
    # Heuristic to find 'idat' or 'idat64'
    candidates = ["idat64", "idat"]
    if sys.platform == "darwin":
        # Common macOS paths
        candidates.extend(
            [
                "/Applications/IDA Pro 9.3/idat64.app/Contents/MacOS/idat64",
                "/Applications/IDA Pro 9.0/idat64.app/Contents/MacOS/idat64",
                "/Applications/IDA Pro 8.3/idat64.app/Contents/MacOS/idat64",
            ]
        )

    # Check env var
    if os.environ.get("IDA_PATH"):
        candidates.insert(0, os.environ["IDA_PATH"])

    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return c

    # Fallback to PATH
    import shutil

    for c in ["idat64", "idat"]:
        path = shutil.which(c)
        if path:
            return path

    return None


def run_worker(binary_path, args):
    ida_bin = find_ida_binary()
    if not ida_bin:
        print("ERROR: Could not find IDA executable (idat64/idat). Set IDA_PATH.")
        sys.exit(1)

    # Write worker script to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(WORKER_SCRIPT_CONTENT)
        script_path = f.name

    env = os.environ.copy()
    env["D810_DEBUG_ARGS"] = json.dumps(args)

    cmd = [ida_bin, "-A", f"-S{script_path}", str(binary_path)]

    print(f"[*] Running diagnostic inside IDA...")
    try:
        subprocess.run(cmd, env=env, check=True)
    finally:
        os.unlink(script_path)


def main():
    parser = argparse.ArgumentParser(description="D810 Diagnostic Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Compare
    p_compare = subparsers.add_parser(
        "compare", help="Compare decompilation (Baseline vs D810)"
    )
    p_compare.add_argument("binary", type=Path, help="Path to input binary/IDB")
    p_compare.add_argument("--func", required=True, help="Function name or address")
    p_compare.add_argument("--config", help="Path to D810 project config (JSON)")

    # Bisect
    p_bisect = subparsers.add_parser("bisect", help="Isolate failing rules")
    p_bisect.add_argument("binary", type=Path, help="Path to input binary/IDB")
    p_bisect.add_argument("--func", required=True, help="Function name or address")
    p_bisect.add_argument("--config", help="Path to D810 project config (JSON)")

    args = parser.parse_args()

    if not args.binary.exists():
        print(f"Error: Binary {args.binary} not found")
        sys.exit(1)

    # Pack args for worker
    worker_args = vars(args)
    # convert path to str
    worker_args["binary"] = str(worker_args["binary"])

    run_worker(args.binary, worker_args)


if __name__ == "__main__":
    main()
