"""Reaching-definitions dump for the return slot (var_8 / 0x7F0), pre-d810 GLBOPT1.

Classifies every writer as CONTROL (xdu/mov from the state var var_7BC) vs DATA
(real computed/loaded value), runs a forward reaching-defs fixpoint, and reports
what value reaches each terminal -- in particular what DATA-lane value (if any)
sits behind each CONTROL clobber. Also reports block->STOP reachability.

Usage: python3 var8_reaching_defs.py <diag.sqlite3> [snapshot_id]
"""
import collections
import json
import sqlite3
import sys

DB = sys.argv[1]
SNAP = int(sys.argv[2]) if len(sys.argv) > 2 else 5
RET_STKOFF = 2032   # var_8 == return slot 0x7F0
STATE_STKOFF = 60   # var_7BC == dispatcher state variable

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

blocks = {}
for r in con.execute(
    "SELECT serial, succs, preds, type_name FROM blocks WHERE snapshot_id=?", (SNAP,)
):
    blocks[r["serial"]] = {
        "succs": json.loads(r["succs"]) if r["succs"] else [],
        "preds": json.loads(r["preds"]) if r["preds"] else [],
        "type": r["type_name"],
    }

# var_8 writers
defs_by_block = collections.defaultdict(list)
defmeta = {}
for r in con.execute(
    "SELECT block_serial, insn_index, opcode_name, src_l_stkoff, src_l_value_hex, dstr "
    "FROM instructions WHERE snapshot_id=? AND dest_stkoff=? ORDER BY block_serial, insn_index",
    (SNAP, RET_STKOFF),
):
    from_state = r["src_l_stkoff"] == STATE_STKOFF
    if r["opcode_name"] == "op_9" and from_state:
        prov = "CONTROL/xdu-state"
    elif from_state:
        prov = "CONTROL/state"
    else:
        prov = "DATA"
    did = (r["block_serial"], r["insn_index"])
    defs_by_block[r["block_serial"]].append(did)
    defmeta[did] = (prov, (r["dstr"] or "").strip())

gen = {b: ds[-1] for b, ds in defs_by_block.items()}  # last var_8 def in block

# forward reaching-defs fixpoint (single variable -> any def kills all others)
IN = collections.defaultdict(set)
OUT = collections.defaultdict(set)
changed = True
while changed:
    changed = False
    for b in blocks:
        inset = set()
        for p in blocks[b]["preds"]:
            inset |= OUT[p]
        outset = {gen[b]} if b in gen else set(inset)
        if inset != IN[b] or outset != OUT[b]:
            IN[b], OUT[b] = inset, outset
            changed = True

# reachability to STOP
stops = [b for b, m in blocks.items() if m["type"] == "BLT_STOP"]
reach_stop = set()
stack = list(stops)
rev = collections.defaultdict(list)
for b, m in blocks.items():
    for s in m["succs"]:
        rev[s].append(b)
while stack:
    n = stack.pop()
    if n in reach_stop:
        continue
    reach_stop.add(n)
    stack.extend(rev[n])


def fmt(did):
    prov, dstr = defmeta[did]
    return f"blk{did[0]}[{prov}] {dstr[:70]}"


print(f"=== var_8 (0x7F0) writers: {len(defmeta)} (snap {SNAP}) ===")
for did in sorted(defmeta):
    print(f"  {fmt(did)}")

control_terms = sorted(
    b for b, ds in defs_by_block.items()
    if any(defmeta[d][0].startswith("CONTROL") for d in ds)
)
print(f"\n=== CONTROL-clobber terminals: {control_terms} ===")
print("For each: what DATA-lane def reaches its ENTRY (behind the clobber)?")
for b in control_terms:
    reaching = IN[b]
    data = [d for d in reaching if defmeta[d][0] == "DATA"]
    ctrl = [d for d in reaching if defmeta[d][0].startswith("CONTROL")]
    print(f"\n  blk{b} (preds={blocks[b]['preds']}, reaches_STOP={b in reach_stop}):")
    if not reaching:
        print("    IN(var_8) = {} -> NO reaching def behind clobber (slot undefined here)")
    for d in sorted(data):
        print(f"    DATA  <- {fmt(d)}")
    for d in sorted(ctrl):
        print(f"    ctrl  <- {fmt(d)}")

print("\n=== corridor / STOP reaching defs ===")
for b in sorted(blocks):
    if blocks[b]["type"] == "BLT_STOP" or len(blocks[b]["preds"]) >= 8:
        ds = sorted(IN[b])
        nd = sum(1 for d in ds if defmeta[d][0] == "DATA")
        nc = len(ds) - nd
        print(f"  blk{b} ({blocks[b]['type']}): {len(ds)} reaching defs ({nd} DATA, {nc} CONTROL)")
