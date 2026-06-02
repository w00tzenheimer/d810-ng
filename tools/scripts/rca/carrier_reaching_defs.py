"""Reaching-def trace of an arbitrary carrier slot to a target block, per snapshot.

Classifies each def as ENTRY-INIT (xdu state_var), STATE, or DATA, runs a forward
reaching-defs fixpoint, and reports what reaches the target block's entry.

Usage: python3 carrier_trace.py <db> <snapshot_id> <carrier_stkoff> [target_block]
"""
import collections
import json
import sqlite3
import sys

DB = sys.argv[1]
SNAP = int(sys.argv[2])
CARRIER = int(sys.argv[3], 0)
TARGET = int(sys.argv[4]) if len(sys.argv) > 4 else None
STATE_STKOFF = 60  # var_7BC

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row

blocks = {}
for r in con.execute("SELECT serial, succs, preds FROM blocks WHERE snapshot_id=?", (SNAP,)):
    blocks[r["serial"]] = {
        "succs": json.loads(r["succs"]) if r["succs"] else [],
        "preds": json.loads(r["preds"]) if r["preds"] else [],
    }

defs_by_block = collections.defaultdict(list)
defmeta = {}
for r in con.execute(
    "SELECT block_serial, insn_index, opcode_name, src_l_stkoff, src_l_value_hex, dstr "
    "FROM instructions WHERE snapshot_id=? AND dest_stkoff=? ORDER BY block_serial, insn_index",
    (SNAP, CARRIER),
):
    d = (r["dstr"] or "").strip()
    if r["opcode_name"] == "op_9" and r["src_l_stkoff"] == STATE_STKOFF:
        prov = "ENTRY-INIT/xdu(state)"
    elif r["src_l_stkoff"] == STATE_STKOFF:
        prov = "STATE"
    else:
        prov = "DATA"
    did = (r["block_serial"], r["insn_index"])
    defs_by_block[r["block_serial"]].append(did)
    defmeta[did] = (prov, d)

gen = {b: ds[-1] for b, ds in defs_by_block.items()}
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


def show(b):
    print(f"  blk{b} preds={blocks.get(b, {}).get('preds')}  IN(carrier):")
    if not IN[b]:
        print("     {}  (carrier undefined here)")
    for d in sorted(IN[b]):
        prov, dstr = defmeta[d]
        print(f"     blk{d[0]}[{prov}]  {dstr[:78]}")


print(f"=== carrier stkoff 0x{CARRIER:x} writers (snap {SNAP}): {len(defmeta)} ===")
for did in sorted(defmeta):
    prov, dstr = defmeta[did]
    print(f"  blk{did[0]}[{prov}]  {dstr[:80]}")
if TARGET is not None:
    print(f"\n=== reaching defs at target block {TARGET} ===")
    show(TARGET)
