# MBA Diagnostic Snapshot Infrastructure

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace text-based microcode dumps with a queryable SQLite snapshot that enables block chain tracing, variable provenance, and DAG correlation without grep/sed.

**Architecture:** Two-layer system — Layer 1 (universal MBA snapshot) writes blocks, instructions, and variables from any D810 optimizer; Layer 2 (strategy metadata) writes DAG edges, modifications, and reachability from Hodur or other strategies. A CLI tool queries both layers. Existing `mba_to_dict()` provides the serialization; `ReconStore` provides the persistence pattern.

**Tech Stack:** SQLite3 (WAL mode), Python dataclasses. Refactors `mba_to_human_readable()` to return semantic dataclasses (BlockSnapshot, InstructionSnapshot) that `__str__()` to the current human-readable format but can also be iterated for SQLite insertion. Uses queue-writer pattern (same as `ReconStoreWriter`) with background thread + batch commits + shutdown hooks. Per-IDB per-run DB isolation: `{log_dir}/{func_ea:016x}_{run_id}.diag.sqlite3` — no shared global DB, safe for parallel Docker runs, multiple IDBs, and abrupt termination (uncommitted rows lost, DB never corrupt).

---

## File Structure

| File | Responsibility |
|-|-|
| `src/d810/diag/__init__.py` | Package init, exports |
| `src/d810/diag/schema.py` | SQLite table definitions + migration |
| `src/d810/diag/snapshot.py` | `snapshot_mba()`, `snapshot_dag()`, `snapshot_modifications()`, `snapshot_reachability()` |
| `src/d810/diag/query.py` | Query helpers: `chain()`, `var_writes()`, `block_detail()`, `return_paths()` |
| `src/d810/diag/__main__.py` | CLI entry point (`python -m d810.diag`) |
| `tests/unit/diag/test_schema.py` | Schema creation + migration tests |
| `tests/unit/diag/test_snapshot.py` | Snapshot serialization tests (mock MBA data) |
| `tests/unit/diag/test_query.py` | Query tests against pre-loaded fixtures |

## SQLite Schema

### Layer 1: Universal MBA State

```sql
-- One row per snapshot checkpoint
CREATE TABLE snapshots (
    id          INTEGER PRIMARY KEY,
    label       TEXT NOT NULL,       -- e.g. "pass0_post_apply", "pass1_post_gut_wire"
    func_ea     INTEGER NOT NULL,
    maturity    TEXT NOT NULL,        -- e.g. "MMAT_GLBOPT1"
    block_count INTEGER NOT NULL,
    timestamp   REAL NOT NULL
);

-- One row per microcode block
CREATE TABLE blocks (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    serial      INTEGER NOT NULL,
    block_type  INTEGER NOT NULL,    -- BLT_1WAY, BLT_2WAY, BLT_STOP, etc.
    type_name   TEXT NOT NULL,       -- human-readable type
    start_ea    INTEGER,
    end_ea      INTEGER,
    nsucc       INTEGER NOT NULL,
    npred       INTEGER NOT NULL,
    succs       TEXT NOT NULL,       -- JSON array of serial ints
    preds       TEXT NOT NULL,       -- JSON array of serial ints
    insn_count  INTEGER NOT NULL,
    meta        TEXT,              -- JSON catch-all: valranges, USE/DEF/DNU, flags (MBL_GOTO etc.)
    PRIMARY KEY (snapshot_id, serial)
);

-- One row per microcode instruction
CREATE TABLE instructions (
    snapshot_id   INTEGER NOT NULL REFERENCES snapshots(id),
    block_serial  INTEGER NOT NULL,
    insn_index    INTEGER NOT NULL,
    ea            INTEGER NOT NULL,
    opcode        INTEGER NOT NULL,
    opcode_name   TEXT NOT NULL,     -- e.g. "m_mov", "m_xdu", "m_goto"
    dest_type     TEXT,              -- mop type: "mop_S", "mop_r", "mop_n", etc.
    dest_stkoff   INTEGER,          -- stack offset if dest is mop_S
    dest_size     INTEGER,
    src_l_type    TEXT,
    src_l_stkoff  INTEGER,
    src_l_value   INTEGER,          -- immediate value if mop_n
    src_r_type    TEXT,
    src_r_stkoff  INTEGER,
    src_r_value   INTEGER,
    dstr          TEXT,             -- IDA's display string for the instruction
    meta          TEXT,             -- JSON catch-all: iprops, sub-instruction tree, full mop details
    PRIMARY KEY (snapshot_id, block_serial, insn_index)
);

-- Derived: which instructions write to a given stack variable
CREATE VIEW var_writes AS
SELECT i.*, b.succs, b.preds
FROM instructions i
JOIN blocks b ON i.snapshot_id = b.snapshot_id AND i.block_serial = b.serial
WHERE i.dest_type = 'mop_S';

-- Index for fast variable provenance queries
CREATE INDEX idx_insn_dest_stkoff ON instructions(snapshot_id, dest_stkoff);
CREATE INDEX idx_insn_opcode ON instructions(snapshot_id, opcode_name);
```

### Layer 2: Strategy Metadata (Hodur-specific, extensible)

```sql
-- DAG nodes (one per handler state)
CREATE TABLE dag_nodes (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    state           INTEGER NOT NULL,  -- handler state constant
    state_hex       TEXT NOT NULL,     -- "0x5D0AEBD3"
    entry_block     INTEGER NOT NULL,
    classification  TEXT NOT NULL,     -- "TRANSITION", "EXIT", "CONDITIONAL"
    shared_suffix   TEXT,             -- JSON array of shared block serials
    PRIMARY KEY (snapshot_id, state)
);

-- DAG edges (one per transition)
CREATE TABLE dag_edges (
    snapshot_id       INTEGER NOT NULL REFERENCES snapshots(id),
    edge_id           INTEGER NOT NULL,
    source_state      INTEGER,
    target_state      INTEGER,
    edge_kind         TEXT NOT NULL CHECK(edge_kind IN ('TRANSITION','CONDITIONAL_TRANSITION','CONDITIONAL_RETURN','EXIT_ROUTINE','UNKNOWN'))
    source_block      INTEGER,
    source_arm        INTEGER,         -- 0=fallthrough, 1=taken, NULL=unconditional
    target_entry      INTEGER,
    ordered_path      TEXT NOT NULL,   -- JSON array of block serials
    PRIMARY KEY (snapshot_id, edge_id)
);

-- Reconstruction modifications (one per emitted mod)
CREATE TABLE modifications (
    snapshot_id     INTEGER NOT NULL REFERENCES snapshots(id),
    mod_index       INTEGER NOT NULL,
    mod_type        TEXT NOT NULL,     -- "goto_redirect", "edge_redirect", "duplicate_and_redirect", "nop_instructions"
    source_block    INTEGER,
    target_block    INTEGER,
    old_target      INTEGER,
    write_site_ea   INTEGER,
    write_site_blk  INTEGER,
    status          TEXT NOT NULL,     -- "emitted", "skipped", "rejected"
    reason          TEXT,
    PRIMARY KEY (snapshot_id, mod_index)
);

-- Block classification (reachability, BST membership, gut status)
CREATE TABLE block_classification (
    snapshot_id   INTEGER NOT NULL REFERENCES snapshots(id),
    serial        INTEGER NOT NULL,
    is_bst        INTEGER NOT NULL DEFAULT 0,
    is_reachable  INTEGER NOT NULL DEFAULT 1,
    is_gutted     INTEGER NOT NULL DEFAULT 0,
    in_claimed    INTEGER NOT NULL DEFAULT 0,  -- in claimed_sources
    PRIMARY KEY (snapshot_id, serial)
);
```

---

## Tasks

### Task 1: Schema + DB creation

**Files:**
- Create: `src/d810/diag/__init__.py`
- Create: `src/d810/diag/schema.py`
- Test: `tests/unit/diag/test_schema.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/diag/test_schema.py
import sqlite3
from d810.diag.schema import create_tables

def test_create_tables_creates_all_expected_tables():
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = [row[0] for row in cursor]
    assert "blocks" in tables
    assert "instructions" in tables
    assert "snapshots" in tables
    assert "dag_edges" in tables
    assert "modifications" in tables
    assert "block_classification" in tables

def test_create_tables_idempotent():
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    create_tables(conn)  # should not raise

def test_json_extract_on_meta_columns():
    """Verify SQLite JSON extension works for meta column queries."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    # Insert a block with JSON meta containing valranges
    conn.execute(
        "INSERT INTO snapshots VALUES (1, 'test', 0x1000, 'GLBOPT1', 3, 0.0)"
    )
    conn.execute(
        "INSERT INTO blocks VALUES (1, 206, 2, 'BLT_2WAY', NULL, NULL, 2, 2, "
        "'[207,208]', '[62,204]', 1, ?)",
        ('{"valranges": {"0x3C": "==432DC789"}, "flags": ["MBL_GOTO"]}',),
    )
    # Query with json_extract
    row = conn.execute(
        "SELECT json_extract(meta, '$.valranges.0x3C') FROM blocks "
        "WHERE snapshot_id=1 AND serial=206"
    ).fetchone()
    assert row[0] == "==432DC789"
    # Query with json_each on succs
    succs = conn.execute(
        "SELECT value FROM json_each("
        "(SELECT succs FROM blocks WHERE snapshot_id=1 AND serial=206))"
    ).fetchall()
    assert [r[0] for r in succs] == [207, 208]

def test_edge_kind_check_constraint_rejects_invalid():
    """Verify CHECK constraint on edge_kind column."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots VALUES (1, 'test', 0x1000, 'GLBOPT1', 3, 0.0)"
    )
    import pytest
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO dag_edges VALUES (1, 1, NULL, NULL, 'INVALID_KIND', "
            "NULL, NULL, NULL, '[]')"
        )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/unit/diag/test_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'd810.diag'`

- [ ] **Step 3: Implement schema.py**

```python
# src/d810/diag/schema.py
"""SQLite schema for MBA diagnostic snapshots."""
from __future__ import annotations
import sqlite3

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS snapshots ( ... );
CREATE TABLE IF NOT EXISTS blocks ( ... );
CREATE TABLE IF NOT EXISTS instructions ( ... );
CREATE TABLE IF NOT EXISTS dag_nodes ( ... );
CREATE TABLE IF NOT EXISTS dag_edges ( ... );
CREATE TABLE IF NOT EXISTS modifications ( ... );
CREATE TABLE IF NOT EXISTS block_classification ( ... );
CREATE VIEW IF NOT EXISTS var_writes AS ...;
CREATE INDEX IF NOT EXISTS idx_insn_dest_stkoff ON instructions(snapshot_id, dest_stkoff);
CREATE INDEX IF NOT EXISTS idx_insn_opcode ON instructions(snapshot_id, opcode_name);
"""

def create_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(_SCHEMA_SQL)
```

Use the full SQL from the schema section above.

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src pytest tests/unit/diag/test_schema.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/d810/diag/ tests/unit/diag/
git commit -m "feat(diag): add SQLite schema for MBA diagnostic snapshots"
```

---

### Task 2: MBA snapshot writer (Layer 1)

**Files:**
- Create: `src/d810/diag/snapshot.py`
- Modify: `src/d810/recon/microcode_dump.py` (refactor `mba_to_human_readable` → return `List[BlockSnapshot]`)
- Test: `tests/unit/diag/test_snapshot.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/diag/test_snapshot.py
import sqlite3
from d810.diag.schema import create_tables
from d810.diag.snapshot import snapshot_mba

def test_snapshot_mba_writes_blocks(mock_mba_3_blocks):
    """mock_mba_3_blocks is a fixture with 3 blocks, 2 instructions each."""
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    snap_id = snapshot_mba(conn, mock_mba_3_blocks, label="test", func_ea=0x1000)
    assert snap_id == 1
    rows = conn.execute("SELECT serial, nsucc, npred FROM blocks WHERE snapshot_id=1").fetchall()
    assert len(rows) == 3

def test_snapshot_mba_writes_instructions(mock_mba_3_blocks):
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    snapshot_mba(conn, mock_mba_3_blocks, label="test", func_ea=0x1000)
    rows = conn.execute("SELECT COUNT(*) FROM instructions WHERE snapshot_id=1").fetchone()
    assert rows[0] == 6  # 3 blocks * 2 insns
```

The `mock_mba_3_blocks` fixture should be a dataclass-based mock that mimics the MBA iteration pattern without importing IDA. Use the same fields that `mba_to_dict()` accesses.

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/unit/diag/test_snapshot.py -v`
Expected: FAIL

- [ ] **Step 3: Implement snapshot_mba**

```python
# src/d810/diag/snapshot.py
"""Write MBA state to SQLite diagnostic snapshot."""
from __future__ import annotations
import json
import sqlite3
import time
from typing import Any

def snapshot_mba(
    conn: sqlite3.Connection,
    mba: Any,  # ida_hexrays.mbl_array_t or mock
    label: str,
    func_ea: int,
    maturity: str = "UNKNOWN",
) -> int:
    """Snapshot MBA blocks + instructions into SQLite. Returns snapshot_id."""
    ...
```

Core logic:
1. Insert into `snapshots`, get `lastrowid`
2. Call `mba_to_semantic(mba)` (refactored from `mba_to_human_readable`) → returns `list[BlockSnapshot]`
3. Iterate `BlockSnapshot` objects → insert into `blocks` table
4. For each block, iterate `BlockSnapshot.instructions` → insert into `instructions` table
5. `str(block_snapshot)` still produces the same text as old `mba_to_human_readable()` — no text output regression

**Key design: single serialization path.** `mba_to_human_readable()` currently returns `List[str]`. Refactor it to return `List[BlockSnapshot]` where `BlockSnapshot.__str__()` produces the same text. Code that calls `"\n\n".join(mba_to_human_readable(mba))` continues to work because `str()` on each element produces the text. But now the structured data is also available for SQLite insertion.

**Dataclasses** (in `src/d810/recon/microcode_dump.py` alongside the existing function):
```python
@dataclass
class InstructionSnapshot:
    index: int
    ea: int
    opcode: int
    opcode_name: str
    dest_type: str | None
    dest_stkoff: int | None
    dest_size: int | None
    src_l_type: str | None
    src_l_stkoff: int | None
    src_l_value: int | None
    src_r_type: str | None
    src_r_stkoff: int | None
    src_r_value: int | None
    dstr: str  # IDA's display string
    def __str__(self) -> str:
        return self.dstr

@dataclass
class BlockSnapshot:
    serial: int
    block_type: int
    type_name: str
    start_ea: int | None
    end_ea: int | None
    nsucc: int
    npred: int
    succs: list[int]
    preds: list[int]
    instructions: list[InstructionSnapshot]
    use_def_dnu: str  # the USE/DEF/DNU/VALRANGES text block
    def __str__(self) -> str:
        # Produces the same text as old mba_to_human_readable per block
        ...
```

**Important**: The refactored function lives in `microcode_dump.py` (which already imports IDA). The `diag/snapshot.py` writer takes `List[BlockSnapshot]` — no IDA imports needed in the diag package. Unit tests create `BlockSnapshot` directly.

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 3: Strategy metadata writers (Layer 2)

**Files:**
- Modify: `src/d810/diag/snapshot.py`
- Test: `tests/unit/diag/test_snapshot.py` (extend)

- [ ] **Step 1: Write failing tests for `snapshot_dag`, `snapshot_modifications`, `snapshot_reachability`**

```python
def test_snapshot_dag_writes_nodes_and_edges(mock_dag):
    conn = sqlite3.connect(":memory:")
    create_tables(conn)
    snap_id = snapshot_mba(conn, mock_mba, label="test", func_ea=0x1000)
    snapshot_dag(conn, snap_id, mock_dag)
    nodes = conn.execute("SELECT COUNT(*) FROM dag_nodes WHERE snapshot_id=?", (snap_id,)).fetchone()[0]
    edges = conn.execute("SELECT COUNT(*) FROM dag_edges WHERE snapshot_id=?", (snap_id,)).fetchone()[0]
    assert nodes == 3
    assert edges == 4

def test_snapshot_modifications(mock_modifications):
    ...

def test_snapshot_reachability(mock_reachable_set, mock_bst_set, mock_gutted_set):
    ...
```

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement `snapshot_dag()`, `snapshot_modifications()`, `snapshot_reachability()`**

Each function takes `(conn, snapshot_id, data)` and bulk-inserts rows. Use `executemany` for performance.

`snapshot_dag()`:
- Iterates `dag.nodes` → inserts into `dag_nodes`
- Iterates `dag.edges` → inserts into `dag_edges` with `ordered_path` as JSON array

`snapshot_modifications()`:
- Takes the `modifications` list from reconstruction
- Inserts each with type, source/target blocks, status, reason

`snapshot_reachability()`:
- Takes `reachable: set[int]`, `bst_serials: set[int]`, `gutted: set[int]`, `claimed_sources: set[int]`
- Inserts into `block_classification`

- [ ] **Step 4: Run tests to verify they pass**
- [ ] **Step 5: Commit**

---

### Task 3b: Scenario fixture — the chain we actually debugged

**Files:**
- Create: `tests/unit/diag/fixtures.py`
- Create: `tests/unit/diag/test_scenarios.py`

This fixture encodes the exact debugging scenario from this session: the chain `blk[131] → blk[174] → blk[176] → blk[200] → blk[23] → blk[32] → blk[62] → blk[206] → blk[207] → blk[218] → blk[219]` with the m_xdu variable aliasing bug at blk[207].

- [ ] **Step 1: Write the fixture**

```python
# tests/unit/diag/fixtures.py
"""Pre-loaded diagnostic DB fixtures based on real debugging scenarios."""
import json
import sqlite3
from d810.diag.schema import create_tables

def create_sub_7ffd_scenario(conn: sqlite3.Connection) -> int:
    """Populate DB with the 0xACD0BD5 → 0x432DC789 chain scenario.

    Returns snapshot_id.

    Encodes:
    - blk[131] (0xACD0BD5 handler entry) → blk[174] (MBA check)
    - blk[174] fallthrough → blk[175] (early return, writes var_8 from var_7C8)
    - blk[174] taken → blk[176] → blk[200] → blk[23] (0x6465D165)
    - blk[23] → blk[32] (STATE_432DC789_target body) → blk[62] (0x432DC789)
    - blk[62] → blk[206] (0x298372CC mask check)
    - blk[206] fallthrough → blk[207] (m_xdu: writes var_8 from var_7BC!)
    - blk[207] → blk[218] (return corridor) → blk[219] (BLT_STOP)
    - blk[217] (correct return corridor: writes var_8 from var_178)
    """
    create_tables(conn)
    conn.execute(
        "INSERT INTO snapshots VALUES (1, 'pass0_post_apply', 0x180012B60, 'MMAT_GLBOPT1', 233, 0.0)"
    )

    # Blocks with succs/preds and key meta
    blocks = [
        (131, 1, "BLT_1WAY", 1, 0, [174], [129, 148], 2, None),
        (174, 2, "BLT_2WAY", 2, 1, [175, 176], [131, 173], 1,
         '{"valranges": {"0x3C": "==ACD0BD5"}}'),
        (175, 1, "BLT_1WAY", 1, 0, [218], [174], 2, None),
        (176, 1, "BLT_1WAY", 1, 0, [200], [174], 3, None),
        (200, 1, "BLT_1WAY", 1, 0, [23], [176], 5, None),
        (23, 1, "BLT_1WAY", 1, 0, [24], [200, 170], 2,
         '{"valranges": {"0x3C": "==6465D165"}}'),
        (24, 1, "BLT_1WAY", 1, 0, [32], [23], 1, None),
        (32, 1, "BLT_1WAY", 1, 0, [62], [24], 12, None),
        (62, 1, "BLT_1WAY", 1, 0, [206], [32], 3,
         '{"valranges": {"0x3C": "==432DC789"}}'),
        (206, 2, "BLT_2WAY", 2, 1, [207, 208], [62, 204], 1,
         '{"valranges": {"0x3C": "==298372CC"}}'),
        (207, 1, "BLT_1WAY", 1, 0, [218], [206], 3, None),
        (217, 1, "BLT_1WAY", 1, 0, [218], [119, 162], 3, None),
        (218, 1, "BLT_1WAY", 1, 0, [219], [175, 207, 217], 1, None),
        (219, 0, "BLT_STOP", 0, 0, [], [218], 0, None),
    ]
    for serial, btype, tname, nsucc, npred, succs, preds, icnt, meta in blocks:
        conn.execute(
            "INSERT INTO blocks VALUES (1,?,?,?,NULL,NULL,?,?,?,?,?,?)",
            (serial, btype, tname, nsucc, len(preds),
             json.dumps(succs), json.dumps(preds), icnt, meta),
        )

    # Key instructions — the ones that matter for variable provenance
    instructions = [
        # blk[131]: assert mov state var
        (131, 0, 0x180014852, 4, "m_mov", "mop_S", 0x3C, 4, "mop_n", None, 0x0ACD0BD5, None, None, None,
         "mov #0xACD0BD5, %var_7BC.4", None),
        # blk[175]: writes var_8 from var_7C8 (CORRECT return path)
        (175, 0, 0x180015C7A, 12, "m_add", "mop_S", 0x7F0, 8, None, None, None, None, None, None,
         "add (MBA+0xFE), %var_8.8", None),
        # blk[207]: m_xdu writes var_8 from var_7BC (BUG: should be var_7C8)
        (207, 1, 0x1800161C8, 38, "m_xdu", "mop_S", 0x7F0, 8, "mop_S", 0x3C, None, None, None, None,
         "xdu %var_7BC.4, %var_8.8",
         '{"note": "IDA aliased var_7C8(stkoff=0x30) as var_7BC(stkoff=0x3C) via xdu"}'),
        # blk[217]: writes var_8 from var_178 (CORRECT shared corridor)
        (217, 2, 0x1800164C5, 4, "m_mov", "mop_S", 0x7F0, 8, "mop_S", 0x680, None, None, None, None,
         "mov %var_178.8, %var_8.8", None),
        # blk[218]: reads var_8 into rax (final return)
        (218, 0, 0x1800164CD, 4, "m_mov", "mop_r", None, 8, "mop_S", 0x7F0, None, None, None, None,
         "mov %var_8.8, rax.8", None),
        # blk[32]: state write 0x432DC789 (un-NOPed in duplicate-and-redirect path)
        (32, 10, 0x180013405, 4, "m_mov", "mop_S", 0x3C, 4, "mop_n", None, 0x432DC789, None, None, None,
         "mov #0x432DC789, %var_7BC.4", None),
    ]
    for row in instructions:
        conn.execute(
            "INSERT INTO instructions VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            row,
        )

    # DAG edges
    dag_edges = [
        (0, 0x0ACD0BD5, 0x258ED455, "CONDITIONAL_TRANSITION", 174, 1, 199, "[131,174,176,199]"),
        (1, 0x0ACD0BD5, None, "CONDITIONAL_RETURN", 174, 0, None, "[131,174,175,218,219]"),
        (2, 0x258ED455, 0x6465D165, "TRANSITION", 199, None, 23, "[199]"),
        (3, 0x6465D165, 0x432DC789, "TRANSITION", 23, None, 62, "[23,24,32]"),
        (4, 0x432DC789, 0x298372CC, "TRANSITION", 62, None, 205, "[62]"),
        (5, 0x298372CC, None, "CONDITIONAL_RETURN", 206, 0, None, "[206,207,218,219]"),
    ]
    for eid, src, tgt, kind, sblk, sarm, tentry, path in dag_edges:
        conn.execute(
            "INSERT INTO dag_edges VALUES (1,?,?,?,?,?,?,?,?)",
            (eid, src, tgt, kind, sblk, sarm, tentry, path),
        )

    # Block classification
    for serial in [131, 174, 175, 176, 200, 23, 24, 32, 62, 206, 207, 217, 218, 219]:
        is_bst = 0
        is_gutted = 0
        conn.execute(
            "INSERT INTO block_classification VALUES (1,?,?,1,?,0)",
            (serial, is_bst, is_gutted),
        )

    conn.commit()
    return 1
```

- [ ] **Step 2: Write scenario tests that verify the diagnostic queries catch the real bugs**

```python
# tests/unit/diag/test_scenarios.py
"""Tests that verify diagnostic queries catch real debugging scenarios."""
import sqlite3
from d810.diag.schema import create_tables
from d810.diag.query import chain, var_writes, block_detail, return_paths
from tests.unit.diag.fixtures import create_sub_7ffd_scenario

def _db():
    conn = sqlite3.connect(":memory:")
    create_sub_7ffd_scenario(conn)
    return conn

def test_chain_detects_broken_hop_at_blk206():
    """The chain 131→...→206→217→218 has a broken hop: blk[206].succs=[207,208], not 217."""
    conn = _db()
    result = chain(conn, 1, [131, 174, 176, 200, 23, 24, 32, 62, 206, 217, 218, 219])
    # Find the hop from 206 to 217
    hop_206 = next(r for r in result if r and r["serial"] == 206)
    assert hop_206["hop_ok"] is False, "blk[206]→blk[217] should be broken (actual succ is 207)"
    assert hop_206["expected_next"] == 217

def test_chain_confirms_correct_hops():
    """All hops except 206→217 should be correct."""
    conn = _db()
    result = chain(conn, 1, [131, 174, 176, 200, 23, 24, 32, 62])
    for r in result:
        if r and "hop_ok" in r:
            assert r["hop_ok"] is True, f"blk[{r['serial']}] hop should be correct"

def test_var_writes_finds_return_slot_clobber():
    """var_writes for stkoff=0x7F0 (return slot) should find both blk[175] and blk[207]."""
    conn = _db()
    writes = var_writes(conn, 1, stkoff=0x7F0)
    writer_blocks = {w["block_serial"] for w in writes}
    assert 175 in writer_blocks, "blk[175] writes correct MBA result to return slot"
    assert 207 in writer_blocks, "blk[207] clobbers return slot with m_xdu from state var"
    assert 217 in writer_blocks, "blk[217] writes var_178 to return slot"

def test_var_writes_identifies_mxdu_as_state_var_source():
    """blk[207]'s write to var_8 sources from stkoff=0x3C (state var), not 0x30 (var_7C8)."""
    conn = _db()
    writes = var_writes(conn, 1, stkoff=0x7F0)
    mxdu_write = next(w for w in writes if w["block_serial"] == 207)
    assert mxdu_write["opcode_name"] == "m_xdu"
    assert mxdu_write["src_l_stkoff"] == 0x3C, "m_xdu reads from state var (0x3C), not var_7C8 (0x30)"

def test_return_path_identifies_mxdu_on_path():
    """CONDITIONAL_RETURN edge [206,207,218,219] includes blk[207] which has m_xdu."""
    conn = _db()
    paths = return_paths(conn, 1)
    # Find the 0x298372CC return path
    ret_path = next(p for p in paths if 206 in p.get("path_serials", []))
    assert 207 in ret_path["path_serials"]
    # The hop check should flag blk[207] as containing an m_xdu to the return slot
    hop_207 = next(h for h in ret_path["hops"] if h["serial"] == 207)
    assert hop_207.get("has_return_slot_write") is True
    assert hop_207.get("write_opcode") == "m_xdu"

def test_var_writes_finds_unnopped_state_write_at_blk32():
    """blk[32] writes 0x432DC789 to state var — the un-NOPed duplicate-and-redirect site."""
    conn = _db()
    writes = var_writes(conn, 1, stkoff=0x3C)
    blk32_write = next(w for w in writes if w["block_serial"] == 32)
    assert blk32_write["src_l_value"] == 0x432DC789
    assert blk32_write["opcode_name"] == "m_mov"

def test_block_detail_shows_valranges_from_meta():
    """block_detail for blk[206] should expose valranges from meta JSON."""
    conn = _db()
    detail = block_detail(conn, 1, serial=206)
    assert detail is not None
    assert detail["type_name"] == "BLT_2WAY"
    assert "valranges" in detail.get("meta_parsed", {})
    assert detail["meta_parsed"]["valranges"]["0x3C"] == "==298372CC"
```

- [ ] **Step 3: Run tests to verify they fail** (query functions not implemented yet)

Run: `PYTHONPATH=src pytest tests/unit/diag/test_scenarios.py -v`
Expected: FAIL with `ImportError` or `AttributeError` (query functions don't exist yet)

- [ ] **Step 4: These tests drive Task 4 (query helpers) — they pass when Task 4 is done**

---

### Task 4: Query helpers

**Files:**
- Create: `src/d810/diag/query.py`
- Test: `tests/unit/diag/test_query.py`

- [ ] **Step 1: Write failing tests**

```python
def test_chain_returns_ordered_block_details(loaded_db):
    """loaded_db has a snapshot with blocks 131,174,176,200,23,32,62,206,207,218."""
    result = chain(loaded_db, snapshot_id=1, serials=[131, 174, 176, 200, 23])
    assert len(result) == 5
    assert result[0]["serial"] == 131
    assert "succs" in result[0]
    assert "instructions" in result[0]

def test_var_writes_finds_return_slot(loaded_db):
    result = var_writes(loaded_db, snapshot_id=1, stkoff=0x7F0)
    assert len(result) > 0
    assert all(r["dest_stkoff"] == 0x7F0 for r in result)

def test_block_detail_includes_classification(loaded_db):
    result = block_detail(loaded_db, snapshot_id=1, serial=206)
    assert "is_bst" in result
    assert "succs" in result
```

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement query helpers**

```python
# src/d810/diag/query.py
"""Query helpers for MBA diagnostic snapshots."""
from __future__ import annotations
import json
import sqlite3
from typing import Any

def chain(conn: sqlite3.Connection, snapshot_id: int, serials: list[int]) -> list[dict]:
    """Return block details for each serial in order, with instructions and hop status."""
    results = []
    for i, serial in enumerate(serials):
        blk = block_detail(conn, snapshot_id, serial)
        if blk and i < len(serials) - 1:
            expected_next = serials[i + 1]
            succs = json.loads(blk["succs"])
            blk["hop_ok"] = expected_next in succs
            blk["expected_next"] = expected_next
        results.append(blk)
    return results

def var_writes(conn: sqlite3.Connection, snapshot_id: int, stkoff: int) -> list[dict]:
    """Return all instructions that write to a given stack offset."""
    ...

def block_detail(conn: sqlite3.Connection, snapshot_id: int, serial: int) -> dict | None:
    """Return full block info with instructions and classification."""
    ...

def return_paths(conn: sqlite3.Connection, snapshot_id: int) -> list[dict]:
    """Return all CONDITIONAL_RETURN edges with per-hop status."""
    ...
```

The `chain()` function is the killer feature. Output format:
```
blk[131] 1WAY succs=[174] preds=[129,148] hop→174 OK
  131.1 mov #0xACD0BD5, var_7BC  (assert)
  131.2 goto @174
blk[174] 2WAY succs=[175,176] preds=[131,173] hop→176 OK
  174.1 jnz (MBA), #-0xFE, @176
blk[176] 1WAY succs=[200] preds=[174] hop→200 OK
  176.1 mov var_1C8, var_3D8
  ...
```

- [ ] **Step 4: Run tests to verify they pass**
- [ ] **Step 5: Commit**

---

### Task 5: CLI entry point

**Files:**
- Create: `src/d810/diag/__main__.py`
- Test: `tests/unit/diag/test_cli.py`

- [ ] **Step 1: Write failing test**

```python
import subprocess
def test_cli_chain(tmp_path, loaded_db_path):
    result = subprocess.run(
        ["python", "-m", "d810.diag", "chain", "--db", str(loaded_db_path),
         "131", "174", "176", "200", "23"],
        capture_output=True, text=True
    )
    assert result.returncode == 0
    assert "blk[131]" in result.stdout
```

- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement CLI**

```python
# src/d810/diag/__main__.py
"""CLI for querying MBA diagnostic snapshots."""
import argparse
import sqlite3
from d810.diag.query import chain, var_writes, block_detail, return_paths

def main():
    parser = argparse.ArgumentParser(prog="d810.diag")
    parser.add_argument("--db", default=".tmp/diag.sqlite3")
    parser.add_argument("--snapshot", type=int, default=-1, help="snapshot ID (-1 = latest)")
    sub = parser.add_subparsers(dest="command")

    p_chain = sub.add_parser("chain", help="Trace a block chain")
    p_chain.add_argument("serials", nargs="+", type=int)

    p_var = sub.add_parser("var-writes", help="Find writes to a stack variable")
    p_var.add_argument("stkoff", type=lambda x: int(x, 0))

    p_blk = sub.add_parser("block", help="Show block detail")
    p_blk.add_argument("serial", type=int)
    p_blk.add_argument("--insns", action="store_true")

    p_ret = sub.add_parser("return-paths", help="Show return path hop status")

    args = parser.parse_args()
    ...
```

Commands:
- `python -m d810.diag chain 131 174 176 200 23 32 62 206 207 218`
- `python -m d810.diag var-writes 0x7F0`
- `python -m d810.diag block 206 --insns`
- `python -m d810.diag return-paths`

- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit**

---

### Task 6: Wire into Hodur pipeline

**Files:**
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/executor.py`
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/strategies/reconstruction.py`
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/unflattener.py`

- [ ] **Step 1: Add `snapshot_mba()` call in executor after each POST-APPLY**

In `executor.py`, after the existing POST-APPLY log (line ~375), add:
```python
from d810.diag.snapshot import snapshot_mba
from d810.diag.schema import get_or_create_diag_db

db = get_or_create_diag_db(mba)  # creates .tmp/diag.sqlite3 or func-specific path
snapshot_mba(db, self.mba, label=f"{fragment.strategy_name}_post_apply", func_ea=self.mba.entry_ea)
```

Gate behind a config flag or environment variable (`D810_DIAG_SNAPSHOT=1`) so it doesn't slow down normal operation.

- [ ] **Step 2: Add `snapshot_dag()` call in reconstruction.py after DAG construction**

In `reconstruction.py`, after the DAG is built and before emission:
```python
if diag_db:
    snapshot_dag(diag_db, snap_id, dag)
```

- [ ] **Step 3: Add `snapshot_modifications()` after emission**

```python
if diag_db:
    snapshot_modifications(diag_db, snap_id, modifications, return_mods, bridge_mods)
```

- [ ] **Step 4: Add `snapshot_reachability()` in unflattener after Gut-and-Wire**

```python
if diag_db:
    snapshot_reachability(diag_db, snap_id, reachable, bst_serials, gutted, claimed_sources)
```

- [ ] **Step 5: Test end-to-end with Docker**

```bash
D810_DIAG_SNAPSHOT=1 ./tools/scripts/run_system_tests_docker.sh dump -f sub_7FFD3338C040 -p hodur_flag2.json -o OUTPUT_DIAG.txt -l
# Check that .tmp/diag.sqlite3 was created
sqlite3 .tmp/diag.sqlite3 "SELECT * FROM snapshots"
python -m d810.diag chain --db .tmp/diag.sqlite3 131 174 176 200 23 32 62 206 207 218
```

- [ ] **Step 6: Commit**

---

### Task 7: Replace text dump emitters with SQLite-backed renderers

**Files:**
- Modify: `src/d810/recon/flow/linearized_state_dag.py` (DOT + text renderers)
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/executor.py` (POST-APPLY dump)

- [ ] **Step 1: Make DOT renderer optionally read from SQLite**

Add `render_dot_from_db(conn, snapshot_id) -> str` that generates DOT from the `dag_nodes` + `dag_edges` + `block_classification` tables. Falls back to the existing renderer when no DB is available.

- [ ] **Step 2: Make DAG text renderer optionally read from SQLite**

Add `render_dag_text_from_db(conn, snapshot_id) -> str`.

- [ ] **Step 3: Make POST-APPLY dump optionally write to SQLite instead of text**

When `D810_DIAG_SNAPSHOT=1`, skip the `mba_to_human_readable()` text dump and rely on the SQLite snapshot. Add `python -m d810.diag block 206 --insns` as the replacement.

- [ ] **Step 4: Test that text output is unchanged when DB is not used**
- [ ] **Step 5: Commit**
