"""Post-D810 handoff diagnostics over persisted microcode snapshots."""

from __future__ import annotations

import dataclasses
import sqlite3


@dataclasses.dataclass(frozen=True, slots=True)
class PostD810ProtectedBundleSpec:
    """Diagnostic bundle that must remain sound across post-D810 compaction."""

    func_ea_i64: int
    maturity_name: str
    name: str
    pre_blocks: tuple[int, ...]
    pre_markers: tuple[str, ...]
    protected_offsets: tuple[int, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class PostD810HandoffViolation:
    """Diagnostic-only post-D810 invariant failure."""

    bundle_name: str
    pre_snapshot_id: int
    post_snapshot_id: int
    missing_def_offsets: tuple[int, ...]
    use_sites: tuple[str, ...]
    def_sites: tuple[str, ...]


_POST_D810_PROTECTED_BUNDLES: tuple[PostD810ProtectedBundleSpec, ...] = (
    PostD810ProtectedBundleSpec(
        func_ea_i64=0x180012B60,
        maturity_name="MMAT_GLBOPT1",
        name="sub7ffd_80_118_setup_bundle",
        pre_blocks=(80, 118),
        pre_markers=(
            "ldx    ds.2, %var_178.8, %var_230.8",
            "#-0x4B6C02C3E6626146.8",
            "#-0x4B6C02C3E6626145.8",
            "#0xE6334342.4",
            "#0x1C6BAB0E.4",
            "%var_230.8",
            "%var_678.8",
            "%var_680.8",
        ),
        protected_offsets=(0x4D8, 0x4E8),
    ),
    PostD810ProtectedBundleSpec(
        func_ea_i64=0x180012B60,
        maturity_name="MMAT_GLBOPT1",
        name="sub7ffd_223_221_private_setup_bundle",
        pre_blocks=(223, 221),
        pre_markers=(
            "ldx    ds.2, %var_178.8, %var_230.8",
            "#-0x4B6C02C3E6626146.8",
            "#-0x4B6C02C3E6626145.8",
            "%var_230.8",
            "%var_678.8",
            "%var_680.8",
        ),
        protected_offsets=(0x4D8, 0x4E8),
    ),
)


def _find_previous_snapshot_id(
    conn: sqlite3.Connection,
    *,
    func_ea_i64: int,
    maturity_name: str,
    phase: str,
    before_snapshot_id: int,
) -> int | None:
    row = conn.execute(
        """
        SELECT id
        FROM snapshots
        WHERE func_ea_i64 = ? AND maturity = ? AND phase = ? AND id < ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (int(func_ea_i64), str(maturity_name), str(phase), int(before_snapshot_id)),
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return int(row[0])


def _snapshot_contains_bundle_markers(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    blocks: tuple[int, ...],
    markers: tuple[str, ...],
) -> bool:
    placeholders = ",".join("?" for _ in blocks)
    rows = conn.execute(
        f"""
        SELECT dstr
        FROM instructions
        WHERE snapshot_id = ? AND block_serial IN ({placeholders})
        ORDER BY block_serial, insn_index
        """,
        (int(snapshot_id), *[int(block) for block in blocks]),
    ).fetchall()
    if not rows:
        return False
    texts = tuple(str(row[0] or "") for row in rows)
    return all(any(marker in text for text in texts) for marker in markers)


def _collect_offset_sites(
    conn: sqlite3.Connection,
    *,
    snapshot_id: int,
    offsets: tuple[int, ...],
) -> tuple[set[int], tuple[str, ...], set[int], tuple[str, ...]]:
    placeholders = ",".join("?" for _ in offsets)
    use_rows = conn.execute(
        f"""
        SELECT block_serial, insn_index, src_l_stkoff, src_r_stkoff, dstr
        FROM instructions
        WHERE snapshot_id = ?
          AND (src_l_stkoff IN ({placeholders}) OR src_r_stkoff IN ({placeholders}))
        ORDER BY block_serial, insn_index
        """,
        (
            int(snapshot_id),
            *[int(offset) for offset in offsets],
            *[int(offset) for offset in offsets],
        ),
    ).fetchall()
    def_rows = conn.execute(
        f"""
        SELECT block_serial, insn_index, dest_stkoff, dstr
        FROM instructions
        WHERE snapshot_id = ? AND dest_stkoff IN ({placeholders})
        ORDER BY block_serial, insn_index
        """,
        (int(snapshot_id), *[int(offset) for offset in offsets]),
    ).fetchall()

    used_offsets: set[int] = set()
    use_sites: list[str] = []
    for block_serial, insn_index, src_l_stkoff, src_r_stkoff, dstr in use_rows:
        if src_l_stkoff in offsets:
            used_offsets.add(int(src_l_stkoff))
        if src_r_stkoff in offsets:
            used_offsets.add(int(src_r_stkoff))
        use_sites.append(f"blk[{int(block_serial)}]:{int(insn_index)} {str(dstr or '')}")

    defined_offsets: set[int] = {int(row[2]) for row in def_rows if row[2] is not None}
    def_sites = tuple(
        f"blk[{int(block_serial)}]:{int(insn_index)} {str(dstr or '')}"
        for block_serial, insn_index, _, dstr in def_rows
    )
    return used_offsets, tuple(use_sites), defined_offsets, def_sites


def detect_post_d810_handoff_violations(
    conn: sqlite3.Connection,
    *,
    func_ea_i64: int,
    maturity_name: str,
    post_snapshot_id: int,
) -> tuple[PostD810HandoffViolation, ...]:
    """Detect protected-bundle def/use violations introduced at post-D810."""

    pre_snapshot_id = _find_previous_snapshot_id(
        conn,
        func_ea_i64=int(func_ea_i64),
        maturity_name=str(maturity_name),
        phase="post_pipeline",
        before_snapshot_id=int(post_snapshot_id),
    )
    if pre_snapshot_id is None:
        return ()

    violations: list[PostD810HandoffViolation] = []
    for bundle in _POST_D810_PROTECTED_BUNDLES:
        if int(bundle.func_ea_i64) != int(func_ea_i64):
            continue
        if bundle.maturity_name != str(maturity_name):
            continue
        if not _snapshot_contains_bundle_markers(
            conn,
            snapshot_id=pre_snapshot_id,
            blocks=bundle.pre_blocks,
            markers=bundle.pre_markers,
        ):
            continue
        used_offsets, use_sites, defined_offsets, def_sites = _collect_offset_sites(
            conn,
            snapshot_id=int(post_snapshot_id),
            offsets=bundle.protected_offsets,
        )
        if not used_offsets:
            continue
        missing_offsets = tuple(sorted(used_offsets - defined_offsets))
        if not missing_offsets:
            continue
        violations.append(
            PostD810HandoffViolation(
                bundle_name=bundle.name,
                pre_snapshot_id=int(pre_snapshot_id),
                post_snapshot_id=int(post_snapshot_id),
                missing_def_offsets=missing_offsets,
                use_sites=use_sites,
                def_sites=def_sites,
            )
        )
    return tuple(violations)
