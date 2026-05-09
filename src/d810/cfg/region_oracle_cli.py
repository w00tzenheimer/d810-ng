"""CLI handler for `python -m d810.core.diag region-diff`.

Lives in d810.cfg because the layered-architecture contract forbids
d810.core.diag from importing d810.cfg. The diag CLI dispatches here
via importlib.import_module(...). The handler is injected with the
core/diag helpers it needs (resolver + persistence) so this module
does NOT static-import them.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

from d810.cfg.ref_region_oracle import (
    FeatureRegion,
    FeatureSource,
    RegionFeature,
    _normalize_func_ea_hex,
    collect_block_views_for_snapshot,
    diff_features,
    ref_features,
    spec_for,
)


def register_region_diff_parser(sub, common) -> None:
    p = sub.add_parser(
        "region-diff",
        parents=[common],
        help=(
            "Recompute REF vs snap17/snap18 region diff and (optionally) "
            "persist scoped feature + DCE-cause rows."
        ),
    )
    p.add_argument("--func-ea", default=None)
    p.add_argument("--auto", action="store_true")
    p.add_argument("--persist", action="store_true")
    p.add_argument("--snap17", type=int, default=None)
    p.add_argument("--snap18", type=int, default=None)
    p.add_argument("--snap17-label", default=None)
    p.add_argument("--snap18-label", default=None)
    p.add_argument("--output", default=None)
    p.add_argument("--microblocks", action="store_true")
    p.add_argument("--json", action="store_true", dest="json_output")


def _resolve_db_path(args) -> str | None:
    if args.db:
        return args.db
    if args.auto:
        diag_dir = Path(".tmp/logs/d810_logs")
        cands = (
            sorted(
                diag_dir.glob("*.diag.sqlite3"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if diag_dir.exists()
            else []
        )
        return str(cands[0]) if cands else None
    return None


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text)
        print(f"oracle written: {output}")
    else:
        print(text, end="")


def _no_ref_spec_stub(func_ea_hex: str) -> str:
    return (
        "# Region Oracle\n\n"
        f"Function: {func_ea_hex}\n"
        "Status: no_ref_spec\n\n"
        "No REF region spec is registered for this function.\n"
        "D810-only feature extraction was skipped from this run.\n"
    )


def _build_snapshot_features(conn, spec, snap_id: int) -> list[RegionFeature]:
    """Build D810 features for one snapshot.

    Skeleton: emits one placeholder row per spec.feature_table entry with
    a count of blocks observed for the snapshot. Real per-feature
    detection logic is intentionally deferred.

    Block-view collection is best-effort against sparse diag DBs that
    only have the ``snapshots`` row populated.
    """
    try:
        blocks = collect_block_views_for_snapshot(conn, snapshot_id=snap_id)
    except sqlite3.OperationalError:
        blocks = {}
    feats: list[RegionFeature] = []
    for entry in spec.feature_table:
        # Each entry is (region, name, value, evidence_path).
        region: FeatureRegion = entry[0]
        name: str = entry[1]
        feats.append(
            RegionFeature(
                source=FeatureSource.D810_SNAPSHOT,
                region=region,
                feature=name,
                value=False,  # placeholder; refine in follow-up
                evidence={
                    "snapshot_id": snap_id,
                    "snapshot_blocks": len(blocks),
                },
                snapshot_id=snap_id,
            )
        )
    return feats


def _render_markdown(
    spec,
    func_ea_hex,
    snap17,
    snap18,
    ref,
    s17_feats,
    s18_feats,
    diff17,
    diff18,
    microblocks,
    blocks17,
    blocks18,
) -> str:
    lines: list[str] = []
    lines.append("# Region Oracle\n")
    lines.append(f"Function: {spec.func_name} ({func_ea_hex})")
    lines.append(f"snap17: {snap17}, snap18: {snap18}\n")
    lines.append("## Summary\n")
    lines.append(f"REF features registered: {len(ref)}")
    lines.append(f"snap17 blocks: {len(blocks17)}")
    lines.append(f"snap18 blocks: {len(blocks18)}\n")
    lines.append("| feature | REF | D810 snap17 | D810 snap18 | verdict |")
    lines.append("|-|-|-|-|-|")
    s17_by_name = {f.feature: f.value for f in s17_feats}
    s18_by_name = {f.feature: f.value for f in s18_feats}
    for f in ref:
        v17 = s17_by_name.get(f.feature, "?")
        v18 = s18_by_name.get(f.feature, "?")
        verdict = "match" if (f.value == v17 == v18) else "diff"
        lines.append(
            f"| {f.feature} | {f.value} | {v17} | {v18} | {verdict} |"
        )
    if microblocks:
        lines.append("\n## Microblock Evidence\n")
        for f in ref:
            lines.append(f"### {f.feature}")
            lines.append(
                f"- REF: present={f.value}; evidence={f.evidence}"
            )
            s17 = next(
                (x for x in s17_feats if x.feature == f.feature), None
            )
            s18 = next(
                (x for x in s18_feats if x.feature == f.feature), None
            )
            if s17:
                lines.append(
                    f"- D810 snap17: present={s17.value}; "
                    f"evidence={s17.evidence}"
                )
            if s18:
                lines.append(
                    f"- D810 snap18: present={s18.value}; "
                    f"evidence={s18.evidence}"
                )
            lines.append("")
    return "\n".join(lines) + "\n"


def handle_region_diff(
    args,
    conn,
    resolve_snap_ids,
    persist_features,
    persist_dce_causes,
) -> int:
    db_path = _resolve_db_path(args)
    if not db_path and args.auto:
        print(
            "oracle skipped: no diag DB present "
            "(run with --enable-debug-logging to capture one)"
        )
        return 0
    if not db_path:
        print("oracle: --db or --auto required", file=sys.stderr)
        return 2

    # Reopen on the resolved path so --auto works.
    if args.auto and not args.db:
        conn = sqlite3.connect(db_path)

    if args.func_ea:
        func_ea_hex = _normalize_func_ea_hex(args.func_ea)
    else:
        try:
            row = conn.execute(
                "SELECT func_ea_hex FROM snapshots LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError as e:
            print(f"oracle: schema mismatch: {e}", file=sys.stderr)
            return 2
        if row is None or row[0] is None:
            print(
                "oracle: cannot infer func_ea from DB; "
                "pass --func-ea explicitly",
                file=sys.stderr,
            )
            return 2
        func_ea_hex = _normalize_func_ea_hex(str(row[0]))

    spec = spec_for(func_ea_hex)
    if spec is None:
        _emit(_no_ref_spec_stub(func_ea_hex), args.output)
        return 0

    snap17 = args.snap17
    snap18 = args.snap18
    if snap17 is None or snap18 is None:
        snap17_labels = (
            (args.snap17_label,)
            if args.snap17_label
            else spec.snap17_label_preferences
        )
        snap18_labels = (
            (args.snap18_label,)
            if args.snap18_label
            else spec.snap18_label_preferences
        )
        try:
            r17, r18 = resolve_snap_ids(
                conn,
                snap17_labels=snap17_labels,
                snap18_labels=snap18_labels,
            )
        except sqlite3.OperationalError as e:
            print(f"oracle: schema mismatch: {e}", file=sys.stderr)
            return 2
        if snap17 is None:
            snap17 = r17
        if snap18 is None:
            snap18 = r18

    if snap17 is None or snap18 is None:
        print(
            f"oracle: cannot resolve snap17/snap18 (snap17={snap17}, "
            f"snap18={snap18}); pass --snap17/--snap18 explicitly.",
            file=sys.stderr,
        )
        return 2

    if snap17 >= snap18:
        print(
            f"oracle: snap17 ({snap17}) must be < snap18 ({snap18}). "
            "Pass valid IDs explicitly.",
            file=sys.stderr,
        )
        return 2

    # Block-view collection is best-effort: a sparse diag DB (e.g. no
    # blocks/instructions tables populated) should still let us render the
    # REF-side oracle. Treat schema/empty failures as "zero blocks" rather
    # than aborting.
    try:
        blocks17 = collect_block_views_for_snapshot(conn, snapshot_id=snap17)
    except sqlite3.OperationalError:
        blocks17 = {}
    try:
        blocks18 = collect_block_views_for_snapshot(conn, snapshot_id=snap18)
    except sqlite3.OperationalError:
        blocks18 = {}

    ref = list(ref_features(spec))
    s17 = _build_snapshot_features(conn, spec, snap17)
    s18 = _build_snapshot_features(conn, spec, snap18)
    diff17 = list(diff_features(ref, s17))
    diff18 = list(diff_features(ref, s18))

    body = _render_markdown(
        spec,
        func_ea_hex,
        snap17,
        snap18,
        ref,
        s17,
        s18,
        diff17,
        diff18,
        args.microblocks,
        blocks17,
        blocks18,
    )

    if args.json_output:
        payload = {
            "function": {"name": spec.func_name, "func_ea_hex": func_ea_hex},
            "snap17": snap17,
            "snap18": snap18,
            "ref_features": [
                {
                    "feature": f.feature,
                    "value": f.value,
                    "evidence": f.evidence,
                }
                for f in ref
            ],
            "snap17_features": [
                {
                    "feature": f.feature,
                    "value": f.value,
                    "evidence": f.evidence,
                }
                for f in s17
            ],
            "snap18_features": [
                {
                    "feature": f.feature,
                    "value": f.value,
                    "evidence": f.evidence,
                }
                for f in s18
            ],
        }
        body = json.dumps(payload, indent=2, sort_keys=True)

    _emit(body, args.output)

    if args.persist:
        all_feats = list(ref) + list(s17) + list(s18)
        persist_features(
            conn,
            func_ea_hex=func_ea_hex,
            func_ea_i64=int(func_ea_hex, 16),
            features=all_feats,
        )

    return 0
