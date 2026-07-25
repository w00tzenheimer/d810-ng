"""Capture and compare isolated Rhad reference/candidate MBA snapshots.

The reference binary must already be a disposable output of the unchanged
neighboring deobfuscator.  This tool never patches bytes or starts D810.  It
serializes each live MBA immediately, then persists and compares only portable
records.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from d810.core.diag import create_diag_database
from d810.core.diag.semantic_route_oracle import (
    load_snapshot_blocks,
    record_route_oracle_capture,
    record_route_oracle_comparisons,
    record_route_oracle_run,
    record_route_reference_rewrite,
)
from d810.core.diag.snapshot import snapshot_mba
from d810.core.semantic_route_oracle import (
    ReferenceRouteRewrite,
    ReferenceRouteOracleCatalog,
    RouteCaptureLane,
    RouteOracleCapture,
    RouteOracleRun,
    SemanticTransferKind,
    compare_route_maturities,
    observe_route_shape,
)


_MANIFEST_SCHEMA_VERSION = 2
_SIDECAR_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".i64")
_CONDITION_BY_OPCODE = {
    "0f80": "o",
    "0f81": "no",
    "0f82": "b",
    "0f83": "ae",
    "0f84": "z",
    "0f85": "nz",
    "0f86": "be",
    "0f87": "a",
    "0f88": "s",
    "0f89": "ns",
    "0f8a": "p",
    "0f8b": "np",
    "0f8c": "l",
    "0f8d": "ge",
    "0f8e": "le",
    "0f8f": "g",
    "70": "o",
    "71": "no",
    "72": "b",
    "73": "ae",
    "74": "z",
    "75": "nz",
    "76": "be",
    "77": "a",
    "78": "s",
    "79": "ns",
    "7a": "p",
    "7b": "np",
    "7c": "l",
    "7d": "ge",
    "7e": "le",
    "7f": "g",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _hex(value: int) -> str:
    return f"0x{int(value):X}"


def _parse_int(value: object, *, field: str) -> int:
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"{field} must be an integer or numeric string")


def _transaction_for_anchor(
    ledger: dict[str, object],
    *,
    function_ea: int,
    rewrite_anchor_ea: int,
) -> dict[str, object]:
    transactions = ledger.get("transactions")
    if not isinstance(transactions, list):
        raise ValueError("reference ledger has no transactions array")
    matches: list[dict[str, object]] = []
    for candidate in transactions:
        if not isinstance(candidate, dict):
            continue
        if candidate.get("status") != "committed":
            continue
        if _parse_int(candidate.get("function_ea"), field="function_ea") != int(
            function_ea
        ):
            continue
        planned = candidate.get("planned_branches")
        if not isinstance(planned, list):
            continue
        anchors = {
            _parse_int(branch.get("anchor_ea"), field="anchor_ea")
            for branch in planned
            if isinstance(branch, dict)
        }
        if anchors == {int(rewrite_anchor_ea)}:
            matches.append(candidate)
    if not matches:
        raise ValueError(
            "no committed reference transaction for "
            f"function={_hex(function_ea)} anchor={_hex(rewrite_anchor_ea)}"
        )
    if len(matches) != 1:
        raise ValueError(
            f"{len(matches)} committed reference transactions for "
            f"function={_hex(function_ea)} anchor={_hex(rewrite_anchor_ea)}"
        )
    return matches[0]


def _original_transfer_kind(
    transaction: dict[str, object],
    rewrite_anchor_ea: int,
) -> SemanticTransferKind:
    corridor = transaction.get("corridor")
    if not isinstance(corridor, list):
        raise ValueError("reference transaction has no corridor")
    owners = [
        instruction
        for instruction in corridor
        if isinstance(instruction, dict)
        and _parse_int(instruction.get("ea"), field="corridor ea") == rewrite_anchor_ea
    ]
    if len(owners) != 1:
        raise ValueError(
            f"reference anchor {_hex(rewrite_anchor_ea)} has {len(owners)} corridor owners"
        )
    mnemonic = str(owners[0].get("mnemonic", ""))
    if mnemonic == "jmp":
        return SemanticTransferKind.DIRECT
    if mnemonic.startswith("j"):
        return SemanticTransferKind.CONDITIONAL
    if mnemonic == "ret":
        return SemanticTransferKind.RETURN
    return SemanticTransferKind.UNKNOWN


def _final_transfer(
    transaction: dict[str, object],
) -> tuple[SemanticTransferKind, int | None, int | None, int | None, str | None]:
    branches = transaction.get("planned_branches")
    if not isinstance(branches, list) or not branches:
        raise ValueError("reference transaction has no planned branches")
    if not all(isinstance(branch, dict) for branch in branches):
        raise ValueError("reference planned branch is not an object")
    if len(branches) == 1:
        branch = branches[0]
        if str(branch.get("opcode", "")).lower() not in {"e9", "eb"}:
            raise ValueError(
                "one-branch reference rewrite is not an unconditional jump"
            )
        return (
            SemanticTransferKind.DIRECT,
            _parse_int(branch.get("target_ea"), field="direct target"),
            None,
            None,
            None,
        )
    if len(branches) == 2:
        conditional, fallback = branches
        conditional_opcode = str(conditional.get("opcode", "")).lower()
        if conditional_opcode not in _CONDITION_BY_OPCODE:
            raise ValueError(
                f"unsupported reference conditional opcode {conditional_opcode!r}"
            )
        if str(fallback.get("opcode", "")).lower() not in {"e9", "eb"}:
            raise ValueError("reference conditional lacks an unconditional false arm")
        return (
            SemanticTransferKind.CONDITIONAL,
            None,
            _parse_int(conditional.get("target_ea"), field="true target"),
            _parse_int(fallback.get("target_ea"), field="false target"),
            _CONDITION_BY_OPCODE[conditional_opcode],
        )
    raise ValueError(
        f"reference rewrite has {len(branches)} branches; expected one or two"
    )


def build_manifest(
    *,
    ledger: dict[str, object],
    run_id: str,
    function_ea: int,
    function_end_ea: int,
    publication_root_ea: int,
    rewrite_owners: dict[int, int],
    fixture_path: Path,
    reference_binary_path: Path,
    reference_commit: str,
    runtime_image: str,
    runtime_image_id: str,
    maturities: tuple[str, ...],
) -> dict[str, object]:
    """Derive selected route identities from an unchanged reference ledger."""

    fixture_sha256 = _sha256(fixture_path)
    ledger_sha256 = ledger.get("binary_sha256")
    if ledger_sha256 is not None and str(ledger_sha256).lower() != fixture_sha256:
        raise ValueError(
            "reference ledger fixture hash does not match the candidate input"
        )
    if not rewrite_owners:
        raise ValueError("oracle manifest requires at least one selected rewrite")
    if int(publication_root_ea) < 0:
        raise ValueError("oracle manifest requires one publication root")
    if not maturities or len(set(maturities)) != len(maturities):
        raise ValueError("oracle manifest maturities must be non-empty and unique")

    routes: list[dict[str, object]] = []
    for rewrite_anchor_ea, owner_ea in sorted(rewrite_owners.items()):
        transaction = _transaction_for_anchor(
            ledger,
            function_ea=function_ea,
            rewrite_anchor_ea=rewrite_anchor_ea,
        )
        corridor_start = _parse_int(
            transaction.get("corridor_start_ea"), field="corridor_start_ea"
        )
        corridor_end = _parse_int(
            transaction.get("corridor_end_ea"), field="corridor_end_ea"
        )
        final_kind, direct_target, true_target, false_target, predicate = (
            _final_transfer(transaction)
        )
        phase = str(transaction.get("phase", ""))
        route_id = f"rhad:{_hex(function_ea)}:{phase}:{_hex(rewrite_anchor_ea)}"
        routes.append(
            {
                "corridor": [[_hex(corridor_start), _hex(corridor_end)]],
                "direct_target_ea": (
                    None if direct_target is None else _hex(direct_target)
                ),
                "false_target_ea": (
                    None if false_target is None else _hex(false_target)
                ),
                "final_transfer_kind": final_kind.value,
                "function_ea": _hex(function_ea),
                "original_transfer_kind": _original_transfer_kind(
                    transaction, rewrite_anchor_ea
                ).value,
                "owner_ea": _hex(owner_ea),
                "predicate_kind": predicate,
                "reference_ledger": transaction,
                "reference_ledger_identity": (f"{phase}:{_hex(rewrite_anchor_ea)}"),
                "reference_phase": phase,
                "rewrite_anchor_ea": _hex(rewrite_anchor_ea),
                "route_id": route_id,
                "true_target_ea": (None if true_target is None else _hex(true_target)),
            }
        )

    return {
        "capture": {
            "function_end_ea": _hex(function_end_ea),
            "maturities": list(maturities),
        },
        "publication_root_ea": _hex(publication_root_ea),
        "routes": routes,
        "run": {
            "cache_disabled": True,
            "candidate_binary_sha256": fixture_sha256,
            "fixture_sha256": fixture_sha256,
            "function_ea": _hex(function_ea),
            "metadata": {
                "reference_ledger_binary_sha256": ledger_sha256,
            },
            "reference_binary_sha256": _sha256(reference_binary_path),
            "reference_commit": reference_commit,
            "run_id": run_id,
            "runtime_image": runtime_image,
            "runtime_image_id": runtime_image_id,
        },
        "schema_version": _MANIFEST_SCHEMA_VERSION,
    }


def run_from_manifest(manifest: dict[str, object]) -> RouteOracleRun:
    return ReferenceRouteOracleCatalog.from_manifest(manifest).run


def routes_from_manifest(
    manifest: dict[str, object],
) -> tuple[ReferenceRouteRewrite, ...]:
    return ReferenceRouteOracleCatalog.from_manifest(manifest).routes


def initialize_oracle_db(manifest: dict[str, object], db_path: Path) -> None:
    if db_path.exists():
        raise FileExistsError(f"refusing to replace existing oracle DB: {db_path}")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    database = create_diag_database(str(db_path))
    try:
        connection = database.connection()
        run = run_from_manifest(manifest)
        record_route_oracle_run(connection, run)
        for route in routes_from_manifest(manifest):
            record_route_reference_rewrite(connection, run.run_id, route)
    finally:
        database.close()


def _clear_sidecars(binary: Path) -> int:
    removed = 0
    for suffix in _SIDECAR_SUFFIXES:
        for stale in (binary.with_suffix(suffix), Path(str(binary) + suffix)):
            if stale.exists():
                stale.unlink()
                removed += 1
    return removed


def capture_lane(
    manifest: dict[str, object],
    *,
    db_path: Path,
    binary: Path,
    lane: RouteCaptureLane,
    candidate_variant: str,
) -> dict[str, int]:
    """Capture one live lane; IDA imports remain inside this adapter boundary."""

    import idapro

    run = run_from_manifest(manifest)
    binary_sha256 = _sha256(binary)
    expected_sha256 = (
        run.reference_binary_sha256
        if lane is RouteCaptureLane.REFERENCE
        else run.candidate_binary_sha256
    )
    if binary_sha256 != expected_sha256:
        raise ValueError(
            f"{lane.value} binary hash mismatch: "
            f"expected={expected_sha256} observed={binary_sha256}"
        )
    capture_config = manifest.get("capture")
    if not isinstance(capture_config, dict):
        raise ValueError("semantic route oracle manifest has no capture object")
    function_end_ea = _parse_int(
        capture_config["function_end_ea"], field="function_end_ea"
    )
    maturities = tuple(str(value) for value in capture_config["maturities"])
    sidecars_removed = _clear_sidecars(binary)
    if idapro.open_database(str(binary), True) != 0:
        raise RuntimeError(f"IDA could not open disposable input {binary}")

    database = None
    try:
        import ida_auto
        import ida_funcs
        import ida_hexrays
        import ida_ua
        import idaapi

        idaapi.auto_wait()
        if not ida_hexrays.init_hexrays_plugin():
            raise RuntimeError("Hex-Rays initialization failed")
        function = ida_funcs.get_func(run.function_ea)
        if function is None:
            ida_auto.plan_and_wait(run.function_ea, function_end_ea)
            ida_ua.create_insn(run.function_ea)
            if not ida_funcs.add_func(run.function_ea, function_end_ea):
                raise RuntimeError(
                    f"IDA could not create function {_hex(run.function_ea)}"
                )
            idaapi.auto_wait()
            function = ida_funcs.get_func(run.function_ea)
        if function is None:
            raise RuntimeError(f"IDA has no function {_hex(run.function_ea)}")
        if int(function.end_ea) != function_end_ea:
            ida_auto.plan_and_wait(run.function_ea, function_end_ea)
            if not ida_funcs.set_func_end(run.function_ea, function_end_ea):
                raise RuntimeError(
                    f"IDA could not set function end {_hex(function_end_ea)}"
                )
            idaapi.auto_wait()
            function = ida_funcs.get_func(run.function_ea)
        if function is None or int(function.end_ea) != function_end_ea:
            raise RuntimeError("IDA function envelope does not match the manifest")

        database = create_diag_database(str(db_path))
        connection = database.connection()
        snapshot_ids: dict[str, int] = {}
        for maturity_name in maturities:
            if not hasattr(ida_hexrays, maturity_name):
                raise ValueError(f"unknown Hex-Rays maturity {maturity_name}")
            maturity = int(getattr(ida_hexrays, maturity_name))
            ranges = ida_hexrays.mba_ranges_t(function)
            failure = ida_hexrays.hexrays_failure_t()
            flags = int(
                ida_hexrays.DECOMP_NO_WAIT
                | ida_hexrays.DECOMP_ALL_BLKS
                | ida_hexrays.DECOMP_NO_CACHE
            )
            mba = ida_hexrays.gen_microcode(
                ranges,
                failure,
                None,
                flags,
                maturity,
            )
            if mba is None or int(failure.code) != 0:
                raise RuntimeError(
                    f"{lane.value} {maturity_name} generation failed: "
                    f"code={int(failure.code)} ea={_hex(int(failure.errea))} "
                    f"description={failure.desc()!r}"
                )
            mba.build_graph()
            from d810.hexrays.mba_serializer import mba_to_block_snapshots

            blocks = mba_to_block_snapshots(mba)
            snapshot_id = snapshot_mba(
                connection,
                blocks,
                label=(
                    f"semantic_route_oracle:{lane.value}:"
                    f"{candidate_variant}:{maturity_name}"
                ),
                func_ea=run.function_ea,
                maturity=maturity_name,
                phase="pre_d810",
                maturity_json={
                    "cache_disabled": True,
                    "d810_enabled": False,
                    "lane": lane.value,
                    "numeric": maturity,
                },
            )
            record_route_oracle_capture(
                connection,
                RouteOracleCapture(
                    run_id=run.run_id,
                    lane=lane,
                    candidate_variant=candidate_variant,
                    maturity=maturity_name,
                    snapshot_id=snapshot_id,
                    binary_sha256=binary_sha256,
                    d810_enabled=False,
                    cache_disabled=True,
                    metadata_json=json.dumps(
                        {
                            "function_end_ea": _hex(function_end_ea),
                            "sidecars_removed": sidecars_removed,
                        },
                        sort_keys=True,
                    ),
                ),
            )
            snapshot_ids[maturity_name] = snapshot_id
        return snapshot_ids
    finally:
        if database is not None:
            database.close()
        idapro.close_database(False)


def compare_oracle_db(
    manifest: dict[str, object],
    *,
    db_path: Path,
    candidate_variant: str,
) -> list[dict[str, object]]:
    run = run_from_manifest(manifest)
    capture_config = manifest["capture"]
    if not isinstance(capture_config, dict):
        raise ValueError("semantic route oracle manifest has no capture object")
    maturities = tuple(str(value) for value in capture_config["maturities"])
    database = create_diag_database(str(db_path))
    summaries: list[dict[str, object]] = []
    try:
        connection = database.connection()
        capture_rows = connection.execute(
            "SELECT lane, candidate_variant, maturity, snapshot_id "
            "FROM semantic_route_oracle_captures WHERE run_id=?",
            (run.run_id,),
        ).fetchall()
        reference_snapshot_ids = {
            str(maturity): int(snapshot_id)
            for lane, variant, maturity, snapshot_id in capture_rows
            if lane == RouteCaptureLane.REFERENCE.value
            and variant == "reference_patched"
        }
        candidate_snapshot_ids = {
            str(maturity): int(snapshot_id)
            for lane, variant, maturity, snapshot_id in capture_rows
            if lane == RouteCaptureLane.CANDIDATE.value and variant == candidate_variant
        }
        if set(reference_snapshot_ids) != set(maturities):
            raise ValueError("reference lane does not contain every manifest maturity")
        if set(candidate_snapshot_ids) != set(maturities):
            raise ValueError("candidate lane does not contain every manifest maturity")

        for route in routes_from_manifest(manifest):
            reference = {
                maturity: observe_route_shape(
                    route,
                    load_snapshot_blocks(connection, reference_snapshot_ids[maturity]),
                    lane=RouteCaptureLane.REFERENCE,
                    maturity=maturity,
                )
                for maturity in maturities
            }
            candidate = {
                maturity: observe_route_shape(
                    route,
                    load_snapshot_blocks(connection, candidate_snapshot_ids[maturity]),
                    lane=RouteCaptureLane.CANDIDATE,
                    maturity=maturity,
                )
                for maturity in maturities
            }
            comparisons = compare_route_maturities(
                route,
                reference,
                candidate,
                maturity_order=maturities,
                candidate_variant=candidate_variant,
            )
            record_route_oracle_comparisons(
                connection,
                run_id=run.run_id,
                reference_snapshot_ids=reference_snapshot_ids,
                candidate_snapshot_ids=candidate_snapshot_ids,
                comparisons=comparisons,
            )
            for comparison in comparisons:
                summaries.append(
                    {
                        "candidate_variant": comparison.candidate_variant,
                        "failed_invariant": comparison.failed_invariant,
                        "first_divergence": comparison.first_divergence,
                        "maturity": comparison.maturity,
                        "outcome": comparison.outcome,
                        "owner_ea": _hex(comparison.owner_ea),
                        "rewrite_anchor_ea": _hex(comparison.rewrite_anchor_ea),
                        "route_id": comparison.route_id,
                    }
                )
        return summaries
    finally:
        database.close()


def _load_json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object required: {path}")
    return payload


def _rewrite_owner(value: str) -> tuple[int, int]:
    anchor, owner = value.split("=", 1)
    return int(anchor, 0), int(owner, 0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build-manifest")
    build.add_argument("--ledger", type=Path, required=True)
    build.add_argument("--run-id", required=True)
    build.add_argument("--function-ea", type=lambda value: int(value, 0), required=True)
    build.add_argument(
        "--function-end-ea", type=lambda value: int(value, 0), required=True
    )
    build.add_argument(
        "--publication-root-ea",
        type=lambda value: int(value, 0),
        required=True,
    )
    build.add_argument("--rewrite-owner", action="append", required=True)
    build.add_argument("--fixture", type=Path, required=True)
    build.add_argument("--reference-binary", type=Path, required=True)
    build.add_argument("--reference-commit", required=True)
    build.add_argument("--runtime-image", required=True)
    build.add_argument("--runtime-image-id", required=True)
    build.add_argument("--maturity", action="append", required=True)
    build.add_argument("--output", type=Path, required=True)

    initialize = subparsers.add_parser("init")
    initialize.add_argument("--manifest", type=Path, required=True)
    initialize.add_argument("--db", type=Path, required=True)

    capture = subparsers.add_parser("capture")
    capture.add_argument("--manifest", type=Path, required=True)
    capture.add_argument("--db", type=Path, required=True)
    capture.add_argument(
        "--lane",
        choices=tuple(lane.value for lane in RouteCaptureLane),
        required=True,
    )
    capture.add_argument("--candidate-variant", required=True)
    capture.add_argument("--binary", type=Path, required=True)

    compare = subparsers.add_parser("compare")
    compare.add_argument("--manifest", type=Path, required=True)
    compare.add_argument("--db", type=Path, required=True)
    compare.add_argument("--candidate-variant", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "build-manifest":
        owners = dict(_rewrite_owner(value) for value in args.rewrite_owner)
        manifest = build_manifest(
            ledger=_load_json(args.ledger),
            run_id=args.run_id,
            function_ea=args.function_ea,
            function_end_ea=args.function_end_ea,
            publication_root_ea=args.publication_root_ea,
            rewrite_owners=owners,
            fixture_path=args.fixture,
            reference_binary_path=args.reference_binary,
            reference_commit=args.reference_commit,
            runtime_image=args.runtime_image,
            runtime_image_id=args.runtime_image_id,
            maturities=tuple(args.maturity),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(args.output, file=sys.stdout)
        return 0
    if args.command == "init":
        initialize_oracle_db(_load_json(args.manifest), args.db)
        print(args.db, file=sys.stdout)
        return 0
    if args.command == "capture":
        result = capture_lane(
            _load_json(args.manifest),
            db_path=args.db,
            binary=args.binary,
            lane=RouteCaptureLane(args.lane),
            candidate_variant=args.candidate_variant,
        )
        print(json.dumps(result, sort_keys=True), file=sys.stdout)
        return 0
    if args.command == "compare":
        result = compare_oracle_db(
            _load_json(args.manifest),
            db_path=args.db,
            candidate_variant=args.candidate_variant,
        )
        print(json.dumps(result, indent=2, sort_keys=True), file=sys.stdout)
        return 0
    raise AssertionError(f"unhandled command {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
