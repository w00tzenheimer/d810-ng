#!/usr/bin/env python3
"""Normalize portable MBA provider outcomes into JSON and Markdown reports.

This is intentionally an offline, IDA-free reporting tool.  Input files may
contain normalized report documents, flat outcome rows, or an ``outcomes``
array of flat rows.  Providers that did not run must emit an explicit
``unavailable`` row rather than disappearing from the input.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from d810.mba.differential_report import (
    compare_provider_outcomes,
    normalize_outcome_rows,
    report_from_dict,
    summary_markdown,
)
from d810.mba.provider_outcome import MbaProviderKind


def _load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: cannot load JSON: {exc}") from exc


def _flat_rows(raw: object, path: Path) -> list[Mapping[str, object]]:
    if isinstance(raw, Mapping) and "cases" in raw:
        report = report_from_dict(raw)
        return [
            {
                "case_id": case.case_id,
                "stratum": case.stratum,
                "profile": case.profile,
                "outcome": outcome,
            }
            for case in report.cases
            for outcome in case.outcomes
        ]
    if isinstance(raw, Mapping):
        raw = raw.get("outcomes")
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected report object, row array, or outcomes array")
    if not all(isinstance(row, Mapping) for row in raw):
        raise ValueError(f"{path}: outcome rows must be objects")
    return list(raw)


def _manifest_cases(path: Path | None) -> tuple[str, ...]:
    if path is None:
        return ()
    raw = _load_json(path)
    cases = raw.get("cases", raw) if isinstance(raw, Mapping) else raw
    if not isinstance(cases, list):
        raise ValueError(f"{path}: manifest cases must be an array")
    case_ids: list[str] = []
    for entry in cases:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("case_id"), str):
            raise ValueError(f"{path}: every manifest case needs a string case_id")
        case_ids.append(entry["case_id"])
    if len(set(case_ids)) != len(case_ids):
        raise ValueError(f"{path}: duplicate manifest case_id")
    return tuple(case_ids)


def _manifest_provider_matrix(path: Path | None) -> tuple[MbaProviderKind, ...]:
    """Return the manifest's declared coverage matrix, if it has one."""

    if path is None:
        return ()
    raw = _load_json(path)
    if not isinstance(raw, Mapping):
        return ()
    values = raw.get("provider_matrix")
    if values is None:
        return ()
    if not isinstance(values, list) or not all(type(value) is str for value in values):
        raise ValueError(f"{path}: provider_matrix must be an array of provider names")
    try:
        providers = tuple(MbaProviderKind(value) for value in values)
    except ValueError as exc:
        raise ValueError(f"{path}: invalid provider_matrix value: {exc}") from exc
    if len(set(providers)) != len(providers):
        raise ValueError(f"{path}: duplicate provider_matrix entry")
    return providers


def _merge_capture_metadata(documents: Sequence[object]) -> Mapping[str, object]:
    """Merge disjoint capture and measurement sidecars without overwriting facts."""

    def merge(left: object, right: object, path: str) -> object:
        if left == right:
            return left
        if path.startswith("capture_metadata.lifecycle_measurements."):
            values = (
                *(left if isinstance(left, list) else (left,)),
                *(right if isinstance(right, list) else (right,)),
            )
            if all(type(value) in (int, float) for value in values):
                return list(values)
        if isinstance(left, Mapping) and isinstance(right, Mapping):
            merged = dict(left)
            for key, value in right.items():
                if type(key) is not str:
                    raise ValueError(f"capture_metadata has a non-string key at {path}")
                merged[key] = (
                    value
                    if key not in merged
                    else merge(merged[key], value, f"{path}.{key}")
                )
            return merged
        if isinstance(left, list) and isinstance(right, list):
            return [*left, *right]
        raise ValueError(f"conflicting capture_metadata at {path}")

    merged: object = {}
    for document in documents:
        value = (
            document.get("capture_metadata", {})
            if isinstance(document, Mapping)
            else document
        )
        if not isinstance(value, Mapping):
            raise ValueError("capture_metadata must be an object")
        merged = merge(merged, value, "capture_metadata")
    return merged  # type: ignore[return-value]


def _merge_toolchain_identity(documents: Sequence[object]) -> dict[str, str]:
    """Preserve producer toolchain facts while adding reporter provenance."""

    identity: dict[str, str] = {}
    for document in documents:
        if not isinstance(document, Mapping) or "toolchain_identity" not in document:
            continue
        value = document["toolchain_identity"]
        if not isinstance(value, Mapping):
            raise ValueError("toolchain_identity must be an object")
        for key, item in value.items():
            if type(key) is not str or type(item) is not str:
                raise ValueError("toolchain_identity must map strings to strings")
            previous = identity.get(key)
            if previous is not None and previous != item:
                raise ValueError(f"conflicting toolchain_identity at {key}")
            identity[key] = item
    identity.setdefault("reporter", "mba_differential_report")
    return identity


def build_report(
    paths: Sequence[Path],
    *,
    manifest: Path | None = None,
    corpus_identity: str | None = None,
    expected_providers: Sequence[MbaProviderKind] = (),
    rollout_evidence: Sequence[Path] = (),
) -> tuple[dict[str, object], str]:
    """Load rows, enforce provider/case completeness, and render both outputs."""

    documents = tuple((path, _load_json(path)) for path in paths)
    rows = [row for path, raw in documents for row in _flat_rows(raw, path)]
    if not rows:
        raise ValueError("at least one outcome row is required")
    observed_providers = tuple(
        sorted(
            {
                MbaProviderKind(
                    str(
                        row["outcome"].provider
                        if hasattr(row.get("outcome"), "provider")
                        else row["outcome"]["provider"]
                    )
                )
                for row in rows
            },
            key=lambda provider: provider.value,
        )
    )
    providers = (
        tuple(expected_providers)
        or _manifest_provider_matrix(manifest)
        or observed_providers
    )
    capture_metadata_documents = tuple(
        raw
        for _path, raw in documents
        if isinstance(raw, Mapping) and "capture_metadata" in raw
    )
    evidence_documents = tuple(_load_json(path) for path in rollout_evidence)
    capture_metadata = _merge_capture_metadata(
        (*capture_metadata_documents, *evidence_documents)
    )
    report = normalize_outcome_rows(
        rows,
        corpus_identity=corpus_identity or (manifest.stem if manifest else "ad-hoc"),
        toolchain_identity=_merge_toolchain_identity(
            tuple(raw for _path, raw in documents)
        ),
        expected_providers=providers,
        capture_metadata=capture_metadata,
    )
    manifest_case_ids = _manifest_cases(manifest)
    if manifest_case_ids:
        actual_case_ids = tuple(case.case_id for case in report.cases)
        missing = tuple(case_id for case_id in manifest_case_ids if case_id not in actual_case_ids)
        unexpected = tuple(case_id for case_id in actual_case_ids if case_id not in manifest_case_ids)
        # Keep the corpus-wide completeness assertion derived from the
        # manifest itself.  ``normalize_outcome_rows`` already rejects
        # duplicate case/provider rows; this check makes a dropped or extra
        # case impossible to mistake for a complete report.
        if (
            len(report.cases) != len(manifest_case_ids)
            or missing
            or unexpected
        ):
            details = []
            if len(report.cases) != len(manifest_case_ids):
                details.append(
                    "manifest case count: "
                    f"expected {len(manifest_case_ids)}, observed {len(report.cases)}"
                )
            if missing:
                details.append("missing manifest cases: " + ", ".join(missing))
            if unexpected:
                details.append("unexpected cases: " + ", ".join(unexpected))
            raise ValueError("; ".join(details))
    summary = compare_provider_outcomes(report)
    payload = report.to_dict() | {"summary": summary.to_dict()}
    return payload, summary_markdown(summary)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--corpus-identity")
    parser.add_argument(
        "--rollout-evidence",
        action="append",
        type=Path,
        default=[],
        help="JSON capture_metadata sidecar from a real native measurement run",
    )
    parser.add_argument(
        "--providers",
        help="comma-separated enabled provider names; makes omitted rows an error",
    )
    parser.add_argument("outcomes", metavar="OUTCOME_JSON", type=Path, nargs="+")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        payload, markdown = build_report(
            args.outcomes,
            manifest=args.manifest,
            corpus_identity=args.corpus_identity,
            expected_providers=(
                ()
                if not args.providers
                else tuple(
                    MbaProviderKind(value)
                    for value in args.providers.split(",")
                    if value
                )
            ),
            rollout_evidence=tuple(args.rollout_evidence),
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(payload, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        markdown_path = args.markdown or args.out.with_suffix(".md")
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(markdown, encoding="utf-8")
        return 0
    except ValueError as exc:
        print(f"mba_differential_report: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
