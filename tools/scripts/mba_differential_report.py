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


def build_report(
    paths: Sequence[Path],
    *,
    manifest: Path | None = None,
    corpus_identity: str | None = None,
    expected_providers: Sequence[MbaProviderKind] = (),
) -> tuple[dict[str, object], str]:
    """Load rows, enforce provider/case completeness, and render both outputs."""

    rows = [row for path in paths for row in _flat_rows(_load_json(path), path)]
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
    providers = tuple(expected_providers) or observed_providers
    report = normalize_outcome_rows(
        rows,
        corpus_identity=corpus_identity or (manifest.stem if manifest else "ad-hoc"),
        toolchain_identity={"reporter": "mba_differential_report"},
        expected_providers=providers,
    )
    manifest_case_ids = _manifest_cases(manifest)
    if manifest_case_ids:
        actual_case_ids = tuple(case.case_id for case in report.cases)
        missing = tuple(case_id for case_id in manifest_case_ids if case_id not in actual_case_ids)
        unexpected = tuple(case_id for case_id in actual_case_ids if case_id not in manifest_case_ids)
        if missing or unexpected:
            details = []
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
