#!/usr/bin/env python3
"""Validate the committed MBA research provenance audit."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple


MANIFEST_PATH = (
    Path(__file__).resolve().parents[2]
    / "tests/fixtures/mba_portfolio/research_sources.json"
)
REQUIRED_FIELDS = frozenset(
    {"name", "url", "reviewed_commit", "license", "copy_allowed", "retained_ideas"}
)
COPY_COMPATIBLE_LICENSES = frozenset({"Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSL-1.0", "MIT"})


class ResearchSource(NamedTuple):
    name: str
    url: str
    reviewed_commit: str
    license: str | None
    copy_allowed: bool
    retained_ideas: tuple[str, ...]


def _type_name(value: object) -> str:
    return type(value).__name__


def load_research_sources(path: Path) -> tuple[ResearchSource, ...]:
    """Load and strictly decode a research provenance JSON file."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: cannot load research sources: {exc}") from exc
    if not isinstance(raw, list):
        raise ValueError(f"manifest: expected an array, got {_type_name(raw)}")

    sources: list[ResearchSource] = []
    for index, entry in enumerate(raw):
        label = f"source[{index}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{label}: expected an object, got {_type_name(entry)}")
        fields = set(entry)
        missing = sorted(REQUIRED_FIELDS - fields)
        unknown = sorted(fields - REQUIRED_FIELDS)
        if missing or unknown:
            details = []
            if missing:
                details.append(f"missing: {', '.join(missing)}")
            if unknown:
                details.append(f"unknown: {', '.join(unknown)}")
            raise ValueError(f"{label}: invalid fields ({'; '.join(details)})")

        for field in ("name", "url", "reviewed_commit"):
            if not isinstance(entry[field], str) or not entry[field]:
                raise ValueError(f"{label}.{field}: expected a non-empty string")
        license_name = entry["license"]
        if license_name is not None and (
            not isinstance(license_name, str) or not license_name
        ):
            raise ValueError(f"{label}.license: expected null or a non-empty string")
        if not isinstance(entry["copy_allowed"], bool):
            raise ValueError(f"{label}.copy_allowed: expected a boolean")
        ideas = entry["retained_ideas"]
        if not isinstance(ideas, list) or not ideas or not all(
            isinstance(idea, str) and idea for idea in ideas
        ):
            raise ValueError(
                f"{label}.retained_ideas: expected a non-empty array of non-empty strings"
            )

        sources.append(
            ResearchSource(
                name=entry["name"],
                url=entry["url"],
                reviewed_commit=entry["reviewed_commit"],
                license=license_name,
                copy_allowed=entry["copy_allowed"],
                retained_ideas=tuple(ideas),
            )
        )
    return tuple(sources)


def validate_research_sources(sources: Iterable[ResearchSource]) -> tuple[str, ...]:
    """Return deterministic policy errors for decoded research sources."""

    errors: list[str] = []
    seen_names: set[str] = set()
    seen_urls: set[str] = set()
    for source in sources:
        if source.name in seen_names:
            errors.append(f"{source.name}: duplicate source name")
        seen_names.add(source.name)
        if source.url in seen_urls:
            errors.append(f"{source.name}: duplicate repository URL {source.url!r}")
        seen_urls.add(source.url)
        if source.copy_allowed and source.license not in COPY_COMPATIBLE_LICENSES:
            errors.append(
                f"{source.name}: copy_allowed=true requires a D810-compatible license; "
                f"observed {source.license!r}"
            )
    return tuple(sorted(errors))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", type=Path, default=MANIFEST_PATH)
    args = parser.parse_args(argv)
    try:
        errors = validate_research_sources(load_research_sources(args.path))
    except ValueError as exc:
        print(exc)
        return 1
    if errors:
        for error in errors:
            print(error)
        return 1
    print(f"MBA research provenance OK: {args.path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
