#!/usr/bin/env python3
"""List searchable algorithm metadata for d810 algorithm families.

Examples:
    python3 tools/scripts/list_algorithm_metadata.py
    python3 tools/scripts/list_algorithm_metadata.py --family structured_semantic_region_lowering
    python3 tools/scripts/list_algorithm_metadata.py --search hammock
    python3 tools/scripts/list_algorithm_metadata.py --json
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import asdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from d810.core.algorithm_metadata import AlgorithmMetadata, find_algorithm_metadata

SOURCE_FILES = (
    "src/d810/cfg/modification_builder.py",
    "src/d810/cfg/plan.py",
    "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/conditional_fork_fallback.py",
    "src/d810/recon/flow/conditional_chain_resolution.py",
    "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/inner_merge_duplication.py",
    "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/edge_split_conflict.py",
    "src/d810/cfg/linearized_flow_graph_fragment_planning.py",
    "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/reconstruction.py",
    "src/d810/cfg/flow/compare_chain.py",
    "src/d810/recon/flow/condition_chain_analysis.py",
    "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/semantic_exact_node.py",
    "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/exact_conditional_node.py",
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", help="Filter by algorithm family")
    parser.add_argument("--tag", help="Filter by tag")
    parser.add_argument("--search", help="Free-text search")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    return parser


def _literal(node: ast.AST):
    return ast.literal_eval(node)


def _load_source_metadata() -> tuple[AlgorithmMetadata, ...]:
    matches: list[AlgorithmMetadata] = []
    for relative_path in SOURCE_FILES:
        path = REPO_ROOT / relative_path
        module_name = ".".join(Path(relative_path).with_suffix("").parts)
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in tree.body:
            if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                if not isinstance(decorator.func, ast.Name) or decorator.func.id != "algorithm_metadata":
                    continue
                kwargs = {
                    keyword.arg: _literal(keyword.value)
                    for keyword in decorator.keywords
                    if keyword.arg is not None
                }
                matches.append(
                    AlgorithmMetadata(
                        algorithm_id=str(kwargs["algorithm_id"]),
                        family=str(kwargs["family"]),
                        summary=str(kwargs["summary"]),
                        use_cases=tuple(str(item) for item in kwargs.get("use_cases", ())),
                        examples=tuple(str(item) for item in kwargs.get("examples", ())),
                        tags=tuple(str(item) for item in kwargs.get("tags", ())),
                        related_paths=tuple(str(item) for item in kwargs.get("related_paths", ())),
                        module=module_name,
                        object_qualname=f"{module_name}.{node.name}",
                    )
                )
    return tuple(matches)


def _filter_matches(
    matches: tuple[AlgorithmMetadata, ...],
    *,
    family: str | None,
    tag: str | None,
    search: str | None,
) -> tuple[AlgorithmMetadata, ...]:
    family_filter = family.casefold() if family else None
    tag_filter = tag.casefold() if tag else None
    search_filter = search.casefold() if search else None
    filtered: list[AlgorithmMetadata] = []
    for metadata in matches:
        if family_filter is not None and metadata.family.casefold() != family_filter:
            continue
        if tag_filter is not None and tag_filter not in {
            item.casefold() for item in metadata.tags
        }:
            continue
        if search_filter is not None:
            haystack = "\n".join(
                (
                    metadata.algorithm_id,
                    metadata.family,
                    metadata.summary,
                    *metadata.use_cases,
                    *metadata.examples,
                    *metadata.tags,
                    *metadata.related_paths,
                    metadata.object_qualname or "",
                )
            ).casefold()
            if search_filter not in haystack:
                continue
        filtered.append(metadata)
    return tuple(filtered)


def main() -> int:
    args = _build_parser().parse_args()
    matches = find_algorithm_metadata(
        family=args.family,
        tag=args.tag,
        search=args.search,
    )
    if not matches:
        matches = _filter_matches(
            _load_source_metadata(),
            family=args.family,
            tag=args.tag,
            search=args.search,
        )

    if args.json:
        print(json.dumps({"matches": [asdict(metadata) for metadata in matches]}, indent=2, sort_keys=True))
        return 0

    for metadata in matches:
        print(f"{metadata.algorithm_id} [{metadata.family}]")
        print(f"  summary: {metadata.summary}")
        if metadata.use_cases:
            print("  use_cases:")
            for item in metadata.use_cases:
                print(f"    - {item}")
        if metadata.examples:
            print("  examples:")
            for item in metadata.examples:
                print(f"    - {item}")
        if metadata.tags:
            print(f"  tags: {', '.join(metadata.tags)}")
        if metadata.related_paths:
            print("  paths:")
            for item in metadata.related_paths:
                print(f"    - {item}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
