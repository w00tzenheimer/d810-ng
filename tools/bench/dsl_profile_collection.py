"""Pytest collection plugin for the per-test DSL profiling harness.

The plugin deliberately has no fixtures or runtest hooks.  It only serializes
the exact parametrized ``case`` objects that pytest collected.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


COLLECTION_OUT_ENV = "D810_DSL_PROFILE_COLLECTION_OUT"


def collection_manifest(items) -> dict:
    nodes = []
    seen = set()
    for item in items:
        nodeid = getattr(item, "nodeid", None)
        if type(nodeid) is not str or not nodeid:
            raise ValueError(
                "unknown DSL project mapping: collected item has no nodeid"
            )
        if nodeid in seen:
            raise ValueError(f"duplicate collected nodeid: {nodeid}")
        seen.add(nodeid)
        callspec = getattr(item, "callspec", None)
        params = getattr(callspec, "params", None)
        case = params.get("case") if isinstance(params, dict) else None
        project = getattr(case, "project", None)
        if type(project) is not str or not project:
            raise ValueError(f"unknown DSL project mapping for {nodeid}")
        nodes.append({"nodeid": nodeid, "project": project})
    return {"schema_version": 1, "nodes": nodes}


def pytest_collection_finish(session) -> None:
    output = os.environ.get(COLLECTION_OUT_ENV)
    if not output:
        raise ValueError(f"{COLLECTION_OUT_ENV} is required")
    document = collection_manifest(session.items)
    Path(output).write_text(
        json.dumps(
            document, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True
        )
        + "\n",
        encoding="utf-8",
    )
