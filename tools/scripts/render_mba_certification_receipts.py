#!/usr/bin/env python3
"""Render checked-in receipts for the fully Z3-certified MBA catalogue."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from d810.mba.certified_rule_compiler import (
    CERTIFICATE_WIDTHS,
    MbaRuleCatalogue,
    _rule_fingerprint,
    compile_mba_rule_catalogue,
)
from d810.mba.rules.catalogue import MBA_RULE_FAMILIES


SCHEMA_VERSION = 1


def _fingerprint(rule_type: type[Any]) -> str:
    payload = json.dumps(
        _rule_fingerprint(rule_type()),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def build_receipt_manifest(catalogue: MbaRuleCatalogue) -> dict[str, object]:
    """Return deterministic receipts bound to current rule declarations."""

    rule_types = {
        (family, rule_type.__name__): rule_type
        for family, family_rules in MBA_RULE_FAMILIES.items()
        for rule_type in family_rules
    }
    receipts = []
    for receipt in catalogue.receipts:
        admitted = receipt.compiled_rule is not None
        receipts.append(
            {
                "canonical_name": receipt.canonical_name,
                "family": receipt.family,
                "reason": receipt.reason,
                "semantic_fingerprint": (
                    _fingerprint(rule_types[receipt.key]) if admitted else None
                ),
                "source_name": receipt.source_name,
                "status": receipt.status.value,
            }
        )
    return {
        "certificate_widths": list(CERTIFICATE_WIDTHS),
        "receipts": receipts,
        "schema_version": SCHEMA_VERSION,
    }


def render_receipt_manifest() -> str:
    return json.dumps(
        build_receipt_manifest(compile_mba_rule_catalogue()),
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered = render_receipt_manifest()
    if args.output is None:
        print(rendered, end="")
    else:
        args.output.write_text(rendered, encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
