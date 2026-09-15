#!/usr/bin/env python3
"""Regenerate exact-byte identities after relinking libobfuscated.dll."""

from __future__ import annotations

import argparse
from pathlib import Path

from d810.testing.hash_bound_build_receipt import write_hash_bound_build_receipt


REPO_ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=REPO_ROOT / "samples/src/masm/hash_bound_seven_manifest.json",
    )
    parser.add_argument(
        "--image",
        type=Path,
        default=REPO_ROOT / "samples/bins/libobfuscated.dll",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "samples/src/masm/hash_bound_seven_build_receipt.json",
    )
    args = parser.parse_args()
    write_hash_bound_build_receipt(
        manifest_path=args.manifest,
        linked_image_path=args.image,
        receipt_path=args.output,
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
