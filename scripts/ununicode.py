#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import sys
import unicodedata
from pathlib import Path


def clean_text(txt: str) -> str:
    # First, handle special characters
    replacements = {
        "–": "-",  # en-dash → hyphen
        "‐": "-",  # unicode hyphen → hyphen
        "‑": "-",  # unicode hyphen → hyphen
        "\u00a0": " ",  # non-breaking space → regular space
        "\u200b": "",  # zero-width space → removed
        "\u200c": "",  # zero-width non-joiner → removed
        "\u200d": "",  # zero-width joiner → removed
        "\u202f": " ",  # narrow no-break space → regular space
        "\u2060": "",  # word joiner → removed
        "\ufeff": "",  # zero-width no-break space (BOM) → removed
        "\u2192": "->",  # right arrow → ->
        "—": "-",  # em-dash → hyphen
        "’": "'",  # right single quote → straight
        "‘": "'",  # left single quote → straight
        "“": '"',  # left double quote → straight
        "”": '"',  # right double quote → straight
        "【": "[",  # left square bracket → [
        "】": "]",  # right square bracket → ]
        "†": "+",  # dagger → *
        "‡": "*",  # double dagger → *
        "§": "*",  # section sign → *
        "¶": "*",  # paragraph sign → *
        "™": "*",  # trademark symbol → *
        "©": "*",  # copyright symbol → *
        "®": "*",  # registered trademark symbol → *
        "`": "`",  # backtick → `,
        "•": "*",
        "◦": "*",
    }
    for uni, ascii_ in replacements.items():
        txt = txt.replace(uni, ascii_)
    normalized = unicodedata.normalize("NFKD", txt)
    result = []
    for char in normalized:
        # Try to get ASCII equivalent through decomposition
        if ord(char) < 128:
            result.append(char)
        elif unicodedata.category(char).startswith(
            "M"
        ):  # Mark category (combining marks)
            # Skip combining marks (they're removed in NFKD normalization)
            continue
        else:
            # Default to "*" for non-ASCII
            result.append("*")
    return "".join(result)


def main():
    parser = argparse.ArgumentParser(
        description="Clean weird Unicode characters in Python source (stdin→stdout by default)."
    )
    parser.add_argument(
        "-i",
        "--in-place",
        action="store_true",
        help="Edit files in-place instead of writing to stdout",
    )
    parser.add_argument(
        "input_file", nargs="?", help="Path to input .py file (reads stdin if omitted)"
    )
    parser.add_argument(
        "output_file",
        nargs="?",
        help="Path to output file (ignored if --in-place; writes stdout if omitted)",
    )

    args = parser.parse_args()

    # in-place requires an input_file
    if args.in_place and not args.input_file:
        parser.error("--in-place requires an input_file")

    try:
        # read
        if args.input_file:
            try:
                content = Path(args.input_file).read_text(encoding="utf-8")
            except FileNotFoundError:
                parser.error(f"File '{args.input_file}' not found")
        else:
            if sys.stdin.isatty():
                parser.error("No input_file and nothing piped in")
            content = sys.stdin.read()

        cleaned = clean_text(content)

        # write
        if args.in_place:
            Path(args.input_file).write_text(cleaned, encoding="utf-8")
        elif args.output_file:
            Path(args.output_file).write_text(cleaned, encoding="utf-8")
        else:
            sys.stdout.write(cleaned)

    except Exception as e:
        parser.error(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()
if __name__ == "__main__":
    main()
if __name__ == "__main__":
    main()
