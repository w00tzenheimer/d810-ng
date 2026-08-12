#!/usr/bin/env python3
"""Keep ``ida-plugin.json`` in sync with ``d810.__version__``.

The single source of truth for the version is ``__version__`` in
``src/d810/__init__.py`` -- ``pyproject.toml`` already derives the package
version from it. IDA's plugin manager and the IDA Plugin Repository read the
version out of ``ida-plugin.json``, so the two must agree. They had already
drifted (manifest 0.6.6 vs package 1.0.0b1) before this script existed.

``__version__`` is read by parsing the source with :mod:`ast` rather than by
importing the module, because importing ``d810`` pulls in ``idaapi``, which
only exists inside IDA. The manifest is parsed and written as JSON so unrelated
fields survive untouched.

Usage:
    python tools/sync_plugin_version.py            # write the manifest in place
    python tools/sync_plugin_version.py --check    # exit 1 if out of sync, no write

The pre-commit hook runs the ``--check`` form; ``tests/unit/test_sync_plugin_version.py``
is the backstop. Adapted from ``~/src/idapro/ida-sigmaker/tools/sync_plugin_version.py``
(that project also pins a ``pythonDependencies`` entry; d810's manifest has no
such field, so that half is dropped).
"""

import argparse
import ast
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
INIT = ROOT / "src" / "d810" / "__init__.py"
MANIFEST = ROOT / "ida-plugin.json"


def package_version() -> str:
    """Return ``__version__`` from the package source without importing it."""
    tree = ast.parse(INIT.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise SystemExit(f"could not find __version__ in {INIT}")


def manifest_version(text: str) -> str:
    return json.loads(text)["plugin"]["version"]


def sync_manifest(text: str, version: str) -> str:
    """Return the manifest JSON with the plugin version updated."""
    manifest = json.loads(text)
    manifest["plugin"]["version"] = version
    return json.dumps(manifest, indent=4) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the manifest matches the package version; do not write",
    )
    args = parser.parse_args(argv)

    version = package_version()
    text = MANIFEST.read_text(encoding="utf-8")
    current = manifest_version(text)

    if current == version:
        return 0

    if args.check:
        print(
            f"ida-plugin.json is out of sync: version={current!r}, expected "
            f"{version!r}; run: python tools/sync_plugin_version.py",
            file=sys.stderr,
        )
        return 1

    MANIFEST.write_text(sync_manifest(text, version), encoding="utf-8")
    print(f"synced ida-plugin.json from version {current} to {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
