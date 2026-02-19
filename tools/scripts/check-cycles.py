#!/usr/bin/env python3
"""Detect circular imports in d810 using the existing DependencyGraph infrastructure."""
import sys
import pathlib

# locate repo root relative to this script
_HERE = pathlib.Path(__file__).resolve()
_REPO = _HERE.parent.parent.parent
sys.path.insert(0, str(_REPO / "src"))

from d810._vendor.ida_reloader.ida_reloader import DependencyGraph  # noqa: E402

PKG_ROOT = _REPO / "src" / "d810"
PKG_PREFIX = "d810"

dg = DependencyGraph(PKG_PREFIX + ".", pkg_paths=[str(PKG_ROOT)])

for py_file in sorted(PKG_ROOT.rglob("*.py")):
    # skip vendor to avoid false positives from third-party code
    if "_vendor" in py_file.parts:
        continue
    rel = py_file.relative_to(_REPO / "src")
    module = str(rel.with_suffix("")).replace("/", ".")
    # __init__.py maps to the package name, matching sys.modules / ida_reloader behaviour
    if module.endswith(".__init__"):
        module = module[: -len(".__init__")]
    dg.update_dependencies(py_file, module)

cycles = dg.get_cycles()
if cycles:
    print(f"ERROR: {len(cycles)} circular import group(s) detected:")
    for c in sorted(cycles, key=lambda s: sorted(s)[0]):
        print(f"  CYCLE: {', '.join(sorted(c))}")
    sys.exit(1)

print(f"OK: no import cycles detected ({len(dg.get_all_tracked_modules())} modules scanned).")
