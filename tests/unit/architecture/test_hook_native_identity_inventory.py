"""No Hex-Rays hook may name a live native object by its Python ``id``.

``id(obj)`` names the SWIG wrapper, not the C++ object: ``mblock_t.mba`` mints
a fresh proxy per access, and a dead proxy's address is reused. Every hook key
built from one -- a safe-point claim, a flow-context cache -- therefore either
splits one live object across two keys or fuses two objects into one.
``d810.hexrays.ir.native_identity`` is the single answer; this ratchet keeps a
second, address-based scheme from growing back.
"""

from __future__ import annotations

import ast
from pathlib import Path

_HOOKS_DIR = Path(__file__).resolve().parents[3] / "src" / "d810" / "hexrays" / "hooks"
_NATIVE_NAMES = frozenset({"mba", "blk", "block", "insn", "ins", "mop"})


def _identity_call_sites(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    sites: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "id":
            continue
        if len(node.args) != 1:
            continue
        argument = node.args[0]
        if isinstance(argument, ast.Name):
            name = argument.id
        elif isinstance(argument, ast.Attribute):
            name = argument.attr
        else:
            continue
        if name in _NATIVE_NAMES:
            sites.append(f"{path.name}:{node.lineno}: id({name})")
    return sites


def test_hooks_never_key_a_live_native_object_on_its_python_id() -> None:
    violations: list[str] = []
    for path in sorted(_HOOKS_DIR.rglob("*.py")):
        violations.extend(_identity_call_sites(path))

    assert (
        not violations
    ), "hook code must use d810.hexrays.ir.native_identity, not id():\n" + "\n".join(
        violations
    )
