"""MBA optimization rules package.

This package contains:
- Base classes for defining optimization rules (VerifiableRule, SymbolicRule)
- Concrete rule implementations for various operations (XOR, AND, OR, etc.)

All rules are automatically registered when their modules are imported.
The registry is accessible via VerifiableRule.registry.

Usage:
    from d810.mba.rules import VerifiableRule

    # All rules are now registered
    for name, rule_cls in VerifiableRule.registry.items():
        print(f"{name}: {rule_cls}")

Note on hot-reload:
    When d810 is reloaded (Ctrl-Shift-D in IDA), new/modified rules are picked up.
    However, DELETED rules remain in the registry until IDA restarts.
    TODO: Consider adding a registry cleanup mechanism on reload if this becomes an issue.
"""

# Import all rule modules to trigger registration
# Each module defines VerifiableRule subclasses that auto-register
# Use relative imports to avoid circular import issues
from . import (
    _base,
    add,
    and_,
    bnot,
    cst,
    hodur,
    misc,
    mov,
    mul,
    neg,
    or_,
    predicates,
    sub,
    xor,
)

# Re-export base classes from _base module
SymbolicRule = _base.SymbolicRule
VerifiableRule = _base.VerifiableRule
isabstract = _base.isabstract

__all__ = [
    # Base classes
    "SymbolicRule",
    "VerifiableRule",
    "isabstract",
    # Rule modules (for explicit access if needed)
    "add",
    "and_",
    "bnot",
    "cst",
    "hodur",
    "misc",
    "mov",
    "mul",
    "neg",
    "or_",
    "predicates",
    "sub",
    "xor",
]
