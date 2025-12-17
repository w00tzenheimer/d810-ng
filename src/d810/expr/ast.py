"""AST module dispatcher - uses Cython speedups if available, otherwise pure Python."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from d810.core.cymode import CythonMode

if TYPE_CHECKING:
    import ida_hexrays


# =============================================================================
# Protocols for hot-reload-safe isinstance() checks
# =============================================================================


@runtime_checkable
class AstNodeProtocol(Protocol):
    """Protocol for structural typing of AstNode - survives hot reloads.

    Attributes accessed after isinstance() checks:
    - opcode: The operation opcode
    - left: Left child
    - right: Right child
    """

    opcode: int | None
    left: "AstBaseProtocol | None"
    right: "AstBaseProtocol | None"

    def is_node(self) -> bool:
        """Returns True for AstNode."""
        ...


@runtime_checkable
class AstLeafProtocol(Protocol):
    """Protocol for structural typing of AstLeaf - survives hot reloads.

    Attributes accessed after isinstance() checks:
    - name: Variable name
    - mop: Associated mop_t
    - ast_index: Unique index for this AST node
    """

    name: str
    mop: "ida_hexrays.mop_t | None"
    ast_index: int | None

    def is_leaf(self) -> bool:
        """Returns True for leaf nodes."""
        ...

    def is_constant(self) -> bool:
        """Returns True if this is a constant value."""
        ...


@runtime_checkable
class AstConstantProtocol(Protocol):
    """Protocol for structural typing of AstConstant - survives hot reloads.

    Attributes accessed after isinstance() checks:
    - name: Constant name
    - value: The constant value (may be None for capturing constants)
    - expected_value: Expected value for pattern matching
    - mop: Associated mop_t
    """

    name: str
    value: int | None
    expected_value: int | None
    mop: "ida_hexrays.mop_t | None"

    def is_constant(self) -> bool:
        """Returns True - AstConstant is always constant."""
        ...


@runtime_checkable
class AstBaseProtocol(Protocol):
    """Protocol for structural typing of AstBase - survives hot reloads.

    Common interface for all AST nodes.
    """

    mop: "ida_hexrays.mop_t | None"
    ast_index: int | None

    def is_node(self) -> bool:
        """Returns True for AstNode, False otherwise."""
        ...

    def is_leaf(self) -> bool:
        """Returns True for leaf nodes (AstLeaf, AstConstant)."""
        ...

    def is_constant(self) -> bool:
        """Returns True if this is a constant value."""
        ...

# Try to import Cython-optimized version first, respecting CythonMode
if CythonMode().is_enabled():
    try:
        from d810.speedups.expr.c_ast import (
            AstBase,
            AstConstant,
            AstLeaf,
            AstNode,
            AstProxy,
            get_constant_mop,
            minsn_to_ast,
            mop_to_ast,
        )

        _USING_CYTHON = True
    except (ModuleNotFoundError, ImportError):
        # Fall back to pure Python implementation
        from d810.expr.p_ast import (
            AstBase,
            AstConstant,
            AstLeaf,
            AstNode,
            AstProxy,
            get_constant_mop,
            minsn_to_ast,
            mop_to_ast,
        )

        _USING_CYTHON = False
else:
    # CythonMode disabled, use pure Python
    from d810.expr.p_ast import (
        AstBase,
        AstConstant,
        AstLeaf,
        AstNode,
        AstProxy,
        get_constant_mop,
        minsn_to_ast,
        mop_to_ast,
    )

    _USING_CYTHON = False

__all__ = [
    # Classes
    "AstBase",
    "AstConstant",
    "AstLeaf",
    "AstNode",
    "AstProxy",
    # Protocols for hot-reload-safe isinstance() checks
    "AstBaseProtocol",
    "AstConstantProtocol",
    "AstLeafProtocol",
    "AstNodeProtocol",
    # Functions
    "get_constant_mop",
    "minsn_to_ast",
    "mop_to_ast",
]
