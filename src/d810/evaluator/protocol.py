"""Evaluator protocol definitions.

Defines the :class:`EvaluatorProtocol` and :class:`HelperProtocol` typing
protocols that all evaluator implementations must satisfy.  These protocols
are the sole contracts shared across the concrete, symbolic, and Cython
evaluation paths; no IDA types are imported here.
"""

from __future__ import annotations

from d810.core.typing import Protocol, runtime_checkable


@runtime_checkable
class EvaluatorProtocol(Protocol):
    """Evaluates a concrete microcode AST to an integer.

    Conforming classes accept an AST node and a mapping from leaf
    ``ast_index`` identifiers to concrete integer values, and return a
    single concrete integer result masked to the destination bit-width.

    Examples:
        >>> class MyEval:
        ...     def evaluate(self, node, env: dict) -> int:
        ...         return 0
        >>> isinstance(MyEval(), EvaluatorProtocol)
        True
    """

    def evaluate(self, node: object, env: dict[int, int]) -> int:
        """Return the concrete integer value of *node*.

        Args:
            node: Root of the AST to evaluate.  In practice an
                ``AstBase`` instance, but typed as ``object`` here to
                avoid a mandatory IDA import at protocol-definition time.
            env: Mapping from ``ast_index`` to concrete integer value for
                each variable leaf.  Constant leaves do not need an entry.

        Returns:
            Concrete integer result, masked to ``node.dest_size`` bits.

        Raises:
            AstEvaluationException: If the AST contains an unsupported
                opcode or a required binding is missing.
        """
        ...


class HelperCallable(Protocol):
    """Minimal protocol for any callable usable as an evaluation helper.

    Plain functions or lambdas satisfy this protocol; they do **not** need
    to carry ``name`` or ``bit_width`` attributes.  When registering such a
    callable with :class:`~d810.evaluator.helpers.HelperRegistry`, the
    caller must supply the *name* argument explicitly.

    Examples:
        >>> def my_fn(value: int, count: int) -> int:
        ...     return value >> count
        >>> callable(my_fn)
        True
    """

    def __call__(self, value: int, count: int) -> int:
        """Evaluate the helper.

        Args:
            value: The integer operand.
            count: The rotation or shift amount (in bits).

        Returns:
            The integer result.
        """
        ...


class HelperProtocol(HelperCallable, Protocol):
    """A callable that evaluates a named rotate/arithmetic helper.

    Extends :class:`HelperCallable` with mandatory ``name`` and
    ``bit_width`` metadata attributes.  Conforming objects wrap functions
    such as ``__ROL4__`` or ``__ROR8__`` from :mod:`d810.core.bits` and
    expose their bit-width metadata so the evaluator can dispatch them by
    name.

    All :class:`HelperProtocol` instances also satisfy
    :class:`HelperCallable`; use :class:`HelperCallable` as the looser
    type when metadata is not required.

    Examples:
        >>> class MyHelper:
        ...     name = "__ROL4__"
        ...     bit_width = 32
        ...     def __call__(self, value: int, count: int) -> int:
        ...         return value
        >>> h = MyHelper()
        >>> h(0xDEAD, 0)
        57005
    """

    name: str
    bit_width: int

    def __call__(self, value: int, count: int) -> int:
        """Evaluate the helper on *value* rotated/shifted by *count*.

        Args:
            value: The integer operand to rotate or shift.
            count: The rotation or shift amount (in bits).

        Returns:
            The result, masked to :attr:`bit_width` bits.
        """
        ...
