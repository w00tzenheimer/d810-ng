"Portable transform-layer Protocols.\n\nCanonical home for the ``OptimizationRule`` Protocol per the\nllvm-lisa-restructure plan (``docs/plans/preanalysis-and-cfg-restructuring.md``)\nand Phase 0 inventory\n(``docs/plans/preanalysis-and-cfg-restructuring-phase0-inventory.md``).\n\nMoved here from ``d810.optimizers.core`` (commit landing this slice)\nonce slice 7 removed the live ``ida_hexrays`` coupling from\n``OptimizationContext``.  No back-compat re-export is left at the old\nlocation -- the canonical import path is::\n\n    from d810.transforms.protocols import OptimizationRule\n\n``OptimizationRule`` is the abstract, backend-neutral contract for\n*any* optimization rule (Hex-Rays microcode, future angr / Ghidra /\nLLVM lifts).  Concrete rule hierarchies under ``d810.optimizers`` (the\n``FlowOptimizationRule`` / ``InstructionOptimizationRule`` / ``CtreeOptimizationRule``\nclasses) satisfy this Protocol structurally; they do not subclass it.\n\nThe ``context`` and ``element`` parameters are typed as ``Any``: the\nProtocol describes the structural contract only, and structural\ntyping of Protocol method parameters is contravariant.  Using\n``object`` would force every conforming implementation to accept\n*any* object (because narrowing a parameter is a contract violation);\n``Any`` opts out of that check so concrete callers can declare\nnarrower parameter types such as\n``d810.optimizers.core.OptimizationContext`` for the Hex-Rays\nintegration path (or any future backend-specific context dataclass).\nThis keeps ``d810.transforms`` free of any ``d810.optimizers`` import\nedge and preserves the portable-core layer order:\n``support < ir < capabilities < analyses < transforms < passes < families < backends``.\n\nWhen the IR slice introduces a lower-layer ``TransformContext``\nProtocol with shared structural fields, tighten ``context: Any``\nhere to ``context: TransformContext`` -- but only AFTER that\ncontract lands; do NOT widen back to ``object``.\n"

from __future__ import annotations

from d810.core.typing import Any, Protocol


class OptimizationRule(Protocol):
    """A protocol defining the contract for any optimization rule.

    This protocol-based interface decouples rules from their execution
    engine, making it easy to test rules in isolation and compose
    different optimization strategies.

    Any class implementing this protocol can be used as an optimization
    rule, regardless of its inheritance hierarchy.
    """

    @property
    def name(self) -> str:
        """A unique identifier for this rule.

        Returns:
            A string uniquely identifying this optimization rule.
        """
        ...

    def apply(self, context: Any, element: Any) -> int:
        """Applies the optimization to a program element.

        This method is the main entry point for rule execution.  It
        receives an immutable context and a program element to
        optimize.

        Args:
            context: The current optimization context.  Typed as
                ``Any`` to keep the Protocol backend-neutral; concrete
                callers narrow it to a backend-specific context
                dataclass (e.g.
                ``d810.optimizers.core.OptimizationContext`` for the
                Hex-Rays integration path).  ``Any`` is used instead
                of ``object`` because Protocol method parameter
                positions are contravariant -- using ``object`` would
                force every implementation to also accept ``object``,
                so narrower impls (``apply(context: OptimizationContext, ...)``)
                would not structurally satisfy the Protocol.
            element: The program element to optimize. This could be:

                - mblock_t for flow-level optimizations
                - minsn_t for instruction-level optimizations
                - any other program element the rule operates on.

        Returns:
            The number of changes made by this rule.  Return 0 if no
            changes were made.  This allows the optimizer to track
            progress and decide when to stop iterating.
        """
        ...


__all__ = ["OptimizationRule"]
