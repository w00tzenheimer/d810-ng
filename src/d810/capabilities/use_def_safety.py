"""Use-def safety capability Protocol + portable result type.

Describes the backend boundary for "would this CFG edit sever a
use-def dominance chain?" queries.  The Hex-Rays implementation
(:class:`HexRaysUseDefSafetyBackend`) lives at
``d810.evaluator.hexrays_microcode.use_def_dominance`` because the
algorithm requires live ``ida_hexrays`` access (DU chains, live
instruction stream, dominator tree over post-mod adjacency).  Future
angr / Ghidra backends would implement this Protocol next to their
own dominance + DU-chain analyses.

``redirect_use_def_violations`` takes ``mod: RedirectIntent`` -- the
portable IR-level intent type at ``d810.ir.redirect`` (slice 10 of
the llvm-lisa-restructure plan).  Call sites convert their CFG-layer
redirect (``RedirectGoto`` / ``RedirectBranch``) into the IR intent
via ``d810.transforms.graph_modification.to_redirect_intent`` immediately
before the capability call; the CFG types stay where they are
because they own ``__post_init__`` construction diagnostics that do
not belong in IR.

``live_function`` and ``pre_cfg`` stay ``Any`` -- ``d810.capabilities``
must not import ``d810.cfg`` (where ``FlowGraph`` lives) or
``ida_hexrays`` (where ``mba_t`` lives).  Protocol method parameter
positions are contravariant, so a concrete impl typing them against
``FlowGraph`` / ``mba_t`` structurally satisfies this contract.

The ``Any`` choice (vs ``object``) on those two parameters follows
the same LSP-contravariance rationale documented in
``d810.capabilities.constant_fixpoint``.

Slice 5 of the llvm-lisa-restructure plan; the canonical home for
``UseDefSafetyCapability``.  The old name ``UseDefSafetyBackend`` is
preserved as a back-compat alias re-exported from
``d810.evaluator.hexrays_microcode.use_def_dominance`` so the two
existing Hodur consumers do not have to update at the same time.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Any, Protocol
from d810.ir.redirect import RedirectIntent

__all__ = ["SeveranceViolation", "UseDefSafetyCapability"]


@dataclass(frozen=True, slots=True)
class SeveranceViolation:
    """A single use-def dominance severance.

    Portable result type.  Lives in the capability layer so any
    backend implementation can construct violations without an upward
    import.

    A violation indicates that after applying the proposed redirect,
    a definition in :attr:`src_block` would no longer dominate a use
    at :attr:`use_block` for the stack variable identified by
    ``(var_stkoff, var_size)``.

    Attributes:
        src_block: Block serial that defines the stack variable.
        new_target: New successor target after the redirect.
        var_stkoff: Stack offset of the affected variable.
        var_size: Operand size in bytes.
        use_block: Block serial of the orphaned use.
        use_ea: Effective address of the orphaned use instruction.
    """

    src_block: int
    new_target: int
    var_stkoff: int
    var_size: int
    use_block: int
    use_ea: int


class UseDefSafetyCapability(Protocol):
    """Capability boundary for use-def redirect safety checks.

    A concrete backend answers: "if I applied this CFG redirect, which
    stack-variable definitions in the source block would stop
    dominating their downstream uses?"  The portable answer is a
    (possibly empty) tuple of :class:`SeveranceViolation` records.
    """

    def redirect_use_def_violations(
        self,
        mod: RedirectIntent,
        live_function: Any,
        pre_cfg: Any,
    ) -> tuple[SeveranceViolation, ...]:
        """Return use-def violations that the proposed redirect would cause.

        Args:
            mod: Portable redirect intent.  Construct via
                ``d810.transforms.graph_modification.to_redirect_intent(mod)``
                at the call site, where ``mod`` is the CFG-layer
                ``RedirectGoto`` / ``RedirectBranch`` the caller will
                also queue with ``DeferredGraphModifier`` if the
                capability returns no violations.
            live_function: The live function representation the
                backend uses to answer DU-chain queries
                (``ida_hexrays.mba_t`` for the Hex-Rays backend;
                an angr AIL function for a future angr backend).
                ``Any`` for layer discipline.
            pre_cfg: Pre-modification CFG snapshot
                (``d810.cfg.flowgraph.FlowGraph`` today).  ``Any`` for
                the same layer-discipline reason as ``live_function``.

        Returns:
            A tuple of :class:`SeveranceViolation`s, empty if the
            redirect preserves all use-def dominance chains.
        """
