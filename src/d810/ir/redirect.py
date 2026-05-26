"""Portable redirect-intent value types.

These are the IR-layer counterparts of ``d810.cfg.graph_modification.RedirectGoto``
and ``RedirectBranch``: pure data, three integer fields per type, no
construction diagnostics, no CFG-mutation machinery.  They exist so
``UseDefSafetyCapability.redirect_use_def_violations`` can accept a
portable intent value without dragging ``d810.cfg`` into the
``d810.capabilities`` layer (the slice-5 follow-up the capability
docstring records).

Discipline:

* The CFG-layer redirect types KEEP their construction tracing
  (``__post_init__`` diagnostics under
  ``d810.cfg.graph_modification``).  Those are CFG-layer diagnostics
  and must not bleed into ``d810.ir``.
* Call sites build the CFG redirect first (so the construction trace
  fires), then convert to the IR intent only at the capability
  boundary via ``d810.cfg.graph_modification.to_redirect_intent``.
* The IR types are intentionally NOT constructible from CFG objects
  here -- the converter lives next to the CFG types so ``d810.ir``
  carries no upward edge into ``d810.cfg``.

LLVM analog: ``llvm::IR::Instruction`` carries identity + operands;
the diagnostic / dwarf metadata sits on a sibling object.  Same split
here: pure intent in IR, diagnostics in CFG.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import TypeAlias

__all__ = ["RedirectBranchIntent", "RedirectGotoIntent", "RedirectIntent"]


@dataclass(frozen=True, slots=True)
class RedirectGotoIntent:
    """Intent: redirect the unconditional successor of a 1-way block.

    Portable counterpart of ``d810.cfg.graph_modification.RedirectGoto``.
    Capability consumers see this; the CFG-layer ``RedirectGoto`` is
    what actually gets queued into ``DeferredGraphModifier``.

    Attributes:
        from_serial: Source block serial number (must be a 1-way block).
        old_target: Current goto target block serial.
        new_target: New goto target block serial.
    """

    from_serial: int
    old_target: int
    new_target: int


@dataclass(frozen=True, slots=True)
class RedirectBranchIntent:
    """Intent: redirect one branch edge of a 2-way block.

    Portable counterpart of ``d810.cfg.graph_modification.RedirectBranch``.

    Attributes:
        from_serial: Source block serial number (must be a 2-way block).
        old_target: Current branch target block serial to be replaced.
        new_target: New branch target block serial.
    """

    from_serial: int
    old_target: int
    new_target: int


RedirectIntent: TypeAlias = "RedirectGotoIntent | RedirectBranchIntent"
"""Union of the two redirect-intent shapes.

Used by ``UseDefSafetyCapability.redirect_use_def_violations`` as the
narrowest type that covers all five active call sites.  Concrete
backend impls accept this union and dispatch on the runtime type.
"""
