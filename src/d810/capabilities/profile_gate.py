"""Profile-gate capability Protocol.

Describes the backend boundary for live function profile admission --
"does this live function match the conditions a strategy requires to
admit it for processing?".  The default Hodur implementation lives at
``d810.optimizers.microcode.flow.flattening.hodur.profile_gate``;
future angr / Ghidra backends would implement this Protocol next to
their own live-state introspection.

Parameter and return types are annotated as ``Any`` to keep the
``d810.capabilities`` layer free of upward dependencies on
``d810.optimizers`` / vendor-specific live-function types.  Concrete
implementations may type themselves against richer types: Protocol
satisfaction is structural so the widened annotations here do not
constrain consumers.

The ``Any`` choice (vs ``object``) follows the same LSP-contravariance
rationale documented in ``d810.capabilities.constant_fixpoint``.
"""
from __future__ import annotations

from d810.core.typing import Any, Protocol

__all__ = ["HodurProfileGateBackend"]


class HodurProfileGateBackend(Protocol):
    """Backend/profile gate for live Hodur strategy admission.

    Concrete implementations inspect a live function object (e.g.
    ``ida_hexrays.mba_t``) and decide whether it matches the strategy's
    required entry EA + maturity profile.
    """

    def accepts_function(
        self,
        live_function: Any,
        *,
        expected_entry_ea: int,
        required_maturity: str,
    ) -> bool:
        """Return ``True`` when ``live_function`` matches the profile gate."""
